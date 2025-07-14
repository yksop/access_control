import hashlib
import hmac
import qrcode
import secrets
import base64
import json
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS
import os
import sys
import select
import tty
import termios
import time
import threading
import uuid
import paho.mqtt.client as mqtt

try:
    from picamera2 import Picamera2, Preview
    from pyzbar import pyzbar
    CAMERA_AVAILABLE = True
except ImportError:
    CAMERA_AVAILABLE = False

INFLUX_URL = "http://localhost:8086"
INFLUX_TOKEN = "to6IrrBSsr9TC4lfA64puJ2K5p5agfhexdwJ0cR1plJB0yfN8xKRfTJKijYIpz9s0JQ4axkl2FNgL3hOSCQT0g=="
INFLUX_ORG = "Unitn"
INFLUX_BUCKET = "access_control"

MQTT_BROKER = "localhost"
MQTT_PORT = 1883
MQTT_KEEPALIVE = 60
MQTT_CLIENT_ID = "bnb_backend"

MQTT_TOPICS = {
    "guest_auth_request": "bnb/guest/auth/request",
    "guest_auth_response": "bnb/guest/auth/response",
    "qr_generate_request": "bnb/qr/generate/request",
    "qr_generate_response": "bnb/qr/generate/response",
    "qr_validate_request": "bnb/qr/validate/request",
    "qr_validate_response": "bnb/qr/validate/response",
    "access_event": "bnb/access/event",
    "system_status": "bnb/system/status",
    "guest_add_request": "bnb/guest/add/request",
    "guest_add_response": "bnb/guest/add/response",
    "guest_list_request": "bnb/guest/list/request",
    "guest_list_response": "bnb/guest/list/response"
}

TEMP_QR_LIFETIME_SECONDS = 15
MAX_AUTH_ATTEMPTS = 3
AUTH_LOCKOUT_MINUTES = 10
MASTER_SECRET = "BnB_MASTER_SECRET_2025"


class MQTTHandler:
    """Handles MQTT communication"""

    def __init__(self, bnb_system):
        self.bnb_system = bnb_system
        self.client = mqtt.Client(client_id=MQTT_CLIENT_ID)
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.client.on_disconnect = self.on_disconnect
        self.connected = False

    def connect(self):
        """Connect to MQTT broker"""
        try:
            self.client.connect(MQTT_BROKER, MQTT_PORT, MQTT_KEEPALIVE)
            self.client.loop_start()
            return True
        except Exception as e:
            print(f"MQTT connection error: {e}")
            return False

    def disconnect(self):
        """Disconnect from MQTT broker"""
        self.client.loop_stop()
        self.client.disconnect()

    def on_connect(self, client, userdata, flags, rc):
        """Callback for MQTT connection"""
        if rc == 0:
            self.connected = True
            print("Connected to MQTT broker")

            for topic in [
                MQTT_TOPICS["guest_auth_request"],
                MQTT_TOPICS["qr_generate_request"],
                MQTT_TOPICS["qr_validate_request"],
                MQTT_TOPICS["guest_add_request"],
                MQTT_TOPICS["guest_list_request"]
            ]:
                client.subscribe(topic)
                print(f"Subscribed to {topic}")
        else:
            print(f"MQTT connection failed with code {rc}")

    def on_disconnect(self, client, userdata, rc):
        """Callback for MQTT disconnection"""
        self.connected = False
        print("Disconnected from MQTT broker")

    def on_message(self, client, userdata, msg):
        """Handle incoming MQTT messages"""
        try:
            topic = msg.topic
            payload = json.loads(msg.payload.decode())
            print(f"Received message on {topic}: {payload}")

            if topic == MQTT_TOPICS["guest_auth_request"]:
                self.handle_guest_auth_request(payload)
            elif topic == MQTT_TOPICS["qr_generate_request"]:
                self.handle_qr_generate_request(payload)
            elif topic == MQTT_TOPICS["qr_validate_request"]:
                self.handle_qr_validate_request(payload)
            elif topic == MQTT_TOPICS["guest_add_request"]:
                self.handle_guest_add_request(payload)
            elif topic == MQTT_TOPICS["guest_list_request"]:
                self.handle_guest_list_request(payload)

        except Exception as e:
            print(f"Error handling MQTT message: {e}")

    def publish(self, topic, payload):
        """Publish message to MQTT topic"""
        try:
            if self.connected:
                self.client.publish(topic, json.dumps(payload))
                return True
            else:
                print("MQTT not connected")
                return False
        except Exception as e:
            print(f"Error publishing MQTT message: {e}")
            return False

    def handle_guest_auth_request(self, payload):
        """Handle guest authentication request"""
        try:
            guest_id = payload.get("guest_id")
            pin_code = payload.get("pin_code")
            request_id = payload.get("request_id", str(uuid.uuid4()))

            if not guest_id or not pin_code:
                response = {
                    "request_id": request_id,
                    "success": False,
                    "message": "Missing guest_id or pin_code"
                }
            else:
                auth_success, auth_result = self.bnb_system.authenticator.authenticate_guest(
                    guest_id, pin_code)

                if auth_success:
                    response = {
                        "request_id": request_id,
                        "success": True,
                        "guest_data": {
                            "guest_id": auth_result["guest_id"],
                            "room": auth_result["room"],
                            "check_in": auth_result["check_in"],
                            "check_out": auth_result["check_out"]
                        }
                    }
                else:
                    response = {
                        "request_id": request_id,
                        "success": False,
                        "message": auth_result
                    }

            self.publish(MQTT_TOPICS["guest_auth_response"], response)

        except Exception as e:
            response = {
                "request_id": payload.get("request_id", "unknown"),
                "success": False,
                "message": f"Server error: {str(e)}"
            }
            self.publish(MQTT_TOPICS["guest_auth_response"], response)

    def handle_qr_generate_request(self, payload):
        """Handle QR generation request"""
        try:
            guest_id = payload.get("guest_id")
            pin_code = payload.get("pin_code")
            request_id = payload.get("request_id", str(uuid.uuid4()))

            if not guest_id or not pin_code:
                response = {
                    "request_id": request_id,
                    "success": False,
                    "message": "Missing guest_id or pin_code"
                }
            else:
                success, qr_file = self.bnb_system.authenticate_and_generate_qr(
                    guest_id, pin_code)

                if success:
                    qr_data = self.bnb_system.temp_qr_manager.get_last_generated_qr()

                    response = {
                        "request_id": request_id,
                        "success": True,
                        "qr_data": qr_data,
                        "qr_file": qr_file,
                        "expires_in": TEMP_QR_LIFETIME_SECONDS
                    }
                else:
                    response = {
                        "request_id": request_id,
                        "success": False,
                        "message": qr_file
                    }

            self.publish(MQTT_TOPICS["qr_generate_response"], response)

        except Exception as e:
            response = {
                "request_id": payload.get("request_id", "unknown"),
                "success": False,
                "message": f"Server error: {str(e)}"
            }
            self.publish(MQTT_TOPICS["qr_generate_response"], response)

    def handle_qr_validate_request(self, payload):
        """Handle QR validation request"""
        try:
            qr_data = payload.get("qr_data")
            request_id = payload.get("request_id", str(uuid.uuid4()))

            if not qr_data:
                response = {
                    "request_id": request_id,
                    "success": False,
                    "message": "Missing qr_data"
                }
            else:
                valid, result = self.bnb_system.validate_access_qr(qr_data)

                response = {
                    "request_id": request_id,
                    "success": valid,
                    "message": result
                }

                if valid:
                    self.publish(MQTT_TOPICS["access_event"], {
                        "timestamp": datetime.now().isoformat(),
                        "event_type": "access_granted",
                        "message": result
                    })

            self.publish(MQTT_TOPICS["qr_validate_response"], response)

        except Exception as e:
            response = {
                "request_id": payload.get("request_id", "unknown"),
                "success": False,
                "message": f"Server error: {str(e)}"
            }
            self.publish(MQTT_TOPICS["qr_validate_response"], response)

    def handle_guest_add_request(self, payload):
        """Handle add guest request"""
        try:
            guest_id = payload.get("guest_id")
            room = payload.get("room")
            check_in = payload.get("check_in")
            check_out = payload.get("check_out")
            request_id = payload.get("request_id", str(uuid.uuid4()))

            if not all([guest_id, room, check_in, check_out]):
                response = {
                    "request_id": request_id,
                    "success": False,
                    "message": "Missing required fields"
                }
            else:
                success, pin = self.bnb_system.add_guest(
                    guest_id, room, check_in, check_out)

                if success:
                    response = {
                        "request_id": request_id,
                        "success": True,
                        "guest_id": guest_id,
                        "pin": pin,
                        "room": room
                    }
                else:
                    response = {
                        "request_id": request_id,
                        "success": False,
                        "message": "Failed to add guest"
                    }

            self.publish(MQTT_TOPICS["guest_add_response"], response)

        except Exception as e:
            response = {
                "request_id": payload.get("request_id", "unknown"),
                "success": False,
                "message": f"Server error: {str(e)}"
            }
            self.publish(MQTT_TOPICS["guest_add_response"], response)

    def handle_guest_list_request(self, payload):
        """Handle guest list request"""
        try:
            request_id = payload.get("request_id", str(uuid.uuid4()))

            guests = self.bnb_system.get_active_guests_list()

            response = {
                "request_id": request_id,
                "success": True,
                "guests": guests
            }

            self.publish(MQTT_TOPICS["guest_list_response"], response)

        except Exception as e:
            response = {
                "request_id": payload.get("request_id", "unknown"),
                "success": False,
                "message": f"Server error: {str(e)}"
            }
            self.publish(MQTT_TOPICS["guest_list_response"], response)

    def publish_system_status(self):
        """Publish system status"""
        try:
            status = {
                "timestamp": datetime.now().isoformat(),
                "active_qr_codes": self.bnb_system.temp_qr_manager.get_active_count(),
                "qr_lifetime": TEMP_QR_LIFETIME_SECONDS,
                "camera_available": CAMERA_AVAILABLE,
                "locked_accounts": len([
                    guest_id for guest_id, data in self.bnb_system.authenticator.failed_attempts.items()
                    if self.bnb_system.authenticator._is_locked_out(guest_id)
                ])
            }

            self.publish(MQTT_TOPICS["system_status"], status)

        except Exception as e:
            print(f"Error publishing system status: {e}")


class TemporaryQRManager:
    """Manages temporary QR codes with automatic cleanup"""

    def __init__(self):
        self.active_qrs = {}
        self.last_generated = None
        self.cleanup_thread = threading.Thread(
            target=self._cleanup_expired, daemon=True)
        self.cleanup_thread.start()

    def generate_temp_qr(self, guest_id, room, access_type="entry"):
        """Generate temporary QR code"""
        qr_id = str(uuid.uuid4())
        expires_at = datetime.now() + timedelta(seconds=TEMP_QR_LIFETIME_SECONDS)

        qr_data = {
            "qr_id": qr_id,
            "guest_id": guest_id,
            "room": room,
            "access_type": access_type,
            "expires_at": expires_at.isoformat(),
            "created_at": datetime.now().isoformat()
        }

        qr_json = json.dumps(qr_data, separators=(',', ':'))
        signature = hmac.new(
            MASTER_SECRET.encode(),
            qr_json.encode(),
            hashlib.sha256
        ).hexdigest()

        final_qr = {
            "data": qr_data,
            "signature": signature
        }

        self.active_qrs[qr_id] = {
            "data": qr_data,
            "expires_at": expires_at
        }

        qr_string = json.dumps(final_qr, separators=(',', ':'))
        self.last_generated = qr_string

        return qr_string

    def get_last_generated_qr(self):
        """Get last generated QR code for mobile app"""
        return self.last_generated

    def validate_temp_qr(self, qr_string):
        """Validate temporary QR code"""
        try:
            qr_obj = json.loads(qr_string)
            qr_data = qr_obj["data"]
            received_signature = qr_obj["signature"]

            qr_json = json.dumps(qr_data, separators=(',', ':'))
            expected_signature = hmac.new(
                MASTER_SECRET.encode(),
                qr_json.encode(),
                hashlib.sha256
            ).hexdigest()

            if not hmac.compare_digest(received_signature, expected_signature):
                return False, "Invalid QR signature"

            qr_id = qr_data["qr_id"]

            if qr_id not in self.active_qrs:
                return False, "QR code not found or expired"

            stored_qr = self.active_qrs[qr_id]
            if datetime.now() > stored_qr["expires_at"]:
                del self.active_qrs[qr_id]
                return False, "QR code expired"

            del self.active_qrs[qr_id]

            return True, qr_data

        except Exception as e:
            return False, f"QR validation error: {str(e)}"

    def _cleanup_expired(self):
        """Background cleanup of expired QR codes"""
        while True:
            try:
                now = datetime.now()
                expired_ids = [
                    qr_id for qr_id, qr_info in self.active_qrs.items()
                    if now > qr_info["expires_at"]
                ]

                for qr_id in expired_ids:
                    del self.active_qrs[qr_id]

                time.sleep(5)
            except Exception:
                time.sleep(5)

    def get_active_count(self):
        """Get number of active QR codes"""
        return len(self.active_qrs)


class GuestAuthenticator:
    """Handles guest authentication with PIN system"""

    def __init__(self, db_client):
        self.db_client = db_client
        self.failed_attempts = {}

    def authenticate_guest(self, guest_id, pin_code):
        """Authenticate guest with ID and PIN"""

        if self._is_locked_out(guest_id):
            remaining = self._get_lockout_remaining(guest_id)
            return False, f"Account locked. Try again in {remaining} minutes"

        guest_data = self._get_guest_data(guest_id)
        if not guest_data:
            self._record_failed_attempt(guest_id)
            return False, "Guest not found"

        if not self._verify_pin(guest_data, pin_code):
            self._record_failed_attempt(guest_id)
            return False, "Invalid PIN"

        if not self._is_booking_valid(guest_data):
            return False, "Booking not valid for current time"

        if guest_id in self.failed_attempts:
            del self.failed_attempts[guest_id]

        return True, guest_data

    def _get_guest_data(self, guest_id):
        """Get guest data from database"""
        try:
            query = f'''
            from(bucket: "{INFLUX_BUCKET}")
            |> range(start: -30d)
            |> filter(fn: (r) => r["_measurement"] == "authorized_guests")
            |> filter(fn: (r) => r["guest_id"] == "{guest_id}")
            |> filter(fn: (r) => r["_field"] == "active")
            |> last()
            '''

            query_api = self.db_client.query_api()
            tables = query_api.query(query, org=INFLUX_ORG)

            if tables and tables[0].records:
                record = tables[0].records[0]
                if record.get_value():
                    return {
                        "guest_id": record.values.get("guest_id"),
                        "room": record.values.get("room"),
                        "pin": record.values.get("pin"),
                        "check_in": record.values.get("check_in"),
                        "check_out": record.values.get("check_out")
                    }
            return None

        except Exception:
            return None

    def _verify_pin(self, guest_data, pin_code):
        """Verify PIN code"""
        stored_pin = guest_data.get("pin")
        if not stored_pin:
            return False
        return stored_pin == pin_code

    def _is_booking_valid(self, guest_data):
        """Check if booking is valid for current time"""
        try:
            now = datetime.now()
            check_in = datetime.fromisoformat(guest_data["check_in"])
            check_out = datetime.fromisoformat(guest_data["check_out"])
            return check_in <= now <= check_out
        except Exception:
            return False

    def _is_locked_out(self, guest_id):
        """Check if guest is locked out"""
        if guest_id not in self.failed_attempts:
            return False

        attempts = self.failed_attempts[guest_id]
        if attempts["count"] >= MAX_AUTH_ATTEMPTS:
            lockout_until = attempts["locked_until"]
            return datetime.now() < lockout_until

        return False

    def _get_lockout_remaining(self, guest_id):
        """Get remaining lockout time in minutes"""
        if guest_id not in self.failed_attempts:
            return 0

        lockout_until = self.failed_attempts[guest_id]["locked_until"]
        remaining = lockout_until - datetime.now()
        return max(0, int(remaining.total_seconds() / 60))

    def _record_failed_attempt(self, guest_id):
        """Record failed authentication attempt"""
        now = datetime.now()

        if guest_id not in self.failed_attempts:
            self.failed_attempts[guest_id] = {
                "count": 1,
                "first_attempt": now,
                "locked_until": None
            }
        else:
            self.failed_attempts[guest_id]["count"] += 1

        if self.failed_attempts[guest_id]["count"] >= MAX_AUTH_ATTEMPTS:
            self.failed_attempts[guest_id]["locked_until"] = now + \
                timedelta(minutes=AUTH_LOCKOUT_MINUTES)


class BnBSystem:
    """B&B system with MQTT integration"""

    def __init__(self):
        self.client = InfluxDBClient(
            url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
        self.write_api = self.client.write_api(write_options=SYNCHRONOUS)
        self.temp_qr_manager = TemporaryQRManager()
        self.authenticator = GuestAuthenticator(self.client)
        self.mqtt_handler = MQTTHandler(self)
        self.picam2 = None

        self.mqtt_handler.connect()

        self.status_thread = threading.Thread(
            target=self._publish_status_periodically, daemon=True)
        self.status_thread.start()

    def _publish_status_periodically(self):
        """Publish system status every 30 seconds"""
        while True:
            try:
                self.mqtt_handler.publish_system_status()
                time.sleep(30)
            except Exception:
                time.sleep(30)

    def generate_guest_pin(self):
        """Generate secure 6-digit PIN"""
        return f"{secrets.randbelow(900000) + 100000}"

    def add_guest(self, guest_id, room, check_in_date, check_out_date):
        """Add guest with auto-generated PIN"""
        try:
            pin = self.generate_guest_pin()

            point = Point("authorized_guests") \
                .tag("guest_id", guest_id) \
                .tag("room", room) \
                .tag("pin", pin) \
                .field("active", True) \
                .tag("check_in", check_in_date) \
                .tag("check_out", check_out_date) \
                .time(datetime.utcnow(), WritePrecision.NS)

            self.write_api.write(bucket=INFLUX_BUCKET,
                                 org=INFLUX_ORG, record=point)

            print(f"Guest {guest_id} added for {room}")
            print(f"Period: {check_in_date} → {check_out_date}")
            print(f"PIN: {pin}")

            return True, pin

        except Exception as e:
            print(f"Error adding guest: {e}")
            return False, None

    def get_active_guests_list(self):
        """Get list of active guests for MQTT response"""
        try:
            query = f'''
            from(bucket: "{INFLUX_BUCKET}")
            |> range(start: -30d)
            |> filter(fn: (r) => r["_measurement"] == "authorized_guests")
            |> filter(fn: (r) => r["_field"] == "active")
            |> group(columns: ["guest_id", "room"])
            |> last()
            '''

            query_api = self.client.query_api()
            tables = query_api.query(query, org=INFLUX_ORG)

            guests = []
            if tables and tables[0].records:
                for table in tables:
                    for record in table.records:
                        if record.get_value():
                            guests.append({
                                "guest_id": record.values.get("guest_id"),
                                "room": record.values.get("room"),
                                "pin": record.values.get("pin"),
                                "check_in": record.values.get("check_in"),
                                "check_out": record.values.get("check_out")
                            })

            return guests

        except Exception as e:
            print(f"Error getting guests list: {e}")
            return []

    def authenticate_and_generate_qr(self, guest_id, pin_code):
        """Authenticate guest and generate temporary QR"""
        auth_success, auth_result = self.authenticator.authenticate_guest(
            guest_id, pin_code)

        if not auth_success:
            print(f"Authentication failed: {auth_result}")
            return False, auth_result

        guest_data = auth_result

        qr_string = self.temp_qr_manager.generate_temp_qr(
            guest_data["guest_id"],
            guest_data["room"]
        )

        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(qr_string)
        qr.make(fit=True)

        os.makedirs("./temp_qr", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        qr_filename = f"./temp_qr/temp_qr_{guest_id}_{timestamp}.png"
        qr_img = qr.make_image(fill_color="black", back_color="white")
        qr_img.save(qr_filename)

        print(f"Temporary QR generated for {guest_id}")
        print(f"Valid for {TEMP_QR_LIFETIME_SECONDS} seconds")
        print(f"QR saved: {qr_filename}")

        return True, qr_filename

    def validate_access_qr(self, qr_string):
        """Validate access QR code"""
        valid, result = self.temp_qr_manager.validate_temp_qr(qr_string)

        if not valid:
            self.log_access_event("unknown", "unknown", "entry", False, result)
            return False, result

        qr_data = result
        guest_id = qr_data["guest_id"]
        room = qr_data["room"]
        access_type = qr_data["access_type"]

        self.log_access_event(guest_id, room, access_type,
                              True, "Access granted")

        return True, f"Access granted - {guest_id} ({room})"

    def log_access_event(self, guest_id, room, access_type, success, message):
        """Log access event"""
        try:
            point = Point("access_events") \
                .tag("guest_id", guest_id) \
                .tag("room", room) \
                .tag("access_type", access_type) \
                .tag("success", str(success)) \
                .field("message", message) \
                .field("timestamp", datetime.now().isoformat()) \
                .time(datetime.utcnow(), WritePrecision.NS)

            self.write_api.write(bucket=INFLUX_BUCKET,
                                 org=INFLUX_ORG, record=point)

        except Exception as e:
            print(f"Error logging access: {e}")

    def get_key(self):
        """Non-blocking key detection"""
        if not CAMERA_AVAILABLE:
            return None

        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            if select.select([sys.stdin], [], [], 0.01)[0]:
                return sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        return None

    def scan_qr_code(self, image_array):
        """Scan QR code from image"""
        if not CAMERA_AVAILABLE:
            return False, None

        qr_codes = pyzbar.decode(image_array)
        if qr_codes:
            return True, qr_codes[0].data.decode('utf-8')
        return False, None

    def start_access_scanner(self):
        """Start QR scanner for access control"""
        if not CAMERA_AVAILABLE:
            print("Camera not available - test mode")
            while True:
                qr_data = input("Enter QR code (or 'q' to quit): ").strip()
                if qr_data.lower() == 'q':
                    break
                if qr_data:
                    valid, message = self.validate_access_qr(qr_data)
                    if valid:
                        print(f"SUCCESS: {message}")
                    else:
                        print(f"DENIED: {message}")
            return

        try:
            print("Starting access scanner...")
            self.picam2 = Picamera2()

            camera_config = self.picam2.create_still_configuration(
                main={"size": (1920, 1080)},
                lores={"size": (640, 480)},
                display="lores"
            )
            self.picam2.configure(camera_config)
            self.picam2.start_preview(Preview.QTGL)
            self.picam2.start()

            print("Scanner active - Press 'q' to exit")

            while True:
                key = self.get_key()
                if key == 'q':
                    break

                try:
                    image_array = self.picam2.capture_array("lores")
                    qr_found, qr_data = self.scan_qr_code(image_array)

                    if qr_found:
                        valid, message = self.validate_access_qr(qr_data)
                        if valid:
                            print(f"ACCESS GRANTED: {message}")
                        else:
                            print(f"ACCESS DENIED: {message}")

                        time.sleep(2)

                except Exception as e:
                    print(f"Scan error: {e}")

                time.sleep(0.1)

        except Exception as e:
            print(f"Camera error: {e}")
        finally:
            if self.picam2:
                self.picam2.stop()

    def guest_auth_interface(self):
        """Interactive guest authentication interface"""
        while True:
            print("\n=== GUEST AUTHENTICATION ===")
            print("1. Generate access QR")
            print("2. Back to main menu")

            choice = input("Choose option (1-2): ").strip()

            if choice == "1":
                guest_id = input("Enter Guest ID: ").strip()
                pin_code = input("Enter PIN: ").strip()

                success, qr_file = self.authenticate_and_generate_qr(
                    guest_id, pin_code)
                if success:
                    print(f"QR code ready: {qr_file}")
                    print(
                        f"Show QR to scanner within {TEMP_QR_LIFETIME_SECONDS} seconds")

            elif choice == "2":
                break
            else:
                print("Invalid option")

    def management_interface(self):
        """Management interface for adding guests"""
        while True:
            print("\n=== MANAGEMENT ===")
            print("1. Add new guest")
            print("2. List active guests")
            print("3. View access log")
            print("4. System status")
            print("5. Back to main menu")

            choice = input("Choose option (1-5): ").strip()

            if choice == "1":
                guest_id = input("Guest ID: ").strip()
                room = input("Room: ").strip()

                default_checkin = datetime.now().replace(
                    hour=15, minute=0, second=0, microsecond=0)
                default_checkout = (
                    default_checkin + timedelta(days=1)).replace(hour=11, minute=0)

                checkin_str = input(
                    f"Check-in (YYYY-MM-DD HH:MM) [{default_checkin.strftime('%Y-%m-%d %H:%M')}]: ").strip()
                if not checkin_str:
                    checkin_str = default_checkin.isoformat()
                else:
                    try:
                        checkin_str = datetime.strptime(
                            checkin_str, "%Y-%m-%d %H:%M").isoformat()
                    except:
                        print("Invalid date format")
                        continue

                checkout_str = input(
                    f"Check-out (YYYY-MM-DD HH:MM) [{default_checkout.strftime('%Y-%m-%d %H:%M')}]: ").strip()
                if not checkout_str:
                    checkout_str = default_checkout.isoformat()
                else:
                    try:
                        checkout_str = datetime.strptime(
                            checkout_str, "%Y-%m-%d %H:%M").isoformat()
                    except:
                        print("Invalid date format")
                        continue

                self.add_guest(guest_id, room, checkin_str, checkout_str)

            elif choice == "2":
                self.list_active_guests()

            elif choice == "3":
                self.view_access_log()

            elif choice == "4":
                self.show_system_status()

            elif choice == "5":
                break
            else:
                print("Invalid option")

    def list_active_guests(self):
        """List active guests"""
        try:
            query = f'''
            from(bucket: "{INFLUX_BUCKET}")
            |> range(start: -30d)
            |> filter(fn: (r) => r["_measurement"] == "authorized_guests")
            |> filter(fn: (r) => r["_field"] == "active")
            |> group(columns: ["guest_id", "room"])
            |> last()
            '''

            query_api = self.client.query_api()
            tables = query_api.query(query, org=INFLUX_ORG)

            if not tables or not tables[0].records:
                print("No active guests")
                return

            print("\nACTIVE GUESTS:")
            print("-" * 40)

            for table in tables:
                for record in table.records:
                    if record.get_value():
                        guest_id = record.values.get("guest_id")
                        room = record.values.get("room")
                        pin = record.values.get("pin")
                        print(f"{guest_id} → {room} (PIN: {pin})")

        except Exception as e:
            print(f"Error listing guests: {e}")

    def view_access_log(self, hours=24):
        """View recent access log"""
        try:
            query = f'''
            from(bucket: "{INFLUX_BUCKET}")
            |> range(start: -{hours}h)
            |> filter(fn: (r) => r["_measurement"] == "access_events")
            |> sort(columns: ["_time"], desc: true)
            |> limit(n: 20)
            '''

            query_api = self.client.query_api()
            tables = query_api.query(query, org=INFLUX_ORG)

            if not tables or not tables[0].records:
                print("No access events")
                return

            print(f"\nACCESS LOG (last {hours} hours):")
            print("-" * 60)

            for record in tables[0].records:
                if record.get_field() == "message":
                    timestamp = record.get_time().strftime("%d/%m/%Y %H:%M:%S")
                    guest_id = record.values.get("guest_id", "N/A")
                    room = record.values.get("room", "N/A")
                    access_type = record.values.get("access_type", "N/A")
                    success = record.values.get("success", "N/A")
                    message = record.get_value()

                    status = "OK" if success == "True" else "DENIED"
                    print(
                        f"{timestamp} | {guest_id} | {room} | {access_type} | {status} | {message}")

        except Exception as e:
            print(f"Error viewing log: {e}")

    def show_system_status(self):
        """Show system status"""
        print("\nSYSTEM STATUS:")
        print("-" * 30)
        print(f"MQTT connected: {self.mqtt_handler.connected}")
        print(
            f"Active temporary QR codes: {self.temp_qr_manager.get_active_count()}")
        print(f"QR code lifetime: {TEMP_QR_LIFETIME_SECONDS} seconds")
        print(f"Max auth attempts: {MAX_AUTH_ATTEMPTS}")
        print(f"Auth lockout: {AUTH_LOCKOUT_MINUTES} minutes")
        print(f"Camera available: {CAMERA_AVAILABLE}")

        locked_accounts = [
            guest_id for guest_id, data in self.authenticator.failed_attempts.items()
            if self.authenticator._is_locked_out(guest_id)
        ]

        if locked_accounts:
            print(f"Locked accounts: {', '.join(locked_accounts)}")
        else:
            print("No locked accounts")

    def close(self):
        """Close connections"""
        if self.picam2:
            self.picam2.stop()
        self.mqtt_handler.disconnect()
        self.client.close()


def main():
    """Main application with MQTT support"""
    system = BnBSystem()

    try:
        health = system.client.health()
        print(f"Database connected: {health.status}")
    except Exception as e:
        print(f"Database connection error: {e}")
        return

    while True:
        print("\n=== MAIN MENU ===")
        print("1. Guest Authentication (Generate QR)")
        print("2. Access Scanner")
        print("3. Management")
        print("4. MQTT Status")
        print("5. Exit")

        choice = input("Choose option (1-5): ").strip()

        if choice == "1":
            system.guest_auth_interface()
        elif choice == "2":
            system.start_access_scanner()
        elif choice == "3":
            system.management_interface()
        elif choice == "4":
            print(
                f"MQTT Status: {'Connected' if system.mqtt_handler.connected else 'Disconnected'}")
            if not system.mqtt_handler.connected:
                print("Attempting to reconnect...")
                system.mqtt_handler.connect()
        elif choice == "5":
            break
        else:
            print("Invalid option")

    system.close()


if __name__ == "__main__":
    main()
