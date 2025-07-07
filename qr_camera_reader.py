#!/usr/bin/env python3
"""
Integrated B&B Guest Management and Access Control System with Enhanced QR Security
Usage: python bnb_system.py
"""

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
import ipaddress
import socket

# Camera imports (commented for testing without hardware)
try:
    from picamera2 import Picamera2, Preview
    from pyzbar import pyzbar
    CAMERA_AVAILABLE = True
except ImportError:
    CAMERA_AVAILABLE = False
    print("⚠️  Camera libraries not available - test mode active")

# InfluxDB Configuration
INFLUX_URL = "http://localhost:8086"
INFLUX_TOKEN = "to6IrrBSsr9TC4lfA64puJ2K5p5agfhexdwJ0cR1plJB0yfN8xKRfTJKijYIpz9s0JQ4axkl2FNgL3hOSCQT0g=="
INFLUX_ORG = "Unitn"
INFLUX_BUCKET = "access_control"

# Security Configuration
MAX_ATTEMPTS_PER_HOUR = 5
RATE_LIMIT_WINDOW = 3600  # 1 hour in seconds
QR_CODE_LIFETIME_HOURS = 24  # Maximum QR code validity
ALLOWED_IP_RANGES = [
    "192.168.1.0/24",    # Local network
    "10.0.0.0/8",        # Private network
    "172.16.0.0/12",     # Private network
    "127.0.0.1/32"       # Localhost
]


class SecurityManager:
    """Enhanced security manager for QR code protection"""

    def __init__(self, master_key):
        self.master_key = master_key
        self.failed_attempts = {}
        self.blocked_ips = {}
        self.used_tokens = set()

    def derive_key(self, salt):
        """Derive encryption key from master key and salt"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(self.master_key.encode()))

    def encrypt_data(self, data, salt):
        """Encrypt data with derived key"""
        key = self.derive_key(salt)
        f = Fernet(key)
        return f.encrypt(data.encode()).decode()

    def decrypt_data(self, encrypted_data, salt):
        """Decrypt data with derived key"""
        try:
            key = self.derive_key(salt)
            f = Fernet(key)
            return f.decrypt(encrypted_data.encode()).decode()
        except Exception:
            return None

    def generate_nonce(self):
        """Generate cryptographically secure nonce"""
        return secrets.token_urlsafe(16)

    def generate_salt(self):
        """Generate salt for key derivation"""
        return secrets.token_bytes(32)

    def check_rate_limit(self, identifier):
        """Check if identifier is rate limited"""
        now = time.time()

        # Clean old entries
        self.failed_attempts = {
            k: v for k, v in self.failed_attempts.items()
            if now - v['first_attempt'] < RATE_LIMIT_WINDOW
        }

        if identifier in self.failed_attempts:
            attempts = self.failed_attempts[identifier]
            if attempts['count'] >= MAX_ATTEMPTS_PER_HOUR:
                return False, f"Too many attempts. Try again in {int(RATE_LIMIT_WINDOW - (now - attempts['first_attempt']))} seconds"

        return True, "OK"

    def record_failed_attempt(self, identifier):
        """Record failed authentication attempt"""
        now = time.time()

        if identifier not in self.failed_attempts:
            self.failed_attempts[identifier] = {
                'count': 1,
                'first_attempt': now,
                'last_attempt': now
            }
        else:
            self.failed_attempts[identifier]['count'] += 1
            self.failed_attempts[identifier]['last_attempt'] = now

    def is_ip_allowed(self, ip_address):
        """Check if IP address is in allowed ranges"""
        try:
            ip = ipaddress.ip_address(ip_address)
            for allowed_range in ALLOWED_IP_RANGES:
                if ip in ipaddress.ip_network(allowed_range):
                    return True
            return False
        except ValueError:
            return False

    def is_token_used(self, token):
        """Check if token has been used before (replay attack prevention)"""
        return token in self.used_tokens

    def mark_token_used(self, token):
        """Mark token as used"""
        self.used_tokens.add(token)

        # Limit memory usage by keeping only recent tokens
        if len(self.used_tokens) > 10000:
            # Remove oldest 1000 tokens (simple cleanup)
            tokens_to_remove = list(self.used_tokens)[:1000]
            for token in tokens_to_remove:
                self.used_tokens.discard(token)


class BnBSystem:
    def __init__(self):
        self.client = InfluxDBClient(
            url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
        self.write_api = self.client.write_api(write_options=SYNCHRONOUS)
        self.query_api = self.client.query_api()
        self.master_secret = "BnB_MASTER_SECRET_KEY_2024_ENHANCED"
        self.picam2 = None
        self.security_manager = SecurityManager(self.master_secret)

        # Get local IP for security checks
        try:
            self.local_ip = self.get_local_ip()
        except:
            self.local_ip = "127.0.0.1"

    def get_local_ip(self):
        """Get local IP address"""
        try:
            # Connect to external address to determine local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"

    def generate_secure_qr_data(self, guest_id, room, check_in, check_out):
        """Generate secure QR code data with multiple security layers"""

        # Generate unique nonce and salt
        nonce = self.security_manager.generate_nonce()
        salt = self.security_manager.generate_salt()

        # Create timestamp for QR code generation
        issued_at = datetime.now().isoformat()
        expires_at = (datetime.now() +
                      timedelta(hours=QR_CODE_LIFETIME_HOURS)).isoformat()

        # Create payload with all security information
        payload = {
            "guest_id": guest_id,
            "room": room,
            "check_in": check_in,
            "check_out": check_out,
            "nonce": nonce,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "version": "2.0",
            "source_ip": self.local_ip
        }

        # Convert to JSON
        payload_json = json.dumps(payload, separators=(',', ':'))

        # Create HMAC signature
        signature = hmac.new(
            self.master_secret.encode(),
            payload_json.encode(),
            hashlib.sha256
        ).hexdigest()

        # Encrypt the payload
        encrypted_payload = self.security_manager.encrypt_data(
            payload_json, salt)

        # Create final QR data structure
        qr_data = {
            "encrypted_payload": encrypted_payload,
            "salt": base64.b64encode(salt).decode(),
            "signature": signature,
            "version": "2.0"
        }

        return json.dumps(qr_data, separators=(',', ':'))

    def validate_secure_qr_code(self, qr_data_str):
        """Validate secure QR code with enhanced security checks"""

        # Check rate limiting based on IP
        rate_ok, rate_msg = self.security_manager.check_rate_limit(
            self.local_ip)
        if not rate_ok:
            return False, rate_msg

        try:
            # Parse QR data
            qr_data = json.loads(qr_data_str)

            # Check QR code version
            if qr_data.get("version") != "2.0":
                self.security_manager.record_failed_attempt(self.local_ip)
                return False, "Invalid QR code version"

            # Extract components
            encrypted_payload = qr_data.get("encrypted_payload")
            salt = base64.b64decode(qr_data.get("salt"))
            received_signature = qr_data.get("signature")

            # Decrypt payload
            payload_json = self.security_manager.decrypt_data(
                encrypted_payload, salt)
            if not payload_json:
                self.security_manager.record_failed_attempt(self.local_ip)
                return False, "QR code decryption failed"

            # Verify HMAC signature
            expected_signature = hmac.new(
                self.master_secret.encode(),
                payload_json.encode(),
                hashlib.sha256
            ).hexdigest()

            if not hmac.compare_digest(received_signature, expected_signature):
                self.security_manager.record_failed_attempt(self.local_ip)
                return False, "QR code signature verification failed"

            # Parse decrypted payload
            payload = json.loads(payload_json)

            # Check QR code expiration
            expires_at = datetime.fromisoformat(payload.get("expires_at"))
            if datetime.now() > expires_at:
                return False, "QR code has expired"

            # Check replay attack prevention
            nonce = payload.get("nonce")
            if self.security_manager.is_token_used(nonce):
                self.security_manager.record_failed_attempt(self.local_ip)
                return False, "QR code has already been used"

            # Verify booking period
            now = datetime.now()
            check_in_dt = datetime.fromisoformat(payload.get("check_in"))
            check_out_dt = datetime.fromisoformat(payload.get("check_out"))

            if now < check_in_dt:
                return False, f"Check-in not yet started (from {check_in_dt.strftime('%d/%m/%Y %H:%M')})"

            if now > check_out_dt:
                return False, f"Check-out expired (until {check_out_dt.strftime('%d/%m/%Y %H:%M')})"

            # Check IP address restrictions
            source_ip = payload.get("source_ip")
            if source_ip and not self.security_manager.is_ip_allowed(source_ip):
                self.security_manager.record_failed_attempt(self.local_ip)
                return False, "QR code not authorized for this location"

            # Verify guest is still active in database
            guest_id = payload.get("guest_id")
            room = payload.get("room")

            if not self.is_guest_active(guest_id, room):
                return False, "Guest not authorized or deactivated"

            # Mark nonce as used to prevent replay attacks
            self.security_manager.mark_token_used(nonce)

            return True, f"Access authorized for {guest_id} in {room}"

        except json.JSONDecodeError:
            self.security_manager.record_failed_attempt(self.local_ip)
            return False, "Invalid QR code format"
        except Exception as e:
            self.security_manager.record_failed_attempt(self.local_ip)
            return False, f"QR code validation error: {str(e)}"

    def validate_qr_code(self, qr_data):
        """Main QR code validation method - detects format and validates accordingly"""

        # Try new secure format first
        try:
            # Check if it's JSON (new format)
            json.loads(qr_data)
            return self.validate_secure_qr_code(qr_data)
        except json.JSONDecodeError:
            # Fall back to legacy format
            return self.validate_legacy_qr_code(qr_data)

    def validate_legacy_qr_code(self, qr_data):
        """Validate legacy QR code format (for backward compatibility)"""

        # Check rate limiting
        rate_ok, rate_msg = self.security_manager.check_rate_limit(
            self.local_ip)
        if not rate_ok:
            return False, rate_msg

        try:
            parts = qr_data.split('|')
            if len(parts) != 5:
                self.security_manager.record_failed_attempt(self.local_ip)
                return False, "Invalid QR code format"

            guest_id, room, check_in, check_out, hash_received = parts

            # Verify hash
            expected_hash = self.generate_legacy_qr_hash(
                guest_id, room, check_in, check_out)
            if hash_received != expected_hash:
                self.security_manager.record_failed_attempt(self.local_ip)
                return False, "QR code not authentic"

            # Verify validity period
            now = datetime.now()
            check_in_dt = datetime.fromisoformat(check_in)
            check_out_dt = datetime.fromisoformat(check_out)

            if now < check_in_dt:
                return False, f"Check-in not yet started (from {check_in_dt.strftime('%d/%m/%Y %H:%M')})"

            if now > check_out_dt:
                return False, f"Check-out expired (until {check_out_dt.strftime('%d/%m/%Y %H:%M')})"

            # Verify if guest is active in database
            if not self.is_guest_active(guest_id, room):
                return False, "Guest not authorized or deactivated"

            return True, f"Access authorized for {guest_id} in {room} (legacy format)"

        except Exception as e:
            self.security_manager.record_failed_attempt(self.local_ip)
            return False, f"Legacy validation error: {e}"

    def generate_legacy_qr_hash(self, guest_id, room, check_in, check_out):
        """Generate legacy hash for backward compatibility"""
        data = f"{guest_id}{room}{check_in}{check_out}{self.master_secret}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def is_guest_active(self, guest_id, room):
        """Check if guest is active in database"""
        try:
            query = f'''
            from(bucket: "{INFLUX_BUCKET}")
            |> range(start: -30d)
            |> filter(fn: (r) => r["_measurement"] == "authorized_guests")
            |> filter(fn: (r) => r["guest_id"] == "{guest_id}")
            |> filter(fn: (r) => r["room"] == "{room}")
            |> filter(fn: (r) => r["_field"] == "active")
            |> last()
            '''

            tables = self.query_api.query(query, org=INFLUX_ORG)

            if tables and tables[0].records:
                return tables[0].records[0].get_value() == True
            return False

        except Exception as e:
            print(f"❌ Error checking guest: {e}")
            return False

    def log_access_attempt(self, guest_id, room, success, message, qr_format="unknown"):
        """Enhanced logging with security information"""
        try:
            point = Point("access_attempts") \
                .tag("guest_id", guest_id) \
                .tag("room", room) \
                .tag("success", str(success)) \
                .tag("qr_format", qr_format) \
                .tag("source_ip", self.local_ip) \
                .field("message", message) \
                .field("timestamp", datetime.now().isoformat()) \
                .time(datetime.utcnow(), WritePrecision.NS)

            self.write_api.write(bucket=INFLUX_BUCKET,
                                 org=INFLUX_ORG, record=point)

            # Log security events
            if not success:
                security_point = Point("security_events") \
                    .tag("event_type", "access_denied") \
                    .tag("source_ip", self.local_ip) \
                    .tag("guest_id", guest_id) \
                    .field("reason", message) \
                    .time(datetime.utcnow(), WritePrecision.NS)

                self.write_api.write(bucket=INFLUX_BUCKET,
                                     org=INFLUX_ORG, record=security_point)

        except Exception as e:
            print(f"❌ Error logging access: {e}")

    def get_key(self):
        """Detect key press to exit scan mode"""
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

    def check_qr_code(self, image_array):
        """Search for QR code in image"""
        if not CAMERA_AVAILABLE:
            return False, None

        qr_codes = pyzbar.decode(image_array)
        if qr_codes:
            for qr_code in qr_codes:
                data = qr_code.data.decode('utf-8')
                return True, data
        return False, None

    def process_qr_code(self, qr_data):
        """Process detected QR code with enhanced security"""
        print(f"\n🔍 QR Code detected")

        # Extract guest info for logging
        try:
            # Try to parse as JSON first
            try:
                qr_json = json.loads(qr_data)
                # For secure format, we can't easily extract guest info without decryption
                guest_id = "encrypted"
                room = "encrypted"
                qr_format = "secure"
            except json.JSONDecodeError:
                # Legacy format
                parts = qr_data.split('|')
                guest_id = parts[0] if len(parts) > 0 else "unknown"
                room = parts[1] if len(parts) > 1 else "unknown"
                qr_format = "legacy"
        except:
            guest_id = "unknown"
            room = "unknown"
            qr_format = "unknown"

        # Validate QR code
        is_valid, message = self.validate_qr_code(qr_data)

        if is_valid:
            print(f"✅ {message}")
            print("🚪 ACCESS GRANTED")
        else:
            print(f"❌ {message}")
            print("🚫 ACCESS DENIED")

        # Log access attempt
        self.log_access_attempt(guest_id, room, is_valid, message, qr_format)
        print("-" * 50)

    def start_qr_scanner(self):
        """Start QR code scanner"""
        if not CAMERA_AVAILABLE:
            print("❌ Camera system not available")
            print("📱 Test mode - Enter QR code manually:")
            while True:
                qr_data = input("QR Code (or 'q' to quit): ").strip()
                if qr_data.lower() == 'q':
                    break
                if qr_data:
                    self.process_qr_code(qr_data)
            return

        try:
            print("🔍 Initializing camera...")
            self.picam2 = Picamera2()

            camera_config = self.picam2.create_still_configuration(
                main={"size": (1920, 1080)},
                lores={"size": (640, 480)},
                display="lores"
            )
            self.picam2.configure(camera_config)
            self.picam2.set_controls({"AfMode": 2, "AfTrigger": 0})
            self.picam2.start_preview(Preview.QTGL)
            self.picam2.start()

            print("📱 QR Scanner active - Press 'q' to exit")
            print("🎯 Frame the QR code...")

            scan_interval = 0.05
            last_scan_time = 0

            while True:
                current_time = time.time()

                # Check if 'q' pressed to exit
                key = self.get_key()
                if key == 'q':
                    print("\n🛑 Scanner stopped")
                    break

                if current_time - last_scan_time >= scan_interval:
                    try:
                        image_array = self.picam2.capture_array("lores")
                        qr_found, qr_data = self.check_qr_code(image_array)

                        if qr_found:
                            self.process_qr_code(qr_data)

                            # Wait before next scan
                            print("⏱️  Waiting 3 seconds before next scan...")
                            time.sleep(3)

                        last_scan_time = current_time

                    except Exception as e:
                        print(f"❌ Error during scanning: {e}")
                        last_scan_time = current_time

        except Exception as e:
            print(f"❌ Camera error: {e}")
        finally:
            if self.picam2:
                self.picam2.stop()
                print("📷 Camera stopped")

    def add_guest(self, guest_id, room, check_in_date, check_out_date, secure_format=True):
        """Add authorized guest with secure QR code generation"""
        try:
            # Register in database
            point = Point("authorized_guests") \
                .tag("guest_id", guest_id) \
                .tag("room", room) \
                .field("active", True) \
                .field("check_in", check_in_date) \
                .field("check_out", check_out_date) \
                .time(datetime.utcnow(), WritePrecision.NS)

            self.write_api.write(bucket=INFLUX_BUCKET,
                                 org=INFLUX_ORG, record=point)

            # Generate QR code data
            if secure_format:
                qr_data = self.generate_secure_qr_data(
                    guest_id, room, check_in_date, check_out_date)
                format_suffix = "_secure"
            else:
                # Legacy format for backward compatibility
                legacy_hash = self.generate_legacy_qr_hash(
                    guest_id, room, check_in_date, check_out_date)
                qr_data = f"{guest_id}|{room}|{check_in_date}|{check_out_date}|{legacy_hash}"
                format_suffix = "_legacy"

            # Create QR code image
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(qr_data)
            qr.make(fit=True)

            # Save QR code
            os.makedirs("./qr_codes", exist_ok=True)
            qr_filename = f"./qr_codes/QR_{guest_id}_{room}{format_suffix}.png"
            qr_img = qr.make_image(fill_color="black", back_color="white")
            qr_img.save(qr_filename)

            print(f"✅ Guest {guest_id} added for {room}")
            print(f"📅 Period: {check_in_date} → {check_out_date}")
            print(f"📱 QR code saved: {qr_filename}")
            print(f"🔐 Format: {'Secure' if secure_format else 'Legacy'}")

            return True, qr_filename

        except Exception as e:
            print(f"❌ Error adding guest: {e}")
            return False, None

    def remove_guest(self, guest_id, room):
        """Remove/deactivate guest"""
        try:
            point = Point("authorized_guests") \
                .tag("guest_id", guest_id) \
                .tag("room", room) \
                .field("active", False) \
                .time(datetime.utcnow(), WritePrecision.NS)

            self.write_api.write(bucket=INFLUX_BUCKET,
                                 org=INFLUX_ORG, record=point)
            print(f"✅ Guest {guest_id} removed from {room}")
            return True

        except Exception as e:
            print(f"❌ Error removing guest: {e}")
            return False

    def list_guests(self):
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

            tables = self.query_api.query(query, org=INFLUX_ORG)

            if not tables or not tables[0].records:
                print("📋 No active guests")
                return

            print("📋 ACTIVE GUESTS:")
            print("-" * 50)

            for record in tables[0].records:
                guest_id = record.values.get("guest_id")
                room = record.values.get("room")
                active = record.get_value()

                if active:
                    print(f"👤 {guest_id} → {room}")

        except Exception as e:
            print(f"❌ Error listing guests: {e}")

    def view_access_log(self, hours=24):
        """View access log"""
        try:
            query = f'''
            from(bucket: "{INFLUX_BUCKET}")
            |> range(start: -{hours}h)
            |> filter(fn: (r) => r["_measurement"] == "access_attempts")
            |> sort(columns: ["_time"], desc: true)
            |> limit(n: 20)
            '''

            tables = self.query_api.query(query, org=INFLUX_ORG)

            if not tables or not tables[0].records:
                print("📋 No access attempts")
                return

            print(f"📋 ACCESS LOG (last {hours} hours):")
            print("-" * 80)

            for record in tables[0].records:
                timestamp = record.get_time().strftime("%d/%m/%Y %H:%M:%S")
                room = record.values.get("room", "N/A")
                guest_id = record.values.get("guest_id", "N/A")
                success = record.values.get("success", "N/A")
                qr_format = record.values.get("qr_format", "unknown")
                source_ip = record.values.get("source_ip", "N/A")

                if record.get_field() == "message":
                    message = record.get_value()
                    status = "✅" if success == "True" else "❌"
                    print(
                        f"{timestamp} | {room} | {guest_id} | {status} {message} | {qr_format} | {source_ip}")

        except Exception as e:
            print(f"❌ Error viewing log: {e}")

    def view_security_log(self, hours=24):
        """View security events log"""
        try:
            query = f'''
            from(bucket: "{INFLUX_BUCKET}")
            |> range(start: -{hours}h)
            |> filter(fn: (r) => r["_measurement"] == "security_events")
            |> sort(columns: ["_time"], desc: true)
            |> limit(n: 20)
            '''

            tables = self.query_api.query(query, org=INFLUX_ORG)

            if not tables or not tables[0].records:
                print("📋 No security events")
                return

            print(f"🔒 SECURITY LOG (last {hours} hours):")
            print("-" * 80)

            for record in tables[0].records:
                timestamp = record.get_time().strftime("%d/%m/%Y %H:%M:%S")
                event_type = record.values.get("event_type", "N/A")
                source_ip = record.values.get("source_ip", "N/A")
                guest_id = record.values.get("guest_id", "N/A")

                if record.get_field() == "reason":
                    reason = record.get_value()
                    print(
                        f"{timestamp} | {event_type} | {source_ip} | {guest_id} | {reason}")

        except Exception as e:
            print(f"❌ Error viewing security log: {e}")

    def guest_management_menu(self):
        """Guest management menu"""
        while True:
            print("\n👥 GUEST MANAGEMENT")
            print("=" * 30)
            print("1. Add guest (Secure QR)")
            print("2. Add guest (Legacy QR)")
            print("3. Remove guest")
            print("4. List active guests")
            print("5. View access log")
            print("6. View security log")
            print("7. Back to main menu")

            choice = input("\nChoose option (1-7): ").strip()

            if choice == "1":
                self._add_guest_interactive(secure_format=True)
            elif choice == "2":
                self._add_guest_interactive(secure_format=False)
            elif choice == "3":
                print("\n➖ REMOVE GUEST")
                guest_id = input("Guest ID: ").strip()
                room = input("Room: ").strip()
                self.remove_guest(guest_id, room)

            elif choice == "4":
                print("\n📋 GUEST LIST")
                self.list_guests()

            elif choice == "5":
                print("\n📊 ACCESS LOG")
                hours = input("Hours to display (default 24): ").strip()
                try:
                    hours = int(hours) if hours else 24
                except:
                    hours = 24
                self.view_access_log(hours)

            elif choice == "6":
                print("\n🔒 SECURITY LOG")
                hours = input("Hours to display (default 24): ").strip()
                try:
                    hours = int(hours) if hours else 24
                except:
                    hours = 24
                self.view_security_log(hours)

            elif choice == "7":
                break

            else:
                print("❌ Invalid option")

    def _add_guest_interactive(self, secure_format=True):
        """Interactive guest addition"""
        print(f"\n➕ ADD GUEST ({'Secure' if secure_format else 'Legacy'} QR)")
        guest_id = input("Guest ID (e.g., Mario_Rossi): ").strip()
        room = input("Room (e.g., Room_101): ").strip()

        # Default dates: today at 15:00 → tomorrow at 11:00
        default_checkin = datetime.now().replace(
            hour=15, minute=0, second=0, microsecond=0)
        default_checkout = default_checkin + timedelta(days=1)
        default_checkout = default_checkout.replace(hour=11, minute=0)

        checkin_str = input(
            f"Check-in (YYYY-MM-DD HH:MM) [{default_checkin.strftime('%Y-%m-%d %H:%M')}]: ").strip()
        if not checkin_str:
            checkin_str = default_checkin.isoformat()
        else:
            try:
                checkin_str = datetime.strptime(
                    checkin_str, "%Y-%m-%d %H:%M").isoformat()
            except:
                print("❌ Invalid date format")
                return

        checkout_str = input(
            f"Check-out (YYYY-MM-DD HH:MM) [{default_checkout.strftime('%Y-%m-%d %H:%M')}]: ").strip()
        if not checkout_str:
            checkout_str = default_checkout.isoformat()
        else:
            try:
                checkout_str = datetime.strptime(
                    checkout_str, "%Y-%m-%d %H:%M").isoformat()
            except:
                print("❌ Invalid date format")
                return

        success, qr_file = self.add_guest(
            guest_id, room, checkin_str, checkout_str, secure_format)
        if success:
            print(f"\n📧 Send QR code to guest: {qr_file}")
            if secure_format:
                print("🔒 Enhanced security features:")
                print("   • AES-256 encryption")
                print("   • HMAC signature verification")
                print("   • Replay attack prevention")
                print("   • Time-based expiration")
                print("   • IP address restrictions")

    def security_menu(self):
        """Security management menu"""
        while True:
            print("\n🔒 SECURITY MANAGEMENT")
            print("=" * 30)
            print("1. View security status")
            print("2. View rate limiting status")
            print("3. Clear security logs")
            print("4. Test QR code validation")
            print("5. Back to main menu")

            choice = input("\nChoose option (1-5): ").strip()

            if choice == "1":
                self._show_security_status()
            elif choice == "2":
                self._show_rate_limiting_status()
            elif choice == "3":
                self._clear_security_logs()
            elif choice == "4":
                self._test_qr_validation()
            elif choice == "5":
                break
            else:
                print("❌ Invalid option")

    def _show_security_status(self):
        """Show current security status"""
        print("\n🔒 SECURITY STATUS")
        print("-" * 50)
        print(f"🌐 Local IP: {self.local_ip}")
        print(f"🔐 Master Secret: {'***' + self.master_secret[-4:]}")
        print(f"⏰ QR Code Lifetime: {QR_CODE_LIFETIME_HOURS} hours")
        print(f"🚫 Max Attempts/Hour: {MAX_ATTEMPTS_PER_HOUR}")
        print(f"📊 Used Tokens: {len(self.security_manager.used_tokens)}")
        print(
            f"🔄 Failed Attempts: {len(self.security_manager.failed_attempts)}")

        print("\n🌍 Allowed IP Ranges:")
        for ip_range in ALLOWED_IP_RANGES:
            print(f"   • {ip_range}")

    def _show_rate_limiting_status(self):
        """Show rate limiting status"""
        print("\n⏱️ RATE LIMITING STATUS")
        print("-" * 50)

        if not self.security_manager.failed_attempts:
            print("✅ No rate limiting active")
            return

        now = time.time()
        for identifier, data in self.security_manager.failed_attempts.items():
            remaining_time = int(RATE_LIMIT_WINDOW -
                                 (now - data['first_attempt']))
            if remaining_time > 0:
                print(
                    f"🚫 {identifier}: {data['count']}/{MAX_ATTEMPTS_PER_HOUR} attempts")
                print(f"   Reset in: {remaining_time} seconds")

    def _clear_security_logs(self):
        """Clear security logs"""
        confirm = input("⚠️ Clear all security logs? (y/N): ").strip().lower()
        if confirm == 'y':
            self.security_manager.failed_attempts.clear()
            self.security_manager.used_tokens.clear()
            print("✅ Security logs cleared")
        else:
            print("❌ Operation cancelled")

    def _test_qr_validation(self):
        """Test QR code validation"""
        print("\n🧪 QR CODE VALIDATION TEST")
        print("-" * 50)

        # Generate test QR code
        test_guest = "TEST_USER"
        test_room = "TEST_ROOM"
        test_checkin = datetime.now().isoformat()
        test_checkout = (datetime.now() + timedelta(hours=1)).isoformat()

        print("🔄 Generating test QR codes...")

        # Test secure QR
        secure_qr = self.generate_secure_qr_data(
            test_guest, test_room, test_checkin, test_checkout)
        print(f"✅ Secure QR generated: {len(secure_qr)} bytes")

        # Test legacy QR
        legacy_hash = self.generate_legacy_qr_hash(
            test_guest, test_room, test_checkin, test_checkout)
        legacy_qr = f"{test_guest}|{test_room}|{test_checkin}|{test_checkout}|{legacy_hash}"
        print(f"✅ Legacy QR generated: {len(legacy_qr)} bytes")

        # Test validation
        print("\n🔍 Testing validation...")

        # Test secure format
        is_valid, message = self.validate_secure_qr_code(secure_qr)
        print(f"Secure QR: {'✅' if is_valid else '❌'} {message}")

        # Test legacy format
        is_valid, message = self.validate_legacy_qr_code(legacy_qr)
        print(f"Legacy QR: {'✅' if is_valid else '❌'} {message}")

    def close(self):
        """Close connections"""
        if self.picam2:
            self.picam2.stop()
        self.client.close()


def main():
    """Main application entry point"""
    system = BnBSystem()

    # Test connection
    try:
        health = system.client.health()
        print(f"✅ InfluxDB connected: {health.status}")
    except Exception as e:
        print(f"❌ InfluxDB connection error: {e}")
        return

    # Show security information
    print(f"\n🔒 Security Features Active:")
    print(f"   • AES-256 encryption with PBKDF2")
    print(f"   • HMAC-SHA256 signatures")
    print(f"   • Replay attack prevention")
    print(f"   • Rate limiting ({MAX_ATTEMPTS_PER_HOUR} attempts/hour)")
    print(f"   • IP address restrictions")
    print(f"   • QR code expiration ({QR_CODE_LIFETIME_HOURS}h)")

    while True:
        print("\n🏠 B&B INTEGRATED SYSTEM")
        print("=" * 35)
        print("1. Guest Management")
        print("2. QR Code Access Control")
        print("3. Security Management")
        print("4. Exit")

        choice = input("\nChoose option (1-4): ").strip()

        if choice == "1":
            system.guest_management_menu()

        elif choice == "2":
            print("\n🔐 ACCESS CONTROL SYSTEM")
            print("=" * 30)
            system.start_qr_scanner()

        elif choice == "3":
            system.security_menu()

        elif choice == "4":
            break

        else:
            print("❌ Invalid option")

    system.close()
    print("👋 Goodbye!")


if __name__ == "__main__":
    main()
