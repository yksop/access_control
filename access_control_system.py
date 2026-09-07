"""
Top-level orchestrator. Wires together the database, authenticator, QR
manager, MQTT handler and camera scanner, and exposes the operations the
CLI and MQTT handler both call into.
"""

import secrets
import threading
import time
from datetime import datetime

import config
from authenticator import Authenticator
from camera_scanner import CAMERA_AVAILABLE, CameraScanner
from database import Database
from mqtt_handler import MQTTHandler
from notifier import send_telegram_message, send_telegram_photo
from qr_manager import TemporaryQRManager


class AccessControlSystem:
    def __init__(self):
        config.validate_config()

        self.db = Database()
        self.qr_manager = TemporaryQRManager()
        self.authenticator = Authenticator(self.db)
        self.mqtt_handler = MQTTHandler(self)
        self.camera_available = CAMERA_AVAILABLE
        self.scanner = CameraScanner(on_qr_scanned=self._scan_callback)

        self.mqtt_handler.connect()

        self.status_thread = threading.Thread(target=self._publish_status_periodically, daemon=True)
        self.status_thread.start()

    def _publish_status_periodically(self):
        while True:
            try:
                self.mqtt_handler.publish_system_status()
            except Exception:
                pass
            time.sleep(30)

    # ---------- user management ----------

    def generate_pin(self):
        return f"{secrets.randbelow(900000) + 100000}"

    def add_user(self, user_id, zone, check_in, check_out):
        try:
            pin = self.generate_pin()
            self.db.add_user(user_id, zone, pin, check_in, check_out)
            print(f"User {user_id} added for zone '{zone}'")
            print(f"Access window: {check_in} -> {check_out}")
            print(f"PIN: {pin}")
            return True, pin
        except Exception as e:
            print(f"Error adding user: {e}")
            return False, None

    def remove_user(self, user_id):
        """Revoke a user's access. This is the piece the original script
        was missing: an add-only access list with no way to remove someone."""
        try:
            removed = self.db.remove_user(user_id)
            if removed:
                print(f"User {user_id} access revoked")
            else:
                print(f"User {user_id} not found or already inactive")
            return removed
        except Exception as e:
            print(f"Error removing user: {e}")
            return False

    def get_active_users_list(self):
        return self.db.list_active_users()

    # ---------- QR / access flow ----------

    def authenticate_and_generate_qr(self, user_id, pin_code):
        auth_success, result = self.authenticator.authenticate(user_id, pin_code)
        if not auth_success:
            print(f"Authentication failed: {result}")
            return False, result

        user_data = result
        qr_string = self.qr_manager.generate_temp_qr(user_data["user_id"], user_data["zone"])
        qr_filename = self.qr_manager.save_qr_image(qr_string, user_data["user_id"])

        print(f"Temporary QR generated for {user_data['user_id']}")
        print(f"Valid for {config.TEMP_QR_LIFETIME_SECONDS} seconds")
        print(f"QR saved: {qr_filename}")
        return True, qr_filename

    def validate_access_qr(self, qr_string):
        valid, result = self.qr_manager.validate_temp_qr(qr_string)
        if not valid:
            self.log_access_event("unknown", "unknown", "entry", False, result)
            return False, result

        qr_data = result
        user_id, zone, access_type = qr_data["user_id"], qr_data["zone"], qr_data["access_type"]
        self.log_access_event(user_id, zone, access_type, True, "Access granted")

        message = (
            f"Access granted\nUser: {user_id}\nZone: {zone}\n"
            f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        send_telegram_message(message)
        return True, f"Access granted - {user_id} ({zone})"

    def log_access_event(self, user_id, zone, access_type, success, message):
        self.db.log_access_event(user_id, zone, access_type, success, message)

    def _scan_callback(self, qr_string, image_array):
        """Called by the camera scanner for every decoded QR. Handles the
        surveillance side (snapshot on every attempt) alongside validation."""
        valid, message = self.validate_access_qr(qr_string)

        if image_array is not None:
            outcome = "granted" if valid else "denied"
            snapshot_path = self.scanner.save_snapshot(image_array, outcome)
            if snapshot_path and not valid:
                # Denied attempts are the ones worth a closer look, so
                # send those straight to Telegram along with the reason.
                send_telegram_photo(snapshot_path, caption=f"Access denied: {message}")

        return valid, message

    def start_scanner(self):
        self.scanner.start()

    def get_recent_access_events(self, limit=20):
        return self.db.get_recent_access_events(limit)
