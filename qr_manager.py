"""
Generates and validates short-lived, HMAC-signed QR codes.

Each QR encodes a small JSON payload (user, zone, expiry) plus an HMAC
signature over that payload using MASTER_SECRET, so a scanner can verify
authenticity without hitting the database.
"""

import hashlib
import hmac
import json
import os
import threading
import time
import uuid
from datetime import datetime, timedelta

import qrcode

import config


class TemporaryQRManager:
    def __init__(self):
        self.active_qrs = {}
        self.last_generated = None
        self._lock = threading.Lock()
        self.cleanup_thread = threading.Thread(target=self._cleanup_expired, daemon=True)
        self.cleanup_thread.start()

    def generate_temp_qr(self, user_id, zone, access_type="entry"):
        qr_id = str(uuid.uuid4())
        expires_at = datetime.now() + timedelta(seconds=config.TEMP_QR_LIFETIME_SECONDS)

        qr_data = {
            "qr_id": qr_id,
            "user_id": user_id,
            "zone": zone,
            "access_type": access_type,
            "expires_at": expires_at.isoformat(),
            "created_at": datetime.now().isoformat(),
        }
        signature = self._sign(qr_data)
        final_qr = {"data": qr_data, "signature": signature}

        with self._lock:
            self.active_qrs[qr_id] = {"data": qr_data, "expires_at": expires_at}

        qr_string = json.dumps(final_qr, separators=(",", ":"))
        self.last_generated = qr_string
        return qr_string

    def save_qr_image(self, qr_string, user_id):
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(qr_string)
        qr.make(fit=True)

        os.makedirs(config.QR_OUTPUT_DIR, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(config.QR_OUTPUT_DIR, f"temp_qr_{user_id}_{timestamp}.png")

        qr_img = qr.make_image(fill_color="black", back_color="white")
        qr_img.save(filename)
        return filename

    def get_last_generated_qr(self):
        return self.last_generated

    def validate_temp_qr(self, qr_string):
        try:
            qr_obj = json.loads(qr_string)
            qr_data = qr_obj["data"]
            received_signature = qr_obj["signature"]

            expected_signature = self._sign(qr_data)
            if not hmac.compare_digest(received_signature, expected_signature):
                return False, "Invalid QR signature"

            qr_id = qr_data["qr_id"]
            with self._lock:
                stored = self.active_qrs.get(qr_id)
                if not stored:
                    return False, "QR code not found or expired"
                if datetime.now() > stored["expires_at"]:
                    del self.active_qrs[qr_id]
                    return False, "QR code expired"
                del self.active_qrs[qr_id]

            return True, qr_data
        except Exception as e:
            return False, f"QR validation error: {str(e)}"

    def get_active_count(self):
        with self._lock:
            return len(self.active_qrs)

    def _sign(self, qr_data):
        qr_json = json.dumps(qr_data, separators=(",", ":"))
        return hmac.new(
            config.MASTER_SECRET.encode(), qr_json.encode(), hashlib.sha256
        ).hexdigest()

    def _cleanup_expired(self):
        while True:
            try:
                now = datetime.now()
                with self._lock:
                    expired_ids = [
                        qr_id for qr_id, info in self.active_qrs.items() if now > info["expires_at"]
                    ]
                    for qr_id in expired_ids:
                        del self.active_qrs[qr_id]
            except Exception:
                pass
            time.sleep(5)
