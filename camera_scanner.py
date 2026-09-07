"""
Camera handling: decodes QR codes from frames, and adds the surveillance
piece the original script was missing — every access attempt (granted or
denied) saves a timestamped snapshot, so there's a visual record of who
was at the door, not just a log line.

Falls back to a keyboard-driven CLI mode when no Pi camera is available
(e.g. developing on a laptop), same as the original script.
"""

import os
import select
import sys
import termios
import time
import tty
from datetime import datetime

try:
    from picamera2 import Picamera2, Preview
    from pyzbar import pyzbar

    CAMERA_AVAILABLE = True
except ImportError:
    CAMERA_AVAILABLE = False

import config


class CameraScanner:
    def __init__(self, on_qr_scanned):
        """on_qr_scanned: callback(qr_string) -> (valid: bool, message: str)"""
        self.on_qr_scanned = on_qr_scanned
        self.picam2 = None

    def get_key(self):
        """Non-blocking key detection for the 'press q to quit' loop."""
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
        qr_codes = pyzbar.decode(image_array)
        if qr_codes:
            return True, qr_codes[0].data.decode("utf-8")
        return False, None

    def save_snapshot(self, image_array, outcome):
        """Save a still for the surveillance log. outcome: 'granted' | 'denied'."""
        try:
            import numpy as np
            from PIL import Image

            os.makedirs(config.SNAPSHOT_DIR, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            filename = os.path.join(config.SNAPSHOT_DIR, f"{outcome}_{timestamp}.jpg")
            Image.fromarray(image_array).convert("RGB").save(filename)
            return filename
        except Exception as e:
            print(f"Snapshot error: {e}")
            return None

    def start(self):
        if not CAMERA_AVAILABLE:
            print("Camera not available - test mode (type QR payloads manually)")
            while True:
                qr_data = input("Enter QR code (or 'q' to quit): ").strip()
                if qr_data.lower() == "q":
                    break
                if qr_data:
                    valid, message = self.on_qr_scanned(qr_data, image_array=None)
                    print(("SUCCESS: " if valid else "DENIED: ") + message)
            return

        try:
            print("Starting access scanner...")
            self.picam2 = Picamera2()
            camera_config = self.picam2.create_still_configuration(
                main={"size": (1920, 1080)}, lores={"size": (640, 480)}, display="lores"
            )
            self.picam2.configure(camera_config)
            self.picam2.start_preview(Preview.QTGL)
            self.picam2.start()
            print("Scanner active - Press 'q' to exit")

            while True:
                key = self.get_key()
                if key == "q":
                    break
                try:
                    image_array = self.picam2.capture_array("lores")
                    qr_found, qr_data = self.scan_qr_code(image_array)
                    if qr_found:
                        valid, message = self.on_qr_scanned(qr_data, image_array=image_array)
                        print(("ACCESS GRANTED: " if valid else "ACCESS DENIED: ") + message)
                        time.sleep(2)
                except Exception as e:
                    print(f"Scan error: {e}")
                time.sleep(0.1)
        except Exception as e:
            print(f"Camera error: {e}")
        finally:
            if self.picam2:
                self.picam2.stop()
