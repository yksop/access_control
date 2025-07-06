from picamera2 import Picamera2, Preview
import time
import sys
import select
import tty
import termios
from pyzbar import pyzbar


def get_key():
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(sys.stdin.fileno())
        if select.select([sys.stdin], [], [], 0.01)[0]:
            return sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return None


def check_qr_code(image_array):
    qr_codes = pyzbar.decode(image_array)
    if qr_codes:
        for qr_code in qr_codes:
            data = qr_code.data.decode('utf-8')
            return True, data
    return False, None


picam2 = Picamera2()
camera_config = picam2.create_still_configuration(
    main={"size": (1920, 1080)},
    lores={"size": (640, 480)},
    display="lores")
picam2.configure(camera_config)

picam2.set_controls({"AfMode": 2, "AfTrigger": 0})
picam2.start_preview(Preview.QTGL)
picam2.start()

scan_interval = 0.05
last_scan_time = 0

while True:
    current_time = time.time()

    if current_time - last_scan_time >= scan_interval:
        try:
            image_array = picam2.capture_array("lores")

            qr_found, qr_data = check_qr_code(image_array)

            if qr_found:

                # final_image = picam2.capture_array("main")

                print(f"QR Code: {qr_data}")

                break

            last_scan_time = current_time

        except Exception as e:
            print(f"Error during scanning: {e}")
            last_scan_time = current_time

picam2.stop()
