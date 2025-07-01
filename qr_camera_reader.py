from picamera2 import Picamera2, Preview
import time
import sys
import select
import tty
import termios
import cv2
from pyzbar import pyzbar
import numpy as np


def get_key():
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(sys.stdin.fileno())
        if select.select([sys.stdin], [], [], 0.1)[0]:
            return sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return None


def check_qr_code(image_array):
    qr_codes = pyzbar.decode(image_array)
    if qr_codes:
        for qr_code in qr_codes:
            data = qr_code.data.decode('utf-8')
            print(f"QR Code trovato: {data}")
        return True
    return False


picam2 = Picamera2()
camera_config = picam2.create_still_configuration(
    main={"size": (1920, 1080)},
    lores={"size": (640, 480)},
    display="lores")
picam2.configure(camera_config)

# Abilita autofocus
picam2.set_controls({"AfMode": 2, "AfTrigger": 0})  # AfMode 2 = Continuous AF

picam2.start_preview(Preview.QTGL)
picam2.start()

print("Premi SPAZIO per scattare foto, 'f' per focus manuale, 'q' per uscire")

while True:
    key = get_key()
    if key == ' ':
        # Trigger autofocus prima dello scatto
        picam2.set_controls({"AfTrigger": 1})
        time.sleep(0.5)  # Aspetta che metta a fuoco

        # Cattura immagine in memoria
        image_array = picam2.capture_array()

        if check_qr_code(image_array):
            timestamp = int(time.time())
            filename = f"./files/qr_photo_{timestamp}.jpg"
            cv2.imwrite(filename, cv2.cvtColor(image_array, cv2.COLOR_RGB2BGR))
            print(f"Foto con QR salvata: {filename}")
        else:
            print("Nessun QR code trovato")

    elif key == 'f':
        # Trigger manuale del focus
        picam2.set_controls({"AfTrigger": 1})
        print("Focus attivato")

    elif key == 'q':
        break

picam2.stop()
print("Camera chiusa")
