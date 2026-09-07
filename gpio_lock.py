"""
Physical door-lock actuation via a GPIO-driven relay.

Typical wiring: a relay module's IN pin goes to the configured GPIO pin,
the relay's COM/NO contacts sit in series with a 12V electric strike or
solenoid lock's power feed. When the pin goes HIGH, the relay closes and
the strike releases; after DOOR_UNLOCK_SECONDS it opens again.

This is the "optional hardware actuation" piece from the assignment brief
— disabled by default (DOOR_LOCK_ENABLED=false) since not everyone will
have a relay wired up. When disabled, or when RPi.GPIO isn't importable
(e.g. developing off the Pi), calls are simulated with a log line instead
of touching any hardware, so the rest of the system never needs to
special-case "no lock attached".
"""

import threading
import time

import config

try:
    import RPi.GPIO as GPIO

    GPIO_AVAILABLE = True
except (ImportError, RuntimeError):
    GPIO_AVAILABLE = False


class DoorLock:
    def __init__(self):
        self.pin = config.DOOR_LOCK_GPIO_PIN
        self.unlock_seconds = config.DOOR_UNLOCK_SECONDS
        self._lock = threading.Lock()

        self.ready = GPIO_AVAILABLE and config.DOOR_LOCK_ENABLED
        if self.ready:
            GPIO.setmode(GPIO.BCM)
            GPIO.setup(self.pin, GPIO.OUT, initial=GPIO.LOW)
            print(f"[door-lock] GPIO{self.pin} ready (unlock pulse: {self.unlock_seconds}s)")
        else:
            reason = "disabled in .env" if not config.DOOR_LOCK_ENABLED else "RPi.GPIO not available"
            print(f"[door-lock] running in simulation mode ({reason})")

    def unlock(self):
        """Pulse the relay HIGH for DOOR_UNLOCK_SECONDS, then release it.

        Runs in a background thread so a slow unlock pulse never blocks
        the QR-validation / MQTT response path that triggered it.
        """
        if not self.ready:
            print(f"[door-lock] (simulated) unlocking for {self.unlock_seconds}s")
            return

        def _pulse():
            with self._lock:
                GPIO.output(self.pin, GPIO.HIGH)
                print(f"[door-lock] unlocked (GPIO{self.pin} HIGH)")
                time.sleep(self.unlock_seconds)
                GPIO.output(self.pin, GPIO.LOW)
                print(f"[door-lock] relocked (GPIO{self.pin} LOW)")

        threading.Thread(target=_pulse, daemon=True).start()

    def cleanup(self):
        if self.ready:
            GPIO.cleanup(self.pin)
