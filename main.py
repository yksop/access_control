#!/usr/bin/env python3
"""Entry point. Run with `python main.py`."""

from access_control_system import AccessControlSystem
from cli import main_menu


def main():
    system = AccessControlSystem()
    try:
        main_menu(system)
    finally:
        system.mqtt_handler.disconnect()


if __name__ == "__main__":
    main()
