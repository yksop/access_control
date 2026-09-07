# Access Control & Surveillance System

A QR-code-based access control system built for Project 7 (Access Control
System and Surveillance with Web Cam). A Raspberry Pi camera scans a
time-limited, cryptographically signed QR code; a valid code unlocks
access to a zone (e.g. a lab), logs the event, saves a snapshot, and
notifies a Telegram chat.

## Architecture

The original single-file prototype has been split into modules:

| File | Responsibility |
|---|---|
| `config.py` | Loads all settings/secrets from environment variables |
| `database.py` | InfluxDB reads/writes (users, access log) |
| `authenticator.py` | PIN verification, access-window check, lockout |
| `qr_manager.py` | Generates & validates signed, short-lived QR codes |
| `camera_scanner.py` | Reads frames from the Pi camera, decodes QR codes, saves surveillance snapshots |
| `notifier.py` | Telegram messages/photos |
| `mqtt_handler.py` | Subscribes to request topics, publishes responses/events |
| `access_control_system.py` | Orchestrates all of the above |
| `cli.py` / `main.py` | Terminal menus for scanning, user management, logs |

## Setup

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# then edit .env with real values (see below)
```

On the Raspberry Pi itself, also install `picamera2` (already on Raspberry
Pi OS images, or `pip install picamera2`). On a laptop without a Pi
camera, the scanner automatically falls back to a keyboard-driven test
mode so you can develop without hardware.

Run with:

```bash
python main.py
```

## Configuration (`.env`)

All secrets live in `.env`, which is git-ignored and never committed.
Required:

- `INFLUX_TOKEN` — InfluxDB API token
- `MASTER_SECRET` — random string used to HMAC-sign QR payloads (generate
  with `python -c "import secrets; print(secrets.token_hex(32))"`)

Optional (Telegram notifications are skipped if left blank):

- `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`

See `.env.example` for the full list.

> **Note:** an earlier version of this repo had these values hardcoded
> directly in `qr_camera_reader.py` and committed to a public GitHub
> repo. If you're reusing this codebase, treat the old InfluxDB token,
> master secret, and Telegram bot token as compromised and rotate them
> (revoke the old InfluxDB token, generate a new master secret, and
> talk to @BotFather to regenerate the Telegram bot token).

## How it maps to the assignment brief

- **Access control for an environment (lab)**: `add_user` / `remove_user`
  grant and revoke access to a named zone.
- **QR-code authentication**: `qr_manager.py` — HMAC-signed, 15-second
  (configurable) validity window.
- **RPi Cam**: `camera_scanner.py` via `picamera2` + `pyzbar`.
- **MQTT as main protocol**: `mqtt_handler.py` — full request/response
  topic set for auth, QR generate/validate, user add/remove/list, plus
  access-event and system-status broadcasts.
- **Telegram bot to display results**: `notifier.py` — sends a message on
  every successful entry, and a photo on denied attempts.
- **Simple access control list with add/remove UI**: `cli.py` menus
  (`Add user` / `Remove user` / `List active users`), also exposed over
  MQTT for a future GUI/web front end.
- **Surveillance**: every scan attempt — granted or denied — saves a
  timestamped snapshot to `SNAPSHOT_DIR`, and denied attempts are pushed
  to Telegram automatically.
- **Optional door-lock actuation**: not implemented. The natural place to
  add it is `access_control_system.py::validate_access_qr` — trigger a
  GPIO relay there on `valid == True`.

## Known limitations / next steps

- User management is CLI-only; the MQTT topics for add/remove/list are
  ready for a real web or mobile front end if a nicer UI is wanted.
- No automated tests yet.
- Door-lock hardware actuation is not implemented (optional in the brief).
