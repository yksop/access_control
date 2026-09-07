"""Telegram notifications for access events."""

import requests

import config


def send_telegram_message(message):
    """Send a message to the configured Telegram chat via bot.

    Silently no-ops if Telegram isn't configured, so the rest of the
    system doesn't need to special-case a missing bot token.
    """
    if not config.TELEGRAM_BOT_TOKEN or not config.TELEGRAM_CHAT_ID:
        return

    try:
        url = f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {"chat_id": config.TELEGRAM_CHAT_ID, "text": message}
        response = requests.post(url, json=payload, timeout=5)
        if response.status_code != 200:
            print(f"Failed to send Telegram message: {response.text}")
    except Exception as e:
        print(f"Telegram error: {e}")


def send_telegram_photo(photo_path, caption=None):
    """Send a snapshot image to the configured Telegram chat."""
    if not config.TELEGRAM_BOT_TOKEN or not config.TELEGRAM_CHAT_ID:
        return

    try:
        url = f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/sendPhoto"
        with open(photo_path, "rb") as photo:
            files = {"photo": photo}
            data = {"chat_id": config.TELEGRAM_CHAT_ID}
            if caption:
                data["caption"] = caption
            response = requests.post(url, data=data, files=files, timeout=10)
        if response.status_code != 200:
            print(f"Failed to send Telegram photo: {response.text}")
    except Exception as e:
        print(f"Telegram photo error: {e}")
