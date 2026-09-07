"""
Handles user authentication: PIN verification, time-window validity
(check-in/check-out), and lockout after repeated failed attempts.
"""

from datetime import datetime, timedelta

import config


class Authenticator:
    def __init__(self, db):
        self.db = db
        self.failed_attempts = {}

    def authenticate(self, user_id, pin_code):
        if self._is_locked_out(user_id):
            remaining = self._get_lockout_remaining(user_id)
            return False, f"Account locked. Try again in {remaining} minutes"

        user_data = self.db.get_user_data(user_id)
        if not user_data:
            self._record_failed_attempt(user_id)
            return False, "User not found"

        if not self._verify_pin(user_data, pin_code):
            self._record_failed_attempt(user_id)
            return False, "Invalid PIN"

        if not self._is_window_valid(user_data):
            return False, "Access window not valid for current time"

        if user_id in self.failed_attempts:
            del self.failed_attempts[user_id]

        return True, user_data

    def _verify_pin(self, user_data, pin_code):
        stored_pin = user_data.get("pin")
        return bool(stored_pin) and stored_pin == pin_code

    def _is_window_valid(self, user_data):
        try:
            now = datetime.now()
            check_in = self._parse(user_data["check_in"])
            check_out = self._parse(user_data["check_out"])
            return check_in <= now <= check_out
        except Exception as e:
            print(f"Error validating access window: {e}")
            return False

    @staticmethod
    def _parse(value):
        return datetime.fromisoformat(value) if isinstance(value, str) else value

    def _is_locked_out(self, user_id):
        attempts = self.failed_attempts.get(user_id)
        if not attempts or attempts["count"] < config.MAX_AUTH_ATTEMPTS:
            return False
        return datetime.now() < attempts["locked_until"]

    def _get_lockout_remaining(self, user_id):
        attempts = self.failed_attempts.get(user_id)
        if not attempts:
            return 0
        remaining = attempts["locked_until"] - datetime.now()
        return max(0, int(remaining.total_seconds() / 60))

    def _record_failed_attempt(self, user_id):
        now = datetime.now()
        if user_id not in self.failed_attempts:
            self.failed_attempts[user_id] = {"count": 1, "locked_until": None}
        else:
            self.failed_attempts[user_id]["count"] += 1

        if self.failed_attempts[user_id]["count"] >= config.MAX_AUTH_ATTEMPTS:
            self.failed_attempts[user_id]["locked_until"] = now + timedelta(
                minutes=config.AUTH_LOCKOUT_MINUTES
            )

    def locked_account_count(self):
        return len([uid for uid in self.failed_attempts if self._is_locked_out(uid)])
