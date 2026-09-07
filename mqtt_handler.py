"""MQTT communication layer: subscribes to request topics, dispatches to
the AccessControlSystem, and publishes responses/events/status."""

import json
import uuid
from datetime import datetime

import paho.mqtt.client as mqtt

import config


class MQTTHandler:
    def __init__(self, system):
        self.system = system
        self.client = mqtt.Client(client_id=config.MQTT_CLIENT_ID)
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.client.on_disconnect = self.on_disconnect
        self.connected = False

    def connect(self):
        try:
            self.client.connect(config.MQTT_BROKER, config.MQTT_PORT, config.MQTT_KEEPALIVE)
            self.client.loop_start()
            return True
        except Exception as e:
            print(f"MQTT connection error: {e}")
            return False

    def disconnect(self):
        self.client.loop_stop()
        self.client.disconnect()

    def on_connect(self, client, userdata, flags, rc):
        if rc != 0:
            print(f"MQTT connection failed with code {rc}")
            return
        self.connected = True
        print("Connected to MQTT broker")
        topics = config.MQTT_TOPICS
        for key in (
            "auth_request",
            "qr_generate_request",
            "qr_validate_request",
            "user_add_request",
            "user_remove_request",
            "user_list_request",
        ):
            client.subscribe(topics[key])
            print(f"Subscribed to {topics[key]}")

    def on_disconnect(self, client, userdata, rc):
        self.connected = False
        print("Disconnected from MQTT broker")

    def on_message(self, client, userdata, msg):
        try:
            payload = json.loads(msg.payload.decode())
            print(f"Received message on {msg.topic}: {payload}")

            handlers = {
                config.MQTT_TOPICS["auth_request"]: self._handle_auth,
                config.MQTT_TOPICS["qr_generate_request"]: self._handle_qr_generate,
                config.MQTT_TOPICS["qr_validate_request"]: self._handle_qr_validate,
                config.MQTT_TOPICS["user_add_request"]: self._handle_user_add,
                config.MQTT_TOPICS["user_remove_request"]: self._handle_user_remove,
                config.MQTT_TOPICS["user_list_request"]: self._handle_user_list,
            }
            handler = handlers.get(msg.topic)
            if handler:
                handler(payload)
        except Exception as e:
            print(f"Error handling MQTT message: {e}")

    def publish(self, topic, payload):
        if not self.connected:
            print("MQTT not connected")
            return False
        try:
            self.client.publish(topic, json.dumps(payload))
            return True
        except Exception as e:
            print(f"Error publishing MQTT message: {e}")
            return False

    # ---------- request handlers ----------

    def _handle_auth(self, payload):
        request_id = payload.get("request_id", str(uuid.uuid4()))
        user_id, pin_code = payload.get("user_id"), payload.get("pin_code")
        if not user_id or not pin_code:
            response = {"request_id": request_id, "success": False, "message": "Missing user_id or pin_code"}
        else:
            success, result = self.system.authenticator.authenticate(user_id, pin_code)
            response = (
                {"request_id": request_id, "success": True, "user_data": result}
                if success
                else {"request_id": request_id, "success": False, "message": result}
            )
        self.publish(config.MQTT_TOPICS["auth_response"], response)

    def _handle_qr_generate(self, payload):
        request_id = payload.get("request_id", str(uuid.uuid4()))
        user_id, pin_code = payload.get("user_id"), payload.get("pin_code")
        if not user_id or not pin_code:
            response = {"request_id": request_id, "success": False, "message": "Missing user_id or pin_code"}
        else:
            success, qr_file_or_error = self.system.authenticate_and_generate_qr(user_id, pin_code)
            if success:
                response = {
                    "request_id": request_id,
                    "success": True,
                    "qr_data": self.system.qr_manager.get_last_generated_qr(),
                    "qr_file": qr_file_or_error,
                    "expires_in": config.TEMP_QR_LIFETIME_SECONDS,
                }
            else:
                response = {"request_id": request_id, "success": False, "message": qr_file_or_error}
        self.publish(config.MQTT_TOPICS["qr_generate_response"], response)

    def _handle_qr_validate(self, payload):
        request_id = payload.get("request_id", str(uuid.uuid4()))
        qr_data = payload.get("qr_data")
        if not qr_data:
            response = {"request_id": request_id, "success": False, "message": "Missing qr_data"}
        else:
            valid, result = self.system.validate_access_qr(qr_data)
            response = {"request_id": request_id, "success": valid, "message": result}
            if valid:
                self.publish(
                    config.MQTT_TOPICS["access_event"],
                    {"timestamp": datetime.now().isoformat(), "event_type": "access_granted", "message": result},
                )
        self.publish(config.MQTT_TOPICS["qr_validate_response"], response)

    def _handle_user_add(self, payload):
        request_id = payload.get("request_id", str(uuid.uuid4()))
        user_id, zone = payload.get("user_id"), payload.get("zone")
        check_in, check_out = payload.get("check_in"), payload.get("check_out")
        if not all([user_id, zone, check_in, check_out]):
            response = {"request_id": request_id, "success": False, "message": "Missing required fields"}
        else:
            success, pin = self.system.add_user(user_id, zone, check_in, check_out)
            response = (
                {"request_id": request_id, "success": True, "user_id": user_id, "pin": pin, "zone": zone}
                if success
                else {"request_id": request_id, "success": False, "message": "Failed to add user"}
            )
        self.publish(config.MQTT_TOPICS["user_add_response"], response)

    def _handle_user_remove(self, payload):
        request_id = payload.get("request_id", str(uuid.uuid4()))
        user_id = payload.get("user_id")
        if not user_id:
            response = {"request_id": request_id, "success": False, "message": "Missing user_id"}
        else:
            success = self.system.remove_user(user_id)
            response = (
                {"request_id": request_id, "success": True, "user_id": user_id}
                if success
                else {"request_id": request_id, "success": False, "message": "User not found or already inactive"}
            )
        self.publish(config.MQTT_TOPICS["user_remove_response"], response)

    def _handle_user_list(self, payload):
        request_id = payload.get("request_id", str(uuid.uuid4()))
        users = self.system.get_active_users_list()
        self.publish(
            config.MQTT_TOPICS["user_list_response"],
            {"request_id": request_id, "success": True, "users": users},
        )

    def publish_system_status(self):
        try:
            status = {
                "timestamp": datetime.now().isoformat(),
                "active_qr_codes": self.system.qr_manager.get_active_count(),
                "qr_lifetime": config.TEMP_QR_LIFETIME_SECONDS,
                "camera_available": self.system.camera_available,
                "locked_accounts": self.system.authenticator.locked_account_count(),
            }
            self.publish(config.MQTT_TOPICS["system_status"], status)
        except Exception as e:
            print(f"Error publishing system status: {e}")
