"""
InfluxDB access layer.

Keeps all Flux queries and point-writing in one place so the rest of the
system doesn't need to know how persistence works.
"""

from datetime import datetime

from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

import config


class Database:
    def __init__(self):
        self.client = InfluxDBClient(
            url=config.INFLUX_URL, token=config.INFLUX_TOKEN, org=config.INFLUX_ORG
        )
        self.write_api = self.client.write_api(write_options=SYNCHRONOUS)
        self.query_api = self.client.query_api()

    # ---------- users ----------

    def add_user(self, user_id, zone, pin, check_in, check_out):
        point = (
            Point("authorized_users")
            .tag("user_id", user_id)
            .tag("zone", zone)
            .tag("pin", pin)
            .tag("check_in", check_in)
            .tag("check_out", check_out)
            .field("active", True)
            .time(datetime.utcnow(), WritePrecision.NS)
        )
        self.write_api.write(bucket=config.INFLUX_BUCKET, org=config.INFLUX_ORG, record=point)

    def remove_user(self, user_id):
        """Revoke a user's access by writing a new 'active=False' point.

        InfluxDB is append-only, so revocation is expressed as a new point
        with the same tags and active=False; `_get_user_data` always reads
        the *last* point, so this is enough to lock the user out immediately.
        """
        existing = self._get_user_data(user_id)
        if not existing:
            return False

        point = (
            Point("authorized_users")
            .tag("user_id", existing["user_id"])
            .tag("zone", existing["zone"])
            .tag("pin", existing["pin"])
            .tag("check_in", existing["check_in"])
            .tag("check_out", existing["check_out"])
            .field("active", False)
            .time(datetime.utcnow(), WritePrecision.NS)
        )
        self.write_api.write(bucket=config.INFLUX_BUCKET, org=config.INFLUX_ORG, record=point)
        return True

    def _get_user_data(self, user_id):
        # Deliberately no `|> last()` here: if a user has been added under
        # more than one zone over time, each zone is a distinct InfluxDB
        # series (different tag set), so InfluxDB returns one table per
        # series. `last()` only picks the last point *within* each table,
        # and naively reading tables[0] can return a stale/revoked series
        # instead of the actual most recent one. Instead we scan every
        # record across every table and pick the single most recent point.
        query = f'''
        from(bucket: "{config.INFLUX_BUCKET}")
          |> range(start: -30d)
          |> filter(fn: (r) => r["_measurement"] == "authorized_users")
          |> filter(fn: (r) => r["user_id"] == "{user_id}")
          |> filter(fn: (r) => r["_field"] == "active")
        '''
        try:
            tables = self.query_api.query(query, org=config.INFLUX_ORG)
            latest_record = None
            for table in tables:
                for record in table.records:
                    if latest_record is None or record.get_time() > latest_record.get_time():
                        latest_record = record
            if latest_record:
                record = latest_record
                return {
                    "user_id": record.values.get("user_id"),
                    "zone": record.values.get("zone"),
                    "pin": record.values.get("pin"),
                    "check_in": record.values.get("check_in"),
                    "check_out": record.values.get("check_out"),
                    "active": record.get_value(),
                }
            return None
        except Exception:
            return None

    def get_user_data(self, user_id):
        data = self._get_user_data(user_id)
        if data and data.get("active"):
            return data
        return None

    def list_active_users(self):
        query = f'''
        from(bucket: "{config.INFLUX_BUCKET}")
          |> range(start: -30d)
          |> filter(fn: (r) => r["_measurement"] == "authorized_users")
          |> filter(fn: (r) => r["_field"] == "active")
          |> group(columns: ["user_id", "zone"])
          |> last()
        '''
        users = []
        try:
            tables = self.query_api.query(query, org=config.INFLUX_ORG)
            for table in tables:
                for record in table.records:
                    if record.get_value():
                        users.append(
                            {
                                "user_id": record.values.get("user_id"),
                                "zone": record.values.get("zone"),
                                "pin": record.values.get("pin"),
                                "check_in": record.values.get("check_in"),
                                "check_out": record.values.get("check_out"),
                            }
                        )
        except Exception as e:
            print(f"Error listing users: {e}")
        return users

    # ---------- access log ----------

    def log_access_event(self, user_id, zone, access_type, success, message):
        try:
            point = (
                Point("access_events")
                .tag("user_id", user_id)
                .tag("zone", zone)
                .tag("access_type", access_type)
                .tag("success", str(success))
                .field("message", message)
                .field("timestamp", datetime.now().isoformat())
                .time(datetime.utcnow(), WritePrecision.NS)
            )
            self.write_api.write(bucket=config.INFLUX_BUCKET, org=config.INFLUX_ORG, record=point)
        except Exception as e:
            print(f"Error logging access: {e}")

    def get_recent_access_events(self, limit=20):
        query = f'''
        from(bucket: "{config.INFLUX_BUCKET}")
          |> range(start: -7d)
          |> filter(fn: (r) => r["_measurement"] == "access_events")
          |> filter(fn: (r) => r["_field"] == "message")
          |> sort(columns: ["_time"], desc: true)
          |> limit(n: {limit})
        '''
        events = []
        try:
            tables = self.query_api.query(query, org=config.INFLUX_ORG)
            for table in tables:
                for record in table.records:
                    events.append(
                        {
                            "time": record.get_time(),
                            "user_id": record.values.get("user_id"),
                            "zone": record.values.get("zone"),
                            "success": record.values.get("success"),
                            "message": record.get_value(),
                        }
                    )
        except Exception as e:
            print(f"Error fetching access log: {e}")
        return events
