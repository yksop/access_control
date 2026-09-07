"""
Minimal web front end for managing the access control list.

This is intentionally separate from main.py / the CLI: it only needs the
database and authenticator (for PIN generation), not MQTT or the camera,
so it can run alongside the CLI app without clashing over the MQTT
client ID. Run it with:

    python3 web_app.py

Then open http://<pi-ip>:5000 from any device on the same network.
"""

from datetime import datetime, timedelta

from flask import Flask, jsonify, request

import config
from database import Database

app = Flask(__name__)
db = Database()

INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Access Control</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 720px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }
  h1 { font-size: 1.4rem; }
  h2 { font-size: 1.1rem; margin-top: 2rem; }
  table { width: 100%; border-collapse: collapse; margin-top: 0.5rem; }
  th, td { text-align: left; padding: 0.4rem 0.6rem; border-bottom: 1px solid #ddd; font-size: 0.9rem; }
  th { color: #555; font-weight: 600; }
  form { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.5rem; align-items: end; }
  label { display: flex; flex-direction: column; font-size: 0.8rem; color: #555; }
  input { padding: 0.4rem; border: 1px solid #ccc; border-radius: 4px; font-size: 0.9rem; }
  button { padding: 0.45rem 0.9rem; border: none; border-radius: 4px; background: #1a73e8; color: white; cursor: pointer; font-size: 0.9rem; }
  button.danger { background: #d93025; }
  button:hover { opacity: 0.9; }
  .pin { font-family: monospace; font-weight: 600; }
  #status { color: #555; font-size: 0.85rem; margin-top: 1rem; }
  #msg { margin-top: 0.5rem; font-size: 0.9rem; }
</style>
</head>
<body>
  <h1>Access Control — User Management</h1>

  <h2>Add user</h2>
  <form id="add-form">
    <label>User ID <input name="user_id" required></label>
    <label>Zone <input name="zone" required placeholder="lab-1"></label>
    <label>Start <input name="check_in" type="datetime-local" required></label>
    <label>End <input name="check_out" type="datetime-local" required></label>
    <button type="submit">Add</button>
  </form>
  <div id="msg"></div>

  <h2>Active users</h2>
  <table id="users-table">
    <thead><tr><th>User ID</th><th>Zone</th><th>PIN</th><th>Start</th><th>End</th><th></th></tr></thead>
    <tbody></tbody>
  </table>

  <div id="status"></div>

<script>
async function loadUsers() {
  const res = await fetch('/api/users');
  const users = await res.json();
  const tbody = document.querySelector('#users-table tbody');
  tbody.innerHTML = '';
  users.forEach(u => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${u.user_id}</td>
      <td>${u.zone}</td>
      <td class="pin">${u.pin}</td>
      <td>${u.check_in}</td>
      <td>${u.check_out}</td>
      <td><button class="danger" onclick="removeUser('${u.user_id}')">Remove</button></td>
    `;
    tbody.appendChild(tr);
  });
}

async function removeUser(userId) {
  if (!confirm(`Revoke access for ${userId}?`)) return;
  await fetch(`/api/users/${encodeURIComponent(userId)}`, { method: 'DELETE' });
  loadUsers();
}

document.getElementById('add-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = e.target;
  const payload = Object.fromEntries(new FormData(form).entries());
  const msg = document.getElementById('msg');
  const res = await fetch('/api/users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  const data = await res.json();
  if (res.ok) {
    msg.style.color = 'green';
    msg.textContent = `Added ${data.user_id} — PIN: ${data.pin}`;
    form.reset();
    loadUsers();
  } else {
    msg.style.color = '#d93025';
    msg.textContent = data.error || 'Failed to add user';
  }
});

async function loadStatus() {
  const res = await fetch('/api/status');
  const s = await res.json();
  document.getElementById('status').textContent =
    `Camera: ${s.camera_available ? 'available' : 'not available'} · Door lock: ${s.door_lock_ready ? 'armed' : 'simulated'}`;
}

loadUsers();
loadStatus();
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return INDEX_HTML


@app.route("/api/users", methods=["GET"])
def api_list_users():
    return jsonify(db.list_active_users())


@app.route("/api/users", methods=["POST"])
def api_add_user():
    data = request.get_json(force=True)
    user_id = (data.get("user_id") or "").strip()
    zone = (data.get("zone") or "").strip()
    check_in = data.get("check_in")
    check_out = data.get("check_out")

    if not all([user_id, zone, check_in, check_out]):
        return jsonify({"error": "user_id, zone, check_in, and check_out are all required"}), 400

    try:
        # datetime-local inputs come as "YYYY-MM-DDTHH:MM"; isoformat() is fine as-is.
        datetime.fromisoformat(check_in)
        datetime.fromisoformat(check_out)
    except ValueError:
        return jsonify({"error": "check_in/check_out must be valid datetimes"}), 400

    import secrets

    pin = f"{secrets.randbelow(900000) + 100000}"
    db.add_user(user_id, zone, pin, check_in, check_out)
    return jsonify({"user_id": user_id, "zone": zone, "pin": pin})


@app.route("/api/users/<user_id>", methods=["DELETE"])
def api_remove_user(user_id):
    removed = db.remove_user(user_id)
    if not removed:
        return jsonify({"error": "user not found or already inactive"}), 404
    return jsonify({"user_id": user_id, "removed": True})


@app.route("/api/log", methods=["GET"])
def api_log():
    return jsonify(
        [
            {**e, "time": e["time"].isoformat() if e["time"] else None}
            for e in db.get_recent_access_events()
        ]
    )


@app.route("/api/status", methods=["GET"])
def api_status():
    try:
        from camera_scanner import CAMERA_AVAILABLE
    except ImportError:
        CAMERA_AVAILABLE = False
    return jsonify(
        {
            "camera_available": CAMERA_AVAILABLE,
            "door_lock_ready": config.DOOR_LOCK_ENABLED,
        }
    )


if __name__ == "__main__":
    app.run(host=config.WEB_UI_HOST, port=config.WEB_UI_PORT, debug=False)
