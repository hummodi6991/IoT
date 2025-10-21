
import os, json
from flask import Flask, request, jsonify
from app.device import Device
from app.state import load_state, save_state, now_ts
from app.notify.emailer import send_email

app = Flask(__name__)

ALERT_COOLDOWN_MINUTES = int(os.environ.get("ALERT_COOLDOWN_MINUTES", "240"))
BATTERY_LOW_THRESHOLD = int(os.environ.get("BATTERY_LOW_THRESHOLD", "0"))

def alert(subject: str, html: str):
    send_email(subject, html)

@app.route('/health', methods=['GET'])
def health():
    return {'ok': True}

@app.route('/event', methods=['POST'])
def event():
    # Expected JSON: { deviceId, name, online, battery }
    payload = request.get_json(force=True)
    d = Device(
        id=str(payload.get('deviceId') or payload.get('id')),
        name=str(payload.get('name') or 'device'),
        online=bool(payload.get('online')),
        battery=payload.get('battery')
    )

    state = load_state()
    s = state.setdefault(d.id, {})
    last_status = s.get('online')
    now = now_ts()

    if last_status is None or last_status != d.online:
        s['online'] = d.online
        s['last_change_ts'] = now

        if d.online is False:
            alert(f"IoT ALERT: {d.name} is OFFLINE", f"<p><b>{d.name}</b> went offline.</p>")
        elif last_status is False and d.online is True:
            alert(f"IoT NOTICE: {d.name} recovered", f"<p><b>{d.name}</b> is back online.</p>")

    if BATTERY_LOW_THRESHOLD and d.battery is not None and d.battery <= BATTERY_LOW_THRESHOLD:
        last_b = s.get('last_battery_alert_ts', 0.0)
        if (now - last_b) / 60.0 >= ALERT_COOLDOWN_MINUTES:
            alert(f"IoT WARNING: {d.name} low battery ({d.battery}%)", f"<p><b>{d.name}</b> battery {d.battery}%.</p>")
            s['last_battery_alert_ts'] = now

    state[d.id] = s
    save_state(state)
    return jsonify({'ok': True})
