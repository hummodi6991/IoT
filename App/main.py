
import os, time, traceback
from typing import Dict
from app.device import Device
from app.state import load_state, save_state, now_ts
from app.notify.emailer import send_email
from app.providers.demo import DemoProvider
from app.providers.boomnow_http import BoomNowHttpProvider

PROVIDER = os.environ.get("PROVIDER", "demo").lower()  # 'demo' or 'boomnow_http'
ALERT_COOLDOWN_MINUTES = int(os.environ.get("ALERT_COOLDOWN_MINUTES", "240"))
OFFLINE_GRACE_MINUTES = int(os.environ.get("OFFLINE_GRACE_MINUTES", "0"))
BATTERY_LOW_THRESHOLD = int(os.environ.get("BATTERY_LOW_THRESHOLD", "0"))  # 0 = disabled
STRICT_EMAIL = (os.environ.get("STRICT_EMAIL", "1") == "1")

def provider():
    if PROVIDER == "demo":
        return DemoProvider()
    elif PROVIDER == "boomnow_http":
        return BoomNowHttpProvider()
    else:
        raise RuntimeError(f"Unknown PROVIDER: {PROVIDER}")

def fmt_device(d: Device) -> str:
    b = f" | Battery: {d.battery}%" if d.battery is not None else ""
    return f"{d.name} (id={d.id}){b}"

def alert_offline(d: Device):
    subject = f"IoT ALERT: {d.name} is OFFLINE"
    html = f"""
    <h3>Device offline</h3>
    <p><b>{d.name}</b> (id={d.id}) appears to be <b style='color:#b00020'>OFFLINE</b>.</p>
    {('<p>Battery: ' + str(d.battery) + '%</p>') if d.battery is not None else ''}
    <p>Timestamp (UTC): {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())}</p>
    """
    send_email(subject, html)

def alert_recovered(d: Device):
    subject = f"IoT NOTICE: {d.name} recovered (online)"
    html = f"""
    <h3>Device recovered</h3>
    <p><b>{d.name}</b> (id={d.id}) is back <b style='color:green'>ONLINE</b>.</p>
    <p>Timestamp (UTC): {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())}</p>
    """
    send_email(subject, html)

def alert_low_battery(d: Device):
    subject = f"IoT WARNING: {d.name} low battery ({d.battery}%)"
    html = f"""
    <h3>Low battery</h3>
    <p><b>{d.name}</b> (id={d.id}) battery is at <b>{d.battery}%</b>.</p>
    <p>Timestamp (UTC): {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())}</p>
    """
    send_email(subject, html)

def main():
    p = provider()
    devices = p.get_devices()
    print(f"[monitor] provider={PROVIDER} fetched {len(devices)} devices", flush=True)
    if devices:
        offline = [d for d in devices if d.online is False]
        print(f"[monitor] offline_count={len(offline)}", flush=True)
    state: Dict = load_state()
    now = now_ts()
    changed = False

    for d in devices:
        s = state.setdefault(d.id, {})
        last_status = s.get("online")
        last_change = s.get("last_change_ts", now)
        last_alert = s.get("last_offline_alert_ts", 0.0)
        last_batt_alert = s.get("last_battery_alert_ts", 0.0)

        # Update online status and last_change timestamp if changed
        if last_status is None or last_status != d.online:
            s["online"] = d.online
            s["last_change_ts"] = now
            changed = True

        # OFFLINE alerting logic
        if d.online is False:
            offline_duration_min = (now - s.get("last_change_ts", now)) / 60.0
            cooldown_min = (now - last_alert) / 60.0

            if offline_duration_min >= OFFLINE_GRACE_MINUTES and cooldown_min >= ALERT_COOLDOWN_MINUTES:
                try:
                    alert_offline(d)
                    s["last_offline_alert_ts"] = now
                    changed = True
                except Exception as exc:
                    traceback.print_exc()
                    print(
                        f"[email] offline alert failed for device={d.id} name={d.name}: {exc}",
                        flush=True,
                    )
                    if STRICT_EMAIL:
                        raise

        # Recovery logic
        if last_status is False and d.online is True:
            try:
                alert_recovered(d)
                changed = True
            except Exception as exc:
                traceback.print_exc()
                print(
                    f"[email] recovery alert failed for device={d.id} name={d.name}: {exc}",
                    flush=True,
                )
                if STRICT_EMAIL:
                    raise

        # Low battery logic (optional)
        if BATTERY_LOW_THRESHOLD and d.battery is not None and d.battery <= BATTERY_LOW_THRESHOLD:
            batt_cooldown_min = (now - last_batt_alert) / 60.0
            if batt_cooldown_min >= ALERT_COOLDOWN_MINUTES:
                try:
                    alert_low_battery(d)
                    s["last_battery_alert_ts"] = now
                    changed = True
                except Exception as exc:
                    traceback.print_exc()
                    print(
                        f"[email] low battery alert failed for device={d.id} name={d.name}: {exc}",
                        flush=True,
                    )
                    if STRICT_EMAIL:
                        raise

        # Save back any updates
        state[d.id] = s

    if changed:
        save_state(state)

if __name__ == "__main__":
    main()
