import os, time, traceback
from typing import Dict
from app.device import Device
from app.state import load_state, save_state, now_ts
from app.notify.emailer import send_email, _smtp_client
from app.providers.demo import DemoProvider
from app.providers.boomnow_http import BoomNowHttpProvider

PROVIDER = os.environ.get("PROVIDER", "demo").lower()  # 'demo' or 'boomnow_http'
ALERT_COOLDOWN_MINUTES = int(os.environ.get("ALERT_COOLDOWN_MINUTES", "240"))
OFFLINE_GRACE_MINUTES = int(os.environ.get("OFFLINE_GRACE_MINUTES", "0"))
BATTERY_LOW_THRESHOLD = int(os.environ.get("BATTERY_LOW_THRESHOLD", "0"))  # 0 = disabled
STRICT_EMAIL = (os.environ.get("STRICT_EMAIL", "1") == "1")
ALERT_BATCH_LIMIT = int(os.environ.get("ALERT_BATCH_LIMIT", "20"))
SUPPRESS_FIRST_RUN = (os.environ.get("SUPPRESS_FIRST_RUN", "1") == "1")

def provider():
    if PROVIDER == "demo":
        return DemoProvider()
    elif PROVIDER == "boomnow_http":
        return BoomNowHttpProvider()
    else:
        raise RuntimeError(f"Unknown PROVIDER: {PROVIDER}")

def _listing_name(d: Device) -> str:
    e = (d.extra or {})
    # common patterns from listing-devices
    if isinstance(e.get("listing"), dict):
        return e["listing"].get("name") or e["listing"].get("title")
    for k in ("listingName","listing_name","unitName","roomName",
              "apartmentName","propertyName","buildingName"):
        if isinstance(e.get(k), str) and e[k].strip():
            return e[k].strip()
    return ""


def _details_table(d: Device) -> str:
    listing = _listing_name(d)
    battery = f"{d.battery}%" if d.battery is not None else "—"
    rows = [
        ("Device", d.name),
        ("Listing", listing or "—"),
        ("Device ID", f"<code>{d.id}</code>"),
        ("Battery", battery),
        ("Timestamp (UTC)", time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())),
    ]
    tr = "".join(
        f"<tr><td style='padding:4px 8px;color:#666'>{k}</td>"
        f"<td style='padding:4px 8px'><b>{v}</b></td></tr>" for k, v in rows
    )
    return f"<table style='border-collapse:collapse;margin-top:6px'>{tr}</table>"


def _details_text(d: Device) -> str:
    listing = _listing_name(d) or "—"
    battery = f"{d.battery}%" if d.battery is not None else "—"
    lines = [
        f"Device: {d.name}",
        f"Listing: {listing}",
        f"Device ID: {d.id}",
        f"Battery: {battery}",
        f"Timestamp (UTC): {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())}",
    ]
    return "\n".join(lines)

def alert_offline(d: Device, client=None):
    subject = f"IoT ALERT: {d.name} is OFFLINE"
    html = (
        f"<h3>Device offline</h3>"
        f"<p><b style='color:#b00020'>OFFLINE</b></p>"
        f"{_details_table(d)}"
    )
    text = "Device offline\n" + _details_text(d)
    return send_email(subject, html, text_body=text, client=client)

def alert_recovered(d: Device, client=None):
    subject = f"IoT NOTICE: {d.name} recovered (online)"
    html = (
        f"<h3>Device recovered</h3>"
        f"<p><b style='color:green'>ONLINE</b></p>"
        f"{_details_table(d)}"
    )
    text = "Device recovered\n" + _details_text(d)
    return send_email(subject, html, text_body=text, client=client)

def alert_low_battery(d: Device, client=None):
    subject = f"IoT WARNING: {d.name} low battery ({d.battery}%)"
    html = (
        f"<h3>Low battery</h3>"
        f"{_details_table(d)}"
    )
    text = "Low battery\n" + _details_text(d)
    return send_email(subject, html, text_body=text, client=client)

def main():
    p = provider()
    devices = p.get_devices()
    print(f"[monitor] fetched {len(devices)} devices")
    print(f"[monitor] offline_count={sum(1 for d in devices if d.online is False)}")
    state: Dict = load_state()
    now = now_ts()
    changed = False

    alerts_sent = 0
    state_meta = state.get("_meta", {})
    first_run = not bool(state_meta.get("initialized"))

    # Use one SMTP connection for the whole run (created on-demand)
    smtp = None
    try:
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

                if first_run and SUPPRESS_FIRST_RUN:
                    # Prime state, but do not alert on initial run
                    pass
                elif offline_duration_min >= OFFLINE_GRACE_MINUTES and cooldown_min >= ALERT_COOLDOWN_MINUTES:
                    if ALERT_BATCH_LIMIT > 0 and alerts_sent >= ALERT_BATCH_LIMIT:
                        # Defer remaining alerts to next runs
                        pass
                    else:
                        try:
                            if smtp is None:
                                smtp = _smtp_client()
                            smtp = alert_offline(d, client=smtp) or smtp
                            s["last_offline_alert_ts"] = now
                            changed = True
                            alerts_sent += 1
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
                    if smtp is None:
                        smtp = _smtp_client()
                    smtp = alert_recovered(d, client=smtp) or smtp
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
                        if ALERT_BATCH_LIMIT <= 0 or alerts_sent < ALERT_BATCH_LIMIT:
                            if smtp is None:
                                smtp = _smtp_client()
                            smtp = alert_low_battery(d, client=smtp) or smtp
                            alerts_sent += 1
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
    finally:
        if smtp is not None:
            try:
                smtp.quit()
            except Exception:
                pass

    new_meta = dict(state_meta)
    if "since" not in new_meta:
        new_meta["since"] = now
    new_meta["initialized"] = True
    state["_meta"] = new_meta
    if changed:
        save_state(state)

if __name__ == "__main__":
    main()
