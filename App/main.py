import html
import os, time, traceback
from typing import Dict, Iterable, Optional
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

def _normalize_str(value: Optional[str]) -> str:
    if not value:
        return ""
    return " ".join(value.split())


def _string_from(value) -> str:
    if isinstance(value, str):
        return _normalize_str(value)
    if isinstance(value, (list, tuple)):
        for item in value:
            s = _string_from(item)
            if s:
                return s
        return ""
    if isinstance(value, dict):
        for key in (
            "name",
            "label",
            "title",
            "displayName",
            "display_name",
            "description",
            "value",
            "text",
        ):
            s = _string_from(value.get(key))
            if s:
                return s
    return ""


def _get_by_path(data: Dict, path: str):
    current = data
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _first_field(extra: Dict, candidates: Iterable[str]) -> str:
    for key in candidates:
        value = None
        if "." in key:
            value = _get_by_path(extra, key)
        else:
            value = extra.get(key)
        s = _string_from(value)
        if s:
            return s
    return ""


def _listing_name(d: Device) -> str:
    e = (d.extra or {})
    if isinstance(e.get("listing"), dict):
        listing = _string_from(e["listing"])
        if listing:
            return listing
        for key in ("name", "title"):
            listing = _string_from(e["listing"].get(key))
            if listing:
                return listing
    return _first_field(
        e,
        (
            "listingName",
            "listing_name",
            "unitName",
            "unit_name",
            "roomName",
            "room_name",
            "apartmentName",
            "propertyName",
            "buildingName",
        ),
    )


def _entry_point_name(d: Device) -> str:
    e = d.extra or {}
    return _first_field(
        e,
        (
            "entryPointName",
            "entryPoint",
            "entry_point",
            "entry.name",
            "entry.label",
            "doorName",
            "door.name",
            "door.label",
            "lockName",
            "lock.name",
            "lock.label",
            "boom.entryPoint.name",
            "boom.door.name",
        ),
    )


def _entry_details(d: Device) -> str:
    e = d.extra or {}
    return _first_field(
        e,
        (
            "entryDetails",
            "entry_details",
            "entry.detail",
            "entryDetail",
            "entry_detail",
            "codeName",
            "code_name",
            "accessCode",
            "access_code",
            "accessCodeName",
            "access_code_name",
            "pinCode",
            "pin_code",
            "credential",
            "credentialName",
            "credential_name",
            "boom.entry.details",
            "boom.entry.codeName",
        ),
    )


def _hardware_label(d: Device) -> str:
    if d.name and d.name != d.id:
        hardware = _normalize_str(d.name)
        if hardware:
            return hardware
    e = d.extra or {}
    return _first_field(
        e,
        (
            "deviceName",
            "device_name",
            "deviceLabel",
            "device_label",
            "hardwareName",
            "hardware_name",
            "lockModel",
            "modelName",
        ),
    )


def _device_display_label(d: Device) -> str:
    e = d.extra or {}
    candidates = [
        _entry_point_name(d),
        _first_field(
            e,
            (
                "displayName",
                "display_name",
                "alias",
                "nickname",
                "name",
            ),
        ),
        _hardware_label(d),
    ]
    for candidate in candidates:
        if candidate and candidate != d.id:
            return candidate
    return d.id


def _subject_label(d: Device) -> str:
    parts = [_device_display_label(d), _listing_name(d)]
    seen = []
    for part in parts:
        normalized = _normalize_str(part)
        if normalized and normalized not in seen:
            seen.append(normalized)
    return " — ".join(seen) if seen else d.id


def _details_rows(d: Device):
    rows = []
    display = _device_display_label(d)
    if display and display != d.id:
        rows.append(("Device", display))

    listing = _listing_name(d)
    if listing:
        rows.append(("Listing", listing))

    entry = _entry_point_name(d)
    if entry and entry != display:
        rows.append(("Entry point", entry))

    detail = _entry_details(d)
    if detail:
        rows.append(("Entry details", detail))

    hardware = _hardware_label(d)
    if hardware and hardware not in {display, entry}:
        rows.append(("Hardware name", hardware))

    rows.append(("Device ID", d.id))
    battery = f"{d.battery}%" if d.battery is not None else "—"
    rows.append(("Battery", battery))
    rows.append(("Timestamp (UTC)", time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())))
    return rows


def _details_table(d: Device) -> str:
    tr = "".join(
        f"<tr><td style='padding:4px 8px;color:#666'>{html.escape(label)}</td>"
        f"<td style='padding:4px 8px'><b>{html.escape(value)}</b></td></tr>"
        for label, value in _details_rows(d)
    )
    return f"<table style='border-collapse:collapse;margin-top:6px'>{tr}</table>"


def _details_text(d: Device) -> str:
    return "\n".join(f"{label}: {value}" for label, value in _details_rows(d))

def alert_offline(d: Device, client=None):
    subject = f"IoT ALERT: {_subject_label(d)} is OFFLINE"
    friendly = _device_display_label(d)
    friendly_html = html.escape(friendly)
    html = (
        "<h3 style='margin:0 0 8px'>Device offline</h3>"
        f"<p style='margin:0 0 12px'>We stopped receiving updates from "
        f"<b>{friendly_html}</b>. Please verify the lock, hub, or network.</p>"
        f"<p style='margin:0 0 12px;color:#b00020;font-weight:bold'>OFFLINE</p>"
        f"{_details_table(d)}"
    )
    text = (
        "Device offline\n"
        f"We stopped receiving updates from {friendly}.\n\n"
        f"{_details_text(d)}"
    )
    return send_email(subject, html, text_body=text, client=client)

def alert_recovered(d: Device, client=None):
    subject = f"IoT NOTICE: {_subject_label(d)} recovered (online)"
    friendly = _device_display_label(d)
    friendly_html = html.escape(friendly)
    html = (
        "<h3 style='margin:0 0 8px'>Device recovered</h3>"
        f"<p style='margin:0 0 12px'>Connectivity has been restored for "
        f"<b>{friendly_html}</b>.</p>"
        f"<p style='margin:0 0 12px;color:green;font-weight:bold'>ONLINE</p>"
        f"{_details_table(d)}"
    )
    text = (
        "Device recovered\n"
        f"Connectivity has been restored for {friendly}.\n\n"
        f"{_details_text(d)}"
    )
    return send_email(subject, html, text_body=text, client=client)

def alert_low_battery(d: Device, client=None):
    subject = f"IoT WARNING: {_subject_label(d)} low battery ({d.battery}%)"
    friendly = _device_display_label(d)
    friendly_html = html.escape(friendly)
    html = (
        "<h3 style='margin:0 0 8px'>Low battery</h3>"
        f"<p style='margin:0 0 12px'>The reported battery level for "
        f"<b>{friendly_html}</b> is at or below the configured threshold.</p>"
        f"{_details_table(d)}"
    )
    text = (
        "Low battery\n"
        f"The reported battery level for {friendly} is at or below the configured threshold.\n\n"
        f"{_details_text(d)}"
    )
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
