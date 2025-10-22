import os, re, requests
from typing import List, Union
from app.device import Device
from .base import DeviceStatusProvider

BASE_URL = os.environ.get("BOOMNOW_BASE_URL", "").rstrip("/")
DEVICES_ENDPOINT = os.environ.get("BOOMNOW_DEVICES_ENDPOINT", "/api/devices")

# Preferred: long-lived token if you ever get one
API_KEY = os.environ.get("BOOMNOW_API_KEY")

# Programmatic sign-in (service account)
LOGIN_URL = os.environ.get("BOOMNOW_LOGIN_URL")
LOGIN_KIND = (os.environ.get("BOOMNOW_LOGIN_KIND") or "form").lower()  # "json" or "form"
EMAIL = os.environ.get("BOOMNOW_EMAIL")
PASSWORD = os.environ.get("BOOMNOW_PASSWORD")

DEFAULT_HEADERS = {"Accept": "application/json", "User-Agent": "iot-monitor/1.0"}

def _extract_csrf(html: str):
    m = re.search(r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']', html, re.I)
    if m:
        return m.group(1)
    m = re.search(r'name=["\']authenticity_token["\'][^>]*value=["\']([^"\']+)["\']', html, re.I)
    return m.group(1) if m else None

def _login_session() -> requests.Session:
    if not (LOGIN_URL and EMAIL and PASSWORD):
        raise RuntimeError("Service login requested but BOOMNOW_LOGIN_URL/EMAIL/PASSWORD not set")
    s = requests.Session()
    s.headers.update({"User-Agent": DEFAULT_HEADERS["User-Agent"]})

    if LOGIN_KIND == "json":
        # JSON login: {"email": "...", "password": "..."}
        resp = s.post(LOGIN_URL, json={"email": EMAIL, "password": PASSWORD}, timeout=30, allow_redirects=True)
        resp.raise_for_status()
        return s

    # HTML/form login with CSRF
    getp = s.get(LOGIN_URL, timeout=30)
    getp.raise_for_status()
    csrf = _extract_csrf(getp.text)

    # Default fields
    form = {"email": EMAIL, "password": PASSWORD}
    # Support Rails-style nested fields if present
    if re.search(r'name=["\']user\[email\]["\']', getp.text, re.I):
        form = {"user[email]": EMAIL, "user[password]": PASSWORD}
    if csrf:
        form["authenticity_token"] = csrf

    headers = {"Referer": LOGIN_URL, "Origin": BASE_URL or LOGIN_URL.split("/api")[0]}
    postp = s.post(LOGIN_URL, data=form, headers=headers, timeout=30, allow_redirects=True)
    postp.raise_for_status()
    return s

def _coerce_online(value: Union[str, int, float, bool, None]) -> bool:
    # Accept real booleans and 0/1 first
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0

    # Handle common status strings
    if isinstance(value, str):
        v = value.strip().lower()
        if v in {"true", "1", "yes", "online", "up", "connected", "active"}:
            return True
        if v in {"false", "0", "no", "offline", "down", "inactive", "disconnected"}:
            return False

    # Fallback – truthiness
    return bool(value)


class BoomNowHttpProvider(DeviceStatusProvider):
    def get_devices(self) -> List[Device]:
        if not BASE_URL:
            raise RuntimeError("BOOMNOW_BASE_URL must be set for boomnow_http provider")

        url = f"{BASE_URL}{DEVICES_ENDPOINT}"
        headers = dict(DEFAULT_HEADERS)

        # 1) Use API key if you have one in the future
        if API_KEY:
            headers["Authorization"] = f"Bearer {API_KEY}"
            r = requests.get(url, headers=headers, timeout=30)
        else:
            # 2) Programmatic login each run
            session = _login_session()
            headers.setdefault("Origin", BASE_URL)
            headers.setdefault("Referer", BASE_URL + "/dashboard/iot")
            r = session.get(url, headers=headers, timeout=30)

        try:
            r.raise_for_status()
        except requests.HTTPError as e:
            if r.status_code == 401:
                raise RuntimeError("401 Unauthorized: check service creds / LOGIN_KIND / LOGIN_URL") from e
            raise

        payload = r.json()

        # Normalize payload to a list
        if isinstance(payload, dict) and "devices" in payload:
            items = payload["devices"]
        elif isinstance(payload, list):
            items = payload
        else:
            items = payload.get("results", []) if isinstance(payload, dict) else []

        out: List[Device] = []
        for item in items:
            did = str(item.get("id") or item.get("deviceId") or item.get("uuid") or "")
            name = item.get("name") or item.get("label") or item.get("deviceName") or did

            online_raw = item.get("online")
            if online_raw is None:
                online_raw = (
                    item.get("isOnline")
                    or item.get("connected")
                    or (item.get("status") in ("online", "ONLINE", "connected", "up"))
                )
            online = _coerce_online(online_raw)

            battery = None
            for k in ("battery", "batteryPercent", "battery_percentage", "batteryLevel"):
                if k in item and isinstance(item[k], (int, float)):
                    battery = int(item[k])
                    break

            out.append(Device(id=did, name=name, online=online, battery=battery, extra=item))
        return out
