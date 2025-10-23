import os, re, requests
from typing import List, Union, Any
from app.device import Device
from .base import DeviceStatusProvider

BASE_URL = os.environ.get("BOOMNOW_BASE_URL", "").rstrip("/")
DEVICES_ENDPOINT = os.environ.get("BOOMNOW_DEVICES_ENDPOINT", "/api/devices")
DEVICES_JSON_PATH = (os.environ.get("BOOMNOW_DEVICES_JSON_PATH") or "").strip()
DEBUG_PROVIDER = (os.environ.get("DEBUG_PROVIDER", "0") == "1")

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
    s.headers.update(DEFAULT_HEADERS)

    if LOGIN_KIND == "json":
        # JSON login: {"email": "...", "password": "..."}
        resp = s.post(LOGIN_URL, json={"email": EMAIL, "password": PASSWORD}, timeout=30, allow_redirects=True)
        resp.raise_for_status()
        # Some APIs return a token instead of cookie-based auth. If present, attach it.
        try:
            data = resp.json()
            token = data.get("token") or data.get("jwt") or data.get("access_token") or data.get("apiKey")
            if token:
                s.headers.update({"Authorization": f"Bearer {token}"})
        except Exception:
            pass
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
        if v in {"true", "1", "yes", "online", "up", "connected", "active", "alive"}:
            return True
        if v in {
            "false",
            "0",
            "no",
            "offline",
            "down",
            "inactive",
            "disconnected",
            "no data",
            "unknown",
            "n/a",
            "na",
            "not available",
            "none",
            "null",
            "—",
            "-",
        }:
            return False

    # Fallback – truthiness
    return bool(value)


def _get_by_path(obj: Any, path: str):
    if not path:
        return None
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def _is_deviceish(d: Any) -> bool:
    return isinstance(d, dict) and any(k in d for k in ("id", "deviceId", "uuid", "name", "deviceName", "label"))


def _find_first_list_of_devices(o: Any):
    # Depth-first search for the first list of dicts that look like devices.
    if isinstance(o, list):
        if o and all(isinstance(x, dict) for x in o) and any(_is_deviceish(x) for x in o):
            return o
        for x in o:
            found = _find_first_list_of_devices(x)
            if found is not None:
                return found
    elif isinstance(o, dict):
        for v in o.values():
            found = _find_first_list_of_devices(v)
            if found is not None:
                return found
    return None


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

        try:
            payload = r.json()
        except ValueError:
            ct = r.headers.get("content-type")
            raise RuntimeError(f"Expected JSON but got content-type={ct}")

        # Normalize payload to a list of device dicts
        items = None
        # 1) explicit dot-path (e.g., "data" or "data.items")
        if DEVICES_JSON_PATH:
            items = _get_by_path(payload, DEVICES_JSON_PATH)
        # 2) common keys
        if items is None and isinstance(payload, dict):
            for k in ("devices", "data", "items", "rows", "results", "list", "entries", "records", "content"):
                v = payload.get(k)
                if isinstance(v, list):
                    items = v
                    break
        # 3) top-level array
        if items is None and isinstance(payload, list):
            items = payload
        # 4) as a last resort, recursively find the first plausible list
        if items is None:
            items = _find_first_list_of_devices(payload) or []

        if DEBUG_PROVIDER:
            top = list(payload.keys())[:10] if isinstance(payload, dict) else [type(payload).__name__]
            print(f"[provider] top_keys={top} items_count={len(items)}")

        out: List[Device] = []
        for item in items:
            did = str(item.get("id") or item.get("deviceId") or item.get("uuid") or "")
            name = item.get("name") or item.get("label") or item.get("deviceName") or did

            # derive "online" from whatever the API returns
            online_raw = item.get("online")
            if online_raw is None:
                online_raw = item.get("isOnline")
            if online_raw is None:
                online_raw = item.get("connected")
            if online_raw is None and "status" in item:
                status = item.get("status")
                if isinstance(status, dict):
                    online_raw = status.get("name") or status.get("text") or status.get("value") or status.get("color")
                else:
                    online_raw = status
            if online_raw is None:
                indicator = (
                    item.get("statusColor")
                    or item.get("status_color")
                    or item.get("indicator")
                    or item.get("onlineColor")
                    or item.get("statusDot")
                )
                if indicator:
                    sv = str(indicator).strip().lower()
                    if sv in {"green", "success", "ok"}:
                        online_raw = True
                    elif sv in {"red", "danger", "error"}:
                        online_raw = False
            online = _coerce_online(online_raw)

            battery = None
            for k in ("battery", "batteryPercent", "battery_percentage", "batteryLevel", "battery_level"):
                if k in item and isinstance(item[k], (int, float)):
                    battery = int(item[k])
                    break

            out.append(Device(id=did, name=name, online=online, battery=battery, extra=item))
        return out
