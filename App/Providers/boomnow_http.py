import os, re, json, requests
from typing import List, Union, Any, Dict, Iterable, Optional
from app.device import Device
from .base import DeviceStatusProvider

BASE_URL = os.environ.get("BOOMNOW_BASE_URL", "").rstrip("/")
DEVICES_ENDPOINT = os.environ.get("BOOMNOW_DEVICES_ENDPOINT", "/api/devices")
DEVICES_JSON_PATH = (os.environ.get("BOOMNOW_DEVICES_JSON_PATH") or "").strip()
DEBUG_PROVIDER = (os.environ.get("DEBUG_PROVIDER", "0") == "1")
DEVICES_QUERY = (os.environ.get("BOOMNOW_DEVICES_QUERY") or "").lstrip("?")
EXTRA_HEADERS = os.environ.get("BOOMNOW_EXTRA_HEADERS")  # JSON dict, optional

# Preferred: long-lived token if you ever get one
API_KEY = os.environ.get("BOOMNOW_API_KEY")

# Programmatic sign-in (service account)
LOGIN_URL = os.environ.get("BOOMNOW_LOGIN_URL")
LOGIN_KIND = (os.environ.get("BOOMNOW_LOGIN_KIND") or "form").lower()  # "json" or "form"
EMAIL = os.environ.get("BOOMNOW_EMAIL")
PASSWORD = os.environ.get("BOOMNOW_PASSWORD")

DEFAULT_HEADERS = {"Accept": "application/json", "User-Agent": "iot-monitor/1.0"}
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT_SECONDS", "8"))


def _safe_json(resp: requests.Response) -> Optional[Any]:
    try:
        return resp.json()
    except Exception:
        return None


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
        resp = s.post(
            LOGIN_URL,
            json={"email": EMAIL, "password": PASSWORD},
            timeout=HTTP_TIMEOUT,
            allow_redirects=True,
        )
        resp.raise_for_status()
        # Some APIs return a token instead of cookie-based auth. If present, attach it.
        try:
            data = resp.json()
            token = data.get("token") or data.get("jwt") or data.get("access_token") or data.get("apiKey")
            if token:
                s.headers.update({"Authorization": f"Bearer {token}"})
        except Exception:
            pass
        # ---- Warm up the server session so it selects the default team/org ----
        try:
            # These are harmless if they 404; they just help the server set session context.
            s.get(
                f"{BASE_URL}/dashboard/iot",
                headers={"Referer": f"{BASE_URL}/"},
                timeout=HTTP_TIMEOUT,
            )
            for path in (
                "/api/get-current-user",
                "/api/teams",
                "/api/config",
                "/api/all",
                "/api/region?include_counts=false",
                "/api/zone?include_counts=false",
            ):
                try:
                    s.get(f"{BASE_URL}{path}", timeout=HTTP_TIMEOUT)
                except Exception:
                    pass
        except Exception:
            pass
        return s

    # HTML/form login with CSRF
    getp = s.get(LOGIN_URL, timeout=HTTP_TIMEOUT)
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
    postp = s.post(
        LOGIN_URL,
        data=form,
        headers=headers,
        timeout=HTTP_TIMEOUT,
        allow_redirects=True,
    )
    postp.raise_for_status()
    return s


def _discover_scope_headers(s: requests.Session) -> Dict[str, str]:
    """Fetch user/team info and synthesize likely scope headers."""

    hdrs: Dict[str, str] = {"X-Requested-With": "XMLHttpRequest"}

    try:
        cu = s.get(f"{BASE_URL}/api/get-current-user", timeout=HTTP_TIMEOUT)
        cuj = _safe_json(cu) or {}
        teams = s.get(f"{BASE_URL}/api/teams", timeout=HTTP_TIMEOUT)
        tjson = _safe_json(teams) or {}

        ids: List[str] = []

        def collect(node: Any) -> None:
            if isinstance(node, dict):
                for key, value in node.items():
                    if isinstance(value, (int, str)) and re.search(
                        r"(team|tenant|company|org)[-_]?id",
                        key,
                        re.IGNORECASE,
                    ):
                        ids.append(str(value))
                    else:
                        collect(value)
            elif isinstance(node, list):
                for item in node:
                    collect(item)

        collect(cuj)
        collect(tjson)

        val = next((candidate for candidate in ids if candidate and candidate.isdigit()), None)
        if val:
            hdrs.update(
                {
                    "X-Company-Id": val,
                    "X-Org-Id": val,
                    "X-Organization-Id": val,
                    "X-Team-Id": val,
                    "X-Tenant-Id": val,
                }
            )
    except Exception:
        pass

    return hdrs

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
    if not isinstance(d, dict):
        return False

    id_keys: Iterable[str] = (
        "id",
        "deviceId",
        "device_id",
        "deviceID",
        "uuid",
        "lockId",
        "lock_id",
        "serialNumber",
        "serial_number",
    )
    name_keys: Iterable[str] = ("name", "deviceName", "label", "device")
    status_keys: Iterable[str] = (
        "online",
        "isOnline",
        "is_online",
        "connected",
        "status",
        "statusText",
        "status_text",
        "statusColor",
        "status_color",
    )

    has_id = any(k in d and d[k] not in (None, "") for k in id_keys)
    has_name = any(k in d and d[k] not in (None, "") for k in name_keys)
    has_status = any(k in d for k in status_keys)
    return has_id or (has_name and has_status)


def _looks_like_device_wrapper(d: Any) -> bool:
    if _is_deviceish(d):
        return True
    if not isinstance(d, dict):
        return False
    for key in ("node", "device", "attributes", "details", "meta", "metadata", "info", "data"):
        if key in d and isinstance(d[key], dict):
            if _looks_like_device_wrapper(d[key]):
                return True
    return False


def _unwrap_device_dict(item: Any) -> Dict[str, Any]:
    """Flatten common GraphQL/REST wrapper shapes into a device dict."""

    if not isinstance(item, dict):
        return item

    for key in ("node", "device", "attributes", "details", "meta", "metadata", "info", "data"):
        if key in item and isinstance(item[key], dict):
            outer = {k: v for k, v in item.items() if k != key}
            inner = _unwrap_device_dict(item[key])
            if isinstance(inner, dict):
                merged = dict(inner)
                # Preserve useful metadata (e.g., building/room) without clobbering core fields.
                for k, v in outer.items():
                    if k not in merged:
                        merged[k] = v
                return merged

    if _is_deviceish(item):
        return item

    return item


def _find_first_list_of_devices(o: Any):
    # Depth-first search for the first list of dicts that look like devices.
    if isinstance(o, list):
        if o and all(isinstance(x, dict) for x in o) and any(_looks_like_device_wrapper(x) for x in o):
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


def _extract_device_dicts(payload: Any) -> List[Dict[str, Any]]:
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
            if isinstance(v, dict) and any(isinstance(x, list) for x in v.values()):
                # Some APIs nest the list one level deeper (e.g., {"data": {"devices": []}})
                for vv in v.values():
                    if isinstance(vv, list) and vv:
                        if all(isinstance(x, dict) for x in vv) and any(_looks_like_device_wrapper(x) for x in vv):
                            items = vv
                            break
                if items is not None:
                    break
        # 2b) nested "list" object with its own 'items'/'rows'/'data'
        if items is None and isinstance(payload.get("list"), dict):
            lst = payload["list"]
            # Common subkeys, including Spring-style "content"
            for k in ("items", "rows", "data", "results", "entries", "records", "content"):
                v = lst.get(k)
                if isinstance(v, list):
                    items = v
                    break
            # Ultimate fallback: first list of dicts under "list"
            if items is None:
                for v in lst.values():
                    if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                        items = v
                        break
    # 3) top-level array
    if items is None and isinstance(payload, list):
        items = payload
    # 4) as a last resort, recursively find the first plausible list
    if items is None:
        items = _find_first_list_of_devices(payload) or []

    if not isinstance(items, list):
        return []

    normalized: List[Dict[str, Any]] = []
    for item in items:
        if isinstance(item, dict):
            normalized.append(_unwrap_device_dict(item))
    return normalized


class BoomNowHttpProvider(DeviceStatusProvider):
    def get_devices(self) -> List[Device]:
        if not BASE_URL:
            raise RuntimeError("BOOMNOW_BASE_URL must be set for boomnow_http provider")

        def _with_q(ep: str, q: str) -> str:
            base = f"{BASE_URL}{ep}"
            if q:
                base += ("&" if "?" in base else "?") + q
            return base

        query = DEVICES_QUERY or "size=100"
        candidates = [
            _with_q(DEVICES_ENDPOINT, query),
            _with_q("/api/iot-devices", query),
            _with_q("/api/all", query),
        ]

        headers = dict(DEFAULT_HEADERS)
        headers.setdefault("X-Requested-With", "XMLHttpRequest")
        if EXTRA_HEADERS:
            try:
                headers.update(json.loads(EXTRA_HEADERS))
            except Exception:
                pass

        session: Optional[requests.Session] = None
        if API_KEY:
            headers["Authorization"] = f"Bearer {API_KEY}"
            session = requests.Session()
            session.headers.update(headers)
            headers.update(_discover_scope_headers(session))
        else:
            session = _login_session()
            headers.setdefault("Origin", BASE_URL)
            headers.setdefault("Referer", BASE_URL + "/dashboard/iot")
            headers.update(_discover_scope_headers(session))

        payload: Optional[Any] = None
        items: List[Dict[str, Any]] = []
        last_url: Optional[str] = None
        response: Optional[requests.Response] = None

        for url in candidates:
            last_url = url
            try:
                assert session is not None
                response = session.get(url, headers=headers, timeout=HTTP_TIMEOUT)
            except requests.RequestException:
                payload = None
                continue

            try:
                response.raise_for_status()
            except requests.HTTPError as exc:
                if response.status_code == 401:
                    raise RuntimeError(
                        "401 Unauthorized: check service creds / LOGIN_KIND / LOGIN_URL"
                    ) from exc
                payload = None
                continue

            payload = _safe_json(response)
            if payload is None:
                continue

            items = _extract_device_dicts(payload)
            if items:
                break

        if payload is None:
            ct = response.headers.get("content-type") if response is not None else None
            raise RuntimeError(f"Expected JSON but got content-type={ct}")

        if DEBUG_PROVIDER:
            top = list(payload.keys())[:10] if isinstance(payload, dict) else [type(payload).__name__]
            print(f"[provider] url={last_url}")
            print(f"[provider] top_keys={top} items_count={len(items)}")
            if items:
                sample = list(items[0].keys())[:12]
                print(f"[provider] sample_item_keys={sample}")
            else:
                try:
                    import json as _json
                    print(f"[provider] payload_snippet={_json.dumps(payload)[:1200]}")
                except Exception:
                    pass

        out: List[Device] = []
        for item in items:
            did = str(
                item.get("id")
                or item.get("deviceId")
                or item.get("device_id")
                or item.get("deviceID")
                or item.get("uuid")
                or item.get("lockId")
                or item.get("lock_id")
                or item.get("serialNumber")
                or item.get("serial_number")
                or ""
            )
            name = (
                item.get("name")
                or item.get("label")
                or item.get("deviceName")
                or item.get("device")
                or item.get("device_label")
                or item.get("deviceLabel")
                or item.get("roomName")
                or item.get("unitName")
                or did
            )

            # derive "online" from whatever the API returns
            online_raw = item.get("online")
            if online_raw is None:
                online_raw = item.get("isOnline")
            if online_raw is None:
                online_raw = item.get("connected")
            if online_raw is None:
                online_raw = item.get("is_online")
            if online_raw is None:
                online_raw = item.get("onlineStatus")
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
