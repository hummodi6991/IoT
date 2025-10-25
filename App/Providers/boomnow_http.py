import os, re, json, time, requests
from typing import List, Union, Any, Dict, Iterable, Optional
from app.device import Device
from .base import DeviceStatusProvider

BASE_URL = os.environ.get("BOOMNOW_BASE_URL", "").rstrip("/")
DEVICES_ENDPOINT = os.environ.get("BOOMNOW_DEVICES_ENDPOINT", "/api/devices")
DEVICES_JSON_PATH = (os.environ.get("BOOMNOW_DEVICES_JSON_PATH") or "").strip()
DEBUG_PROVIDER = (os.environ.get("DEBUG_PROVIDER", "0") == "1")
DEVICES_QUERY = (os.environ.get("BOOMNOW_DEVICES_QUERY") or "").lstrip("?")
EXTRA_HEADERS = os.environ.get("BOOMNOW_EXTRA_HEADERS")  # JSON dict, optional

API_KEY = os.environ.get("BOOMNOW_API_KEY")

LOGIN_URL = os.environ.get("BOOMNOW_LOGIN_URL")
LOGIN_KIND = (os.environ.get("BOOMNOW_LOGIN_KIND") or "form").lower()  # "json" or "form"
EMAIL = os.environ.get("BOOMNOW_EMAIL")
PASSWORD = os.environ.get("BOOMNOW_PASSWORD")

DEFAULT_HEADERS = {"Accept": "application/json", "User-Agent": "iot-monitor/1.0"}


def _d(msg: str):
    if DEBUG_PROVIDER:
        print(f"[provider] {time.strftime('%H:%M:%S')} {msg}", flush=True)


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
    t0 = time.time()

    if LOGIN_KIND == "json":
        _d(f"login(kind=json) POST {LOGIN_URL}")
        resp = s.post(LOGIN_URL, json={"email": EMAIL, "password": PASSWORD}, timeout=20, allow_redirects=True)
        resp.raise_for_status()
        try:
            data = resp.json()
            token = data.get("token") or data.get("jwt") or data.get("access_token") or data.get("apiKey")
            if token:
                s.headers.update({"Authorization": f"Bearer {token}"})
                _d("login: bearer token attached")
        except Exception:
            pass
        _d(f"login(kind=json) done in {time.time()-t0:.2f}s")
        return s

    _d(f"login(kind=form) GET {LOGIN_URL}")
    getp = s.get(LOGIN_URL, timeout=20)
    getp.raise_for_status()
    csrf = _extract_csrf(getp.text)
    form = {"email": EMAIL, "password": PASSWORD}
    if re.search(r'name=["\']user\[email\]["\']', getp.text, re.I):
        form = {"user[email]": EMAIL, "user[password]": PASSWORD}
    if csrf:
        form["authenticity_token"] = csrf
    headers = {"Referer": LOGIN_URL, "Origin": BASE_URL or LOGIN_URL.split("/api")[0]}
    _d(f"login(kind=form) POST {LOGIN_URL}")
    postp = s.post(LOGIN_URL, data=form, headers=headers, timeout=20, allow_redirects=True)
    postp.raise_for_status()
    _d(f"login(kind=form) done in {time.time()-t0:.2f}s")
    return s


def _safe_json(resp) -> Any:
    """
    Robust JSON loader that tolerates BOM, anti-XSSI prefixes, and HTML error pages.
    """
    ct = resp.headers.get("content-type", "")
    txt = resp.text or ""
    raw = txt.lstrip("\ufeff").lstrip()
    for p in (")]}',\n", "while(1);", "for(;;);"):
        if raw.startswith(p):
            raw = raw[len(p):].lstrip()
            break
    if raw[:10].lower().startswith("<!doctype") or raw[:5].lower().startswith("<html"):
        raise RuntimeError(f"Expected JSON but got HTML; ct={ct}; snippet={raw[:140]!r}")
    first = [i for i in (raw.find("{"), raw.find("[")) if i >= 0]
    if first:
        start = min(first)
        raw = raw[start:]
    try:
        return json.loads(raw)
    except Exception as ex:
        raise RuntimeError(f"Expected JSON but could not decode; ct={ct}; snippet={raw[:220]!r}") from ex


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


def _looks_like_device_wrapper(d: Any) -> bool:
    if not isinstance(d, dict):
        return False
    for k in ("id", "deviceId", "device_id", "uuid", "lockId", "serialNumber", "name", "deviceName", "status", "online"):
        if k in d:
            return True
    for key in ("node", "device", "attributes", "details", "meta", "metadata", "info", "data"):
        if key in d and isinstance(d[key], dict):
            if _looks_like_device_wrapper(d[key]):
                return True
    return False


def _unwrap_device_dict(item: Any) -> Dict[str, Any]:
    if not isinstance(item, dict):
        return item
    for key in ("node", "device", "attributes", "details", "meta", "metadata", "info", "data"):
        if key in item and isinstance(item[key], dict):
            outer = {k: v for k, v in item.items() if k != key}
            inner = _unwrap_device_dict(item[key])
            if isinstance(inner, dict):
                merged = dict(inner)
                for k, v in outer.items():
                    if k not in merged:
                        merged[k] = v
                return merged
    return item


def _find_first_list_of_devices(o: Any):
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
    if DEVICES_JSON_PATH:
        items = _get_by_path(payload, DEVICES_JSON_PATH)
    if items is None and isinstance(payload, dict):
        for k in ("devices", "data", "items", "rows", "results", "list", "entries", "records", "content"):
            v = payload.get(k)
            if isinstance(v, list):
                items = v
                break
            if isinstance(v, dict) and any(isinstance(x, list) for x in v.values()):
                for vv in v.values():
                    if isinstance(vv, list) and vv and all(isinstance(x, dict) for x in vv):
                        items = vv
                        break
                if items is not None:
                    break
        if items is None and isinstance(payload.get("list"), dict):
            lst = payload["list"]
            for k in ("items", "rows", "data", "results", "entries", "records", "content"):
                v = lst.get(k)
                if isinstance(v, list):
                    items = v
                    break
    if items is None and isinstance(payload, list):
        items = payload
    if items is None:
        items = _find_first_list_of_devices(payload) or []
    if not isinstance(items, list):
        return []
    normalized: List[Dict[str, Any]] = []
    for it in items:
        if isinstance(it, dict):
            normalized.append(_unwrap_device_dict(it))
    return normalized


def _coerce_online(value: Union[str, int, float, bool, None]) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        v = value.strip().lower()
        if v in {"true", "1", "yes", "online", "up", "connected", "active", "alive"}:
            return True
        if v in {"false", "0", "no", "offline", "down", "inactive", "disconnected", "no data", "unknown", "n/a", "na", "not available", "none", "null", "—", "-"}:
            return False
    return bool(value)


def _discover_scope_ids(session: requests.Session) -> List[str]:
    out: List[str] = []
    for ep in ("/api/get-current-user", "/api/teams", "/api/all"):
        try:
            url = f"{BASE_URL}{ep}"
            _d(f"discover GET {url}")
            r = session.get(url, timeout=8)
            if r.status_code >= 400:
                continue
            data = _safe_json(r)

            def harvest(obj):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        lk = k.lower()
                        if any(s in lk for s in ("team", "tenant", "org", "company", "account")) and isinstance(v, (str, int)):
                            s = str(v)
                            if s and s not in out:
                                out.append(s)
                        harvest(v)
                elif isinstance(obj, list):
                    for x in obj:
                        harvest(x)

            harvest(data)
        except Exception:
            continue
    return out[:5]


def _scope_header_variants(scope_ids: List[str]) -> List[Dict[str, str]]:
    variants: List[Dict[str, str]] = []
    base_candidates = ("X-Team-Id", "X-Team-ID", "X-Org-Id", "X-Company-Id", "X-Tenant-Id")
    for sid in scope_ids or [""]:
        for h in base_candidates:
            variants.append({h: sid, "X-Requested-With": "XMLHttpRequest"})
    variants.append({"X-Requested-With": "XMLHttpRequest"})
    return variants


class BoomNowHttpProvider(DeviceStatusProvider):
    def get_devices(self) -> List[Device]:
        if not BASE_URL:
            raise RuntimeError("BOOMNOW_BASE_URL must be set for boomnow_http provider")

        def _build(ep: str, q: str) -> str:
            u = f"{BASE_URL}{ep}"
            if DEVICES_QUERY:
                u += ("&" if "?" in u else "?") + DEVICES_QUERY
            if q:
                u += ("&" if "?" in u else "?") + q
            return u

        endpoints = [DEVICES_ENDPOINT, "/api/iot-devices", "/api/devices", "/api/locks"]
        page_params = ["", "size=100", "page=1&size=100", "perPage=100", "limit=100", "limit=100&offset=0"]

        headers = dict(DEFAULT_HEADERS)
        if EXTRA_HEADERS:
            try:
                headers.update(json.loads(EXTRA_HEADERS))
            except Exception:
                pass

        if API_KEY:
            headers["Authorization"] = f"Bearer {API_KEY}"
            session = requests.Session()
        else:
            session = _login_session()
            headers.setdefault("Origin", BASE_URL)
            headers.setdefault("Referer", BASE_URL + "/dashboard/iot")

        scope_ids = _discover_scope_ids(session) if not API_KEY else []
        header_variants = _scope_header_variants(scope_ids)
        header_variants.insert(0, {k: v for k, v in headers.items() if k.lower().startswith("x-")})

        attempts: List[str] = []
        SAFETY_CAP = 30
        items: List[Dict[str, Any]] = []
        payload: Optional[Any] = None
        last_url = None
        attempt_idx = 0

        for ep in endpoints:
            for qp in page_params:
                for hv in header_variants:
                    attempt_idx += 1
                    if attempt_idx > SAFETY_CAP:
                        break
                    req_headers = dict(headers)
                    req_headers.update({k: v for k, v in hv.items() if v})
                    url = _build(ep, qp)
                    last_url = url
                    try:
                        t0 = time.time()
                        r = session.get(url, headers=req_headers, timeout=10, allow_redirects=True)
                        ct = r.headers.get("content-type", "")
                        body_len = int(r.headers.get("content-length", "0") or 0) or len(r.content or b"")
                        _d(f"try[{attempt_idx}] {url} -> {r.status_code} ct={ct} bytes={body_len}")
                        if r.status_code >= 500:
                            try:
                                _d(f"server500 snippet={r.text[:140]!r}")
                            except Exception:
                                pass
                            continue
                        r.raise_for_status()
                        payload = _safe_json(r)
                    except Exception as ex:
                        _d(f"try[{attempt_idx}] decode error: {ex}")
                        continue

                    items = _extract_device_dicts(payload)
                    if items:
                        _d(f"items_count={len(items)} (success on {url})")
                        break
                if items:
                    break
            if items:
                break

        if payload is None:
            ct = "(none)"
            if 'r' in locals():
                ct = r.headers.get("content-type", "")
            raise RuntimeError(f"Expected JSON but got content-type={ct}")

        if DEBUG_PROVIDER:
            top = list(payload.keys())[:10] if isinstance(payload, dict) else [type(payload).__name__]
            _d(f"url={last_url}")
            _d(f"top_keys={top} items_count={len(items)}")
            if items:
                _d(f"sample_item_keys={list(items[0].keys())[:12]}")
            else:
                try:
                    import json as _json
                    _d(f"payload_snippet={_json.dumps(payload)[:1200]}")
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
            online_raw = (
                item.get("online")
                or item.get("isOnline")
                or item.get("connected")
                or item.get("is_online")
                or item.get("onlineStatus")
            )
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
