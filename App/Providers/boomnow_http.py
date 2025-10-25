import os, re, json, requests
from typing import List, Union, Any, Dict, Iterable, Tuple
from urllib.parse import urlencode
from app.device import Device
from .base import DeviceStatusProvider

# --------------------
# Config (env-driven)
# --------------------
BASE_URL = os.environ.get("BOOMNOW_BASE_URL", "").rstrip("/")
DEVICES_ENDPOINT = os.environ.get("BOOMNOW_DEVICES_ENDPOINT", "/api/devices")
DEVICES_JSON_PATH = (os.environ.get("BOOMNOW_DEVICES_JSON_PATH") or "").strip()
DEVICES_QUERY = (os.environ.get("BOOMNOW_DEVICES_QUERY") or "").lstrip("?")
EXTRA_HEADERS = os.environ.get("BOOMNOW_EXTRA_HEADERS")  # JSON dict, optional
DEBUG_PROVIDER = (os.environ.get("DEBUG_PROVIDER", "0") == "1")

# Auth
API_KEY = os.environ.get("BOOMNOW_API_KEY")
LOGIN_URL = os.environ.get("BOOMNOW_LOGIN_URL")
LOGIN_KIND = (os.environ.get("BOOMNOW_LOGIN_KIND") or "form").lower()  # "json" or "form"
EMAIL = os.environ.get("BOOMNOW_EMAIL")
PASSWORD = os.environ.get("BOOMNOW_PASSWORD")

# Runtime limits
REQ_TIMEOUT = 10
ATTEMPT_LIMIT = 24

DEFAULT_HEADERS = {"Accept": "application/json", "User-Agent": "iot-monitor/1.0"}

# Candidate endpoints to sweep if DEVICES_ENDPOINT is not sufficient
ENDPOINT_CANDIDATES = []
if DEVICES_ENDPOINT:
    ENDPOINT_CANDIDATES.append(DEVICES_ENDPOINT)
ENDPOINT_CANDIDATES += ["/api/iot-devices", "/api/locks", "/api/devices", "/api/all"]

# Header names many backends use to scope requests
SCOPE_HEADER_NAMES = (
    "X-Team-Id", "X-Team-ID",
    "X-Company-Id", "X-Company-ID",
    "X-Org-Id", "X-Organization-Id",
    "X-Tenant-Id", "X-Tenant-ID",
)

# Query param names commonly used to scope requests
SCOPE_QUERY_NAMES = (
    "team_id", "teamId",
    "tenant_id", "tenantId",
    "company_id", "companyId",
    "org_id", "orgId",
)

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

# --------------------
# Utilities
# --------------------
def _extract_csrf(html: str):
    m = re.search(r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']', html, re.I)
    if m: return m.group(1)
    m = re.search(r'name=["\']authenticity_token["\'][^>]*value=["\']([^"\']+)["\']', html, re.I)
    return m.group(1) if m else None

def _safe_json(resp) -> Tuple[bool, Any]:
    try:
        return True, resp.json()
    except Exception:
        try:
            return False, (resp.text or "")[:1200]
        except Exception:
            return False, ""

def _join_query(url: str, extra: Union[str, Dict[str, Any]]):
    if not extra:
        return url
    if isinstance(extra, dict):
        extra = urlencode(extra, doseq=True)
    return url + (("&" if "?" in url else "?") + extra)

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
    return isinstance(d, dict) and any(
        k in d for k in (
            "id","deviceId","uuid","lockId","serialNumber","name","deviceName","label",
            "online","isOnline","connected","status","statusText","statusColor"
        )
    ) or (isinstance(d, dict) and any(
        k in d and isinstance(d[k], dict) for k in ("node","device","attributes","details","meta","metadata","info","data")
    ))

def _unwrap_device_dict(item: Any) -> Dict[str, Any]:
    if not isinstance(item, dict): return item
    for key in ("node","device","attributes","details","meta","metadata","info","data"):
        if key in item and isinstance(item[key], dict):
            outer = {k:v for k,v in item.items() if k != key}
            inner = _unwrap_device_dict(item[key])
            if isinstance(inner, dict):
                merged = dict(inner)
                for k,v in outer.items():
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
        for k in ("devices","data","items","rows","results","list","entries","records","content"):
            v = payload.get(k)
            if isinstance(v, list):
                items = v; break
            if isinstance(v, dict) and any(isinstance(x, list) for x in v.values()):
                for vv in v.values():
                    if isinstance(vv, list) and vv and all(isinstance(x, dict) for x in vv):
                        items = vv; break
                if items is not None: break
        if items is None and isinstance(payload.get("list"), dict):
            lst = payload["list"]
            for k in ("items","rows","data","results","entries","records","content"):
                v = lst.get(k)
                if isinstance(v, list):
                    items = v; break
            if items is None:
                for v in lst.values():
                    if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                        items = v; break

    if items is None and isinstance(payload, list):
        items = payload

    if items is None:
        items = _find_first_list_of_devices(payload) or []

    if not isinstance(items, list):
        return []

    out: List[Dict[str, Any]] = []
    for it in items:
        if isinstance(it, dict):
            out.append(_unwrap_device_dict(it))
    return out

def _coerce_online(value: Union[str, int, float, bool, None]) -> bool:
    if isinstance(value, bool): return value
    if isinstance(value, (int, float)): return value != 0
    if isinstance(value, str):
        v = value.strip().lower()
        if v in {"true","1","yes","online","up","connected","active","alive"}: return True
        if v in {"false","0","no","offline","down","inactive","disconnected","no data","unknown","n/a","na","not available","none","null","—","-"}: return False
    return bool(value)

def _discover_scope_ids(session: requests.Session) -> List[str]:
    """Pull candidate team/org/tenant ids from helper endpoints."""
    hits = []
    for path in ("/api/get-current-user", "/api/teams", "/api/all", "/api/config"):
        try:
            r = session.get(f"{BASE_URL}{path}", timeout=REQ_TIMEOUT)
            ok, data = _safe_json(r)
            if not ok or not isinstance(data, (dict, list)): continue

            def walk(x, key_path=""):
                if isinstance(x, dict):
                    for k,v in x.items():
                        kp = (key_path + "." + k).lstrip(".")
                        walk(v, kp)
                elif isinstance(x, list):
                    for v in x[:50]:
                        walk(v, key_path)
                else:
                    key_l = key_path.lower()
                    if isinstance(x, str) and (UUID_RE.match(x) or ("team" in key_l or "tenant" in key_l or "org" in key_l or "company" in key_l)):
                        hits.append(x)
                    elif isinstance(x, int) and ("team" in key_l or "tenant" in key_l or "org" in key_l or "company" in key_l):
                        hits.append(str(x))

            walk(data)
        except Exception:
            pass

    # De‑dupe while preserving order
    seen, out = set(), []
    for h in hits:
        if h not in seen:
            seen.add(h); out.append(h)
    return out[:6]  # keep it tight

def _enumerate_array_paths(o: Any, prefix: str = "") -> List[str]:
    paths = []
    if isinstance(o, list):
        if o and all(isinstance(x, dict) for x in o):
            paths.append(prefix or "$")
        for i, v in enumerate(o[:3]):
            paths += _enumerate_array_paths(v, f"{prefix}[{i}]" if prefix else f"[{i}]")
    elif isinstance(o, dict):
        for k, v in o.items():
            paths += _enumerate_array_paths(v, f"{prefix}.{k}" if prefix else k)
    return paths

# --------------------
# Provider
# --------------------
class BoomNowHttpProvider(DeviceStatusProvider):
    def get_devices(self) -> List[Device]:
        if not BASE_URL:
            raise RuntimeError("BOOMNOW_BASE_URL must be set for boomnow_http provider")

        # Build base headers
        headers = dict(DEFAULT_HEADERS)
        if EXTRA_HEADERS:
            try: headers.update(json.loads(EXTRA_HEADERS))
            except Exception: pass

        # Auth: API key or programmatic login
        session = requests.Session()
        session.headers.update(headers)

        if API_KEY:
            session.headers["Authorization"] = f"Bearer {API_KEY}"
        else:
            if not (LOGIN_URL and EMAIL and PASSWORD):
                raise RuntimeError("BOOMNOW_LOGIN_URL/EMAIL/PASSWORD must be set when no API key is used")
            if LOGIN_KIND == "json":
                resp = session.post(LOGIN_URL, json={"email": EMAIL, "password": PASSWORD},
                                    timeout=REQ_TIMEOUT, allow_redirects=True)
                resp.raise_for_status()
                # optional token in JSON responses
                ok, data = _safe_json(resp)
                if ok and isinstance(data, dict):
                    token = data.get("token") or data.get("jwt") or data.get("access_token") or data.get("apiKey")
                    if token:
                        session.headers["Authorization"] = f"Bearer {token}"
            else:
                g = session.get(LOGIN_URL, timeout=REQ_TIMEOUT)
                g.raise_for_status()
                csrf = _extract_csrf(getattr(g, "text", "") or "")
                form = {"email": EMAIL, "password": PASSWORD}
                if re.search(r'name=["\']user\[email\]["\']', getattr(g, "text", "") or "", re.I):
                    form = {"user[email]": EMAIL, "user[password]": PASSWORD}
                if csrf: form["authenticity_token"] = csrf
                headers2 = {"Referer": LOGIN_URL, "Origin": BASE_URL or LOGIN_URL.split("/api")[0]}
                p = session.post(LOGIN_URL, data=form, headers=headers2, timeout=REQ_TIMEOUT, allow_redirects=True)
                p.raise_for_status()

        # Discover scoping ids (team/org/tenant/company) to try
        ids = _discover_scope_ids(session)

        # Build endpoint + query candidates
        def _build(ep: str) -> str:
            u = f"{BASE_URL}{ep}"
            return _join_query(u, DEVICES_QUERY) if DEVICES_QUERY else u

        endpoints = []
        for ep in ENDPOINT_CANDIDATES:
            u = _build(ep)
            if u not in endpoints:
                endpoints.append(u)

        query_variants = [""]
        for sid in ids:
            for pname in SCOPE_QUERY_NAMES:
                query_variants.append(f"{pname}={sid}")

        header_variants = [dict(session.headers)]
        for sid in ids:
            for hname in SCOPE_HEADER_NAMES:
                hv = dict(session.headers)
                hv[hname] = sid
                header_variants.append(hv)

        # Sweep attempts (bounded)
        tried = set()
        attempt = 0
        found_payload = None
        items: List[Dict[str, Any]] = []

        for url in endpoints:
            for hv in header_variants:
                for q in query_variants:
                    if attempt >= ATTEMPT_LIMIT:
                        break
                    full_url = _join_query(url, q) if q else url
                    key = (full_url, tuple(sorted(hv.items())))
                    if key in tried:
                        continue
                    tried.add(key)
                    attempt += 1

                    r = session.get(full_url, headers=hv, timeout=REQ_TIMEOUT)
                    ct = r.headers.get("content-type")
                    if DEBUG_PROVIDER:
                        print(f"[provider] try[{attempt}] {full_url} => {r.status_code} ct={ct}")

                    if r.status_code != 200:
                        continue

                    is_json, payload = _safe_json(r)
                    if not is_json:
                        if DEBUG_PROVIDER:
                            print(f"[provider] nonjson_snippet={payload[:400]}")
                        continue

                    found_payload = payload
                    # First pass extraction
                    items = _extract_device_dicts(payload)
                    if DEBUG_PROVIDER:
                        top = list(payload.keys())[:10] if isinstance(payload, dict) else [type(payload).__name__]
                        print(f"[provider] top_keys={top} items_count={len(items)}")
                        if not items:
                            try:
                                cand_paths = _enumerate_array_paths(payload)
                                if cand_paths:
                                    print(f"[diag] array_candidates (first 12): {cand_paths[:12]}")
                            except Exception:
                                pass
                    if items:
                        break
                if items:
                    break
            if items:
                break

        # If we never saw JSON, report content-type of the last response
        if found_payload is None:
            # We keep returning empty list so monitor doesn't crash; diagnostics already printed.
            return []

        # Normalize to Device objects
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
                item.get("online") or item.get("isOnline") or item.get("connected") or
                item.get("is_online") or item.get("onlineStatus")
            )
            if online_raw is None and "status" in item:
                status = item.get("status")
                if isinstance(status, dict):
                    online_raw = status.get("name") or status.get("text") or status.get("value") or status.get("color")
                else:
                    online_raw = status
            if online_raw is None:
                indicator = (item.get("statusColor") or item.get("status_color") or
                             item.get("indicator") or item.get("onlineColor") or item.get("statusDot"))
                if indicator:
                    sv = str(indicator).strip().lower()
                    online_raw = True if sv in {"green","success","ok"} else False if sv in {"red","danger","error"} else None

            online = _coerce_online(online_raw)

            battery = None
            for k in ("battery","batteryPercent","battery_percentage","batteryLevel","battery_level"):
                if k in item and isinstance(item[k], (int, float)):
                    battery = int(item[k]); break

            out.append(Device(id=did, name=name, online=online, battery=battery, extra=item))

        return out
