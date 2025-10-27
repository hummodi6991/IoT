import os, re, json, requests
from typing import List, Union, Any, Dict, Tuple
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
# 0/1/2 where 2 prints deep diagnostics
try:
    DEBUG_LEVEL = int(os.environ.get("DEBUG_PROVIDER", "0"))
except Exception:
    DEBUG_LEVEL = 1 if DEBUG_PROVIDER else 0
EXACT_URL = (os.environ.get("BOOMNOW_EXACT_DEVICES_URL") or "").strip()

# Auth
API_KEY = os.environ.get("BOOMNOW_API_KEY")
LOGIN_URL = os.environ.get("BOOMNOW_LOGIN_URL")
LOGIN_KIND = (os.environ.get("BOOMNOW_LOGIN_KIND") or "form").lower()  # "json" or "form"
EMAIL = os.environ.get("BOOMNOW_EMAIL")
PASSWORD = os.environ.get("BOOMNOW_PASSWORD")

# Runtime limits
REQ_TIMEOUT = 10
ATTEMPT_LIMIT = 120

DEFAULT_HEADERS = {
    "Accept": "application/json",
    "User-Agent": "iot-monitor/1.0",
    "X-Requested-With": "XMLHttpRequest",
}

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

    # If the detected container is a dict that wraps an "edges" array (GraphQL),
    # unwrap it before continuing so the downstream normalization sees the
    # individual device dictionaries.
    if isinstance(items, dict):
        if isinstance(items.get("edges"), list):
            items = items["edges"]
        else:
            nested = _find_first_list_of_devices(items)
            items = nested if nested is not None else []

    if isinstance(items, list) and items:
        # Flatten GraphQL style containers (list of objects each with an ``edges`` array)
        edge_wrappers: List[Dict[str, Any]] = []
        for entry in items:
            if not isinstance(entry, dict):
                continue
            if isinstance(entry.get("edges"), list):
                edge_wrappers.extend(x for x in entry["edges"] if isinstance(x, dict))
                continue
            devices = entry.get("devices") if isinstance(entry.get("devices"), dict) else None
            if isinstance(devices, dict) and isinstance(devices.get("edges"), list):
                edge_wrappers.extend(x for x in devices["edges"] if isinstance(x, dict))
        if edge_wrappers:
            items = edge_wrappers
        elif not any(_looks_like_device_wrapper(it) for it in items):
            nested = _find_first_list_of_devices(items)
            if nested is not None:
                items = nested

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
    """Return numeric/uuid IDs only (ignore team/org *names*)."""
    cached = getattr(session, "_boomnow_scope_ids", None)
    if cached is not None:
        return list(cached)

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
                    if isinstance(x, int) and ("team" in key_l or "tenant" in key_l or "org" in key_l or "company" in key_l):
                        hits.append(str(x))
                    elif isinstance(x, str):
                        if x.isdigit() and ("team" in key_l or "tenant" in key_l or "org" in key_l or "company" in key_l):
                            hits.append(x)
                        elif UUID_RE.match(x):
                            hits.append(x)

            walk(data)
        except Exception:
            pass

    # De‑dupe while preserving order
    seen, out = set(), []
    for h in hits:
        if h not in seen:
            seen.add(h); out.append(h)
    out = out[:6]  # keep it tight
    setattr(session, "_boomnow_scope_ids", list(out))
    return out

def _discover_scope_headers(session: requests.Session) -> Dict[str, str]:
    """Return scoped headers inferred from helper endpoints.

    Tests monkeypatch this helper, so keep it factored for flexibility.
    """
    headers: Dict[str, str] = {}
    ids = _discover_scope_ids(session)
    preferred = next((sid for sid in ids if sid), None)
    if preferred:
        for name in SCOPE_HEADER_NAMES:
            headers[name] = preferred
    headers.setdefault("X-Requested-With", "XMLHttpRequest")
    return headers

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
                # JSON login
                resp = session.post(LOGIN_URL, json={"email": EMAIL, "password": PASSWORD},
                                    timeout=REQ_TIMEOUT, allow_redirects=True)
                resp.raise_for_status()
                ok, data = _safe_json(resp)
                if ok and isinstance(data, dict):
                    token = data.get("token") or data.get("jwt") or data.get("access_token") or data.get("apiKey")
                    if token:
                        session.headers["Authorization"] = f"Bearer {token}"
                # Warm-up: load the dashboard once so the server sets tenant context in cookies
                try:
                    session.get(
                        f"{BASE_URL}/dashboard/iot",
                        headers={"Referer": f"{BASE_URL}/"},
                        timeout=REQ_TIMEOUT,
                    )
                except Exception:
                    pass
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

        # Diagnostics: cookie names (values redacted)
        if DEBUG_LEVEL >= 1:
            cookie_names = sorted(session.cookies.get_dict().keys())
            print("[diag] cookies=" + ",".join(cookie_names))

        # IMPORTANT: BoomNow uses cookie context. Do NOT send X-* scope headers/queries.
        ids: List[str] = []  # disable id-scoping entirely (header + query)

        # Build endpoint + query candidates
        def _build(ep: str) -> str:
            u = f"{BASE_URL}{ep}"
            # Default to page=0 if caller didn't provide anything.
            q = DEVICES_QUERY or "size=100&page=0"
            return _join_query(u, q) if q else u

        endpoints = []
        if EXACT_URL:
            endpoints = [EXACT_URL]
            if DEBUG_LEVEL >= 1:
                print(f"[diag] exact_url={EXACT_URL}")
        else:
            for ep in ENDPOINT_CANDIDATES:
                u = _build(ep)
                if u not in endpoints:
                    endpoints.append(u)

        # Compact query variants; we'll try header scoping first, then add query scoping if needed.
        base_query_only = [""]
        scoped_query: List[str] = []

        # Header variants: only sanitized base headers (no scope ids)
        # Strip any stray X-* scope headers; keep only normal headers
        base_hv = {k: v for (k, v) in session.headers.items() if k not in SCOPE_HEADER_NAMES}
        header_variants = [base_hv]

        # Sweep attempts (bounded)
        tried = set()
        attempt = 0
        found_payload = None
        items: List[Dict[str, Any]] = []

        # Round 1: try ALL header variants with the base query only.
        for url in endpoints:
            for hv in header_variants:
                for q in base_query_only:
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
                        scope_bits = []
                        for k in ("X-Team-Id","X-Org-Id","X-Organization-Id","X-Company-Id","X-Tenant-Id"):
                            if k in hv:
                                scope_bits.append(f"{k}={hv[k]}")
                        hb = "|".join(scope_bits) or "(none)"
                        print(f"[provider] try[{attempt}] {full_url} => {r.status_code} ct={ct} hdrs={hb}")

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
                        # Print a short page summary to see real counts
                        try:
                            if isinstance(payload, dict) and isinstance(payload.get("list"), dict):
                                lst = payload["list"]
                                summary = {
                                    "list_keys": list(lst.keys())[:10],
                                    "content_len": len(lst.get("content") or []),
                                    "totalElements": lst.get("totalElements"),
                                    "page": lst.get("pageNumber") or lst.get("number"),
                                }
                                print(f"[diag] list_summary={summary}")
                            if DEBUG_LEVEL >= 2:
                                print(f"[diag] payload_snippet={json.dumps(payload)[:1200]}")
                        except Exception:
                            pass
                    if items:
                        break
                if items:
                    break
            if items:
                break

        # Round 2: if still empty, try query scoping (one header set only to stay under budget).
        if not items:
            for url in endpoints:
                for q in scoped_query:
                    if attempt >= ATTEMPT_LIMIT:
                        break
                    full_url = _join_query(url, q)
                    key = (full_url, tuple(sorted(session.headers.items())))
                    if key in tried:
                        continue
                    tried.add(key)
                    attempt += 1
                    r = session.get(full_url, headers=base_hv, timeout=REQ_TIMEOUT)
                    ct = r.headers.get("content-type")
                    if DEBUG_PROVIDER:
                        scope_bits = []
                        for k in ("X-Team-Id","X-Org-Id","X-Organization-Id","X-Company-Id","X-Tenant-Id"):
                            if k in base_hv:
                                scope_bits.append(f"{k}={base_hv[k]}")
                        hb = "|".join(scope_bits) or "(none)"
                        print(f"[provider] try[{attempt}] {full_url} => {r.status_code} ct={ct} hdrs={hb}")
                    if r.status_code != 200:
                        continue
                    is_json, payload = _safe_json(r)
                    if not is_json:
                        if DEBUG_PROVIDER:
                            print(f"[provider] nonjson_snippet={payload[:400]}")
                        continue
                    found_payload = payload
                    items = _extract_device_dicts(payload)
                    if DEBUG_PROVIDER:
                        top = list(payload.keys())[:10] if isinstance(payload, dict) else [type(payload).__name__]
                        print(f"[provider] top_keys={top} items_count={len(items)}")
                        # Print a short page summary to see real counts
                        try:
                            if isinstance(payload, dict) and isinstance(payload.get("list"), dict):
                                lst = payload["list"]
                                summary = {
                                    "list_keys": list(lst.keys())[:10],
                                    "content_len": len(lst.get("content") or []),
                                    "totalElements": lst.get("totalElements"),
                                    "page": lst.get("pageNumber") or lst.get("number"),
                                }
                                print(f"[diag] list_summary={summary}")
                            if DEBUG_LEVEL >= 2:
                                print(f"[diag] payload_snippet={json.dumps(payload)[:1200]}")
                        except Exception:
                            pass
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
