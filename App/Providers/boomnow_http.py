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
ONLINE_FIELD = (os.environ.get("BOOMNOW_ONLINE_FIELD") or "").strip()
REQUIRED_CAPABILITY = (os.environ.get("BOOMNOW_REQUIRED_CAPABILITY") or "lock").strip().lower()
_ENV_TRUTHY = {"1","true","yes","on","y","t"}
ONLY_ACTIVE = str(os.environ.get("BOOMNOW_ONLY_ACTIVE", "1")).strip().lower() in _ENV_TRUTHY
ONLY_MANAGED = str(os.environ.get("BOOMNOW_ONLY_MANAGED", "1")).strip().lower() in _ENV_TRUTHY
STRICT_UI_COLOR = (os.environ.get("BOOMNOW_STRICT_UI_COLOR", "0") == "1")
STRICT_UI = (os.environ.get("BOOMNOW_STRICT_UI", "0") == "1")
NAME_FIELD = (os.environ.get("BOOMNOW_NAME_FIELD") or "").strip()
# Force “UI color only” logic:
# When set, we ignore boolean/text fields and base status ONLY on a color
# value like "green"/"red" (or "success"/"danger"/"error").
COLOR_ONLY = (os.environ.get("BOOMNOW_COLOR_ONLY", "0") == "1")
COLOR_FIELD = (os.environ.get("BOOMNOW_COLOR_FIELD") or "").strip()
# 0/1/2 where 2 prints deep diagnostics
try:
    DEBUG_LEVEL = int(os.environ.get("DEBUG_PROVIDER", "0"))
except Exception:
    DEBUG_LEVEL = 1 if DEBUG_PROVIDER else 0
EXACT_URL = (os.environ.get("BOOMNOW_EXACT_DEVICES_URL") or "").strip()
SESSION_COOKIE = (os.environ.get("BOOMNOW_SESSION_COOKIE") or "").strip()
# dashboard page we can scrape as a last resort
DASHBOARD_IOT_PATH = os.environ.get("BOOMNOW_DASHBOARD_IOT_PATH", "/dashboard/iot")

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

def _truthy(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    if isinstance(v, str):
        stripped = v.strip()
        if stripped == "":
            return False
        lowered = stripped.lower()
        if lowered in {"false", "0", "no", "off", "inactive", "offline"}:
            return False
        return lowered in {"1", "true", "yes", "on", "active", "connected", "online", "y"}
    return bool(v)

def _get_bool_path(item: Dict[str, Any], path: str) -> bool:
    return _truthy(_get_by_path(item, path))

def _from_ui_color_dictish(v: Any) -> Any:
    """Unwrap tiny dicts used for indicators: {color|text|name|value: 'green'}."""
    if isinstance(v, dict):
        for k in ("color", "value", "text", "name"):
            if k in v and v[k] is not None:
                return v[k]
    return v

def _pick_ui_color(item: Dict[str, Any]) -> Any:
    """
    Return the *UI dot/color* value if present.
    We check common keys seen in lock dashboards.
    """
    keys = (
        "statusColor", "status_color", "statusDot", "indicator", "onlineColor",
        "properties.statusColor", "properties.onlineColor", "properties.statusDot",
        "ui.statusColor", "ui.onlineColor", "ui.dot",
    )
    for k in keys:
        v = _get_by_path(item, k)
        if v is None:
            continue
        v = _from_ui_color_dictish(v)
        if v is not None:
            return v
    return None

def _first_present(d: Dict[str, Any], *keys: str) -> Any:
    """
    Return the first value whose key exists and whose value is not None.
    IMPORTANT: Unlike 'a or b', this preserves explicit False.
    """
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return None

def _has_capability(item: Dict[str, Any], cap: str) -> bool:
    if not cap:
        return True

    value = _first_present(
        item,
        "capabilities_supported",
        "capabilitiesSupported",
        "capabilities",
        "capability",
    )

    if value is None:
        value = _get_by_path(item, "properties.capabilities")

    caps: List[str]
    if isinstance(value, dict):
        caps = [str(k) for k, v in value.items() if _truthy(v)]
    elif isinstance(value, (list, tuple, set)):
        caps = [str(v) for v in value]
    elif isinstance(value, str):
        caps = [part for part in re.split(r"[,\s]+", value) if part]
    else:
        caps = []

    normalized = [c.strip().lower() for c in caps if c and c.strip()]
    return cap.lower() in normalized

def _enumerate_array_paths(o: Any, prefix: str = "") -> List[str]:
    paths: List[str] = []
    if isinstance(o, dict):
        for k, v in list(o.items())[:50]:
            paths.extend(_enumerate_array_paths(v, f"{prefix}.{k}" if prefix else k))
    elif isinstance(o, Iterable) and not isinstance(o, (str, bytes)):
        paths.append(prefix or "$")
        for idx, v in enumerate(list(o)[:20]):
            paths.extend(_enumerate_array_paths(v, f"{prefix}[{idx}]" if prefix else f"[{idx}]"))
    return paths

def _trim_json_preview(obj: Any, limit=800) -> str:
    try:
        s = json.dumps(obj) if not isinstance(obj, str) else obj
    except Exception:
        s = str(type(obj))
    return s[:limit] + ("…" if len(s) > limit else "")

_NEXT_RE = re.compile(r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(\{.*?\})</script>', re.S | re.I)
_STATE_RE = re.compile(r'window\.__INITIAL_STATE__\s*=\s*(\{.*?\});', re.S | re.I)

def _scrape_dashboard_for_devices(session: requests.Session) -> List[Dict[str, Any]]:
    """Fallback: fetch dashboard HTML and pull embedded JSON (Next.js/SPA state)."""
    try:
        r = session.get(f"{BASE_URL}{DASHBOARD_IOT_PATH}", timeout=REQ_TIMEOUT)
        if DEBUG_PROVIDER:
            print(f"[diag] dashboard/iot => {r.status_code} ct={r.headers.get('content-type')}")
        if r.status_code != 200:
            return []
        html = getattr(r, "text", "") or ""
        m = _NEXT_RE.search(html) or _STATE_RE.search(html)
        if not m:
            return []
        data = json.loads(m.group(1))
        arr = _find_first_list_of_devices(data) or []
        if DEBUG_PROVIDER:
            print(
                f"[diag] dashboard_extract paths≈{len(_enumerate_array_paths(data))} "
                f"sample={_trim_json_preview(arr[:2])}"
            )
        out: List[Dict[str, Any]] = []
        for it in arr:
            if isinstance(it, dict):
                out.append(_unwrap_device_dict(it))
        return out
    except Exception as exc:
        if DEBUG_PROVIDER:
            print(f"[diag] dashboard_parse_error={exc}")
        return []

# --- new: diagnostics helpers ----
DEVICE_HINT_KEYS = {
    "id", "deviceId", "uuid", "lockId", "serialNumber",
    "name", "deviceName", "label",
    "online", "isOnline", "connected", "status", "statusText", "statusColor",
}

def _summarize(o: Any, depth: int = 2, max_items: int = 3) -> Any:
    """Return a small, printable structural summary (keys/types/sizes) of a JSON object."""
    if depth < 0:
        return type(o).__name__
    if isinstance(o, dict):
        out = {}
        for k, v in list(o.items())[:20]:
            out[k] = _summarize(v, depth - 1, max_items)
        return out
    if isinstance(o, list):
        return {
            "_type": "list",
            "len": len(o),
            "sample": [_summarize(v, depth - 1, max_items) for v in o[:max_items]],
        }
    return type(o).__name__

def _score_device_list(lst: list) -> float:
    if not isinstance(lst, list) or not lst:
        return 0.0
    checks = 0
    for it in lst[: min(20, len(lst))]:
        if isinstance(it, dict) and any(k in it for k in DEVICE_HINT_KEYS):
            checks += 1
    return checks / min(20, len(lst))

def _probe_device_arrays(payload: Any) -> List[Tuple[str, float, int]]:
    """Return [(json_path, score, length), ...] sorted best-first."""
    candidates: List[Tuple[str, float, int]] = []

    def walk(node: Any, path: str = "") -> None:
        if isinstance(node, list):
            candidates.append((path or "$", _score_device_list(node), len(node)))
        elif isinstance(node, dict):
            for k, v in node.items():
                walk(v, f"{path}.{k}" if path else k)

    walk(payload)
    candidates.sort(key=lambda t: (-t[1], -t[2]))
    return candidates

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

def _coerce_online(value):
    """
    Convert heterogeneous "online" signals to True/False.
    IMPORTANT: unknown / not-present must return None (NOT False),
    otherwise every device without a recognized field is treated as offline.
    """
    # Unknown / missing
    if value is None:
        return None

    # If the backend nests status data in a dict, try common keys inside it.
    if isinstance(value, dict):
        for k in ("online","isOnline","connected","is_connected",
                  "status","statusText","text","name","value","color","indicator"):
            if k in value:
                inner = _coerce_online(value[k])
                if inner is not None:
                    return inner
        return None

    # Primitive forms
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        raw = value.strip()
        if raw == "":
            return None
        v = raw.lower()
        # accept substrings so 'text-success', 'bg-red-500' etc. work
        if (
            "online" in v
            or "success" in v
            or "green" in v
            or v in {"true", "1", "yes", "up", "connected", "active", "alive", "ok", "healthy"}
        ):
            return True
        if (
            "offline" in v
            or "danger" in v
            or "error" in v
            or "red" in v
            or v in {"false", "0", "no", "down", "inactive", "disconnected"}
        ):
            return False
        # unknown / NA values → None (do NOT count as offline)
        if v in {"no data", "unknown", "n/a", "na", "not available", "none", "null", "—", "-"}:
            return None
        return None

    # Any other type – unknown
    return None

def _scan_for_ui_color(o: Any) -> Any:
    """
    Look for UI dot color specifically. We only consider keys that look like the Online column:
    - statusColor, status_color, statusDot, indicator, onlineColor, online_color, onlineDot
    - any key name containing both 'online' and 'color'
    Returns True/False if a clear green/red signal is found, else None.
    """
    KEYS = {
        "statuscolor", "status_color", "statusdot", "indicator",
        "onlinecolor", "online_color", "onlinedot", "online_dot",
    }
    found: List[str] = []

    def walk(x: Any):
        if isinstance(x, dict):
            for k, v in x.items():
                kl = k.lower()
                key_hit = (kl in KEYS) or ("online" in kl and "color" in kl)
                if key_hit and isinstance(v, (str, int, float, bool)):
                    found.append(str(v))
                if isinstance(v, (dict, list)):
                    walk(v)
        elif isinstance(x, list):
            for it in x[:50]:
                walk(it)

    walk(o)

    for s in found:
        v = str(s).strip().lower()
        if "green" in v or "success" in v or "ok" in v or "online" in v:
            return True
        if "red" in v or "danger" in v or "error" in v or "offline" in v:
            return False
    return None

# ---------- NEW: auto-detect which JSON path carries online/offline ----------
def _iter_candidate_status_values(node: Any, prefix: str = ""):
    """Yield (json_path, value) pairs for leaf nodes whose path name hints at status/online/connected."""
    interesting = ("online", "connected", "connect", "status", "state", "indicator", "color", "dot")
    if isinstance(node, dict):
        for k, v in node.items():
            path = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict, list)):
                yield from _iter_candidate_status_values(v, path)
            else:
                lp = path.lower()
                if any(tok in lp for tok in interesting):
                    yield path, v
    elif isinstance(node, list):
        for i, v in enumerate(node[:8]):
            p = f"{prefix}[{i}]" if prefix else f"[{i}]"
            yield from _iter_candidate_status_values(v, p)


def _autodetect_online_field(items: List[Dict[str, Any]]) -> Tuple[str, Dict[str, int]]:
    """Return ``(best_json_path, stats)`` where stats is ``{"cover": N, "true": T, "false": F}``.

    The chosen path must actually yield both True and False within the sample so we know the
    signal carries more than a constant "online" response.
    """

    stats: Dict[str, Dict[str, int]] = {}
    sample = items[: min(len(items), 80)]
    for it in sample:
        for path, value in _iter_candidate_status_values(it):
            norm = _coerce_online(value)
            if norm is None:
                continue
            s = stats.setdefault(path, {"cover": 0, "true": 0, "false": 0})
            s["cover"] += 1
            if norm is True:
                s["true"] += 1
            elif norm is False:
                s["false"] += 1

    best_path, best_score = None, -1.0
    for path, s in stats.items():
        if s["false"] == 0:
            continue  # paths that never produce False are not useful
        name = path.lower()
        name_bonus = 1.0 if ("online" in name or "connect" in name) else (
            0.5 if ("status" in name or "color" in name) else 0.0
        )
        score = s["cover"] + 2.5 * s["false"] + name_bonus
        if score > best_score:
            best_path, best_score = path, score

    return best_path, stats.get(best_path, {"cover": 0, "true": 0, "false": 0})

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

        if SESSION_COOKIE:
            session.cookies.set(
                "_designedvr_dahsboard_session",
                SESSION_COOKIE,
                domain="app.boomnow.com",
                path="/",
            )
            if DEBUG_LEVEL >= 1:
                print("[diag] injected session cookie=_designedvr_dahsboard_session")

        if API_KEY:
            session.headers["Authorization"] = f"Bearer {API_KEY}"
        else:
            if not (LOGIN_URL and EMAIL and PASSWORD):
                raise RuntimeError("BOOMNOW_LOGIN_URL/EMAIL/PASSWORD must be set when no API key is used")
            if LOGIN_KIND == "json":
                try:
                    resp = session.post(
                        LOGIN_URL,
                        json={"email": EMAIL, "password": PASSWORD},
                        timeout=REQ_TIMEOUT,
                        allow_redirects=True,
                    )
                    if DEBUG_LEVEL >= 1:
                        print(
                            f"[diag] json_login status={resp.status_code} set_cookie={bool(resp.headers.get('set-cookie'))}"
                        )
                    resp.raise_for_status()
                    ok, data = _safe_json(resp)
                    if ok and isinstance(data, dict):
                        token = (
                            data.get("token")
                            or data.get("jwt")
                            or data.get("access_token")
                            or data.get("apiKey")
                        )
                        if token:
                            session.headers["Authorization"] = f"Bearer {token}"
                except Exception as e:
                    if DEBUG_LEVEL >= 1:
                        print(f"[diag] json_login failed: {e}")
            try:
                g = session.get(LOGIN_URL, timeout=REQ_TIMEOUT)
                g.raise_for_status()
                csrf = _extract_csrf(getattr(g, "text", "") or "")
                form = {"email": EMAIL, "password": PASSWORD}
                if re.search(r'name=["\']user\[email\]["\']', getattr(g, "text", "") or "", re.I):
                    form = {"user[email]": EMAIL, "user[password]": PASSWORD}
                if csrf:
                    form["authenticity_token"] = csrf
                headers2 = {"Referer": LOGIN_URL, "Origin": BASE_URL or LOGIN_URL.split("/api")[0]}
                p = session.post(
                    LOGIN_URL,
                    data=form,
                    headers=headers2,
                    timeout=REQ_TIMEOUT,
                    allow_redirects=True,
                )
                if DEBUG_LEVEL >= 1:
                    print(
                        f"[diag] form_login status={p.status_code} set_cookie={bool(p.headers.get('set-cookie'))}"
                    )
                p.raise_for_status()
            except Exception as e:
                if DEBUG_LEVEL >= 1:
                    print(f"[diag] form_login failed: {e}")

        if not API_KEY:
            # ----- verify we're authenticated -----
            whoami_candidates = ("/api/get-current-user", "/api/me", "/api/current_user")
            authed = False
            for path in whoami_candidates:
                try:
                    r = session.get(f"{BASE_URL}{path}", timeout=REQ_TIMEOUT, allow_redirects=False)
                    if r.status_code == 200:
                        authed = True
                        break
                except Exception:
                    pass

            if not authed:
                # Fail fast with a clear message (and keep DEBUG_PROVIDER output for context)
                raise RuntimeError("Authentication failed: login completed but 'whoami' endpoints returned 401/404; "
                                   "check BOOMNOW_LOGIN_URL/LOGIN_KIND/EMAIL/PASSWORD and tenant SSO settings.")

        # Diagnostics: cookie names (values redacted)
        if DEBUG_LEVEL >= 1:
            cookie_names = sorted(session.cookies.get_dict().keys())
            print("[diag] cookies=" + ",".join(cookie_names))

            try:
                me = session.get(f"{BASE_URL}/api/get-current-user", timeout=REQ_TIMEOUT)
                ok, me_json = _safe_json(me)
                keys = list(me_json.keys())[:8] if isinstance(me_json, dict) else type(me_json).__name__
                print(
                    f"[diag] whoami status={me.status_code} ok={ok} keys={keys}"
                )
            except Exception as e:
                print(f"[diag] whoami failed: {e}")

        # IMPORTANT: BoomNow uses cookie context. Do NOT send X-* scope headers/queries.
        ids: List[str] = []  # disable id-scoping entirely (header + query)

        # Build endpoint + query candidates
        def _build(ep: str) -> str:
            u = f"{BASE_URL}{ep}"
            # Default to page=0 if caller didn't provide anything.
            q = DEVICES_QUERY or "size=100&page=0"
            return _join_query(u, q) if q else u

        endpoints: List[str] = []
        if EXACT_URL:
            u = EXACT_URL
            if not u.startswith("http"):
                u = f"{BASE_URL}{u}" if u.startswith("/") else f"{BASE_URL}/{u}"
            if DEVICES_QUERY and "?" not in u:
                u = _join_query(u, DEVICES_QUERY)
            endpoints.append(u)
            if DEBUG_PROVIDER:
                print(f"[diag] exact_url={u}")
        for ep in ENDPOINT_CANDIDATES:
            u = _build(ep)
            if u not in endpoints:
                endpoints.append(u)

        # Compact query variants; we'll try header scoping first, then add query scoping if needed.
        base_query_only = [""]
        scoped_query: List[str] = []

        # Header variants: start with discovered scoped headers, then fall back to bare headers
        # Strip any stray X-* scope headers; keep only normal headers
        base_hv = {k: v for (k, v) in session.headers.items() if k not in SCOPE_HEADER_NAMES}
        header_variants: List[Dict[str, str]] = []
        try:
            scoped_headers = _discover_scope_headers(session)
        except Exception:
            scoped_headers = {}
        if scoped_headers:
            hv_scoped = dict(base_hv)
            hv_scoped.update(scoped_headers)
            header_variants.append(hv_scoped)
        header_variants.append(base_hv)

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
                        if attempt == 1:
                            jar = getattr(session, "cookies", None)
                            names = sorted({c.name for c in jar}) if jar else []
                            ck = ",".join(names) or "(none)"
                            print(f"[diag] cookies={ck}")
                        hdrs = "|".join(k for k in hv.keys() if k.startswith("X-")) or "(none)"
                        print(f"[provider] try[{attempt}] {full_url} => {r.status_code} ct={ct} hdrs={hdrs}")

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
                        try:
                            print(f"[diag] payload_shape={json.dumps(_summarize(payload), ensure_ascii=False)[:1000]}")
                        except Exception:
                            pass
                        if not items:
                            try:
                                cands = _probe_device_arrays(payload)
                                if cands:
                                    print(f"[diag] device_array_candidates (top 5)={cands[:5]}")
                                    best_path, score, _len = cands[0]
                                    if score > 0:
                                        guessed = payload if best_path == "$" else _get_by_path(payload, best_path)
                                        if isinstance(guessed, list):
                                            print(f"[diag] json_path_guess='{best_path}' score={score} count={len(guessed)}")
                                            items = _extract_device_dicts(guessed)
                                else:
                                    try:
                                        shape = {"_type": type(payload).__name__.lower()}
                                        if isinstance(payload, list):
                                            shape["len"] = len(payload)
                                            shape["sample"] = payload[:1]
                                        elif isinstance(payload, dict):
                                            shape["keys"] = list(payload.keys())[:10]
                                        print(f"[diag] payload_shape_extra={_trim_json_preview(shape)}")
                                        cands2 = _enumerate_array_paths(payload)
                                        if cands2:
                                            print(f"[diag] device_array_candidates (top 5)={[(p, 0.0, 0) for p in cands2[:5]]}")
                                    except Exception:
                                        pass
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
                        if attempt == 1:
                            jar = getattr(session, "cookies", None)
                            names = sorted({c.name for c in jar}) if jar else []
                            ck = ",".join(names) or "(none)"
                            print(f"[diag] cookies={ck}")
                        hdrs = "|".join(k for k in base_hv.keys() if k.startswith("X-")) or "(none)"
                        print(f"[provider] try[{attempt}] {full_url} => {r.status_code} ct={ct} hdrs={hdrs}")
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
                        try:
                            print(f"[diag] payload_shape={json.dumps(_summarize(payload), ensure_ascii=False)[:1000]}")
                        except Exception:
                            pass
                        if not items:
                            try:
                                cands = _probe_device_arrays(payload)
                                if cands:
                                    print(f"[diag] device_array_candidates (top 5)={cands[:5]}")
                                    best_path, score, _len = cands[0]
                                    if score > 0:
                                        guessed = payload if best_path == "$" else _get_by_path(payload, best_path)
                                        if isinstance(guessed, list):
                                            print(f"[diag] json_path_guess='{best_path}' score={score} count={len(guessed)}")
                                            items = _extract_device_dicts(guessed)
                                else:
                                    try:
                                        shape = {"_type": type(payload).__name__.lower()}
                                        if isinstance(payload, list):
                                            shape["len"] = len(payload)
                                            shape["sample"] = payload[:1]
                                        elif isinstance(payload, dict):
                                            shape["keys"] = list(payload.keys())[:10]
                                        print(f"[diag] payload_shape_extra={_trim_json_preview(shape)}")
                                        cands2 = _enumerate_array_paths(payload)
                                        if cands2:
                                            print(f"[diag] device_array_candidates (top 5)={[(p, 0.0, 0) for p in cands2[:5]]}")
                                    except Exception:
                                        pass
                            except Exception:
                                pass
                    if items:
                        break
                if items:
                    break

        # If we never saw JSON or we got an empty list, try scraping the dashboard as a last resort.
        if found_payload is None or not items:
            scraped = _scrape_dashboard_for_devices(session)
            if scraped:
                items = scraped

        if found_payload is None and not items:
            return []

        # Normalize to Device objects
        out: List[Device] = []

        # If caller didn't force a field, try to auto-detect which JSON path gives us a real online/offline signal.
        auto_online_path = None
        if not ONLINE_FIELD and not COLOR_ONLY:
            auto_online_path, auto_stats = _autodetect_online_field(items)
            if DEBUG_PROVIDER and auto_online_path:
                print(
                    f"[diag] online_field_auto='{auto_online_path}' "
                    f"cover={auto_stats['cover']} true={auto_stats['true']} false={auto_stats['false']}"
                )
        elif DEBUG_PROVIDER:
            print(f"[diag] online_field_override='{ONLINE_FIELD}'")

        color_cover = color_true = color_false = 0
        bool_cover = bool_true = bool_false = 0

        filtered_count = 0
        offline_filtered = 0

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
            if NAME_FIELD:
                name = _get_by_path(item, NAME_FIELD) or name

            in_use = True
            if ONLY_ACTIVE:
                in_use = in_use and _get_bool_path(item, "boom.active")
            if ONLY_MANAGED:
                managed_val = _first_present(item, "is_managed", "isManaged")
                in_use = in_use and _truthy(managed_val)
            if REQUIRED_CAPABILITY:
                in_use = in_use and _has_capability(item, REQUIRED_CAPABILITY)
            if not in_use:
                continue
            filtered_count += 1

            # Collect UI indicator fields the dashboards tend to use (color/dot).
            color_value = None
            if COLOR_FIELD:
                color_value = _get_by_path(item, COLOR_FIELD)
            picked_ui_color = _pick_ui_color(item)
            if color_value is None:
                color_value = picked_ui_color

            color_signal = _scan_for_ui_color(item)
            if color_signal is None and color_value is not None:
                coerced_color = _coerce_online(color_value)
                if coerced_color is not None:
                    color_signal = coerced_color
            if color_signal is not None:
                color_cover += 1
                if color_signal is True:
                    color_true += 1
                if color_signal is False:
                    color_false += 1

            online_raw = None
            bool_candidate = None

            if COLOR_ONLY:
                if color_signal is not None:
                    online_raw = color_signal
                else:
                    online_raw = color_value
            else:
                if ONLINE_FIELD:
                    candidate = _get_by_path(item, ONLINE_FIELD)
                    if candidate is not None:
                        online_raw = candidate
                        bool_candidate = candidate

                if online_raw is None and auto_online_path:
                    candidate = _get_by_path(item, auto_online_path)
                    if candidate is not None:
                        online_raw = candidate
                        if bool_candidate is None:
                            bool_candidate = candidate

                if online_raw is None:
                    candidate = _first_present(
                        item,
                        "online", "isOnline", "connected", "is_online", "onlineStatus",
                        "isConnected", "connectionStatus", "online_status", "onlineText"
                    )
                    if candidate is not None:
                        online_raw = candidate
                        if bool_candidate is None:
                            bool_candidate = candidate

                if bool_candidate is not None:
                    bool_cover += 1
                    coerced_bool = _coerce_online(bool_candidate)
                    if coerced_bool is True:
                        bool_true += 1
                    if coerced_bool is False:
                        bool_false += 1

                if online_raw is None and (STRICT_UI_COLOR or STRICT_UI):
                    if color_signal is not None:
                        online_raw = color_signal
                    elif color_value is not None:
                        online_raw = color_value

                if online_raw is None and not STRICT_UI:
                    if color_signal is not None:
                        online_raw = color_signal
                    elif color_value is not None:
                        online_raw = color_value

                if online_raw is None and "status" in item:
                    status = item.get("status")
                    if isinstance(status, dict):
                        for k in ("color", "text", "name", "value"):
                            s = status.get(k)
                            c = _coerce_online(s)
                            if c is not None:
                                online_raw = c
                                break
                    else:
                        online_raw = _coerce_online(status)

                if online_raw is None:
                    indicator = (
                        item.get("statusColor") or item.get("status_color") or
                        item.get("indicator") or item.get("onlineColor") or item.get("statusDot")
                    )
                    if indicator:
                        sv = str(indicator).strip().lower()
                        online_raw = True if sv in {"green","success","ok"} else False if sv in {"red","danger","error"} else None

            online = _coerce_online(online_raw)
            if online is False:
                offline_filtered += 1

            battery = None
            for k in ("battery","batteryPercent","battery_percentage","batteryLevel","battery_level"):
                if k in item and isinstance(item[k], (int, float)):
                    battery = int(item[k]); break

            out.append(Device(id=did, name=name, online=online, battery=battery, extra=item))

        if DEBUG_LEVEL >= 1:
            print(
                f"[diag] filtered_count={filtered_count} offline_count={offline_filtered} online_field='{ONLINE_FIELD or auto_online_path or '(auto)'}'"
            )
            print(
                "[diag] ui_color cover="
                f"{color_cover} green={color_true} red={color_false} | boolean cover={bool_cover} true={bool_true} false={bool_false}"
            )
        return out
