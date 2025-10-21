
import json, os, time, pathlib
from typing import Dict, Any

STATE_PATH = os.environ.get("STATE_PATH", "state/state.json")

def _ensure_dir():
    pathlib.Path(os.path.dirname(STATE_PATH)).mkdir(parents=True, exist_ok=True)

def load_state() -> Dict[str, Any]:
    _ensure_dir()
    if not os.path.exists(STATE_PATH):
        return {}
    try:
        with open(STATE_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def save_state(data: Dict[str, Any]) -> None:
    _ensure_dir()
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.replace(tmp, STATE_PATH)

def now_ts() -> float:
    return time.time()
