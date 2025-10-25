
import json
import os
from pathlib import Path
from typing import Iterable, List

from app.device import Device
from .base import DeviceStatusProvider


def _candidate_paths() -> Iterable[Path]:
    """Yield possible locations for the demo devices JSON file."""

    env_value = os.environ.get("DEMO_FILE")
    base_dir = Path(__file__).resolve().parents[2]

    if env_value:
        explicit = Path(env_value)
        yield explicit
        if not explicit.is_absolute():
            yield Path.cwd() / explicit
            yield base_dir / explicit

    yield base_dir / "Demo" / "devices.json"


def _resolve_demo_file() -> Path:
    for candidate in _candidate_paths():
        if candidate.is_file():
            return candidate
    search = [str(p) for p in _candidate_paths()]
    raise FileNotFoundError(
        "Unable to locate demo devices JSON file. Checked: " + ", ".join(dict.fromkeys(search))
    )


class DemoProvider(DeviceStatusProvider):
    def get_devices(self) -> List[Device]:
        path = _resolve_demo_file()
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        devices: List[Device] = []
        for row in data.get("devices", []):
            devices.append(
                Device(
                    id=str(row["id"]),
                    name=row["name"],
                    online=bool(row["online"]),
                    battery=row.get("battery"),
                    extra=row,
                )
            )
        return devices
