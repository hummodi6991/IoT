
import json, os, random
from typing import List
from app.device import Device
from .base import DeviceStatusProvider

DEMO_FILE = os.environ.get("DEMO_FILE", "demo/devices.json")

class DemoProvider(DeviceStatusProvider):
    def get_devices(self) -> List[Device]:
        with open(DEMO_FILE, "r") as f:
            data = json.load(f)
        devices = []
        for row in data.get("devices", []):
            devices.append(Device(
                id=str(row["id"]),
                name=row["name"],
                online=bool(row["online"]),
                battery=row.get("battery"),
                extra=row
            ))
        return devices
