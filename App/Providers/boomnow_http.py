
import os, requests
from typing import List
from app.device import Device
from .base import DeviceStatusProvider

# This is a thin, configurable HTTP client. Adapt the JSON mapping below to fit your platform.
BASE_URL = os.environ.get("BOOMNOW_BASE_URL", "").rstrip("/")
DEVICES_ENDPOINT = os.environ.get("BOOMNOW_DEVICES_ENDPOINT", "/api/devices")  # e.g., '/api/devices'
API_KEY = os.environ.get("BOOMNOW_API_KEY")
USERNAME = os.environ.get("BOOMNOW_USERNAME")
PASSWORD = os.environ.get("BOOMNOW_PASSWORD")

HEADERS = {}
if API_KEY:
    HEADERS["Authorization"] = f"Bearer {API_KEY}"
HEADERS["Accept"] = "application/json"

class BoomNowHttpProvider(DeviceStatusProvider):
    def get_devices(self) -> List[Device]:
        if not BASE_URL:
            raise RuntimeError("BOOMNOW_BASE_URL must be set for boomnow_http provider")
        url = f"{BASE_URL}{DEVICES_ENDPOINT}"
        auth = None
        if USERNAME and PASSWORD:
            auth = (USERNAME, PASSWORD)

        r = requests.get(url, headers=HEADERS, auth=auth, timeout=30)
        r.raise_for_status()
        payload = r.json()

        # ---- Map the platform's JSON into a normalized list of Device objects.
        # Common shapes:
        # 1) payload is a list of devices
        # 2) payload is { "devices": [ ... ] }
        if isinstance(payload, dict) and "devices" in payload:
            items = payload["devices"]
        elif isinstance(payload, list):
            items = payload
        else:
            # Try a common alternative
            items = payload.get("results", []) if isinstance(payload, dict) else []

        devices: List[Device] = []
        for item in items:
            # TODO: adjust the following field mappings to your platform
            # Try common keys with fallbacks
            did = str(item.get("id") or item.get("deviceId") or item.get("uuid") or "")
            name = item.get("name") or item.get("label") or item.get("deviceName") or did
            online_raw = item.get("online")
            if online_raw is None:
                # Try alternate names
                online_raw = item.get("isOnline") or item.get("status") in ("online", "ONLINE", "connected", "up")
            online = bool(online_raw)
            battery = None
            # Try to pull a battery percentage if present
            for k in ("battery", "batteryPercent", "battery_percentage", "batteryLevel"):
                if k in item and isinstance(item[k], (int, float)):
                    battery = int(item[k])
                    break

            devices.append(Device(id=did, name=name, online=online, battery=battery, extra=item))

        return devices
