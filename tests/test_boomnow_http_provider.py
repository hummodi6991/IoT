import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.providers import boomnow_http
from app.providers.boomnow_http import _extract_device_dicts, BoomNowHttpProvider


@pytest.fixture(autouse=True)
def reset_globals(monkeypatch):
    # Ensure environment-driven globals have predictable values per test.
    monkeypatch.setattr(boomnow_http, "BASE_URL", "https://example.com", raising=False)
    monkeypatch.setattr(boomnow_http, "DEVICES_ENDPOINT", "/api/devices", raising=False)
    monkeypatch.setattr(boomnow_http, "DEVICES_QUERY", "", raising=False)
    monkeypatch.setattr(boomnow_http, "API_KEY", "test-token", raising=False)
    monkeypatch.setattr(boomnow_http, "EXTRA_HEADERS", None, raising=False)
    monkeypatch.setattr(boomnow_http, "DEVICES_JSON_PATH", "", raising=False)
    monkeypatch.setattr(boomnow_http, "DEBUG_PROVIDER", False, raising=False)
    monkeypatch.setattr(boomnow_http, "LOGIN_URL", None, raising=False)
    monkeypatch.setattr(boomnow_http, "LOGIN_KIND", "form", raising=False)
    monkeypatch.setattr(boomnow_http, "EMAIL", None, raising=False)
    monkeypatch.setattr(boomnow_http, "PASSWORD", None, raising=False)
    yield


def test_extract_devices_handles_graphql_edges():
    payload = {
        "data": {
            "buildings": [
                {
                    "name": "Building A",
                    "devices": {
                        "edges": [
                            {
                                "cursor": "1",
                                "node": {
                                    "uuid": "dev-1",
                                    "deviceName": "Main Door",
                                    "status": {"text": "Offline"},
                                    "batteryPercent": 28,
                                },
                            },
                            {
                                "cursor": "2",
                                "node": {
                                    "uuid": "dev-2",
                                    "attributes": {
                                        "name": "Side Door",
                                        "status": "online",
                                        "battery_level": 81,
                                    },
                                },
                            },
                        ]
                    },
                }
            ]
        }
    }

    items = _extract_device_dicts(payload)
    assert len(items) == 2
    first, second = items
    assert first["uuid"] == "dev-1"
    # Metadata from the wrapper is preserved
    assert first.get("deviceName") == "Main Door"
    assert first["cursor"] == "1"
    assert second["battery_level"] == 81
    assert second["uuid"] == "dev-2"


def test_provider_returns_devices_from_wrapped_payload(monkeypatch):
    payload = {
        "data": {
            "rooms": [
                {
                    "roomName": "Suite 101",
                    "device": {
                        "node": {
                            "id": "room-device-1",
                            "name": "Suite 101 Door",
                            "status": "offline",
                            "battery": 55,
                        }
                    },
                },
                {
                    "roomName": "Suite 102",
                    "device": {
                        "node": {
                            "id": "room-device-2",
                            "name": "Suite 102 Door",
                            "status": "online",
                            "battery": 87,
                        }
                    },
                },
            ]
        }
    }

    class DummyResponse:
        def __init__(self, data):
            self._data = data
            self.status_code = 200
            self.headers = {"content-type": "application/json"}

        def raise_for_status(self):
            return None

        def json(self):
            return self._data

    def fake_get(url, headers, timeout):
        assert url == "https://example.com/api/devices"
        assert headers["Authorization"].startswith("Bearer ")
        return DummyResponse(payload)

    monkeypatch.setattr(boomnow_http.requests, "get", fake_get)

    provider = BoomNowHttpProvider()
    devices = provider.get_devices()

    assert len(devices) == 2
    first, second = devices
    assert first.id == "room-device-1"
    assert first.name == "Suite 101 Door"
    assert first.online is False
    assert first.battery == 55
    assert second.online is True
    assert second.battery == 87

