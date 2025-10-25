import pathlib
import sys

import pytest
import requests

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
    monkeypatch.setattr(
        boomnow_http,
        "_discover_scope",
        lambda session, headers: {
            "team_ids": set(),
            "org_ids": set(),
            "company_ids": set(),
            "tenant_ids": set(),
            "region_ids": set(),
            "zone_ids": set(),
        },
        raising=False,
    )
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


def test_extract_devices_handles_nested_list_content():
    payload = {
        "list": {
            "content": [
                {
                    "id": "dev-1",
                    "name": "Door 1",
                    "status": "Online",
                }
            ]
        }
    }

    items = _extract_device_dicts(payload)
    assert len(items) == 1
    assert items[0]["id"] == "dev-1"
    assert items[0]["name"] == "Door 1"


def test_extract_devices_handles_jsonapi_data_array():
    payload = {
        "data": [
            {
                "id": "dev-10",
                "attributes": {
                    "name": "Front Entrance",
                    "statusText": "Offline",
                    "battery_level": 12,
                },
            }
        ]
    }

    items = _extract_device_dicts(payload)
    assert len(items) == 1
    item = items[0]
    assert item["id"] == "dev-10"
    assert item["name"] == "Front Entrance"
    assert item["statusText"] == "Offline"
    assert item["battery_level"] == 12


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

    def fake_get(self, url, headers=None, timeout=None):
        if url.endswith("/api/devices"):
            assert headers["Authorization"].startswith("Bearer ")
            return DummyResponse(payload)
        return DummyResponse({})

    monkeypatch.setattr(requests.Session, "get", fake_get)

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


def test_provider_interprets_string_and_indicator_status(monkeypatch):
    payload = {
        "list": {
            "content": [
                {
                    "id": "offline-1",
                    "name": "Offline Sensor",
                    "status": "Offline",
                    "battery": 40,
                },
                {
                    "id": "indicator-2",
                    "name": "Indicator Sensor",
                    "statusColor": "green",
                    "batteryPercent": 90,
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

    def fake_get(self, url, headers=None, timeout=None):
        if url.endswith("/api/devices"):
            return DummyResponse(payload)
        return DummyResponse({})

    monkeypatch.setattr(requests.Session, "get", fake_get)

    provider = BoomNowHttpProvider()
    devices = provider.get_devices()

    assert len(devices) == 2
    first, second = devices
    assert first.id == "offline-1"
    assert first.online is False
    assert first.battery == 40
    assert second.id == "indicator-2"
    assert second.online is True
    assert second.battery == 90

