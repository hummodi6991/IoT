import importlib


def test_demo_provider_loads_default_fixture(monkeypatch):
    monkeypatch.delenv("DEMO_FILE", raising=False)
    demo = importlib.import_module("app.providers.demo")
    importlib.reload(demo)

    provider = demo.DemoProvider()
    devices = provider.get_devices()

    assert len(devices) >= 1
    assert any(device.online is False for device in devices)


def test_demo_provider_respects_custom_file(tmp_path, monkeypatch):
    custom = tmp_path / "devices.json"
    custom.write_text(
        """
        {
            "devices": [
                {"id": "custom-1", "name": "Custom", "online": false, "battery": 17}
            ]
        }
        """
    )

    monkeypatch.setenv("DEMO_FILE", str(custom))
    demo = importlib.import_module("app.providers.demo")
    importlib.reload(demo)

    provider = demo.DemoProvider()
    devices = provider.get_devices()

    assert len(devices) == 1
    device = devices[0]
    assert device.id == "custom-1"
    assert device.name == "Custom"
    assert device.online is False
    assert device.battery == 17
