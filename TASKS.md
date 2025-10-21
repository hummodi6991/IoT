
# Tasks & Acceptance

## 1) Implement real provider for BoomNow (or your lock platform)
- Fill environment variables:
  - BOOMNOW_BASE_URL
  - BOOMNOW_DEVICES_ENDPOINT (e.g., `/api/devices`)
  - One of: BOOMNOW_API_KEY or (BOOMNOW_USERNAME + BOOMNOW_PASSWORD)
- Ensure `providers/boomnow_http.py:get_devices()` returns a list of dicts like:
  ```python
  {"id": "abc123", "name": "Apartment 10", "online": True, "battery": 91}
  ```
- Map platform-specific JSON fields to the normalized keys above.

**Acceptance**: `pytest -q` passes; pushing to main triggers the workflow; if you temporarily set a device to `online: false` in the demo JSON (or mock HTTP), email fires once and then again only after cooldown; recovery email fires when back to `true`.

## 2) Optional webhook
- Expose `app/webhook.py` and configure platform webhooks to call `/event` with JSON payloads `{deviceId, name, online, battery}`.
- Reuse `state.py` to decide what notifications to send.

