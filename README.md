
# IoT Offline Monitor (GitHub + Actions)

A lightweight Python monitor that polls your IoT platform for device status and **sends email alerts when a device goes offline** (and a recovery email when it comes back online). It also supports optional low‑battery notifications.

The repository is GitHub‑Actions first (scheduled every 10 minutes by default), but you can run it anywhere that can execute Python.

---

## Quickstart (GitHub)

1. **Create a new GitHub repo** and push this folder's contents.
2. In **Settings → Secrets and variables → Actions**, add these repository **secrets** (values are examples):
   - `SMTP_HOST` = `smtp.gmail.com`
   - `SMTP_PORT` = `587`
   - `SMTP_USERNAME` = `alerts@example.com`
   - `SMTP_PASSWORD` = *your app password*
   - `FROM_EMAIL` = `alerts@example.com`
   - `TO_EMAILS` = `ops@example.com,owner@example.com`
   - `PROVIDER` = `demo`  (switch to `boomnow_http` once you wire the API)
   - `ALERT_COOLDOWN_MINUTES` = `240`  (avoid repeat emails for persistent outages)
   - `BATTERY_LOW_THRESHOLD` = `20`    (optional)
   - `OFFLINE_GRACE_MINUTES` = `0`     (wait N minutes before alerting)
   - (If using the HTTP provider) `BOOMNOW_BASE_URL`, `BOOMNOW_DEVICES_ENDPOINT`, and either `BOOMNOW_API_KEY` **or** `BOOMNOW_USERNAME`/`BOOMNOW_PASSWORD`.
3. The included workflow `.github/workflows/monitor.yml` will run every 10 minutes. It persists state in `state/state.json` by committing back to the repo (using the built‑in `GITHUB_TOKEN`).

> **Gmail note**: If you use Gmail, enable 2‑factor auth and create an **App Password** for SMTP. Put that value in `SMTP_PASSWORD`.

---

## Local run

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export PROVIDER=demo  # or boomnow_http once configured
export SMTP_HOST=smtp.gmail.com SMTP_PORT=587 SMTP_USERNAME=me@example.com SMTP_PASSWORD=xxx FROM_EMAIL=me@example.com TO_EMAILS=you@example.com
python app/main.py
```

---

## Providers

- **demo**: Uses an in-repo JSON file with a few fake devices to prove the pipeline end-to-end.
- **boomnow_http**: A thin, configurable HTTP client. Point it at your IoT platform’s "list devices" endpoint and map fields in `providers/boomnow_http.py` if necessary. The provider now auto-discovers tenant/team/org scope and common pagination patterns; if the payload structure is unusual you can override detection with `BOOMNOW_DEVICES_JSON_PATH` (e.g., `list.content`).

### BoomNow notes

- Keep `BOOMNOW_DEVICES_ENDPOINT=/api/iot-devices` and `BOOMNOW_DEVICES_JSON_PATH=list.content` unless your tenant uses a different surface.
- The provider automatically adds `X-Requested-With: XMLHttpRequest` and tries to infer scope headers such as `X-Org-Id`, `X-Team-Id`, and similar IDs from `/api/get-current-user` and `/api/teams` payloads.
- You can extend request metadata with `BOOMNOW_EXTRA_HEADERS` (JSON dict). Leave SMTP-related secrets untouched.

If your platform can emit webhooks for "device offline/online", you can run `app/webhook.py` on a small host (Railway, Fly.io, Render, etc.) and configure the platform to call it; the same notifier + state logic will apply.

---

## What counts as "offline"?

- The provider returns `online = False`.
- We optionally **wait `OFFLINE_GRACE_MINUTES`** before alerting (to avoid flapping).
- We do **not** send repeated emails for persistent outages until `ALERT_COOLDOWN_MINUTES` elapses.
- When a device recovers (False → True), we send a **recovery** email.

---

## Files

- `app/main.py` — One-shot poller used by GitHub Actions.
- `app/providers/*.py` — Data sources (demo and HTTP).
- `app/notify/emailer.py` — SMTP email.
- `app/state.py` — Persists state and debounces notifications.
- `app/webhook.py` — Optional Flask webhook endpoint for push events.
- `.github/workflows/monitor.yml` — Cron scheduler + state commit.

---

## Using an automated SWE agent

If you use a cloud software engineering agent in your GitHub workflow, create an issue like **"Wire BoomNow API provider"** and point it to `providers/boomnow_http.py` and `TASKS.md`. The tests and `demo` provider show expected shapes.

---

## License

MIT
