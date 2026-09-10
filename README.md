# BravaProxy

Local proxy to intercept, archive, and eventually replace Brava's cloud services.

## Architecture

```
[Android App / Brava Oven]
        |  (DNS or WiFi proxy)
        v
[This machine — mitmproxy :8080]
        |  (logs everything to capture.db)
        v
[Brava Cloud Servers]  ← still live during capture phase
```

## Setup

### 1. Install

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Start the proxy

```powershell
.\start.ps1          # mitmweb UI at http://127.0.0.1:8081
# or
.\start-headless.ps1 # mitmdump, logs only
```

### 3. Android — install the CA cert

1. Connect your phone to the same WiFi as this machine.
2. Go to **WiFi settings → (your network) → Modify → Advanced → Proxy → Manual**
   - Host: `<this machine's LAN IP>`
   - Port: `8080`
3. On the phone browser visit **http://mitm.it** and download the Android cert.
4. Install it: **Settings → Security → Install from storage** (or Encryption & credentials).
5. Open the Brava app and use it normally. Watch the console / mitmweb for traffic.

> **Android 7+ note:** Apps targeting API 24+ only trust system CAs, not user-installed ones.
> If the Brava app ignores your proxy cert, see `docs/android-cert-pinning.md`.

### 4. Brava Appliance — DNS redirect

Once you've identified the domains via the Android app:

1. Add DNS A records pointing each Brava domain to this machine's LAN IP.
2. The oven connects to this machine on port 443.
3. Run mitmproxy on port 443 (requires admin / elevated prompt):

```powershell
mitmweb --listen-port 443 --web-port 8081 -s proxy/addon.py
```

> The oven may reject the mitmproxy cert if it validates TLS strictly.
> Check `capture.db` for TLS errors. Many IoT devices don't pin certs.

## Viewing captured traffic

```powershell
python proxy/viewer.py domains     # all domains seen, sorted by frequency
python proxy/viewer.py brava       # Brava-only requests
python proxy/viewer.py urls        # unique Brava endpoints
python proxy/viewer.py json        # Brava JSON responses (pretty-printed)
python proxy/viewer.py dump <id>   # full request + response for a capture ID
```

## Phases

| Phase | Status | Goal |
|-------|--------|------|
| 1 — Capture | **In progress** | Intercept all app + oven traffic, identify all endpoints |
| 2 — Scrape | Pending | Query Brava API directly to pull all ~5000 recipes |
| 3 — Local server | Pending | FastAPI service that replaces Brava cloud entirely |
