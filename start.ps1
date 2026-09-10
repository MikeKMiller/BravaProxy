# BravaProxy - Android app capture
# Web UI at http://127.0.0.1:8081, proxy on port 8080
#
# Android setup:
#   1. Set WiFi proxy to <this machine's IP>:8080
#   2. Visit http://mitm.it in phone browser, install the Android cert
#   3. Open the Brava app and cook something

$mitmweb = ".\.venv\Scripts\mitmweb.exe"
if (-not (Test-Path $mitmweb)) {
    Write-Error "venv not found. Run: python -m venv .venv && .venv\Scripts\pip install -r requirements.txt"
    exit 1
}

Write-Host "Starting BravaProxy..."
Write-Host "  Proxy:  http://<your-LAN-IP>:8080  (set this on your phone's WiFi)"
Write-Host "  Web UI: http://127.0.0.1:8081"
Write-Host ""
& $mitmweb --listen-port 8080 --web-port 8081 -s proxy/addon.py
