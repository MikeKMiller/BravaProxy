# BravaProxy - start mitmweb with capture addon
# Run from the project root: .\start.ps1

# Web UI on http://127.0.0.1:8081, proxy on port 8080
mitmweb --listen-port 8080 --web-port 8081 -s proxy/addon.py
