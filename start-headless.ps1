# BravaProxy - headless capture (no UI, just logs + DB)
# Use this when capturing appliance traffic long-running

mitmdump --listen-port 8080 -s proxy/addon.py
