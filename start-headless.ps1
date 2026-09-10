# BravaProxy - headless capture (logs to console + capture.db, no UI)
# Use for long-running sessions or when mitmweb isn't needed

$mitmdump = ".\.venv\Scripts\mitmdump.exe"
if (-not (Test-Path $mitmdump)) {
    Write-Error "venv not found. Run: python -m venv .venv && .venv\Scripts\pip install -r requirements.txt"
    exit 1
}

& $mitmdump --listen-port 8080 -s proxy/addon.py
