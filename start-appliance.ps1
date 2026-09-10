# BravaProxy - Brava oven capture via DNS redirect (port 443)
# Requires Administrator — port 443 is a privileged port on Windows.
#
# Before running:
#   1. Fill in .env (copy from .env.example)
#   2. python tools/technitium.py override   <- adds DNS overrides in Technitium
#   3. Run this script as Administrator

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Must run as Administrator (port 443 requires elevation)."
    Write-Host "Right-click PowerShell -> Run as Administrator, then re-run."
    exit 1
}

$mitmdump = ".\.venv\Scripts\mitmdump.exe"
if (-not (Test-Path $mitmdump)) {
    Write-Error "venv not found. Run: python -m venv .venv && .venv\Scripts\pip install -r requirements.txt"
    exit 1
}

Write-Host "Starting BravaProxy on port 443 (appliance mode)..."
& $mitmdump --listen-port 443 -s proxy/addon.py
