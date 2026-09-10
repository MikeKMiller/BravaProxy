# BravaProxy - intercept Brava oven traffic via DNS redirect
# Must run as Administrator (port 443 requires elevated privileges)
# Set up DNS overrides first: python tools/technitium.py override

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must run as Administrator (port 443 requires elevation)."
    Write-Host "Right-click PowerShell → Run as Administrator, then re-run."
    exit 1
}

Write-Host "Starting BravaProxy on port 443 (appliance mode)..."
mitmdump --listen-port 443 -s proxy/addon.py
