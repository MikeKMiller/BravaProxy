"""
Technitium DNS helper for BravaProxy.

Discovers what domains the Brava oven resolves, then adds/removes DNS
override zones that redirect those domains to the local proxy machine.

Usage:
    python tools/technitium.py discover              # domains the oven has queried
    python tools/technitium.py override [--dry-run]  # add DNS overrides → proxy
    python tools/technitium.py list                  # show active BravaProxy zones
    python tools/technitium.py remove                # remove all BravaProxy zones

Reads config from .env (see .env.example).
"""

import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

# ── config ────────────────────────────────────────────────────────────────────

def _load_env():
    env_path = Path(__file__).parent.parent / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip())

_load_env()

TECHNITIUM_URL  = os.environ.get("TECHNITIUM_URL", "http://127.0.0.1:5380").rstrip("/")
TECHNITIUM_USER = os.environ.get("TECHNITIUM_USER", "admin")
TECHNITIUM_PASS = os.environ.get("TECHNITIUM_PASS", "")
PROXY_IP        = os.environ.get("PROXY_IP", "")
BRAVA_OVEN_IP   = os.environ.get("BRAVA_OVEN_IP", "10.10.254.144")

ZONE_TAG = "bravaproxy"   # comment tag added to every record we create

# ── Technitium API ─────────────────────────────────────────────────────────────

class TechnitiumClient:
    def __init__(self):
        self.base = TECHNITIUM_URL
        self.token = self._login()

    def _login(self) -> str:
        r = requests.get(f"{self.base}/api/user/login", params={
            "user": TECHNITIUM_USER,
            "pass": TECHNITIUM_PASS,
            "includeInfo": "false",
        }, timeout=10)
        r.raise_for_status()
        data = r.json()
        if data.get("status") != "ok":
            raise RuntimeError(f"Technitium login failed: {data}")
        return data["response"]["token"]

    def _get(self, path: str, **params):
        r = requests.get(f"{self.base}{path}", params={"token": self.token, **params}, timeout=15)
        r.raise_for_status()
        return r.json()

    def _post(self, path: str, **params):
        r = requests.post(f"{self.base}{path}", params={"token": self.token, **params}, timeout=15)
        r.raise_for_status()
        return r.json()

    # ── query log ──────────────────────────────────────────────────────────────

    def query_log(self, client_ip: str, hours: int = 48) -> list[dict]:
        """Return all DNS query log entries for a given client IP."""
        start = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end   = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        entries = []
        page = 1
        while True:
            data = self._get("/api/logs/query",
                pageNumber=page,
                entriesPerPage=1000,
                startDate=start,
                endDate=end,
                clientIpAddress=client_ip,
            )
            resp = data.get("response", {})
            entries.extend(resp.get("entries", []))
            if page >= resp.get("totalPages", 1):
                break
            page += 1
        return entries

    # ── zones ──────────────────────────────────────────────────────────────────

    def list_zones(self) -> list[dict]:
        data = self._get("/api/zones/list")
        return data.get("response", {}).get("zones", [])

    def add_zone(self, domain: str):
        return self._post("/api/zones/add", zone=domain, type="Primary")

    def delete_zone(self, domain: str):
        return self._post("/api/zones/delete", zone=domain)

    def add_a_record(self, domain: str, ip: str):
        return self._post("/api/zones/records/add",
            domain=domain,
            type="A",
            ipAddress=ip,
            ttl=60,
            comments=ZONE_TAG,
        )

    def bravaproxy_zones(self) -> list[str]:
        """Return zone names that BravaProxy owns (tagged in comments)."""
        zones = []
        for z in self.list_zones():
            name = z.get("name", "")
            # Check for our tag in any A record for this zone
            try:
                records = self._get("/api/zones/records/get", domain=name, type="A")
                for rec in records.get("response", {}).get("records", []):
                    if ZONE_TAG in rec.get("rData", {}).get("comments", ""):
                        zones.append(name)
                        break
            except Exception:
                pass
        return zones


# ── commands ──────────────────────────────────────────────────────────────────

def cmd_discover(hours: int = 48):
    if not BRAVA_OVEN_IP:
        print("Set BRAVA_OVEN_IP in .env")
        sys.exit(1)

    print(f"Querying Technitium logs for {BRAVA_OVEN_IP} (last {hours}h)…")
    client = TechnitiumClient()
    entries = client.query_log(BRAVA_OVEN_IP, hours=hours)

    if not entries:
        print("No log entries found. Make sure query logging is enabled in Technitium.")
        return

    seen: dict[str, int] = {}
    for e in entries:
        name = e.get("question", {}).get("name", "").rstrip(".")
        if name:
            seen[name] = seen.get(name, 0) + 1

    print(f"\n{'DOMAIN':<55} {'QUERIES':>7}")
    print("-" * 65)
    for domain, count in sorted(seen.items(), key=lambda x: -x[1]):
        marker = "  ← BRAVA" if "brava" in domain.lower() else ""
        print(f"{domain:<55} {count:>7}{marker}")

    brava_domains = [d for d in seen if "brava" in d.lower()]
    print(f"\n{len(brava_domains)} Brava domain(s) found.")
    if brava_domains:
        print("Run:  python tools/technitium.py override   to redirect them to the proxy.")


def cmd_override(dry_run: bool = False):
    if not PROXY_IP:
        print("Set PROXY_IP in .env to the LAN IP of the machine running mitmproxy.")
        sys.exit(1)

    client = TechnitiumClient()
    entries = client.query_log(BRAVA_OVEN_IP, hours=48)

    seen = {e.get("question", {}).get("name", "").rstrip(".") for e in entries}
    brava_domains = sorted(d for d in seen if d and "brava" in d.lower())

    if not brava_domains:
        print("No Brava domains found in query log. Run 'discover' first.")
        return

    print(f"{'DRY RUN — ' if dry_run else ''}Adding overrides → {PROXY_IP}\n")
    for domain in brava_domains:
        print(f"  {domain}")
        if not dry_run:
            try:
                client.add_zone(domain)
            except Exception:
                pass  # zone may already exist
            client.add_a_record(domain, PROXY_IP)

    if dry_run:
        print("\n(no changes made — remove --dry-run to apply)")
    else:
        print(f"\nDone. {len(brava_domains)} zone(s) now redirect to {PROXY_IP}.")
        print("Start mitmproxy on port 443 (run as admin):")
        print("  mitmdump --listen-port 443 -s proxy/addon.py")


def cmd_list():
    client = TechnitiumClient()
    zones = client.bravaproxy_zones()
    if not zones:
        print("No BravaProxy-managed zones found.")
        return
    print(f"BravaProxy-managed zones ({len(zones)}):")
    for z in zones:
        print(f"  {z}  →  {PROXY_IP}")


def cmd_remove():
    client = TechnitiumClient()
    zones = client.bravaproxy_zones()
    if not zones:
        print("Nothing to remove.")
        return
    print(f"Removing {len(zones)} zone(s)…")
    for z in zones:
        client.delete_zone(z)
        print(f"  deleted {z}")
    print("Done.")


# ── entry point ───────────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(0)

    cmd = args[0].lower()
    if cmd == "discover":
        cmd_discover()
    elif cmd == "override":
        cmd_override(dry_run="--dry-run" in args)
    elif cmd == "list":
        cmd_list()
    elif cmd == "remove":
        cmd_remove()
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
