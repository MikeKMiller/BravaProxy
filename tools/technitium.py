"""
Technitium DNS helper for BravaProxy.

Discovers what domains the Brava oven resolves, then adds/removes DNS
override zones that redirect those domains to the local proxy machine.

Usage:
    python tools/technitium.py analyze [csv]         # summarize discovered domains + purpose
    python tools/technitium.py override [--dry-run]  # add DNS overrides → proxy
    python tools/technitium.py list                  # show active BravaProxy zones
    python tools/technitium.py remove                # remove all BravaProxy zones
    python tools/technitium.py discover              # live query via Technitium API

CSV source:   brava_query_logs.csv  (exported from Technitium)
API source:   .env credentials      (used by 'discover' and 'override')

Reads config from .env (see .env.example).
"""

import csv
import os
import sys
from collections import defaultdict
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

ZONE_TAG  = "bravaproxy"
CSV_PATH  = Path(__file__).parent.parent / "brava_query_logs.csv"

# Known domain purposes — updated as we learn more
DOMAIN_NOTES = {
    "auth.brava.com":      "Authentication / OAuth tokens",
    "prefs.brava.com":     "Preferences & settings sync",
    "devicenet.brava.com": "Device networking - likely WebSocket for live cook status",
    "images.bravacontent.com": "Recipe image CDN",
    "logs.brava.com":      "Logging - already NxDomain (Brava shutting down)",
    "brava-files-oven-incoming-prod.s3-accelerate.amazonaws.com":
                           "S3 upload - firmware logs or diagnostics",
}

def _domain_note(domain: str) -> str:
    if domain in DOMAIN_NOTES:
        return DOMAIN_NOTES[domain]
    # api-NNNNN.brava.com pattern — device-specific API endpoint
    import re
    if re.match(r"api-\d+\.brava\.com", domain):
        return f"Device API endpoint (device ID: {domain.split('-')[1].split('.')[0]})"
    return ""


# ── CSV parsing ───────────────────────────────────────────────────────────────

def load_csv(path: Path = CSV_PATH) -> list[dict]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def domains_from_csv(rows: list[dict]) -> dict[str, dict]:
    """Return {domain: {count, resolved, nxdomain, answers}} from CSV rows."""
    result: dict[str, dict] = {}
    for row in rows:
        domain = row.get("Domain", "").rstrip(". ")
        if not domain:
            continue
        rcode = row.get("RCODE", "")
        answer = row.get("Answer", "")
        if domain not in result:
            result[domain] = {"count": 0, "resolved": 0, "nxdomain": 0, "answers": set()}
        result[domain]["count"] += 1
        if rcode == "NoError":
            result[domain]["resolved"] += 1
            for part in answer.split(","):
                part = part.strip()
                if part.startswith("A "):
                    result[domain]["answers"].add(part[2:])
        elif rcode == "NxDomain":
            result[domain]["nxdomain"] += 1
    return result


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

    def query_log(self, client_ip: str, hours: int = 48) -> list[dict]:
        start = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end   = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        entries, page = [], 1
        while True:
            data = self._get("/api/logs/query",
                pageNumber=page, entriesPerPage=1000,
                startDate=start, endDate=end, clientIpAddress=client_ip,
            )
            resp = data.get("response", {})
            entries.extend(resp.get("entries", []))
            if page >= resp.get("totalPages", 1):
                break
            page += 1
        return entries

    def list_zones(self) -> list[dict]:
        return self._get("/api/zones/list").get("response", {}).get("zones", [])

    def add_zone(self, domain: str):
        return self._post("/api/zones/add", zone=domain, type="Primary")

    def delete_zone(self, domain: str):
        return self._post("/api/zones/delete", zone=domain)

    def add_a_record(self, domain: str, ip: str):
        return self._post("/api/zones/records/add",
            domain=domain, type="A", ipAddress=ip, ttl=60, comments=ZONE_TAG,
        )

    def bravaproxy_zones(self) -> list[str]:
        zones = []
        for z in self.list_zones():
            name = z.get("name", "")
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

def cmd_analyze(csv_path: Path = CSV_PATH):
    rows = load_csv(csv_path)
    if not rows:
        print(f"No CSV found at {csv_path}. Export query logs from Technitium first.")
        sys.exit(1)

    domains = domains_from_csv(rows)
    brava   = {d: v for d, v in domains.items() if "brava" in d.lower() or "bravacontent" in d.lower()}
    other   = {d: v for d, v in domains.items() if d not in brava}

    print(f"\nBrava domains ({len(brava)}):")
    print("-" * 100)
    for domain, info in sorted(brava.items(), key=lambda x: -x[1]["count"]):
        status = "DOWN (NxDomain)" if info["nxdomain"] and not info["resolved"] else "OK"
        ips    = ", ".join(sorted(info["answers"])) or "-"
        note   = _domain_note(domain)
        print(f"  {'['+status+']':>16}  {domain}")
        if note:
            print(f"  {'':>16}  -> {note}")
        if ips != "-":
            print(f"  {'':>16}  -> IPs: {ips}")

    print(f"\nOther domains ({len(other)}):")
    print("-" * 100)
    for domain, info in sorted(other.items(), key=lambda x: -x[1]["count"]):
        print(f"  {info['count']:>4}x  {domain}")

    intercept = [d for d, v in brava.items() if v["resolved"] > 0]
    print(f"\n{len(intercept)} domain(s) to intercept (currently resolving):")
    for d in sorted(intercept):
        print(f"  {d}")
    print("\nRun:  python tools/technitium.py override   to add DNS overrides.")


def cmd_override(dry_run: bool = False):
    if not PROXY_IP:
        print("Set PROXY_IP in .env to the LAN IP of the machine running mitmproxy.")
        sys.exit(1)

    # Prefer CSV if available, fall back to live API
    rows = load_csv()
    if rows:
        domains_info = domains_from_csv(rows)
        brava_domains = sorted(
            d for d, v in domains_info.items()
            if ("brava" in d.lower() or "bravacontent" in d.lower())
            and v["resolved"] > 0  # only domains that actually resolve
            and "s3-accelerate" not in d  # skip AWS S3 — too broad to override safely
        )
        source = f"CSV ({CSV_PATH.name})"
    else:
        print("No CSV found, querying Technitium API…")
        client = TechnitiumClient()
        entries = client.query_log(BRAVA_OVEN_IP, hours=48)
        seen = {e.get("question", {}).get("name", "").rstrip(".") for e in entries}
        brava_domains = sorted(d for d in seen if d and "brava" in d.lower())
        source = "Technitium API"

    if not brava_domains:
        print("No resolvable Brava domains found.")
        return

    print(f"Source: {source}")
    print(f"{'DRY RUN — ' if dry_run else ''}Adding DNS overrides → {PROXY_IP}\n")

    client = TechnitiumClient() if not dry_run else None
    for domain in brava_domains:
        note = _domain_note(domain)
        print(f"  {domain}" + (f"  ({note})" if note else ""))
        if not dry_run:
            try:
                client.add_zone(domain)
            except Exception:
                pass
            client.add_a_record(domain, PROXY_IP)

    if dry_run:
        print("\n(no changes made — remove --dry-run to apply)")
    else:
        print(f"\nDone. {len(brava_domains)} zone(s) now redirect to {PROXY_IP}.")
        print("\nNext: start the appliance interceptor (run as Administrator):")
        print("  .\\start-appliance.ps1")


def cmd_discover():
    print(f"Querying Technitium logs for {BRAVA_OVEN_IP}…")
    client = TechnitiumClient()
    entries = client.query_log(BRAVA_OVEN_IP, hours=48)
    if not entries:
        print("No entries. Is query logging enabled in Technitium?")
        return
    seen: dict[str, int] = {}
    for e in entries:
        name = e.get("question", {}).get("name", "").rstrip(".")
        if name:
            seen[name] = seen.get(name, 0) + 1
    print(f"\n{'DOMAIN':<55} {'COUNT':>5}")
    print("-" * 65)
    for domain, count in sorted(seen.items(), key=lambda x: -x[1]):
        marker = "  <-" if "brava" in domain.lower() else ""
        print(f"{domain:<55} {count:>5}{marker}")


def cmd_list():
    client = TechnitiumClient()
    zones = client.bravaproxy_zones()
    if not zones:
        print("No BravaProxy-managed zones found.")
        return
    print(f"BravaProxy-managed zones ({len(zones)}) → {PROXY_IP}:")
    for z in sorted(zones):
        print(f"  {z}")


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
    if cmd == "analyze":
        csv_arg = Path(args[1]) if len(args) > 1 else CSV_PATH
        cmd_analyze(csv_arg)
    elif cmd == "override":
        cmd_override(dry_run="--dry-run" in args)
    elif cmd == "list":
        cmd_list()
    elif cmd == "remove":
        cmd_remove()
    elif cmd == "discover":
        cmd_discover()
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
