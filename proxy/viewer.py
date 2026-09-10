"""
BravaProxy capture viewer.

Usage:
    python proxy/viewer.py domains          # all seen domains, sorted by count
    python proxy/viewer.py brava            # Brava-only requests
    python proxy/viewer.py dump <id>        # full request+response for capture id
    python proxy/viewer.py json             # Brava responses with JSON bodies (pretty)
    python proxy/viewer.py urls             # unique Brava URL paths, sorted
"""

import json
import sqlite3
import sys
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "capture.db"


def connect():
    if not DB_PATH.exists():
        print(f"No database found at {DB_PATH}. Run mitmproxy with the addon first.")
        sys.exit(1)
    return sqlite3.connect(str(DB_PATH))


def cmd_domains(db):
    rows = db.execute("""
        SELECT domain, request_count, is_brava, first_seen
        FROM domains ORDER BY request_count DESC
    """).fetchall()
    print(f"{'DOMAIN':<50} {'COUNT':>6}  {'BRAVA':>5}  FIRST SEEN")
    print("-" * 80)
    for domain, count, is_brava, first_seen in rows:
        flag = "  [*]" if is_brava else ""
        print(f"{domain:<50} {count:>6}{flag}  {first_seen[:19]}")


def cmd_brava(db):
    rows = db.execute("""
        SELECT id, ts, method, status, url, content_type
        FROM captures WHERE is_brava = 1
        ORDER BY ts
    """).fetchall()
    print(f"{'ID':>6}  {'TIME':>19}  {'M':>6}  {'ST':>3}  {'CONTENT-TYPE':<30}  URL")
    print("-" * 120)
    for rid, ts, method, status, url, ct in rows:
        print(f"{rid:>6}  {ts[:19]}  {method:>6}  {status:>3}  {(ct or ''):<30}  {url}")


def cmd_dump(db, capture_id):
    row = db.execute("""
        SELECT method, url, status, req_headers, req_body, res_headers, res_body, content_type
        FROM captures WHERE id = ?
    """, (capture_id,)).fetchone()
    if not row:
        print(f"No capture with id {capture_id}")
        return
    method, url, status, req_h, req_b, res_h, res_b, ct = row

    print(f"\n{'='*80}")
    print(f"REQUEST  {method} {url}")
    print("─" * 80)
    for k, v in json.loads(req_h or "{}").items():
        print(f"  {k}: {v}")
    if req_b:
        body = _try_decode(req_b)
        print(f"\n{body}\n")

    print(f"\nRESPONSE  {status}  [{ct}]")
    print("─" * 80)
    for k, v in json.loads(res_h or "{}").items():
        print(f"  {k}: {v}")
    if res_b:
        body = _try_decode(res_b)
        if "json" in (ct or ""):
            try:
                body = json.dumps(json.loads(body), indent=2)
            except Exception:
                pass
        print(f"\n{body}\n")


def cmd_json(db):
    rows = db.execute("""
        SELECT id, url, status, res_body
        FROM captures
        WHERE is_brava = 1 AND content_type LIKE '%json%'
        ORDER BY ts
    """).fetchall()
    for rid, url, status, res_b in rows:
        print(f"\n{'='*80}")
        print(f"[{rid}] {status}  {url}")
        print("─" * 80)
        try:
            print(json.dumps(json.loads(_try_decode(res_b)), indent=2))
        except Exception:
            print(_try_decode(res_b))


def cmd_urls(db):
    rows = db.execute("""
        SELECT DISTINCT
            method,
            SUBSTR(url, INSTR(url, '://') + 3) AS path_part,
            COUNT(*) as cnt
        FROM captures WHERE is_brava = 1
        GROUP BY method, path_part
        ORDER BY path_part
    """).fetchall()
    for method, path, cnt in rows:
        print(f"{method:6s} ({cnt:>4}x)  {path}")


def _try_decode(data):
    if isinstance(data, bytes):
        try:
            return data.decode("utf-8")
        except Exception:
            return repr(data)
    return data or ""


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(0)

    db = connect()
    cmd = args[0].lower()

    if cmd == "domains":
        cmd_domains(db)
    elif cmd == "brava":
        cmd_brava(db)
    elif cmd == "dump" and len(args) > 1:
        cmd_dump(db, int(args[1]))
    elif cmd == "json":
        cmd_json(db)
    elif cmd == "urls":
        cmd_urls(db)
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
