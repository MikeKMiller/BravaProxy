"""
BravaProxy capture addon for mitmproxy.

Run with:
    mitmweb -s proxy/addon.py                  # web UI + capture
    mitmdump -s proxy/addon.py                 # headless capture
    mitmproxy --mode transparent -s proxy/addon.py  # transparent (Linux/iptables)

All traffic is written to capture.db (SQLite) in the project root.
Brava-related requests are highlighted in the console.
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from mitmproxy import ctx, http

DB_PATH = Path(__file__).parent.parent / "capture.db"

# Seed list — will grow automatically as we see new domains
BRAVA_KEYWORDS = ["brava"]


class BravaCapture:
    def __init__(self):
        self.db = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        self._init_db()
        ctx.log.info(f"BravaProxy: writing captures to {DB_PATH}")

    def _init_db(self):
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS captures (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                ts           TEXT    NOT NULL,
                host         TEXT    NOT NULL,
                method       TEXT    NOT NULL,
                url          TEXT    NOT NULL,
                status       INTEGER,
                req_headers  TEXT,
                req_body     BLOB,
                res_headers  TEXT,
                res_body     BLOB,
                content_type TEXT,
                is_brava     INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS domains (
                domain        TEXT PRIMARY KEY,
                first_seen    TEXT,
                request_count INTEGER DEFAULT 1,
                is_brava      INTEGER DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_captures_host     ON captures(host);
            CREATE INDEX IF NOT EXISTS idx_captures_is_brava ON captures(is_brava);
            CREATE INDEX IF NOT EXISTS idx_captures_ts       ON captures(ts);
        """)
        self.db.commit()

    def _is_brava(self, host: str) -> bool:
        h = host.lower()
        return any(kw in h for kw in BRAVA_KEYWORDS)

    def response(self, flow: http.HTTPFlow):
        host = flow.request.pretty_host
        is_brava = self._is_brava(host)
        ts = datetime.now(timezone.utc).isoformat()

        self.db.execute("""
            INSERT INTO domains (domain, first_seen, is_brava)
                VALUES (?, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET
                request_count = request_count + 1
        """, (host, ts, 1 if is_brava else 0))

        if is_brava:
            ct = flow.response.headers.get("content-type", "")
            size = len(flow.response.content)
            ctx.log.info(
                f"[BRAVA] {flow.request.method:6s} {flow.response.status_code} "
                f"{flow.request.pretty_url}  [{ct}  {size}B]"
            )

        self.db.execute("""
            INSERT INTO captures
                (ts, host, method, url, status,
                 req_headers, req_body,
                 res_headers, res_body,
                 content_type, is_brava)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ts,
            host,
            flow.request.method,
            flow.request.pretty_url,
            flow.response.status_code,
            json.dumps(dict(flow.request.headers)),
            flow.request.get_content(),
            json.dumps(dict(flow.response.headers)),
            flow.response.get_content(),
            flow.response.headers.get("content-type", ""),
            1 if is_brava else 0,
        ))
        self.db.commit()


addons = [BravaCapture()]
