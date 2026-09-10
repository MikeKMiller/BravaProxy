"""
BravaProxy capture addon for mitmproxy.

Run with:
    mitmweb -s proxy/addon.py                  # web UI + capture
    mitmdump -s proxy/addon.py                 # headless capture
    mitmproxy --mode transparent -s proxy/addon.py  # transparent (Linux/iptables)

All traffic is written to capture.db (SQLite) in the project root.
Brava-related requests are highlighted in the console.
WebSocket frames are captured separately — live cook status almost certainly
arrives over a WebSocket connection.
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from mitmproxy import ctx, http, websocket

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

            CREATE TABLE IF NOT EXISTS ws_frames (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts        TEXT    NOT NULL,
                host      TEXT    NOT NULL,
                url       TEXT    NOT NULL,
                direction TEXT    NOT NULL,  -- 'client' or 'server'
                content   BLOB,
                is_brava  INTEGER DEFAULT 0
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
            CREATE INDEX IF NOT EXISTS idx_ws_host           ON ws_frames(host);
            CREATE INDEX IF NOT EXISTS idx_ws_is_brava       ON ws_frames(is_brava);
        """)
        self.db.commit()

    def _is_brava(self, host: str) -> bool:
        h = host.lower()
        return any(kw in h for kw in BRAVA_KEYWORDS)

    def _track_domain(self, host: str, ts: str, is_brava: bool):
        self.db.execute("""
            INSERT INTO domains (domain, first_seen, is_brava)
                VALUES (?, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET
                request_count = request_count + 1
        """, (host, ts, 1 if is_brava else 0))

    # ── HTTP ──────────────────────────────────────────────────────────────────

    def response(self, flow: http.HTTPFlow):
        host = flow.request.pretty_host
        is_brava = self._is_brava(host)
        ts = datetime.now(timezone.utc).isoformat()

        self._track_domain(host, ts, is_brava)

        if is_brava:
            ct = flow.response.headers.get("content-type", "")
            size = len(flow.response.content)
            ctx.log.info(
                f"[BRAVA HTTP] {flow.request.method:6s} {flow.response.status_code} "
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

    # ── WebSocket ─────────────────────────────────────────────────────────────

    def websocket_start(self, flow: http.HTTPFlow):
        host = flow.request.pretty_host
        is_brava = self._is_brava(host)
        if is_brava:
            ctx.log.info(f"[BRAVA WS ] OPEN  {flow.request.pretty_url}")

    def websocket_message(self, flow: http.HTTPFlow):
        host = flow.request.pretty_host
        is_brava = self._is_brava(host)
        ts = datetime.now(timezone.utc).isoformat()
        msg = flow.websocket.messages[-1]
        direction = "client" if msg.from_client else "server"

        self._track_domain(host, ts, is_brava)

        if is_brava:
            preview = _ws_preview(msg.content)
            ctx.log.info(f"[BRAVA WS ] {direction.upper():6s}  {flow.request.pretty_url}  {preview}")

        self.db.execute("""
            INSERT INTO ws_frames (ts, host, url, direction, content, is_brava)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            ts,
            host,
            flow.request.pretty_url,
            direction,
            msg.content,
            1 if is_brava else 0,
        ))
        self.db.commit()

    def websocket_end(self, flow: http.HTTPFlow):
        host = flow.request.pretty_host
        if self._is_brava(host):
            ctx.log.info(f"[BRAVA WS ] CLOSE {flow.request.pretty_url}")


def _ws_preview(content: bytes | str, max_len: int = 120) -> str:
    if isinstance(content, bytes):
        try:
            content = content.decode("utf-8")
        except Exception:
            return f"<binary {len(content)}B>"
    try:
        parsed = json.loads(content)
        text = json.dumps(parsed)
    except Exception:
        text = content
    return text[:max_len] + ("…" if len(text) > max_len else "")


addons = [BravaCapture()]
