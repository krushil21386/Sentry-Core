"""
SENTRY-CORE storage layer.
SQLite, single-file DB, zero external dependencies.
"""
import sqlite3
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path(__file__).parent / "sentry.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip TEXT NOT NULL,
    event_type TEXT NOT NULL,      -- e.g. 'ssh_failed_login', 'ssh_success'
    raw_line TEXT NOT NULL,
    timestamp TEXT NOT NULL        -- ISO 8601
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name TEXT NOT NULL,       -- e.g. 'ssh_bruteforce'
    source_ip TEXT NOT NULL,
    severity TEXT NOT NULL,        -- low/medium/high
    detail TEXT NOT NULL,
    event_count INTEGER NOT NULL,  -- how many events triggered this
    window_seconds INTEGER NOT NULL,
    timestamp TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_ip_time ON events (source_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts (timestamp);
"""


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)


def insert_event(source_ip: str, event_type: str, raw_line: str, timestamp: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO events (source_ip, event_type, raw_line, timestamp) VALUES (?, ?, ?, ?)",
            (source_ip, event_type, raw_line, timestamp),
        )


def insert_alert(rule_name: str, source_ip: str, severity: str, detail: str,
                  event_count: int, window_seconds: int, timestamp: str):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO alerts
               (rule_name, source_ip, severity, detail, event_count, window_seconds, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (rule_name, source_ip, severity, detail, event_count, window_seconds, timestamp),
        )


def recent_alert_exists(rule_name: str, source_ip: str, since_timestamp: str) -> bool:
    """Check if this rule already fired for this IP within the window (avoids alert spam)."""
    with get_conn() as conn:
        row = conn.execute(
            """SELECT 1 FROM alerts
               WHERE rule_name = ? AND source_ip = ? AND timestamp >= ?
               LIMIT 1""",
            (rule_name, source_ip, since_timestamp),
        ).fetchone()
        return row is not None


def recent_failed_logins(source_ip: str, since_timestamp: str):
    """All failed SSH login events for an IP since a given ISO timestamp."""
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT * FROM events
               WHERE source_ip = ? AND event_type = 'ssh_failed_login' AND timestamp >= ?
               ORDER BY timestamp ASC""",
            (source_ip, since_timestamp),
        ).fetchall()
        return [dict(r) for r in rows]


def recent_firewall_blocks(source_ip: str, since_timestamp: str):
    """All firewall_block events for an IP since a given ISO timestamp."""
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT * FROM events
               WHERE source_ip = ? AND event_type = 'firewall_block' AND timestamp >= ?
               ORDER BY timestamp ASC""",
            (source_ip, since_timestamp),
        ).fetchall()
        return [dict(r) for r in rows]


if __name__ == "__main__":
    init_db()
    print(f"Initialized DB at {DB_PATH}")
