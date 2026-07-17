import re
from datetime import datetime, timedelta, timezone

from storage import db

# --- Tunable thresholds ---
BRUTEFORCE_FAILED_ATTEMPTS = 5     # how many failed logins...
BRUTEFORCE_WINDOW_SECONDS = 60     # ...within this many seconds triggers an alert

PORTSCAN_DISTINCT_PORTS = 10       # how many distinct ports...
PORTSCAN_WINDOW_SECONDS = 10       # ...within this many seconds triggers an alert

UFW_PORT_RE = re.compile(r"DPT=(?P<port>\d+)")


def check_ssh_bruteforce(event: dict):
    """
    Called every time a new ssh_failed_login event comes in.
    Looks back BRUTEFORCE_WINDOW_SECONDS from now and counts failed
    attempts from the same source IP. If over threshold, raises an alert
    (and avoids raising a duplicate alert for the same burst).
    """
    if event["event_type"] != "ssh_failed_login":
        return None

    source_ip = event["source_ip"]
    now = datetime.now(timezone.utc)
    window_start = (now - timedelta(seconds=BRUTEFORCE_WINDOW_SECONDS)).isoformat()

    recent = db.recent_failed_logins(source_ip, window_start)
    already_alerted = db.recent_alert_exists("ssh_bruteforce", source_ip, window_start)

    if len(recent) >= BRUTEFORCE_FAILED_ATTEMPTS and not already_alerted:
        alert = {
            "rule_name": "ssh_bruteforce",
            "source_ip": source_ip,
            "severity": "high",
            "detail": f"{len(recent)} failed SSH logins from {source_ip} "
                      f"in {BRUTEFORCE_WINDOW_SECONDS}s (threshold: {BRUTEFORCE_FAILED_ATTEMPTS})",
            "event_count": len(recent),
            "window_seconds": BRUTEFORCE_WINDOW_SECONDS,
            "timestamp": now.isoformat(),
        }
        db.insert_alert(**alert)
        return alert

    return None


def check_port_scan(event: dict):
    """
    Called every time a new firewall_block event comes in.
    Looks back PORTSCAN_WINDOW_SECONDS and counts distinct destination ports probed
    by the same source IP. If over threshold, raises an alert.
    """
    if event["event_type"] != "firewall_block":
        return None

    source_ip = event["source_ip"]
    now = datetime.now(timezone.utc)
    window_start = (now - timedelta(seconds=PORTSCAN_WINDOW_SECONDS)).isoformat()

    recent = db.recent_firewall_blocks(source_ip, window_start)
    already_alerted = db.recent_alert_exists("port_scan", source_ip, window_start)

    if already_alerted:
        return None

    ports = set()
    for ev in recent:
        match = UFW_PORT_RE.search(ev["raw_line"])
        if match:
            ports.add(match.group("port"))

    if len(ports) >= PORTSCAN_DISTINCT_PORTS:
        alert = {
            "rule_name": "port_scan",
            "source_ip": source_ip,
            "severity": "medium",
            "detail": f"Port scan detected from {source_ip}: {len(ports)} distinct ports probed "
                      f"in {PORTSCAN_WINDOW_SECONDS}s (ports: {', '.join(sorted(ports))})",
            "event_count": len(recent),
            "window_seconds": PORTSCAN_WINDOW_SECONDS,
            "timestamp": now.isoformat(),
        }
        db.insert_alert(**alert)
        return alert

    return None


# Registry of all active rules — add new rules here as you build them
ACTIVE_RULES = [
    check_ssh_bruteforce,
    check_port_scan,
]


def run_rules(event: dict):
    """Run every active rule against a single event, return any alerts fired."""
    alerts = []
    for rule in ACTIVE_RULES:
        result = rule(event)
        if result:
            alerts.append(result)
    return alerts
