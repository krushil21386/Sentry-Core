"""
Parses Linux SSH auth logs (/var/log/auth.log on Debian/Ubuntu,
/var/log/secure on RHEL/CentOS) into structured events.

Handles the two lines that matter for brute-force detection:
  Failed password for root from 192.168.1.50 port 51422 ssh2
  Accepted password for alian from 192.168.1.10 port 51500 ssh2
"""
import re
from datetime import datetime, timezone
from pathlib import Path

FAILED_LOGIN_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port \d+"
)
SUCCESS_LOGIN_RE = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+) port \d+"
)
UFW_BLOCK_RE = re.compile(
    r"\[UFW BLOCK\].*SRC=(?P<ip>[\d.]+).*DPT=(?P<port>\d+)"
)


def parse_line(line: str):
    """
    Returns a dict {event_type, source_ip, user, raw_line, timestamp} or None
    if the line isn't an SSH login or firewall block event we care about.
    """
    failed = FAILED_LOGIN_RE.search(line)
    if failed:
        return {
            "event_type": "ssh_failed_login",
            "source_ip": failed.group("ip"),
            "user": failed.group("user"),
            "raw_line": line.strip(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    success = SUCCESS_LOGIN_RE.search(line)
    if success:
        return {
            "event_type": "ssh_success",
            "source_ip": success.group("ip"),
            "user": success.group("user"),
            "raw_line": line.strip(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    ufw_block = UFW_BLOCK_RE.search(line)
    if ufw_block:
        return {
            "event_type": "firewall_block",
            "source_ip": ufw_block.group("ip"),
            "raw_line": line.strip(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    return None


def parse_file(path: str):
    """Parse a static log file, yielding structured events. Good for testing."""
    with open(path, "r", errors="ignore") as f:
        for line in f:
            event = parse_line(line)
            if event:
                yield event


def tail_file(path: str):
    """
    Follow a log file live (like `tail -f`), yielding new events as they arrive.
    This is what you'll run against /var/log/auth.log on your lab VM.
    """
    with open(path, "r") as f:
        f.seek(0, 2)  # jump to end of file
        while True:
            line = f.readline()
            if not line:
                continue
            event = parse_line(line)
            if event:
                yield event


if __name__ == "__main__":
    # Quick manual test with fake log lines
    sample_lines = [
        "Jul 17 10:22:01 host sshd[1234]: Failed password for root from 192.168.1.50 port 51422 ssh2",
        "Jul 17 10:22:03 host sshd[1234]: Failed password for invalid user admin from 192.168.1.50 port 51423 ssh2",
        "Jul 17 10:22:10 host sshd[1234]: Accepted password for alian from 192.168.1.10 port 51500 ssh2",
        "Jul 17 10:22:15 host sshd[1234]: some unrelated log line",
    ]
    for line in sample_lines:
        result = parse_line(line)
        print(result)
