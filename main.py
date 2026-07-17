"""
SENTRY-CORE entry point.

Usage:
  python3 main.py --file /var/log/auth.log       # parse a static file once
  python3 main.py --tail /var/log/auth.log        # follow a live log
"""
import argparse
from datetime import datetime, timedelta
from detector import log_parser, rules
from storage import db


def process_event(event: dict):
    db.insert_event(
        source_ip=event["source_ip"],
        event_type=event["event_type"],
        raw_line=event["raw_line"],
        timestamp=event["timestamp"],
    )
    fired = rules.run_rules(event)
    for alert in fired:
        print(f"[ALERT] {alert['rule_name']} | {alert['detail']}")


def main():
    parser = argparse.ArgumentParser(description="SENTRY-CORE intrusion detection engine")
    parser.add_argument("--file", help="Parse a static log file once")
    parser.add_argument("--tail", help="Follow a live log file (like tail -f)")
    args = parser.parse_args()

    db.init_db()

    if args.file:
        for event in log_parser.parse_file(args.file):
            process_event(event)
        print("Done processing file.")
    elif args.tail:
        print(f"Watching {args.tail} for SSH login events... (Ctrl+C to stop)")
        for event in log_parser.tail_file(args.tail):
            process_event(event)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
