# SENTRY-CORE

Self-built Python intrusion detection engine. No third-party IDS in the
detection path — the parsing and detection logic here is hand-written.

## Phase 1 (done): SSH brute-force detection

- `detector/log_parser.py` — parses Linux SSH auth log lines into structured events
- `storage/db.py` — SQLite storage for raw events and fired alerts
- `detector/rules.py` — rule-based detection logic (currently: SSH brute-force)
- `main.py` — entry point, wires it all together

## Try it yourself

```bash
# Test against the included simulated attack log
python3 main.py --file test_auth.log

# On your actual lab VM, watch the real auth log live:
python3 main.py --tail /var/log/auth.log
```

Then from your Kali VM, run a real brute-force against the lab VM:

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<target-ip>
```

Watch SENTRY-CORE catch it in real time.

## Current detection rule

**SSH brute-force**: 5+ failed logins from the same source IP within 60
seconds triggers a `high` severity alert. Tunable in `detector/rules.py`.

Deduplication is built in — a burst of 20 failed logins fires exactly one
alert per 60-second window per IP, not 20 separate alerts.

## Next phases (not built yet)

- [ ] Port scan detection rule (Nmap-style scans against your lab)
- [ ] FastAPI layer exposing `/alerts`, `/stats`, `/attack-test`
- [ ] Claude API reporting layer — turns raw alerts into readable incident summaries
- [ ] Detection rate / false-positive rate measurement script, run against
      a batch of real + benign traffic, for resume-worthy numbers

## Validating against your home lab

Once your AD/pfSense lab is up, point `--tail` at each VM's auth log and
run real attacks (Hydra, Nmap) from Kali. Compare what SENTRY-CORE catches
against what Wazuh/Security Onion catches on the same traffic — that
comparison is your strongest resume talking point.
