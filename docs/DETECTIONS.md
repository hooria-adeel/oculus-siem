# Detection rules

Rules are small, stateless Python classes in `app/services/detection/rules.py`. Each one is tagged with a
[MITRE ATT&CK](https://attack.mitre.org/) technique and evaluated **from the event being processed, never from the
wall clock**, so the same code produces the same result live and when the demo seeder replays history.

Every event enters through `services/ingest.record_event()`, which stores it, applies insider-risk points, and runs the
rules whose `triggers` match. A finding either opens an incident or attaches new evidence to the open one with the same
`dedupe_key`.

| ID | Rule | Trigger | Severity | MITRE tactic | Technique | Logic (defaults) |
|----|------|---------|----------|--------------|-----------|------------------|
| R-BF-001 | Brute-force login attempts | `login_failed` | high | Credential Access | T1110.001 Password Guessing | ≥5 failures for one account from one IP within 15 min |
| R-SPRAY-001 | Password spraying | `login_failed` | high | Credential Access | T1110.003 Password Spraying | ≥5 distinct accounts failing from one IP within 15 min |
| R-CRED-001 | Login success after repeated failures | `login_success` | **critical** | Initial Access | T1078 Valid Accounts | success preceded by ≥3 failures, same account and IP: *correlation rule* |
| R-HP-001 | Honeypot resource accessed | `honeypot_access` | high | Discovery | T1083 File and Directory Discovery | any access to a decoy |
| R-ACC-001 | Repeated denied access | `access_denied` | medium | Discovery | T1083 File and Directory Discovery | ≥3 denials within 30 min |
| R-RISK-001 | Risk threshold exceeded | `access_denied`, `honeypot_access` | high | Collection | T1005 Data from Local System | effective insider-risk score > 70 |

Thresholds are configuration (`app/config.py`), not magic numbers.

## Design choices
* **Failed logins are not scored as insider risk.** Anyone can type a wrong password for someone else's account;
  scoring it would let an attacker frame a colleague. Brute force is an *external* signal handled by R-BF/R-SPRAY.
* **Preventive and detective controls are separate.** `services/bruteforce.py` decides whether a login attempt may even
  be tried (lockout, `429` + `Retry-After`); the rules decide what to *alert* on.
* **Risk decays** (5 points/day by default) so one bad afternoon doesn't brand an employee forever, while repeated violations keep the score high.
* **Deduplication is a database guarantee**, not application logic (see `DATABASE.md`).

## API
`GET /api/rules` lists the catalogue. `GET /api/incidents/<id>/timeline` returns the correlated view: linked evidence,
un-linked context events from the same account/IP around the incident, and the incident's audit trail, in time order.
