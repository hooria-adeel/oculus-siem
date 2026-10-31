# Portfolio kit

Ready-to-use text for your CV, LinkedIn and interviews. Edit anything that is not true for you: everything below is
written from what the repository actually contains, and you should be able to defend every line.

## One-line description (GitHub "About" box)

SIEM with honeypot-based insider-threat detection: MITRE-mapped detections, correlated incidents, SOC-style console. Flask, PostgreSQL, JWT.

Suggested topics: `siem` `cybersecurity` `soc` `threat-detection` `honeypot` `insider-threat` `mitre-attack` `flask` `postgresql` `blue-team`

## CV bullets (pick 3-4)

* Built a SIEM with honeypot-based insider-threat detection (Flask, PostgreSQL 16, vanilla JS): a detection engine with
  6 rules mapped to MITRE ATT&CK, including a correlation rule, feeding an incident workflow with evidence timelines.
* Audited an existing student codebase, found it had **no authentication** (anonymous request could create an admin),
  stored XSS and no brute-force protection, then fixed each finding with a regression test (documented in `SECURITY_AUDIT.md`).
* Designed the PostgreSQL schema and Alembic migrations: `timestamptz`, `inet`, `jsonb`, CHECK constraints, and a partial
  unique index that guarantees one open incident per attack at the database level.
* Implemented JWT auth (httpOnly cookie plus CSRF double-submit, Bearer for API clients), lockout and password-spraying
  detection, and a strict CSP with no inline scripts and self-hosted assets.
* Built a Wazuh/Splunk-style analyst console (dashboard, incidents, event explorer, deception view; dark and light themes
  with colour-blind-checked chart palettes) and a separate office-style employee workspace.
* Wrote 168 tests (89% coverage) including API contract tests against an OpenAPI 3.1 spec, plus GitHub Actions CI
  running on SQLite and PostgreSQL; shipped Swagger UI and a generated Postman collection.

## LinkedIn post (draft)

I just finished a big upgrade of a project I started at university: **Oculus**, a small SIEM that catches insider threats
using decoy files.

The idea: an employee opens "Passwords.txt" in the shared drive. It looks and behaves like any other file. Behind the scenes
that single click opens a high-severity incident, with the evidence, a MITRE ATT&CK mapping and a timeline an analyst can
work from. The employee never sees a warning.

What I learned rebuilding it:
- The original had no authentication at all. I audited it like a pentester would, wrote down every finding, and fixed each
  one with a regression test.
- Detection logic needs to be deterministic. My rules evaluate relative to the event, so replayed history and live traffic
  give the same answer.
- Do not score failed logins as insider risk, or an attacker can frame a colleague by typing wrong passwords.
- Database constraints beat application checks: "one open incident per attack" is a unique index, not an if-statement.

Stack: Flask, PostgreSQL, JWT, vanilla JS, pytest, GitHub Actions. 168 tests, OpenAPI docs, a live attack simulator.

Code and screenshots: <link>

#cybersecurity #SOC #blueteam #SIEM #python #infosec

## Two-minute demo script (for a screen recording)

1. Open the login page. Click **Analyst** under Try the demo. (5 s)
2. Overview: point at the KPI strip, alerts evolution and the MITRE donut. In a second terminal run
   `flask --app run simulate`; the event stream starts moving. (30 s)
3. Wait for an attack. The Incidents badge increments. Open the new incident: evidence timeline, MITRE technique, then
   **Start investigating** and add a note. (40 s)
4. Switch to the light theme with the sun/moon button. (5 s)
5. In a private window, sign in as the **Employee**. Open Shared Drive and click a decoy file. It opens normally. (20 s)
6. Back in the Console: a honeypot incident appears. Say: "the employee saw nothing." (15 s)
7. Open `/api/docs` for two seconds. End. (5 s)

## Interview talking points

| Question | Honest, specific answer |
|---|---|
| What was your contribution? | Be specific: the audit and fixes, schema and migrations, detection engine, API and docs, tests and CI, both interfaces. If anyone else wrote part of the original course project, say so in one sentence. |
| Did you use AI? | Yes, and say how: you made the design decisions, Claude helped build and review, and you can explain and run every part (tests, detections, schema). Be ready to demonstrate that. |
| Hardest bug? | Pick a real one, for example rules that depended on the wall clock gave different results when replaying history; moving to event-relative evaluation fixed it. |
| Why not score failed logins? | Anyone can fail a login for someone else's account; scoring it lets an attacker frame a colleague. Brute force is an external signal, handled separately. |
| How do you avoid alert floods? | Deduplication: one open incident per `dedupe_key`, enforced by a partial unique index; later events attach as evidence. |
| What would you do next? | Streaming updates (SSE), rule tuning UI, MFA/SSO, load testing, shipping logs from real sources (syslog, Windows events). |
| What are the limits? | Demo scale, polling not push, rules in code, simulated data. Say it plainly; it reads as maturity. |

## Before you publish

* Replace `YOUR-USERNAME` in the README CI badge and check the **Origin** section reads true for you.
* Never commit `.env`. It is in `.gitignore`; check with `git status` before the first push.
* Demo credentials in the repo are fictional seeded accounts. Do not reuse those passwords anywhere real.
* Add 2-3 screenshots to the repository's social preview and pin the repo on your GitHub profile.
