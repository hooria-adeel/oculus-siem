# Security audit & remediation log

The original university build worked functionally but had no real security boundary. This document records what an
audit of it found, how each issue was confirmed, how it was fixed, and which test now guards against regression.

| # | Finding | Impact (confirmed by running the app) | Fix | Regression test |
|---|---------|----------------------------------------|-----|-----------------|
| 1 | No authentication or authorisation on any endpoint | Anonymous `POST /api/employees` with `role: "Admin"` returned **201**; anyone could read all employees, logs and incidents | JWT auth on every route; `@admin_required` on admin routes | `TestAuthenticationRequired`, `TestRoleBasedAccess` |
| 2 | Client-supplied identity (`?role=`, `username` in body) | A user could request another role's view or have actions attributed to someone else | Identity is derived only from the verified token | `TestIdentityComesFromTheToken` |
| 3 | No brute-force protection | 30 consecutive wrong passwords all answered `401`; no lockout, no alert | Lockout per (username, IP) after 5 failures / 15 min; per-IP block at 20 (password spraying); one incident opened per attack; `Retry-After` header | `TestBruteForceProtection` |
| 4 | Failed logins raised the *target's* insider-risk score | An attacker could frame any colleague by typing wrong passwords for their username | Failed logins no longer feed the insider score; they raise a brute-force incident on the targeted account instead | `test_failed_logins_do_not_frame_the_victim` |
| 5 | Stored XSS (37 `innerHTML` sinks, unvalidated names, attacker-controlled usernames land in the log view) | Script execution in an admin's browser | No `innerHTML` anywhere (the UI is built with a DOM helper, so data can never become markup), server-side validation, strict CSP (`script-src 'self'`, no inline scripts, self-hosted fonts and icons) | `TestInputHardening`, browser E2E |
| 6 | Session was a plain object in `localStorage` | Forging the role in DevTools "authenticated" the UI | httpOnly + SameSite=Strict JWT cookie, CSRF double-submit token, `alg` pinned to HS256; `localStorage` is now only a non-authoritative UI cache | `TestTokenHandling` |
| 7 | Timestamps stored in server-local time and serialised without a zone | Events displayed hours off for users in other time zones; window queries unreliable | All timestamps UTC; API serialises with `Z` | `test_timestamps_are_explicit_utc` |
| 8 | DB password interpolated into the URL unquoted | Passwords containing `@ : /` broke the connection | URL-quoted credentials (verified against PostgreSQL with `p@ss:w/rd`) | manual + CI |
| 9 | Default secret key / secrets in repo | `.env` with credentials shipped in the zip | `.env` git-ignored; app refuses to start outside development with the default `SECRET_KEY` | `test_production_refuses_default_secret_key` |

## Known limitations (tracked for later phases)
* (Fixed in Phase 3: incident de-duplication is a database guarantee; risk scores decay.)
* Rate limiting is DB-backed per (username, IP); behind a reverse proxy, configure trusted proxy headers before relying on IP data.
