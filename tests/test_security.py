"""Security regression tests. Each class maps to a finding in the project audit."""
import time
from datetime import timedelta

import jwt
import pytest

from app.models import Incident, SecurityEvent, User
from tests.conftest import ADMIN, HR, IT, PASSWORD, Api, get_user

PROTECTED = [
    ("GET", "/api/me"), ("GET", "/api/resources"), ("GET", "/api/my/recent"), ("POST", "/api/access"),
    ("GET", "/api/employees"), ("POST", "/api/employees"),
    ("GET", "/api/events"), ("GET", "/api/incidents"), ("GET", "/api/incidents/1/timeline"),
    ("PATCH", "/api/incidents/1"), ("POST", "/api/incidents/1/notes"),
    ("GET", "/api/overview"), ("GET", "/api/honeypots"), ("GET", "/api/rules"),
]
ADMIN_ONLY = [p for p in PROTECTED if p[1] not in ("/api/me", "/api/resources", "/api/access", "/api/my/recent")]


class TestAuthenticationRequired:  # audit finding #1
    @pytest.mark.parametrize("method,url", PROTECTED)
    def test_anonymous_gets_401(self, anon, method, url):
        assert anon.request(method, url, json={}).status_code == 401


class TestRoleBasedAccess:  # audit finding #1/#2
    @pytest.mark.parametrize("method,url", ADMIN_ONLY)
    def test_non_admin_gets_403(self, it, method, url):
        assert it.request(method, url, json={}).status_code == 403

    def test_employee_cannot_mint_an_admin(self, it):
        r = it.post("/api/employees", json={"fullName": "Evil", "username": "evil", "password": "Passw0rd!x",
                                            "employeeId": "E1", "role": "Admin"})
        assert r.status_code == 403
        assert User.query.filter_by(username="evil").first() is None

    def test_admin_can_list_everything(self, admin):
        for url in ("/api/employees", "/api/events", "/api/incidents", "/api/overview", "/api/honeypots", "/api/rules"):
            assert admin.get(url).status_code == 200


class TestIdentityComesFromTheToken:  # audit finding #2
    def test_resources_ignore_spoofed_role_param(self, it):
        cats = {r["name"]: r["category"] for r in it.get("/api/resources?role=HR").get_json()}
        assert cats["Firewall.config"] == "accessible"   # IT's view, not HR's
        assert cats["Payroll.xlsx"] == "restricted"

    def test_access_ignores_username_in_body(self, it):
        it.post("/api/access", json={"username": HR, "resourceName": "Payroll.xlsx"})
        assert get_user(IT).risk_score == 20      # the caller was penalised...
        assert get_user(HR).risk_score == 0       # ...not the impersonated user
        assert SecurityEvent.query.filter_by(event_type="access_denied").one().username == IT

    def test_me_returns_caller(self, hr):
        body = hr.get("/api/me").get_json()
        assert body["username"] == HR and "password" not in body

    def test_employees_never_receive_their_own_risk_score(self, hr):
        assert "riskScore" not in hr.get("/api/me").get_json()
        assert "riskScore" not in hr.login(HR).get_json()["user"]


class TestTokenHandling:
    def test_login_sets_hardened_cookie_and_returns_token(self, anon):
        r = anon.login(IT)
        set_cookie = [h for h in r.headers.getlist("Set-Cookie") if h.startswith("oculus_token=")][0]
        assert "HttpOnly" in set_cookie and "SameSite=Strict" in set_cookie
        claims = jwt.decode(r.get_json()["token"], options={"verify_signature": False})
        assert claims["sub"] == IT and "exp" in claims and "password" not in claims

    def test_bearer_header_works_without_csrf(self, anon, it):
        fresh = it.app.test_client()
        r = fresh.get("/api/me", headers={"Authorization": f"Bearer {it.token}"})
        assert r.status_code == 200
        r = fresh.post("/api/access", json={"resourceName": "Firewall.config"},
                       headers={"Authorization": f"Bearer {it.token}"})
        assert r.status_code == 200

    def test_cookie_auth_post_requires_csrf_header(self, it):
        assert it.post("/api/access", json={"resourceName": "Firewall.config"}, csrf=False).status_code == 403
        assert it.post("/api/access", json={"resourceName": "Firewall.config"}).status_code == 200

    def test_wrong_csrf_value_rejected(self, it):
        r = it.post("/api/access", json={"resourceName": "Firewall.config"}, headers={"X-CSRF-Token": "forged"}, csrf=False)
        assert r.status_code == 403

    def test_tampered_token_rejected(self, it):
        bad = it.token[:-3] + ("AAA" if not it.token.endswith("AAA") else "BBB")
        r = it.app.test_client().get("/api/me", headers={"Authorization": f"Bearer {bad}"})
        assert r.status_code == 401

    def test_alg_none_token_rejected(self, it):
        forged = jwt.encode({"sub": ADMIN, "exp": int(time.time()) + 600}, key=None, algorithm="none")
        r = it.app.test_client().get("/api/employees", headers={"Authorization": f"Bearer {forged}"})
        assert r.status_code == 401

    def test_token_signed_with_wrong_key_rejected(self, it):
        forged = jwt.encode({"sub": ADMIN, "exp": int(time.time()) + 600}, "not-the-secret", algorithm="HS256")
        r = it.app.test_client().get("/api/employees", headers={"Authorization": f"Bearer {forged}"})
        assert r.status_code == 401

    def test_expired_token_rejected(self, it):
        expired = jwt.encode({"sub": IT, "exp": int(time.time()) - 5}, it.app.config["SECRET_KEY"], algorithm="HS256")
        assert it.app.test_client().get("/api/me", headers={"Authorization": f"Bearer {expired}"}).status_code == 401

    def test_token_for_deleted_user_rejected(self, app, it):
        from app.extensions import db
        db.session.delete(get_user(IT)); db.session.commit()
        assert it.get("/api/me").status_code == 401

    def test_logout_clears_cookie(self, it):
        assert it.post("/api/logout").status_code == 200
        assert it.get("/api/me").status_code == 401


class TestBruteForceProtection:  # audit finding #3
    def _fail(self, api, n, user=IT, ip="203.0.113.9"):
        return [api.login(user, "wrong-password", ip=ip) for _ in range(n)]

    def test_lockout_after_five_failures_even_with_correct_password(self, anon):
        assert [r.status_code for r in self._fail(anon, 5)] == [401] * 5
        blocked = anon.login(IT, PASSWORD, ip="203.0.113.9")
        assert blocked.status_code == 429
        assert int(blocked.headers["Retry-After"]) > 0

    def test_lockout_is_per_ip_so_victim_is_not_locked_out_everywhere(self, anon):
        self._fail(anon, 5, ip="203.0.113.9")
        assert anon.login(IT, PASSWORD, ip="198.51.100.7").status_code == 200

    def test_blocked_attempts_are_logged(self, anon):
        self._fail(anon, 6)
        types = [e.event_type for e in SecurityEvent.query.order_by(SecurityEvent.id)]
        assert types.count("login_failed") == 5 and types.count("login_blocked") == 1

    def test_brute_force_opens_one_incident_not_one_per_attempt(self, anon):
        self._fail(anon, 5)
        anon.login(IT, "x", ip="198.51.100.7")  # more failures from elsewhere
        self._fail(anon, 3, ip="198.51.100.7")
        incidents = Incident.query.filter_by(rule_id="R-BF-001").all()
        assert len(incidents) == 1 and incidents[0].subject == IT
        assert "203.0.113.9" in incidents[0].summary or "198.51.100.7" in incidents[0].summary

    def test_failed_logins_do_not_frame_the_victim(self, anon):  # audit finding #4
        self._fail(anon, 4)
        assert get_user(IT).risk_score == 0

    def test_unknown_usernames_are_logged_for_visibility(self, anon):
        anon.login("ghost@oculus.com", "x", ip="203.0.113.9")
        ev = SecurityEvent.query.one()
        assert (ev.username, ev.outcome, ev.user_id, ev.source_ip) == ("ghost@oculus.com", "failure", None, "203.0.113.9")

    def test_password_spraying_across_usernames_is_blocked_per_ip(self, anon):
        for i in range(20):
            anon.login(f"user{i}@oculus.com", "Summer2026!", ip="203.0.113.50")
        assert anon.login(IT, PASSWORD, ip="203.0.113.50").status_code == 429

    def test_failures_outside_window_do_not_count(self, app, anon):
        from app.extensions import db
        from app.models import utcnow
        self._fail(anon, 4)
        for e in SecurityEvent.query.all():
            e.occurred_at = utcnow() - timedelta(minutes=app.config["LOGIN_WINDOW_MINUTES"] + 1)
        db.session.commit()
        assert anon.login(IT, PASSWORD, ip="203.0.113.9").status_code == 200


class TestInputHardening:  # audit finding #5 (server side)
    def test_employee_fields_reject_markup(self, admin):
        r = admin.post("/api/employees", json={"fullName": "<img src=x onerror=alert(1)>", "username": "x@oculus.com",
                                               "password": "Passw0rd!x", "employeeId": "OC-5", "role": "IT"})
        assert r.status_code == 400

    def test_unknown_role_rejected(self, admin):
        r = admin.post("/api/employees", json={"fullName": "A B", "username": "ab@oculus.com",
                                               "password": "Passw0rd!x", "employeeId": "OC-6", "role": "SuperRoot"})
        assert r.status_code == 400

    def test_weak_password_rejected(self, admin):
        r = admin.post("/api/employees", json={"fullName": "A B", "username": "ab@oculus.com",
                                               "password": "123", "employeeId": "OC-6", "role": "IT"})
        assert r.status_code == 400

    def test_security_headers_present(self, anon):
        r = anon.get("/login.html")
        assert r.headers["X-Content-Type-Options"] == "nosniff"
        assert r.headers["X-Frame-Options"] == "DENY"
        assert "script-src 'self'" in r.headers["Content-Security-Policy"]
        assert "no-store" in anon.get("/api/me").headers["Cache-Control"]

    def test_timestamps_are_explicit_utc(self, admin):
        admin.login(ADMIN)
        ts = admin.get("/api/events").get_json()["events"][0]["timestamp"]
        assert ts.endswith("Z")


def test_production_refuses_default_secret_key(monkeypatch):
    from app import create_app
    from app.config import Config

    class Prod(Config):
        SECRET_KEY = "dev-only-insecure-key"
        SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
        DEBUG = False
        TESTING = False

    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        create_app(Prod)


def test_csp_is_strict_and_fully_self_hosted(anon):
    csp = anon.get("/login.html").headers["Content-Security-Policy"]
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert "https://" not in csp                      # fonts, icons and scripts all ship with the app
    assert "object-src 'none'" in csp and "frame-ancestors 'none'" in csp
