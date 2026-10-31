from app.models import SecurityEvent
from tests.conftest import IT, get_user


def test_login_success_returns_user_without_password_hash(anon):
    r = anon.login(IT)
    assert r.status_code == 200
    body = r.get_json()
    assert body["success"] is True and body["user"]["role"] == "IT"
    assert "password" not in body["user"]


def test_login_wrong_password_is_401(anon):
    r = anon.login(IT, "nope")
    assert r.status_code == 401 and r.get_json()["success"] is False


def test_login_unknown_user_gets_identical_response(anon):
    known = anon.login(IT, "nope").get_json()
    unknown = anon.login("ghost@oculus.com", "nope").get_json()
    assert known == unknown  # no username enumeration via response body


def test_failed_login_is_logged_with_source_ip(anon):
    anon.login(IT, "nope", ip="192.0.2.44")
    ev = SecurityEvent.query.one()
    assert (ev.event_type, ev.outcome, ev.source_ip) == ("login_failed", "failure", "192.0.2.44")


def test_login_handles_missing_or_non_string_json(anon):
    assert anon.client.post("/api/login").status_code == 401
    assert anon.client.post("/api/login", json={"username": 123, "password": ["x"]}).status_code == 401
