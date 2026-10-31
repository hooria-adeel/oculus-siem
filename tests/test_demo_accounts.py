"""The demo sign-in helper must be invisible outside demo mode and must only expose fictional seeded accounts."""
from app.extensions import db
from app.models import User
from app.services.auth import hash_password


def add_demo_user():
    db.session.add(User(username="imran.shah@oculus.com", full_name="Imran Shah", employee_id="OC-9901",
                        role="Admin", password_hash=hash_password("x-Pass-1234")))
    db.session.commit()


def test_off_by_default_and_lists_nothing(anon):
    add_demo_user()
    body = anon.get("/api/demo-accounts").get_json()
    assert body == {"demo": False, "accounts": []}


def test_demo_mode_lists_only_accounts_that_exist(app, anon):
    app.config["DEMO_MODE"] = True
    assert anon.get("/api/demo-accounts").get_json()["accounts"] == []       # not seeded yet
    add_demo_user()
    accounts = anon.get("/api/demo-accounts").get_json()["accounts"]
    assert [a["username"] for a in accounts] == ["imran.shah@oculus.com"]
    assert accounts[0]["opens"] == "Oculus Console"


def test_demo_accounts_endpoint_needs_no_login_but_is_not_cached(app, anon):
    app.config["DEMO_MODE"] = True
    r = anon.get("/api/demo-accounts")
    assert r.status_code == 200 and "no-store" in r.headers["Cache-Control"]
