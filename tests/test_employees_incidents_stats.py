from app.extensions import db
from app.models import Incident, User

def make_incident(subject="x", status="open"):
    return Incident(title="t", severity="high", status=status, rule_id="R-TEST", subject=subject, dedupe_key=f"R-TEST:{subject}", risk_score=90)


NEW = {"fullName": "New Hire", "username": "new@oculus.com", "password": "Passw0rd!2026", "employeeId": "OC-2000", "role": "HR"}


def test_add_employee_hashes_password(admin):
    r = admin.post("/api/employees", json=NEW)
    assert r.status_code == 201
    stored = User.query.filter_by(username="new@oculus.com").one()
    assert stored.password_hash.startswith("$2") and stored.password_hash != "Passw0rd!2026"
    assert stored.risk_score == 0


def test_add_employee_requires_all_fields(admin):
    for missing in NEW:
        body = {k: v for k, v in NEW.items() if k != missing}
        assert admin.post("/api/employees", json=body).status_code == 400


def test_add_employee_rejects_duplicates(admin):
    assert admin.post("/api/employees", json=NEW).status_code == 201
    assert admin.post("/api/employees", json=NEW).status_code == 409
    dup_id = {**NEW, "username": "other@oculus.com"}
    assert admin.post("/api/employees", json=dup_id).status_code == 409


def test_list_employees_never_exposes_hashes(admin):
    users = admin.get("/api/employees").get_json()
    assert len(users) == 3
    assert all("password" not in u for u in users)


def test_employees_listing_includes_risk_and_last_login_for_admins(admin):
    users = {u["username"]: u for u in admin.get("/api/employees").get_json()}
    assert "riskScore" in users["it.user@oculus.com"] and "lastLoginAt" in users["it.user@oculus.com"]
    assert users["admin@oculus.com"]["lastLoginAt"] is not None        # the admin fixture just logged in
