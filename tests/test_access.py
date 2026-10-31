from app.models import Incident, SecurityEvent
from tests.conftest import IT, get_user



def access(api, resource):
    return api.post("/api/access", json={"resourceName": resource})


def test_authorized_access_returns_content_and_no_risk(it):
    body = access(it, "Firewall.config").get_json()
    assert body["authorized"] is True
    assert body["content"] == "rules"
    assert get_user(IT).risk_score == 0


def test_unauthorized_access_adds_20_and_hides_content(it):
    body = access(it, "Payroll.xlsx").get_json()
    assert body["authorized"] is False
    assert body["content"] is None
    assert get_user(IT).risk_score == 20
    assert "riskScore" not in body                         # an insider must not be able to read their own score


def test_honeypot_looks_like_a_normal_file_but_alerts_silently(it):
    body = access(it, "Admin_Passwords.txt").get_json()
    assert body["authorized"] is True and body["content"] == "x"       # decoy opens like any file
    assert body["warning"] is None and "riskScore" not in body
    assert "honeypot" not in str(body).lower() and "logged" not in str(body).lower()   # nothing tips the person off
    assert get_user(IT).risk_score == 50                               # ...but Security sees it
    ev = SecurityEvent.query.filter_by(resource_name="Admin_Passwords.txt").one()
    assert (ev.event_type, ev.outcome, ev.severity) == ("honeypot_access", "failure", "high")
    assert ev.details["riskPoints"] == 50


def test_missing_resource_does_not_change_risk(it):
    body = access(it, "Nope.txt").get_json()
    assert body["message"] == "File not found."
    assert get_user(IT).risk_score == 0


def test_honeypot_hit_opens_an_incident_immediately_and_only_once(it):
    access(it, "Admin_Passwords.txt")
    access(it, "Admin_Passwords.txt")
    honeypot = Incident.query.filter_by(rule_id="R-HP-001").one()   # one incident, not one per hit
    assert honeypot.subject == IT and honeypot.status == "open"
    assert len(honeypot.evidence) == 2                               # second hit attached as extra evidence
    assert {i.rule_id for i in Incident.query} == {"R-HP-001", "R-RISK-001"}   # 2 x 50 = 100 > 70


def test_risk_threshold_incident_fires_only_above_70(it):
    access(it, "Admin_Passwords.txt")   # 50
    access(it, "Payroll.xlsx")          # 70 -> not > 70
    assert {i.rule_id for i in Incident.query} == {"R-HP-001"}
    access(it, "Payroll.xlsx")          # 90 -> risk incident (only 2 denials, so no R-ACC-001)
    assert {i.rule_id for i in Incident.query} == {"R-HP-001", "R-RISK-001"}


def test_three_denials_in_window_opens_reconnaissance_incident(it):
    for _ in range(2):
        access(it, "Payroll.xlsx")
    assert Incident.query.filter_by(rule_id="R-ACC-001").count() == 0
    access(it, "Payroll.xlsx")
    assert Incident.query.filter_by(rule_id="R-ACC-001").one().severity == "medium"


def test_resource_listing_hides_which_files_are_decoys(it):
    files = {r["name"]: r for r in it.get("/api/resources").get_json()}
    assert files["Firewall.config"]["category"] == "accessible" and files["Firewall.config"]["folder"] == "IT"
    assert files["Payroll.xlsx"]["category"] == "restricted" and files["Payroll.xlsx"]["folder"] == "HR"
    decoy = files["Admin_Passwords.txt"]
    assert decoy["category"] == "accessible" and decoy["folder"] == "Shared Drive"     # indistinguishable from a real file
    assert all(k in decoy for k in ("sizeKb", "modifiedAt", "description"))
    assert not any("honeypot" in str(v).lower() for r in files.values() for v in r.values())


def test_file_metadata_is_stable_between_requests(it):
    first = {r["name"]: r["sizeKb"] for r in it.get("/api/resources").get_json()}
    second = {r["name"]: r["sizeKb"] for r in it.get("/api/resources").get_json()}
    assert first == second


def test_my_recent_lists_distinct_opened_files_newest_first(it):
    for name in ("Firewall.config", "Payroll.xlsx", "Admin_Passwords.txt", "Firewall.config"):
        access(it, name)
    names = [r["name"] for r in it.get("/api/my/recent").get_json()]
    assert names == ["Firewall.config", "Admin_Passwords.txt"]      # denied Payroll is not "opened"; no duplicates


def test_folder_is_the_single_owning_department_else_shared_drive(app, it):
    from app.extensions import db
    from app.models import Resource, ResourcePermission
    for name, roles in (("Own.txt", ("IT", "Admin")), ("Wide.pdf", ("IT", "HR", "Finance", "Admin")), ("OnlyAdmin.txt", ("Admin",))):
        r = Resource(name=name, description="d", content="c", is_honeypot=False)
        r.permissions = [ResourcePermission(role=x) for x in roles]
        db.session.add(r)
    db.session.commit()
    folders = {r["name"]: r["folder"] for r in it.get("/api/resources").get_json()}
    assert folders["Own.txt"] == "IT"                      # Admin is always allowed, so it must not be picked as the owner
    assert folders["Wide.pdf"] == folders["OnlyAdmin.txt"] == "Shared Drive"
