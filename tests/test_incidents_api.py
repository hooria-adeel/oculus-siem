from datetime import datetime, timedelta, timezone

from app.extensions import db
from app.models import Incident, IncidentActivity, Resource, User
from app.services.ingest import record_event
from tests.conftest import ADMIN, HR, IT

T0 = datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc)
ATTACKER = "203.0.113.45"


def at(m):
    return T0 + timedelta(minutes=m)


def make_brute_force_incident():
    it = User.query.filter_by(username=IT).one()
    for m in range(6):
        record_event("login_failed", user=it, username=IT, source_ip=ATTACKER, occurred_at=at(m))
    return Incident.query.filter_by(rule_id="R-BF-001").one()


class TestListing:
    def test_filters_by_status_and_severity(self, admin):
        make_brute_force_incident()
        record_event("honeypot_access", user=User.query.filter_by(username=HR).one(),
                     resource=Resource.query.filter_by(name="Admin_Passwords.txt").one(), occurred_at=at(30))
        everything = admin.get("/api/incidents").get_json()
        assert {i["ruleId"] for i in everything} == {"R-BF-001", "R-HP-001"}
        assert [i["ruleId"] for i in admin.get("/api/incidents?severity=high").get_json()].count("R-HP-001") == 1
        assert admin.get("/api/incidents?status=resolved").get_json() == []
        assert admin.get("/api/incidents?status=bogus").get_json() == everything   # unknown filter values ignored

    def test_incident_payload_has_analyst_fields(self, admin):
        make_brute_force_incident()
        i = admin.get("/api/incidents").get_json()[0]
        assert i["ref"] == f"INC-{i['id']:04d}"
        assert i["mitreTechnique"] == "T1110.001" and i["mitreTactic"] == "Credential Access"
        assert i["evidenceCount"] == 6 and i["openedAt"].endswith("Z")

    def test_rules_catalogue_endpoint(self, admin):
        rules = admin.get("/api/rules").get_json()
        assert len(rules) >= 6 and all(r["mitreTechnique"].startswith("T") for r in rules)


class TestTimelineCorrelation:
    def test_timeline_links_evidence_adds_context_and_excludes_strangers(self, admin):
        inc = make_brute_force_incident()
        # context: same account, later, from a different address (not linked, but relevant to an analyst)
        record_event("login_success", user=User.query.filter_by(username=IT).one(), source_ip="10.0.0.9",
                     occurred_at=at(20))
        # noise: a different user, same time -> must NOT appear
        record_event("access_granted", user=User.query.filter_by(username=HR).one(),
                     resource=Resource.query.filter_by(name="Payroll.xlsx").one(), source_ip="10.0.0.77", occurred_at=at(3))
        body = admin.get(f"/api/incidents/{inc.id}/timeline").get_json()
        events = [i for i in body["items"] if i["kind"] == "event"]
        assert body["stats"]["linkedEvents"] == 6 and body["stats"]["contextEvents"] == 1
        assert sum(1 for e in events if e["linked"]) == 6
        context = [e for e in events if not e["linked"]]
        assert context[0]["event"]["eventType"] == "login_success"
        assert all(e["event"]["username"] != HR for e in events)
        times = [i["time"] for i in body["items"]]
        assert times == sorted(times)                       # chronological
        assert any(i["kind"] == "activity" for i in body["items"])

    def test_timeline_of_unknown_incident_404(self, admin):
        assert admin.get("/api/incidents/999/timeline").status_code == 404


class TestWorkflow:
    def test_status_change_records_actor_and_note(self, admin):
        inc = make_brute_force_incident()
        r = admin.request("PATCH", f"/api/incidents/{inc.id}", json={"status": "investigating", "note": "Blocked the IP."})
        assert r.status_code == 200 and r.get_json()["incident"]["status"] == "investigating"
        kinds = [(a.kind, a.actor.username if a.actor else None) for a in IncidentActivity.query.filter_by(incident_id=inc.id)]
        assert ("status_changed", ADMIN) in kinds and ("note", ADMIN) in kinds

    def test_resolving_sets_resolver_and_timestamp(self, admin):
        inc = make_brute_force_incident()
        body = admin.request("PATCH", f"/api/incidents/{inc.id}", json={"status": "resolved"}).get_json()["incident"]
        assert body["resolvedBy"] == ADMIN and body["resolvedAt"].endswith("Z")

    def test_invalid_status_rejected(self, admin):
        inc = make_brute_force_incident()
        assert admin.request("PATCH", f"/api/incidents/{inc.id}", json={"status": "banana"}).status_code == 400

    def test_reopen_conflicts_with_a_newer_open_incident(self, admin):
        inc = make_brute_force_incident()
        admin.request("PATCH", f"/api/incidents/{inc.id}", json={"status": "resolved"})
        for m in range(30, 36):                           # attack resumes -> a NEW incident opens
            record_event("login_failed", user=User.query.filter_by(username=IT).one(), username=IT,
                         source_ip=ATTACKER, occurred_at=at(m))
        assert Incident.query.filter_by(rule_id="R-BF-001", status="open").count() == 1
        r = admin.request("PATCH", f"/api/incidents/{inc.id}", json={"status": "open"})
        assert r.status_code == 409
        assert db.session.get(Incident, inc.id).status == "resolved"

    def test_notes(self, admin):
        inc = make_brute_force_incident()
        assert admin.post(f"/api/incidents/{inc.id}/notes", json={"note": "  Looks malicious. "}).status_code == 201
        assert admin.post(f"/api/incidents/{inc.id}/notes", json={"note": "   "}).status_code == 400
        assert IncidentActivity.query.filter_by(incident_id=inc.id, kind="note").one().message == "Looks malicious."

    def test_non_admins_cannot_touch_incidents(self, it):
        inc = make_brute_force_incident()
        assert it.get(f"/api/incidents/{inc.id}/timeline").status_code == 403
        assert it.request("PATCH", f"/api/incidents/{inc.id}", json={"status": "resolved"}).status_code == 403
        assert it.post(f"/api/incidents/{inc.id}/notes", json={"note": "x"}).status_code == 403
