"""Endpoints that feed the SOC console: event search / live cursor, overview aggregates, deception inventory."""
from datetime import timedelta

from app.models import Resource, User, utcnow
from app.services.ingest import record_event
from tests.conftest import HR, IT

ATTACKER = "203.0.113.45"


def user(name):
    return User.query.filter_by(username=name).one()


def res(name):
    return Resource.query.filter_by(name=name).one()


def ago(minutes):
    return utcnow() - timedelta(minutes=minutes)


def events(api, query=""):
    return api.get(f"/api/events?{query}").get_json()


class TestEventSearch:
    def seed(self):
        record_event("login_success", user=user(IT), source_ip="10.0.0.5", occurred_at=ago(50))
        record_event("login_failed", username="ghost@oculus.com", source_ip=ATTACKER, occurred_at=ago(40))
        record_event("access_denied", user=user(HR), resource=res("Firewall.config"), source_ip="10.0.0.6", occurred_at=ago(30))
        record_event("honeypot_access", user=user(IT), resource=res("Admin_Passwords.txt"), source_ip="10.0.0.5", occurred_at=ago(20))

    def test_returns_newest_first_with_total_and_cursor(self, admin):
        self.seed()
        body = events(admin)
        types = [e["eventType"] for e in body["events"] if e["username"] != "admin@oculus.com"]
        assert types == ["honeypot_access", "access_denied", "login_failed", "login_success"]
        assert body["total"] >= 4 and body["latestId"] == body["events"][0]["id"]

    def test_filters_combine(self, admin):
        self.seed()
        assert [e["username"] for e in events(admin, "type=login_failed")["events"]] == ["ghost@oculus.com"]
        assert {e["eventType"] for e in events(admin, "severity=high")["events"]} == {"honeypot_access"}
        assert {e["outcome"] for e in events(admin, "outcome=failure")["events"]} == {"failure"}
        assert [e["eventType"] for e in events(admin, f"user={IT}&type=login_success,honeypot_access")["events"]] == \
               ["honeypot_access", "login_success"]
        assert [e["username"] for e in events(admin, f"ip={ATTACKER}")["events"]] == ["ghost@oculus.com"]

    def test_free_text_search_covers_user_file_and_ip(self, admin):
        self.seed()
        assert len(events(admin, "q=passwords")["events"]) == 1                       # file name, case-insensitive
        assert len(events(admin, "q=ghost")["events"]) == 1                           # username
        assert len(events(admin, "q=203.0.113")["events"]) == 1                       # partial IP

    def test_invalid_ip_is_a_400_not_a_database_error(self, admin):
        assert admin.get("/api/events?ip=not-an-ip").status_code == 400

    def test_unknown_filter_values_are_ignored(self, admin):
        self.seed()
        assert events(admin, "type=bogus")["total"] == events(admin)["total"]

    def test_time_window_filter(self, admin):
        self.seed()
        recent = events(admin, f"hours=1&type=login_success&user={IT}")
        assert recent["total"] == 1
        record_event("login_success", user=user(HR), occurred_at=utcnow() - timedelta(hours=5))
        assert events(admin, f"hours=1&type=login_success&user={HR}")["total"] == 0
        assert events(admin, f"hours=24&type=login_success&user={HR}")["total"] == 1

    def test_since_id_returns_only_newer_events_oldest_first(self, admin):
        self.seed()
        cursor = events(admin)["latestId"]
        assert events(admin, f"since_id={cursor}")["events"] == []                    # nothing new yet
        record_event("login_failed", username="a@oculus.com", source_ip=ATTACKER)
        record_event("login_failed", username="b@oculus.com", source_ip=ATTACKER)
        fresh = events(admin, f"since_id={cursor}")["events"]
        assert [e["username"] for e in fresh] == ["a@oculus.com", "b@oculus.com"]    # ascending: append in order

    def test_before_id_pages_backwards_without_overlap(self, admin):
        for i in range(25):
            record_event("access_granted", username=f"u{i}@oculus.com", commit=False)
        page1 = events(admin, "limit=10&type=access_granted")["events"]
        page2 = events(admin, f"limit=10&type=access_granted&before_id={page1[-1]['id']}")["events"]
        ids = [e["id"] for e in page1 + page2]
        assert len(ids) == len(set(ids)) == 20 and ids == sorted(ids, reverse=True)

    def test_limit_is_capped(self, admin):
        assert len(events(admin, "limit=100000")["events"]) <= 500


class TestOverview:
    def test_kpis_compare_window_with_previous_window(self, admin):
        for m in (10, 20, 30):
            record_event("login_failed", username="x@oculus.com", source_ip=ATTACKER, occurred_at=ago(m))
        record_event("login_failed", username="x@oculus.com", source_ip=ATTACKER, occurred_at=ago(60 * 25))   # previous 24h
        k = admin.get("/api/overview?hours=24").get_json()["kpis"]
        assert k["failedLogins"] == {"value": 3, "previous": 1}
        assert k["events"]["value"] >= 4

    def test_timeline_has_contiguous_buckets_that_add_up(self, admin):
        for m in (5, 6, 7):
            record_event("login_failed", username="x@oculus.com", source_ip=ATTACKER, occurred_at=ago(m))
        record_event("honeypot_access", user=user(IT), resource=res("Admin_Passwords.txt"), occurred_at=ago(8))
        body = admin.get("/api/overview?hours=1").get_json()
        assert body["window"]["bucketMinutes"] == 5 and len(body["timeline"]) == 12
        assert sum(b["low"] for b in body["timeline"]) == 3 and sum(b["high"] for b in body["timeline"]) == 1
        assert all(set(b) == {"t", "info", "low", "medium", "high", "critical"} for b in body["timeline"])

    def test_unsupported_window_falls_back_to_24h(self, admin):
        assert admin.get("/api/overview?hours=13").get_json()["window"]["hours"] == 24

    def test_top_sources_rank_failures_and_count_distinct_accounts(self, admin):
        for i in range(4):
            record_event("login_failed", username=f"user{i}@oculus.com", source_ip=ATTACKER, occurred_at=ago(i + 1))
        record_event("login_failed", username="solo@oculus.com", source_ip="198.51.100.9", occurred_at=ago(2))
        top = admin.get("/api/overview").get_json()["topSources"]
        assert top[0] == {"ip": ATTACKER, "failures": 4, "accounts": 4}
        assert top[1]["ip"] == "198.51.100.9"

    def test_open_incidents_by_severity_and_mitre_coverage(self, admin):
        record_event("honeypot_access", user=user(IT), resource=res("Admin_Passwords.txt"))
        body = admin.get("/api/overview").get_json()
        assert body["kpis"]["openIncidents"]["value"] == 1 and body["kpis"]["openIncidents"]["bySeverity"]["high"] >= 1
        assert {"tactic": "Discovery", "count": 1, "techniques": ["T1083"]} in body["mitre"]

    def test_risk_leaderboard_excludes_admins_and_zero_scores(self, admin):
        record_event("honeypot_access", user=user(IT), resource=res("Admin_Passwords.txt"))
        board = admin.get("/api/overview").get_json()["riskUsers"]
        assert [u["username"] for u in board] == [IT] and board[0]["riskScore"] == 50


class TestDeceptionAndRules:
    def test_honeypot_inventory_counts_hits_and_last_actor(self, admin):
        trap = res("Admin_Passwords.txt")
        record_event("honeypot_access", user=user(IT), resource=trap, source_ip="10.0.0.5", occurred_at=ago(30))
        record_event("honeypot_access", user=user(HR), resource=trap, source_ip="10.0.0.6", occurred_at=ago(5))
        [row] = admin.get("/api/honeypots").get_json()
        assert (row["name"], row["hits"], row["lastUser"], row["lastIp"], row["uniqueUsers"]) == \
               ("Admin_Passwords.txt", 2, HR, "10.0.0.6", 2)

    def test_untouched_decoy_is_listed_with_zero_hits(self, admin):
        [row] = admin.get("/api/honeypots").get_json()
        assert row["hits"] == 0 and row["lastHitAt"] is None

    def test_rules_endpoint_reports_incident_counts_per_rule(self, admin):
        record_event("honeypot_access", user=user(IT), resource=res("Admin_Passwords.txt"))
        rules = {r["id"]: r for r in admin.get("/api/rules").get_json()}
        assert rules["R-HP-001"]["incidents"] == 1 and rules["R-HP-001"]["openIncidents"] == 1
        assert rules["R-BF-001"]["incidents"] == 0


def test_timeline_buckets_sit_on_clock_boundaries(admin):
    from datetime import datetime
    for hours, minutes in ((1, 5), (6, 15), (24, 60), (168, 360)):
        stamps = [datetime.fromisoformat(b["t"].replace("Z", "+00:00")) for b in admin.get(f"/api/overview?hours={hours}").get_json()["timeline"]]
        assert all(t.second == 0 and (t.hour * 60 + t.minute) % minutes == 0 for t in stamps), hours
        assert all((b - a).total_seconds() == minutes * 60 for a, b in zip(stamps, stamps[1:]))
        assert len(stamps) * minutes == hours * 60


def test_overview_has_wazuh_style_aggregates(admin, it):
    for _ in range(6):
        it.post("/api/access", json={"resourceName": "Payroll.xlsx"})       # denied -> medium/low events + incidents
    it.post("/api/access", json={"resourceName": "Admin_Passwords.txt"})    # decoy -> honeypot incident
    o = admin.get("/api/overview?hours=24").get_json()
    assert o["kpis"]["successfulLogins"]["value"] >= 2                       # the admin and it fixtures signed in
    tech = {t["id"]: t for t in o["techniques"]}
    assert tech["T1083"]["name"] == "File and Directory Discovery" and tech["T1083"]["events"] >= 2
    acts = o["accountActivity"]
    assert acts["accounts"][0]["username"] == "it.user@oculus.com" and len(acts["buckets"]) == 12
    assert all(len(a["counts"]) == 12 for a in acts["accounts"])
    assert sum(sum(a["counts"]) for a in acts["accounts"]) == acts["total"]


def test_overview_aggregates_are_empty_not_missing_on_a_quiet_system(admin):
    o = admin.get("/api/overview?hours=1").get_json()
    assert o["techniques"] == [] and o["accountActivity"]["accounts"] == []
