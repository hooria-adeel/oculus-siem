"""Detection rules, tested deterministically by replaying events with explicit timestamps."""
import re
from datetime import datetime, timedelta, timezone

import pytest

from app.extensions import db
from app.models import EVENT_TYPES, Incident, Resource, User
from app.services import incidents as incident_svc
from app.services.detection import RULES
from app.services.ingest import record_event
from tests.conftest import ADMIN, HR, IT

T0 = datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc)
ATTACKER = "203.0.113.45"


def at(minutes):
    return T0 + timedelta(minutes=minutes)


def user(name):
    return User.query.filter_by(username=name).one()


def fail(username, minutes, ip=ATTACKER):
    return record_event("login_failed", user=User.query.filter_by(username=username).first(), username=username,
                        source_ip=ip, occurred_at=at(minutes))


def rule_ids(**filters):
    return sorted(i.rule_id for i in Incident.query.filter_by(**filters))


def deny(who, minutes, res="Payroll.xlsx"):
    return record_event("access_denied", user=user(who), resource=Resource.query.filter_by(name=res).one(),
                        occurred_at=at(minutes))


def honeypot(who, minutes):
    return record_event("honeypot_access", user=user(who),
                        resource=Resource.query.filter_by(name="Admin_Passwords.txt").one(), occurred_at=at(minutes))


class TestRuleCatalogue:
    def test_every_rule_is_mapped_to_a_valid_mitre_technique(self):
        for r in RULES:
            assert re.fullmatch(r"T\d{4}(\.\d{3})?", r.technique), r.id
            assert r.tactic and r.technique_name

    def test_rule_ids_are_unique_and_triggers_are_real_event_types(self):
        assert len({r.id for r in RULES}) == len(RULES)
        assert all(set(r.triggers) <= set(EVENT_TYPES) for r in RULES)


class TestBruteForce:  # T1110.001
    def test_fires_on_the_fifth_failure_not_before(self, app):
        for m in range(4):
            fail(IT, m)
        assert rule_ids() == []
        fail(IT, 4)
        inc = Incident.query.one()
        assert (inc.rule_id, inc.severity, inc.mitre_technique) == ("R-BF-001", "high", "T1110.001")
        assert len(inc.evidence) == 5 and inc.source_ip == ATTACKER

    def test_later_failures_extend_the_same_incident(self, app):
        for m in range(8):
            fail(IT, m)
        inc = Incident.query.one()
        assert len(inc.evidence) == 8
        assert [a.kind for a in inc.activity].count("opened") == 1

    def test_slow_guessing_outside_the_window_is_not_flagged(self, app):
        for m in (0, 4, 8, 12, 16):          # never 5 inside any 15-minute window
            fail(IT, m)
        assert rule_ids() == []

    def test_failures_from_different_addresses_do_not_add_up(self, app):
        for m in range(3):
            fail(IT, m, ip="203.0.113.1")
        for m in range(3, 6):
            fail(IT, m, ip="203.0.113.2")
        assert rule_ids() == []

    def test_unknown_account_is_not_a_brute_force_incident(self, app):
        for m in range(6):
            fail("ghost@oculus.com", m)
        assert rule_ids() == []


class TestPasswordSpraying:  # T1110.003
    def test_five_distinct_accounts_from_one_ip(self, app):
        names = ["a@x.com", "b@x.com", "c@x.com", "d@x.com"]
        for i, n in enumerate(names):
            fail(n, i)
        assert rule_ids() == []
        fail(IT, 4)
        inc = Incident.query.filter_by(rule_id="R-SPRAY-001").one()
        assert inc.subject == ATTACKER and inc.user_id is None and inc.mitre_technique == "T1110.003"
        assert len(inc.evidence) == 5

    def test_same_account_repeatedly_is_not_spraying(self, app):
        for m in range(4):
            fail(IT, m)
        assert Incident.query.filter_by(rule_id="R-SPRAY-001").count() == 0


class TestCredentialCompromise:  # T1078
    def test_success_after_three_failures_is_critical(self, app):
        for m in range(3):
            fail(IT, m)
        record_event("login_success", user=user(IT), source_ip=ATTACKER, occurred_at=at(4))
        inc = Incident.query.filter_by(rule_id="R-CRED-001").one()
        assert inc.severity == "critical" and len(inc.evidence) == 4   # 3 failures + the success

    def test_two_failures_then_success_is_just_a_typo(self, app):
        for m in range(2):
            fail(IT, m)
        record_event("login_success", user=user(IT), source_ip=ATTACKER, occurred_at=at(3))
        assert rule_ids() == []

    def test_success_from_a_different_address_is_not_correlated(self, app):
        for m in range(4):
            fail(IT, m)
        record_event("login_success", user=user(IT), source_ip="10.0.0.5", occurred_at=at(5))
        assert "R-CRED-001" not in rule_ids()


class TestHoneypot:  # T1083
    def test_single_touch_opens_high_severity_incident(self, app):
        honeypot(IT, 0)
        inc = Incident.query.filter_by(rule_id="R-HP-001").one()
        assert (inc.severity, inc.mitre_technique, inc.subject) == ("high", "T1083", IT)
        assert "Admin_Passwords.txt" in inc.summary

    def test_second_touch_by_another_user_is_a_separate_incident(self, app):
        honeypot(IT, 0)
        honeypot(HR, 1)
        assert Incident.query.filter_by(rule_id="R-HP-001").count() == 2


class TestRepeatedDenied:
    def test_three_within_thirty_minutes(self, app):
        deny(IT, 0), deny(IT, 10)
        assert Incident.query.filter_by(rule_id="R-ACC-001").count() == 0
        deny(IT, 20)
        assert Incident.query.filter_by(rule_id="R-ACC-001").one().severity == "medium"

    def test_spread_out_denials_are_not_flagged(self, app):
        for m in (0, 40, 80, 120):
            deny(IT, m)
        assert Incident.query.filter_by(rule_id="R-ACC-001").count() == 0


class TestRiskThresholdAndLifecycle:
    def test_risk_incident_after_crossing_70(self, app):
        honeypot(IT, 0)                       # 50
        deny(IT, 1)                           # 70 -> exactly 70 does not fire
        assert Incident.query.filter_by(rule_id="R-RISK-001").count() == 0
        deny(IT, 2)                           # 90
        assert Incident.query.filter_by(rule_id="R-RISK-001").one().risk_score == 90

    def test_resolved_incident_can_be_raised_again(self, app):
        """Regression: the original code never raised a second incident for a user once one existed."""
        honeypot(IT, 0), deny(IT, 1), deny(IT, 2)
        first = Incident.query.filter_by(rule_id="R-RISK-001").one()
        incident_svc.set_status(first, "resolved", user(ADMIN), when=at(3))
        db.session.commit()
        deny(IT, 4)
        assert Incident.query.filter_by(rule_id="R-RISK-001").count() == 2

    def test_severity_escalates_but_never_downgrades(self, app):
        deny(IT, 0), deny(IT, 1), deny(IT, 2)             # medium R-ACC-001
        inc = Incident.query.filter_by(rule_id="R-ACC-001").one()
        assert inc.severity == "medium"
        inc.severity = "high"
        deny(IT, 3)
        assert Incident.query.filter_by(rule_id="R-ACC-001").one().severity == "high"
