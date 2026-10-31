from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.exc import IntegrityError, StatementError

from app.extensions import db
from app.models import Incident, SecurityEvent, User, utcnow
from app.services import risk
from tests.conftest import IT, get_user


def incident(**kw):
    base = dict(title="t", severity="high", rule_id="R-X", subject="s", risk_score=0, dedupe_key="k")
    return Incident(**{**base, **kw})


class TestDatabaseGuarantees:
    def test_check_constraint_rejects_unknown_role(self, app):
        db.session.add(User(username="x@x.com", password_hash="h", full_name="X", employee_id="E9", role="Wizard"))
        with pytest.raises(IntegrityError):
            db.session.commit()

    def test_risk_score_is_bounded(self, app):
        get_user(IT).risk_score = 101
        with pytest.raises(IntegrityError):
            db.session.commit()

    def test_only_one_open_incident_per_dedupe_key_is_enforced_by_the_database(self, app):
        db.session.add(incident())
        db.session.commit()
        db.session.add(incident())
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()

    def test_resolved_incidents_do_not_block_a_new_open_one(self, app):
        db.session.add(incident(status="resolved"))
        db.session.add(incident(status="open"))
        db.session.commit()
        assert Incident.query.count() == 2

    def test_deleting_a_user_keeps_the_audit_trail(self, app):
        from app.services.ingest import record_event
        record_event("login_success", user=get_user(IT), source_ip="10.0.0.1")
        db.session.delete(get_user(IT))
        db.session.commit()
        ev = SecurityEvent.query.one()
        assert ev.user_id is None and ev.username == IT          # evidence survives, link is nulled

    def test_naive_datetimes_are_refused(self, app):
        db.session.add(SecurityEvent(event_type="logout", outcome="success", username="u", occurred_at=datetime.now()))
        with pytest.raises((ValueError, StatementError)):
            db.session.commit()

    def test_datetimes_round_trip_as_aware_utc(self, app):
        db.session.add(SecurityEvent(event_type="logout", outcome="success", username="u", occurred_at=utcnow()))
        db.session.commit()
        db.session.expire_all()
        assert SecurityEvent.query.one().occurred_at.tzinfo == timezone.utc


class TestRiskDecay:
    def test_score_fades_by_configured_points_per_day(self, app):
        u = get_user(IT)
        now = utcnow()
        u.risk_score, u.risk_updated_at = 60, now - timedelta(days=3)
        assert risk.effective_score(u, now) == 60 - 3 * app.config["RISK_DECAY_PER_DAY"]

    def test_never_negative(self, app):
        u = get_user(IT)
        u.risk_score, u.risk_updated_at = 10, utcnow() - timedelta(days=60)
        assert risk.effective_score(u) == 0

    def test_adding_points_materialises_decay_first_and_clamps_at_100(self, app):
        u = get_user(IT)
        now = utcnow()
        u.risk_score, u.risk_updated_at = 90, now - timedelta(days=2)
        assert risk.add_points(u, 50, now) == 100            # (90-10)+50 = 130 -> clamped
        assert risk.add_points(u, 5, now) == 100

    def test_api_exposes_decayed_score(self, app, admin):
        u = get_user(IT)
        u.risk_score, u.risk_updated_at = 50, utcnow() - timedelta(days=4)
        db.session.commit()
        score = {e["username"]: e["riskScore"] for e in admin.get("/api/employees").get_json()}[IT]
        assert score == 50 - 4 * app.config["RISK_DECAY_PER_DAY"]
