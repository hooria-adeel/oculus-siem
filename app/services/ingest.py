"""The single entry point for security telemetry.

Every login and every resource access goes through ``record_event``. It stores the event, applies insider-risk
points, then runs the detection engine, so no code path can log an event and forget to evaluate it.
"""
from datetime import datetime

from ..extensions import db
from ..models import SecurityEvent, utcnow
from . import risk
from .detection import engine

# event_type -> (outcome, severity, insider-risk points)
EVENT_META = {
    "login_success":   ("success", "info", 0),
    "login_failed":    ("failure", "low", 0),     # not scored: anyone can fail a login for someone else
    "login_blocked":   ("blocked", "medium", 0),
    "logout":          ("success", "info", 0),
    "access_granted":  ("success", "info", 0),
    "access_denied":   ("failure", "low", 20),
    "honeypot_access": ("failure", "high", 50),
}


def record_event(event_type: str, *, user=None, username: str | None = None, resource=None,
                 source_ip: str | None = None, user_agent: str | None = None, details: dict | None = None,
                 occurred_at: datetime | None = None, commit: bool = True) -> SecurityEvent:
    outcome, severity, points = EVENT_META[event_type]
    when = occurred_at or utcnow()

    event = SecurityEvent(
        occurred_at=when,
        event_type=event_type,
        severity=severity,
        outcome=outcome,
        user_id=user.id if user else None,
        username=(user.username if user else (username or "<invalid>"))[:100],
        source_ip=source_ip,
        user_agent=(user_agent or "")[:255] or None,
        resource_id=resource.id if resource else None,
        resource_name=resource.name if resource else None,
        details=details or {},
    )
    db.session.add(event)

    if user is not None and points:
        risk.add_points(user, points, when)
        event.details = {**event.details, "riskPoints": points, "riskAfter": user.risk_score}

    db.session.flush()           # event.id is needed by the rules that link evidence
    engine.evaluate(event)
    if commit:
        db.session.commit()
    return event
