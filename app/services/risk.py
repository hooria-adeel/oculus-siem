"""Insider-risk scoring with time decay.

The stored ``risk_score`` is a snapshot taken at ``risk_updated_at``. The *effective* score is the snapshot
minus ``RISK_DECAY_PER_DAY`` points per elapsed day, so one bad afternoon does not brand an employee forever,
while repeated violations keep the score high. Decay is computed lazily on read: no background job needed.
"""
from datetime import datetime

from flask import current_app

from ..models import utcnow

MAX_SCORE = 100


def effective_score(user, now: datetime | None = None) -> int:
    now = now or utcnow()
    elapsed_days = max(0.0, (now - user.risk_updated_at).total_seconds() / 86400)
    decayed = int(elapsed_days * current_app.config["RISK_DECAY_PER_DAY"])
    return max(0, (user.risk_score or 0) - decayed)


def add_points(user, points: int, now: datetime | None = None) -> int:
    """Materialise decay up to `now`, add the points, clamp to 0..100. Returns the new effective score."""
    now = now or utcnow()
    user.risk_score = min(MAX_SCORE, effective_score(user, now) + points)
    user.risk_updated_at = max(now, user.risk_updated_at)
    return user.risk_score


def band(score: int) -> str:
    if score <= 30:
        return "low"
    if score <= 70:
        return "medium"
    return "high"


def warning_for(user) -> str:
    score = effective_score(user)
    if score <= 30:
        return f"Warning: {user.username}, please follow file access policy."
    if score <= current_app.config["RISK_INCIDENT_THRESHOLD"]:
        return f"Final Warning: {user.username}, repeated policy violations detected."
    return "This request was logged and reported to Security."
