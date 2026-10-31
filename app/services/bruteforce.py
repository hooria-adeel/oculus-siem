"""Login lockout (preventive control).

Detection of brute-force / spraying and the resulting incidents live in the rule engine
(services/detection/rules.py). This module only answers "should this login attempt even be tried?".
State is the security_events table itself, so it survives restarts and is auditable.
"""
import math
from datetime import timedelta

from flask import current_app

from ..models import SecurityEvent, utcnow


def _window() -> timedelta:
    return timedelta(minutes=current_app.config["LOGIN_WINDOW_MINUTES"])


def recent_failures(username=None, ip=None):
    q = SecurityEvent.query.filter(SecurityEvent.event_type == "login_failed",
                                   SecurityEvent.occurred_at >= utcnow() - _window())
    if username is not None:
        q = q.filter(SecurityEvent.username == username)
    if ip is not None:
        q = q.filter(SecurityEvent.source_ip == ip)
    return q.order_by(SecurityEvent.occurred_at, SecurityEvent.id).all()


def _seconds_until_slot_frees(events, limit) -> int:
    pivot = events[len(events) - limit]
    return max(1, math.ceil((pivot.occurred_at + _window() - utcnow()).total_seconds()))


def lockout_seconds(username: str, ip: str) -> int:
    """0 if the attempt may proceed, otherwise the Retry-After value in seconds."""
    cfg = current_app.config
    waits = []
    by_pair = recent_failures(username=username, ip=ip)
    if len(by_pair) >= cfg["LOGIN_MAX_FAILURES"]:
        waits.append(_seconds_until_slot_frees(by_pair, cfg["LOGIN_MAX_FAILURES"]))
    by_ip = recent_failures(ip=ip)
    if len(by_ip) >= cfg["LOGIN_IP_MAX_FAILURES"]:
        waits.append(_seconds_until_slot_frees(by_ip, cfg["LOGIN_IP_MAX_FAILURES"]))
    return max(waits) if waits else 0
