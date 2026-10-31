"""Incident lifecycle and correlation."""
from datetime import timedelta

from flask import current_app
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError

from ..extensions import db
from ..models import (INCIDENT_STATUSES, OPEN_STATUSES, SEVERITY_RANK, Incident, IncidentActivity,
                      IncidentEvent, SecurityEvent, utcnow)
from . import risk


def _activity(incident, kind, message, actor=None, when=None):
    db.session.add(IncidentActivity(incident=incident, kind=kind, message=message,
                                    actor_id=actor.id if actor else None, created_at=when or utcnow()))


def _link_evidence(incident, events, when) -> int:
    already = {row.event_id for row in IncidentEvent.query.filter_by(incident_id=incident.id)}
    added = 0
    for ev in events:
        if ev.id not in already:
            db.session.add(IncidentEvent(incident_id=incident.id, event_id=ev.id, linked_at=when))
            already.add(ev.id)
            added += 1
    return added


def raise_finding(finding, trigger_event) -> Incident:
    """Open a new incident, or attach new evidence to the open one with the same dedupe key."""
    when = trigger_event.occurred_at
    existing = Incident.query.filter(Incident.dedupe_key == finding.dedupe_key,
                                     Incident.status.in_(OPEN_STATUSES)).first()
    if existing is None:
        incident = Incident(
            title=finding.title, summary=finding.summary, severity=finding.severity,
            rule_id=finding.rule.id, mitre_tactic=finding.rule.tactic, mitre_technique=finding.rule.technique,
            user_id=finding.user.id if finding.user else None, subject=finding.subject,
            source_ip=finding.source_ip, dedupe_key=finding.dedupe_key,
            risk_score=risk.effective_score(finding.user, when) if finding.user else 0,
            opened_at=when, updated_at=when,
        )
        try:
            with db.session.begin_nested():       # SAVEPOINT: lets us survive a concurrent duplicate insert
                db.session.add(incident)
                db.session.flush()
        except IntegrityError:
            existing = Incident.query.filter(Incident.dedupe_key == finding.dedupe_key,
                                             Incident.status.in_(OPEN_STATUSES)).one()
        else:
            _link_evidence(incident, finding.evidence, when)
            _activity(incident, "opened", f"Opened by rule {finding.rule.id} ({finding.rule.name}).", when=when)
            return incident

    added = _link_evidence(existing, finding.evidence, when)
    if SEVERITY_RANK[finding.severity] > SEVERITY_RANK[existing.severity]:
        existing.severity = finding.severity
    if finding.user:
        existing.risk_score = max(existing.risk_score, risk.effective_score(finding.user, when))
    existing.summary = finding.summary
    existing.updated_at = max(when, existing.updated_at)
    if added:
        _activity(existing, "evidence_added", f"{added} more event(s) linked by {finding.rule.id}.", when=when)
    return existing


class InvalidTransition(ValueError):
    pass


def set_status(incident, new_status, actor, note=None, when=None) -> Incident:
    if new_status not in INCIDENT_STATUSES:
        raise InvalidTransition(f"Unknown status '{new_status}'.")
    when = when or utcnow()
    old = incident.status
    if new_status != old:
        incident.status = new_status
        incident.updated_at = when
        if new_status in OPEN_STATUSES:
            incident.resolved_at, incident.resolved_by_id = None, None
        else:
            incident.resolved_at, incident.resolved_by_id = when, actor.id
        try:
            with db.session.begin_nested():
                db.session.flush()
        except IntegrityError as exc:   # re-opening would duplicate another open incident with the same key
            raise InvalidTransition("Another open incident already exists for this subject and rule.") from exc
        _activity(incident, "status_changed", f"Status changed from {old} to {new_status}.", actor, when)
    if note:
        add_note(incident, actor, note, when)
    return incident


def add_note(incident, actor, text, when=None):
    when = when or utcnow()
    incident.updated_at = when
    _activity(incident, "note", text, actor, when)


def timeline(incident) -> dict:
    """Everything an analyst needs on one screen: linked evidence, un-linked context from the same
    user/IP around the incident, and the incident's own audit trail, merged chronologically."""
    linked = [row.event for row in incident.evidence]
    linked.sort(key=lambda e: (e.occurred_at, e.id))
    pad = timedelta(minutes=current_app.config["TIMELINE_CONTEXT_MINUTES"])
    start = (linked[0].occurred_at if linked else incident.opened_at) - pad
    end = (linked[-1].occurred_at if linked else incident.opened_at) + pad

    matchers = []
    if incident.user_id:
        matchers.append(SecurityEvent.user_id == incident.user_id)
    if incident.source_ip:
        matchers.append(SecurityEvent.source_ip == incident.source_ip)
    context = []
    if matchers:
        q = SecurityEvent.query.filter(SecurityEvent.occurred_at >= start, SecurityEvent.occurred_at <= end,
                                       or_(*matchers))
        if linked:
            q = q.filter(SecurityEvent.id.notin_([e.id for e in linked]))
        context = q.order_by(SecurityEvent.occurred_at, SecurityEvent.id).limit(200).all()

    items = [{"kind": "event", "linked": True, "time": e.to_dict()["timestamp"], "_t": e.occurred_at,
              "event": e.to_dict()} for e in linked]
    items += [{"kind": "event", "linked": False, "time": e.to_dict()["timestamp"], "_t": e.occurred_at,
               "event": e.to_dict()} for e in context]
    items += [{"kind": "activity", "linked": True, "time": a.to_dict()["timestamp"], "_t": a.created_at,
               "activity": a.to_dict()} for a in incident.activity]
    items.sort(key=lambda i: i["_t"])
    for i in items:
        del i["_t"]
    return {
        "incident": incident.to_dict(),
        "items": items,
        "stats": {"linkedEvents": len(linked), "contextEvents": len(context), "activities": len(incident.activity),
                  "firstSeen": items[0]["time"] if items else None, "lastSeen": items[-1]["time"] if items else None},
    }
