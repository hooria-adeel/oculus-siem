import ipaddress

from flask import Blueprint, jsonify, request
from sqlalchemy import func, or_

from ..extensions import db
from ..models import EVENT_TYPES, OUTCOMES, SEVERITIES, SecurityEvent, utcnow
from ..security import admin_required
from datetime import timedelta

bp = Blueprint("events", __name__, url_prefix="/api")


def _csv(name, allowed):
    values = [v.strip() for v in request.args.get(name, "").split(",") if v.strip()]
    return [v for v in values if v in allowed]


@bp.get("/events")
@admin_required
def search_events():
    """Event explorer + live tail.

    Filters: q (free text over user / file / IP), type, outcome, severity (comma lists), user, ip, hours.
    Paging: ``before_id`` walks backwards through history; ``since_id`` returns only NEWER events (ascending),
    which is what the live view polls. ``id`` is the ingest sequence, so it orders events like time does.
    """
    q = SecurityEvent.query
    if types := _csv("type", EVENT_TYPES):
        q = q.filter(SecurityEvent.event_type.in_(types))
    if outcomes := _csv("outcome", OUTCOMES):
        q = q.filter(SecurityEvent.outcome.in_(outcomes))
    if severities := _csv("severity", SEVERITIES):
        q = q.filter(SecurityEvent.severity.in_(severities))
    if user := request.args.get("user", "").strip().lower():
        q = q.filter(SecurityEvent.username == user)
    if ip := request.args.get("ip", "").strip():
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({"success": False, "message": "Invalid IP address."}), 400
        q = q.filter(SecurityEvent.source_ip == ip)
    if hours := request.args.get("hours", type=int):
        q = q.filter(SecurityEvent.occurred_at >= utcnow() - timedelta(hours=min(hours, 24 * 30)))
    if text := request.args.get("q", "").strip()[:100]:
        like = f"%{text}%"
        q = q.filter(or_(SecurityEvent.username.ilike(like), SecurityEvent.resource_name.ilike(like),
                         db.cast(SecurityEvent.source_ip, db.String).ilike(like)))

    total = q.order_by(None).count()
    limit = max(1, min(request.args.get("limit", 100, type=int), 500))

    if since_id := request.args.get("since_id", type=int):
        rows = q.filter(SecurityEvent.id > since_id).order_by(SecurityEvent.id.asc()).limit(limit).all()
    else:
        if before_id := request.args.get("before_id", type=int):
            q = q.filter(SecurityEvent.id < before_id)
        rows = q.order_by(SecurityEvent.id.desc()).limit(limit).all()

    latest = db.session.query(func.max(SecurityEvent.id)).scalar() or 0
    return jsonify({"events": [e.to_dict() for e in rows], "total": total, "latestId": latest})
