from flask import Blueprint, g, jsonify, request

from ..extensions import db
from ..models import INCIDENT_STATUSES, OPEN_STATUSES, SEVERITIES, Incident
from ..security import admin_required
from ..services import incidents as svc
from ..services.detection import RULES

bp = Blueprint("incidents", __name__, url_prefix="/api")
TECHNIQUE_NAMES = {r.technique: r.technique_name for r in RULES}


def _dict(incident):
    return {**incident.to_dict(), "mitreTechniqueName": TECHNIQUE_NAMES.get(incident.mitre_technique)}


def _get_or_404(incident_id):
    incident = db.session.get(Incident, incident_id)
    if incident is None:
        return None, (jsonify({"success": False, "message": "Incident not found."}), 404)
    return incident, None


def _csv(name, allowed):
    raw = request.args.get(name, "")
    values = [v for v in (x.strip() for x in raw.split(",")) if v]
    return [v for v in values if v in allowed]


@bp.get("/incidents")
@admin_required
def list_incidents():
    q = Incident.query
    if statuses := _csv("status", INCIDENT_STATUSES):
        q = q.filter(Incident.status.in_(statuses))
    if severities := _csv("severity", SEVERITIES):
        q = q.filter(Incident.severity.in_(severities))
    limit = min(request.args.get("limit", 200, type=int), 500)
    return jsonify([_dict(i) for i in q.order_by(Incident.opened_at.desc(), Incident.id.desc()).limit(limit)])


@bp.get("/incidents/<int:incident_id>")
@admin_required
def get_incident(incident_id):
    incident, err = _get_or_404(incident_id)
    return err or jsonify(_dict(incident))


@bp.get("/incidents/<int:incident_id>/timeline")
@admin_required
def incident_timeline(incident_id):
    incident, err = _get_or_404(incident_id)
    return err or jsonify(svc.timeline(incident))


@bp.patch("/incidents/<int:incident_id>")
@admin_required
def update_incident(incident_id):
    incident, err = _get_or_404(incident_id)
    if err:
        return err
    data = request.get_json(silent=True) or {}
    note = data.get("note") if isinstance(data.get("note"), str) else None
    try:
        svc.set_status(incident, data.get("status", incident.status), g.current_user, note=(note or "").strip() or None)
    except svc.InvalidTransition as exc:
        db.session.rollback()
        return jsonify({"success": False, "message": str(exc)}), 409 if "already exists" in str(exc) else 400
    db.session.commit()
    return jsonify({"success": True, "incident": _dict(incident)})


@bp.post("/incidents/<int:incident_id>/notes")
@admin_required
def add_note(incident_id):
    incident, err = _get_or_404(incident_id)
    if err:
        return err
    text = (request.get_json(silent=True) or {}).get("note")
    if not isinstance(text, str) or not text.strip():
        return jsonify({"success": False, "message": "Note text is required."}), 400
    svc.add_note(incident, g.current_user, text.strip()[:2000])
    db.session.commit()
    return jsonify({"success": True, "incident": _dict(incident)}), 201


@bp.get("/rules")
@admin_required
def rules():
    counts = {rule_id: (total, active) for rule_id, total, active in db.session.query(
        Incident.rule_id, db.func.count(Incident.id),
        db.func.sum(db.case((Incident.status.in_(OPEN_STATUSES), 1), else_=0))).group_by(Incident.rule_id)}
    return jsonify([{**r.meta(), "incidents": counts.get(r.id, (0, 0))[0], "openIncidents": int(counts.get(r.id, (0, 0))[1] or 0)}
                    for r in RULES])
