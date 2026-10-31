"""Aggregates that feed the SOC console dashboard."""
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from flask import Blueprint, jsonify, request
from sqlalchemy import func

from ..extensions import db
from ..models import OPEN_STATUSES, SEVERITIES, Incident, IncidentEvent, Resource, SecurityEvent, User, iso, utcnow
from ..security import admin_required
from ..services import risk
from ..services.detection import RULES

bp = Blueprint("overview", __name__, url_prefix="/api")

BUCKET_MINUTES = {1: 5, 6: 15, 24: 60, 168: 360}
TOP_ACCOUNTS = 5
ACCOUNT_BUCKETS = 12
TECHNIQUE_NAMES = {r.technique: r.technique_name for r in RULES}


def _techniques(start):
    """MITRE ATT&CK techniques seen in the window, weighted by how many events back each incident up."""
    rows = (db.session.query(Incident.id, Incident.mitre_technique, Incident.mitre_tactic, func.count(IncidentEvent.event_id))
            .outerjoin(IncidentEvent, IncidentEvent.incident_id == Incident.id)
            .filter(Incident.opened_at >= start, Incident.mitre_technique.isnot(None))
            .group_by(Incident.id, Incident.mitre_technique, Incident.mitre_tactic).all())
    agg = defaultdict(lambda: {"events": 0, "incidents": 0, "tactic": None})
    for _, technique, tactic, n in rows:
        a = agg[technique]
        a["events"] += max(n, 1); a["incidents"] += 1; a["tactic"] = tactic
    return sorted(({"id": t, "name": TECHNIQUE_NAMES.get(t, t), "tactic": v["tactic"], "events": v["events"], "incidents": v["incidents"]}
                   for t, v in agg.items()), key=lambda r: (-r["events"], r["id"]))


def _account_activity(start, now):
    """Accounts with the most security-relevant (non-info) events, plus their activity over time for a stacked bar."""
    rows = (db.session.query(SecurityEvent.username, SecurityEvent.occurred_at)
            .filter(SecurityEvent.occurred_at >= start, SecurityEvent.severity != "info").limit(100_000).all())
    totals = Counter(u for u, _ in rows)
    top = [u for u, _ in sorted(totals.items(), key=lambda kv: (-kv[1], kv[0]))[:TOP_ACCOUNTS]]
    size = (now - start) / ACCOUNT_BUCKETS
    series = {u: [0] * ACCOUNT_BUCKETS for u in top}
    other = [0] * ACCOUNT_BUCKETS
    for username, occurred_at in rows:
        i = max(0, min(int((occurred_at - start) / size), ACCOUNT_BUCKETS - 1))
        (series[username] if username in series else other)[i] += 1
    names = {u.username: u.full_name for u in User.query.filter(User.username.in_(top))} if top else {}
    out = [{"username": u, "label": names.get(u, u), "total": totals[u], "counts": series[u]} for u in top]
    if sum(other):
        out.append({"username": None, "label": "Other", "total": sum(other), "counts": other})
    return {"total": len(rows), "accounts": out, "buckets": [iso(start + i * size) for i in range(ACCOUNT_BUCKETS)]}


def _count(q, start, end):
    return q.filter(SecurityEvent.occurred_at >= start, SecurityEvent.occurred_at < end).count()


@bp.get("/overview")
@admin_required
def overview():
    hours = request.args.get("hours", 24, type=int)
    hours = hours if hours in BUCKET_MINUTES else 24
    now = utcnow()
    start, prev_start = now - timedelta(hours=hours), now - timedelta(hours=2 * hours)

    def kpi(event_type=None):
        base = SecurityEvent.query if event_type is None else SecurityEvent.query.filter_by(event_type=event_type)
        return {"value": _count(base, start, now + timedelta(seconds=1)), "previous": _count(base, prev_start, start)}

    # --- time series: stacked by severity, contiguous buckets (zeros included) so the chart has no gaps.
    # Buckets sit on clock boundaries (e.g. :00 for hourly) and the last one is the current, partial interval.
    size = timedelta(minutes=BUCKET_MINUTES[hours])
    n_buckets = int(timedelta(hours=hours) / size)
    size_s = int(size.total_seconds())
    floored = datetime.fromtimestamp(int(now.timestamp()) // size_s * size_s, tz=now.tzinfo)
    first = floored - (n_buckets - 1) * size
    buckets = [{"t": iso(first + i * size), **{s: 0 for s in SEVERITIES}} for i in range(n_buckets)]
    for occurred_at, severity in (db.session.query(SecurityEvent.occurred_at, SecurityEvent.severity)
                                  .filter(SecurityEvent.occurred_at >= first).limit(100_000)):
        idx = max(0, min(int((occurred_at - first) / size), n_buckets - 1))
        buckets[idx][severity] += 1

    # --- failed logins by source address
    sources = (db.session.query(SecurityEvent.source_ip, func.count(SecurityEvent.id),
                                func.count(func.distinct(SecurityEvent.username)))
               .filter(SecurityEvent.event_type == "login_failed", SecurityEvent.occurred_at >= start,
                       SecurityEvent.source_ip.isnot(None))
               .group_by(SecurityEvent.source_ip).order_by(func.count(SecurityEvent.id).desc()).limit(6).all())

    # --- people by effective (decayed) risk
    scored = sorted(((risk.effective_score(u), u) for u in User.query.filter(User.role != "Admin")),
                    key=lambda p: (-p[0], p[1].username))
    risk_users = [{"username": u.username, "fullName": u.full_name, "role": u.role, "riskScore": s}
                  for s, u in scored[:6] if s > 0]

    # --- incidents
    open_incidents = Incident.query.filter(Incident.status.in_(OPEN_STATUSES)).all()
    by_severity = Counter(i.severity for i in open_incidents)
    mitre = defaultdict(lambda: {"count": 0, "techniques": set()})
    for i in Incident.query.filter(Incident.opened_at >= start):
        if i.mitre_tactic:
            mitre[i.mitre_tactic]["count"] += 1
            mitre[i.mitre_tactic]["techniques"].add(i.mitre_technique)

    return jsonify({
        "window": {"hours": hours, "from": iso(start), "to": iso(now), "bucketMinutes": BUCKET_MINUTES[hours]},
        "kpis": {
            "events": kpi(), "failedLogins": kpi("login_failed"), "successfulLogins": kpi("login_success"),
            "honeypotHits": kpi("honeypot_access"), "deniedAccess": kpi("access_denied"),
            "openIncidents": {"value": len(open_incidents), "bySeverity": {s: by_severity.get(s, 0) for s in SEVERITIES}},
            "highRiskUsers": {"value": sum(1 for s, _ in scored if s > 70)},
        },
        "timeline": buckets,
        "topSources": [{"ip": ip, "failures": n, "accounts": accts} for ip, n, accts in sources],
        "riskUsers": risk_users,
        "mitre": sorted(({"tactic": t, "count": v["count"], "techniques": sorted(v["techniques"])}
                         for t, v in mitre.items()), key=lambda m: -m["count"]),
        "techniques": _techniques(start),
        "accountActivity": _account_activity(start, now),
        "latestEventId": db.session.query(func.max(SecurityEvent.id)).scalar() or 0,
    })


@bp.get("/honeypots")
@admin_required
def honeypots():
    """Deception inventory: every decoy, how often it was touched, and by whom last."""
    decoys = Resource.query.filter_by(is_honeypot=True).order_by(Resource.name).all()
    hits = defaultdict(list)
    for e in SecurityEvent.query.filter_by(event_type="honeypot_access").order_by(SecurityEvent.id.desc()):
        hits[e.resource_id].append(e)
    return jsonify(sorted((
        {"name": r.name, "description": r.description, "hits": len(hits[r.id]),
         "lastHitAt": iso(hits[r.id][0].occurred_at) if hits[r.id] else None,
         "lastUser": hits[r.id][0].username if hits[r.id] else None,
         "lastIp": hits[r.id][0].source_ip if hits[r.id] else None,
         "uniqueUsers": len({e.username for e in hits[r.id]})}
        for r in decoys), key=lambda d: (-d["hits"], d["name"])))
