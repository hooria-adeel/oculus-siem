import hashlib
from datetime import timedelta

from flask import Blueprint, g, jsonify, request

from ..models import Resource, SecurityEvent, iso, utcnow
from ..security import login_required
from ..services.access import attempt_access

bp = Blueprint("access", __name__, url_prefix="/api")

SHARED_FOLDER = "Shared Drive"


def _file_meta(name: str) -> dict:
    """Stable, plausible size/modified-date for a file, derived from its name (no extra columns needed)."""
    h = int.from_bytes(hashlib.sha256(name.encode()).digest()[:4], "big")
    modified = utcnow() - timedelta(days=h % 45, hours=(h >> 8) % 24, minutes=(h >> 16) % 60)
    return {"sizeKb": 12 + h % 2400, "modifiedAt": iso(modified)}


def _folder(resource, allowed) -> str:
    """A file lives in its one owning department's folder; anything shared more widely (and every decoy) is in the Shared Drive."""
    owners = sorted(set(allowed) - {"Admin"})
    return owners[0] if len(owners) == 1 and not resource.is_honeypot else SHARED_FOLDER


@bp.post("/access")
@login_required
def access():
    """The caller is always the authenticated user; any username in the body is ignored."""
    data = request.get_json(silent=True) or {}
    name = data.get("resourceName")
    name = name if isinstance(name, str) else ""
    return jsonify(attempt_access(g.current_user, name, request.remote_addr, request.headers.get("User-Agent")))


@bp.get("/resources")
@login_required
def resources():
    """File listing for the employee workspace.

    Decoys are deliberately indistinguishable from real files: they sit in the shared drive and look openable.
    """
    role = g.current_user.role
    output = []
    for r in Resource.query.order_by(Resource.name):
        allowed = r.allowed_roles()
        output.append({
            "name": r.name,
            "description": r.description,
            "folder": _folder(r, allowed),
            "category": "accessible" if r.is_honeypot or role in allowed else "restricted",
            **_file_meta(r.name),
        })
    return jsonify(output)


@bp.get("/my/recent")
@login_required
def my_recent():
    """The caller's most recently opened files (distinct), newest first."""
    rows = (SecurityEvent.query
            .filter(SecurityEvent.user_id == g.current_user.id,
                    SecurityEvent.event_type.in_(("access_granted", "honeypot_access")))
            .order_by(SecurityEvent.id.desc()).limit(60).all())
    seen, recent = set(), []
    for e in rows:
        if e.resource_name and e.resource_name not in seen:
            seen.add(e.resource_name)
            recent.append({"name": e.resource_name, "openedAt": iso(e.occurred_at)})
        if len(recent) == 8:
            break
    return jsonify(recent)
