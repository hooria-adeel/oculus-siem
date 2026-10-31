from flask import Blueprint, current_app, g, jsonify, make_response, request

from ..models import User
from ..security import clear_auth_cookies, issue_token, login_required, set_auth_cookies
from ..services import bruteforce
from ..services.auth import authenticate
from ..services.ingest import record_event

bp = Blueprint("auth", __name__, url_prefix="/api")


def _client():
    return {"source_ip": request.remote_addr or "unknown", "user_agent": request.headers.get("User-Agent")}


@bp.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username") if isinstance(data.get("username"), str) else ""
    password = data.get("password") if isinstance(data.get("password"), str) else ""
    username = username[:100]
    client = _client()

    retry_after = bruteforce.lockout_seconds(username, client["source_ip"])
    if retry_after:
        record_event("login_blocked", username=username, details={"retryAfter": retry_after}, **client)
        resp = make_response(jsonify({"success": False,
                                      "message": f"Too many failed attempts. Try again in {retry_after} seconds."}), 429)
        resp.headers["Retry-After"] = str(retry_after)
        return resp

    user = authenticate(username, password)
    if user is None:
        # Unknown usernames are recorded too: a SIEM must see password spraying.
        record_event("login_failed", user=User.query.filter_by(username=username).first(),
                     username=username, **client)
        return jsonify({"success": False, "message": "Invalid credentials."}), 401

    record_event("login_success", user=user, **client)
    token, csrf = issue_token(user)
    resp = make_response(jsonify({"success": True, "user": user.to_dict(), "token": token}))
    return set_auth_cookies(resp, token, csrf)


@bp.post("/logout")
@login_required
def logout():
    record_event("logout", user=g.current_user, **_client())
    return clear_auth_cookies(make_response(jsonify({"success": True})))


@bp.get("/me")
@login_required
def me():
    return jsonify(g.current_user.to_dict())


DEMO_ACCOUNTS = (("imran.shah@oculus.com", "Analyst", "Oculus Console", "ADMIN_PASSWORD"),
                 ("ahmed.khan@oculus.com", "Employee", "Oculus Workspace", "DEMO_PASSWORD"))


@bp.get("/demo-accounts")
def demo_accounts():
    """Credentials for the fictional seeded users, so a visitor can try both interfaces in one click.

    Off unless DEMO_MODE is set, and only lists accounts that actually exist in this database."""
    if not current_app.config.get("DEMO_MODE"):
        return jsonify({"demo": False, "accounts": []})
    from .. import seed_data
    existing = {u.username for u in User.query.filter(User.username.in_([a[0] for a in DEMO_ACCOUNTS])).all()}
    return jsonify({"demo": True, "accounts": [
        {"username": name, "label": label, "opens": opens, "password": getattr(seed_data, pw)}
        for name, label, opens, pw in DEMO_ACCOUNTS if name in existing]})
