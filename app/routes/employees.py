from flask import Blueprint, jsonify, request

from ..extensions import db
from ..models import SecurityEvent, User, iso
from ..security import admin_required
from ..services.auth import hash_password
from ..validation import validate_new_employee

bp = Blueprint("employees", __name__, url_prefix="/api")


@bp.get("/employees")
@admin_required
def list_employees():
    last_login = dict(db.session.query(SecurityEvent.user_id, db.func.max(SecurityEvent.occurred_at))
                      .filter(SecurityEvent.event_type == "login_success").group_by(SecurityEvent.user_id))
    return jsonify([{**u.to_dict(include_risk=True), "lastLoginAt": iso(last_login.get(u.id))}
                    for u in User.query.order_by(User.employee_id)])


@bp.post("/employees")
@admin_required
def add_employee():
    fields, password, error = validate_new_employee(request.get_json(silent=True) or {})
    if error:
        return jsonify({"success": False, "message": error}), 400
    if User.query.filter_by(username=fields["username"]).first():
        return jsonify({"success": False, "message": "Username already exists."}), 409
    if User.query.filter_by(employee_id=fields["employee_id"]).first():
        return jsonify({"success": False, "message": "Employee ID already exists."}), 409

    user = User(password_hash=hash_password(password), risk_score=0, **fields)
    db.session.add(user)
    db.session.commit()
    return jsonify({"success": True, "user": user.to_dict(include_risk=True)}), 201
