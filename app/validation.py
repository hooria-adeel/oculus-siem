"""Server-side input validation. Never rely on the frontend for this."""
import re

from flask import current_app

NAME_RE = re.compile(r"^[^\W\d_][\w .'\-]{1,99}$")                      # letters first; no markup characters
USERNAME_RE = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,35}$")
EMPLOYEE_ID_RE = re.compile(r"^[A-Za-z0-9\-]{1,20}$")


def validate_new_employee(data: dict):
    """Return (clean_fields, password, error_message). error_message is None when valid."""
    full_name = str(data.get("fullName") or "").strip()
    username = str(data.get("username") or "").strip()
    employee_id = str(data.get("employeeId") or "").strip()
    role = str(data.get("role") or "").strip()
    password = data.get("password") if isinstance(data.get("password"), str) else ""

    if not (full_name and username and employee_id and role and password):
        return None, None, "All fields are required."
    if not NAME_RE.match(full_name):
        return None, None, "Full name contains invalid characters."
    if not USERNAME_RE.match(username):
        return None, None, "Username must be a valid email-style identifier."
    if not EMPLOYEE_ID_RE.match(employee_id):
        return None, None, "Employee ID may only contain letters, digits and hyphens."
    if role not in current_app.config["ALLOWED_ROLES"]:
        return None, None, "Unknown role."
    if len(password) < current_app.config["PASSWORD_MIN_LENGTH"] or not (
        re.search(r"[A-Za-z]", password) and re.search(r"\d", password)
    ):
        return None, None, f"Password must be at least {current_app.config['PASSWORD_MIN_LENGTH']} characters and contain a letter and a digit."

    return {"full_name": full_name, "username": username, "employee_id": employee_id, "role": role}, password, None
