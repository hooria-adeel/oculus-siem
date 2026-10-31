"""Token issuing/verification, CSRF protection and the auth decorators.

Design
------
* Browser clients: JWT in an httpOnly + SameSite=Strict cookie (JavaScript can't read it, so XSS can't
  steal it) plus a CSRF token in a readable cookie that must be echoed in the X-CSRF-Token header on
  every state-changing request (double-submit; the expected value is also signed inside the JWT).
* API clients (Postman, curl, Swagger UI): `Authorization: Bearer <token>`. Not ambient-credential
  based, so CSRF does not apply.
* The user is always re-loaded from the database: deleting a user or changing a role takes effect
  immediately instead of waiting for the token to expire.
"""
import hmac
import secrets
import time
from functools import wraps

import jwt
from flask import current_app, g, jsonify, request

from .models import User

TOKEN_COOKIE = "oculus_token"
CSRF_COOKIE = "oculus_csrf"
CSRF_HEADER = "X-CSRF-Token"
ALGORITHM = "HS256"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _error(status: int, message: str):
    return jsonify({"success": False, "message": message}), status


def issue_token(user: User):
    """Return (jwt, csrf_token)."""
    now = int(time.time())
    csrf = secrets.token_urlsafe(24)
    claims = {
        "sub": user.username,
        "role": user.role,  # informational only; authorisation re-reads the DB
        "csrf": csrf,
        "iat": now,
        "exp": now + current_app.config["JWT_EXPIRES_MINUTES"] * 60,
    }
    return jwt.encode(claims, current_app.config["SECRET_KEY"], algorithm=ALGORITHM), csrf


def set_auth_cookies(response, token: str, csrf: str):
    cfg = current_app.config
    max_age = cfg["JWT_EXPIRES_MINUTES"] * 60
    common = dict(max_age=max_age, secure=cfg["COOKIE_SECURE"], samesite="Strict", path="/")
    response.set_cookie(TOKEN_COOKIE, token, httponly=True, **common)
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, **common)
    return response


def clear_auth_cookies(response):
    for name in (TOKEN_COOKIE, CSRF_COOKIE):
        response.delete_cookie(name, path="/")
    return response


def _decode(token: str):
    try:
        return jwt.decode(
            token,
            current_app.config["SECRET_KEY"],
            algorithms=[ALGORITHM],  # pin the algorithm: blocks alg=none and key-confusion tricks
            options={"require": ["exp", "sub", "csrf"]},
        )
    except jwt.PyJWTError:
        return None


def _resolve_request_user():
    """Returns (user, error_response). Exactly one of the two is None."""
    header = request.headers.get("Authorization", "")
    from_bearer = header.lower().startswith("bearer ")
    token = header[7:].strip() if from_bearer else request.cookies.get(TOKEN_COOKIE)
    if not token:
        return None, _error(401, "Authentication required.")

    claims = _decode(token)
    if claims is None:
        return None, _error(401, "Invalid or expired session.")

    if not from_bearer and request.method not in SAFE_METHODS:
        supplied = request.headers.get(CSRF_HEADER, "")
        if not hmac.compare_digest(supplied, claims["csrf"]):
            return None, _error(403, "CSRF token missing or invalid.")

    user = User.query.filter_by(username=claims["sub"]).first()
    if user is None:
        return None, _error(401, "Invalid or expired session.")
    return user, None


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user, err = _resolve_request_user()
        if err is not None:
            return err
        g.current_user = user
        return fn(*args, **kwargs)

    return wrapper


def roles_required(*roles):
    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapper(*args, **kwargs):
            if g.current_user.role not in roles:
                return _error(403, "You do not have permission to perform this action.")
            return fn(*args, **kwargs)

        return wrapper

    return decorator


admin_required = roles_required("Admin")


def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    )
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response
