"""Password hashing and credential checks."""
import bcrypt
from flask import current_app

from ..models import Resource, User


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=current_app.config.get("BCRYPT_ROUNDS", 12))).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:  # malformed hash in DB
        return False


def authenticate(username: str, password: str):
    """Return the User if credentials are valid, else None."""
    user = User.query.filter_by(username=username).first()
    if user is not None and verify_password(password, user.password_hash):
        return user
    return None


def check_permission(role: str, resource_name: str) -> bool:
    resource = Resource.query.filter_by(name=resource_name).first()
    return resource is not None and role in resource.allowed_roles()
