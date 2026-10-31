"""Resource access controller: permission check -> event -> risk -> detection."""
from ..models import Resource
from . import risk
from .ingest import record_event


def attempt_access(user, resource_name: str, source_ip=None, user_agent=None) -> dict:
    resource = Resource.query.filter_by(name=resource_name).first()
    if resource is None:
        return {"authorized": False, "message": "File not found.", "content": None, "warning": None}

    if resource.is_honeypot:
        # Real deception: the decoy opens like any other file and Security is alerted silently.
        # Telling the person "this is a honeypot" would end the investigation before it started.
        event_type, authorized, reason = "honeypot_access", True, "decoy_resource"
        message = f"Access granted to {resource.name}."
    elif user.role not in resource.allowed_roles():
        event_type, authorized, reason = "access_denied", False, "role_not_permitted"
        message = "Access denied. You do not have permission to open this file."
    else:
        event_type, authorized, reason = "access_granted", True, "role_permitted"
        message = f"Access granted to {resource.name}."

    record_event(event_type, user=user, resource=resource, source_ip=source_ip, user_agent=user_agent,
                 details={"reason": reason, "role": user.role})

    return {
        "authorized": authorized,
        "message": message,
        "content": resource.content if authorized else None,
        "warning": None if authorized else risk.warning_for(user),
    }
