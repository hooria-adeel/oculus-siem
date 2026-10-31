"""Relational model.

Design notes
* Surrogate BIGINT identity keys everywhere; relationships are real foreign keys.
* All timestamps are timestamptz (UTC) and naive datetimes are rejected (see db_types.UTCDateTime).
* Enumerations are CHECK constraints (simpler to migrate than native PG enums).
* ``security_events`` is the append-only evidence log. Incidents never copy events: they LINK to them
  (``incident_events``), which is what makes correlation and timelines possible.
* A partial unique index guarantees at most one *open* incident per dedupe_key. The database enforces it,
  not application code, so concurrent requests cannot create duplicates.
* Deleting a user NULLs the foreign keys on events/incidents but keeps the denormalised username, so
  the audit trail survives account removal.
"""
from datetime import datetime, timezone

from sqlalchemy import CheckConstraint, Index, text

from .db_types import BigInt, IPAddress, JSONType, UTCDateTime
from .extensions import db

ROLES = ("Admin", "IT", "HR", "Finance", "Marketing", "Operations")
SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
OUTCOMES = ("success", "failure", "blocked")
EVENT_TYPES = (
    "login_success", "login_failed", "login_blocked", "logout",
    "access_granted", "access_denied", "honeypot_access",
)
INCIDENT_STATUSES = ("open", "investigating", "resolved")
OPEN_STATUSES = ("open", "investigating")
ACTIVITY_KINDS = ("opened", "evidence_added", "status_changed", "note")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt):
    """ISO-8601 in UTC with a 'Z' suffix."""
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if dt else None


def _in(column: str, values) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


class User(db.Model):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("username = lower(username)", name="username_lowercase"),
        CheckConstraint(_in("role", ROLES), name="role_valid"),
        CheckConstraint("risk_score BETWEEN 0 AND 100", name="risk_score_range"),
    )

    id = db.Column(BigInt, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    employee_id = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    # Snapshot taken at risk_updated_at; the *effective* score decays from here (see services/risk.py).
    risk_score = db.Column(db.Integer, nullable=False, default=0, server_default="0")
    risk_updated_at = db.Column(UTCDateTime, nullable=False, default=utcnow, server_default=db.func.now())
    created_at = db.Column(UTCDateTime, nullable=False, default=utcnow, server_default=db.func.now())

    @property
    def effective_risk(self) -> int:
        from .services import risk
        return risk.effective_score(self)

    def to_dict(self, include_risk=False):
        """The risk score is analyst-only: showing it to the person being scored lets an insider probe thresholds."""
        data = {
            "username": self.username,
            "fullName": self.full_name,
            "employeeId": self.employee_id,
            "role": self.role,
            "createdAt": iso(self.created_at),
        }
        if include_risk:
            data["riskScore"] = self.effective_risk
        return data


class Resource(db.Model):
    __tablename__ = "resources"

    id = db.Column(BigInt, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(255))
    content = db.Column(db.Text)
    is_honeypot = db.Column(db.Boolean, nullable=False, default=False, server_default=text("false"))

    permissions = db.relationship("ResourcePermission", backref="resource", cascade="all, delete-orphan")

    def allowed_roles(self):
        return [p.role for p in self.permissions]


class ResourcePermission(db.Model):
    __tablename__ = "resource_permissions"
    __table_args__ = (CheckConstraint(_in("role", ROLES), name="role_valid"),)

    resource_id = db.Column(BigInt, db.ForeignKey("resources.id", ondelete="CASCADE"), primary_key=True)
    role = db.Column(db.String(20), primary_key=True)


class SecurityEvent(db.Model):
    """Append-only evidence log."""

    __tablename__ = "security_events"
    __table_args__ = (
        CheckConstraint(_in("event_type", EVENT_TYPES), name="event_type_valid"),
        CheckConstraint(_in("outcome", OUTCOMES), name="outcome_valid"),
        CheckConstraint(_in("severity", SEVERITIES), name="severity_valid"),
        Index("ix_security_events_occurred_at", "occurred_at"),
        Index("ix_security_events_user_time", "user_id", "occurred_at"),
        Index("ix_security_events_ip_time", "source_ip", "occurred_at"),
        Index("ix_security_events_type_time", "event_type", "occurred_at"),
    )

    id = db.Column(BigInt, primary_key=True)
    occurred_at = db.Column(UTCDateTime, nullable=False, default=utcnow, server_default=db.func.now())
    event_type = db.Column(db.String(30), nullable=False)
    outcome = db.Column(db.String(10), nullable=False)
    severity = db.Column(db.String(10), nullable=False, default="info", server_default="info")
    user_id = db.Column(BigInt, db.ForeignKey("users.id", ondelete="SET NULL"))
    username = db.Column(db.String(100), nullable=False)      # what was typed / who acted; survives user deletion
    resource_id = db.Column(BigInt, db.ForeignKey("resources.id", ondelete="SET NULL"))
    resource_name = db.Column(db.String(100))
    source_ip = db.Column(IPAddress)
    user_agent = db.Column(db.String(255))
    details = db.Column(JSONType, nullable=False, default=dict)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": iso(self.occurred_at),
            "eventType": self.event_type,
            "outcome": self.outcome,
            "severity": self.severity,
            "username": self.username,
            "resourceName": self.resource_name,
            "sourceIp": self.source_ip,
            "userAgent": self.user_agent,
            "details": self.details or {},
        }


class Incident(db.Model):
    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint(_in("severity", SEVERITIES), name="severity_valid"),
        CheckConstraint(_in("status", INCIDENT_STATUSES), name="status_valid"),
        Index(
            "uq_incidents_open_dedupe", "dedupe_key", unique=True,
            postgresql_where=text("status IN ('open', 'investigating')"),
            sqlite_where=text("status IN ('open', 'investigating')"),
        ),
        Index("ix_incidents_status_opened", "status", "opened_at"),
    )

    id = db.Column(BigInt, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    summary = db.Column(db.Text, nullable=False, default="", server_default="")
    severity = db.Column(db.String(10), nullable=False)
    status = db.Column(db.String(15), nullable=False, default="open", server_default="open")
    rule_id = db.Column(db.String(20), nullable=False)          # e.g. R-BF-001 (rules live in code)
    mitre_tactic = db.Column(db.String(60))
    mitre_technique = db.Column(db.String(12))
    user_id = db.Column(BigInt, db.ForeignKey("users.id", ondelete="SET NULL"))
    subject = db.Column(db.String(100), nullable=False)         # username or IP the incident is about
    source_ip = db.Column(IPAddress)
    dedupe_key = db.Column(db.String(200), nullable=False)
    risk_score = db.Column(db.Integer, nullable=False, default=0, server_default="0")
    resolved_by_id = db.Column(BigInt, db.ForeignKey("users.id", ondelete="SET NULL"))
    opened_at = db.Column(UTCDateTime, nullable=False, default=utcnow, server_default=db.func.now())
    updated_at = db.Column(UTCDateTime, nullable=False, default=utcnow, server_default=db.func.now())
    resolved_at = db.Column(UTCDateTime)

    user = db.relationship("User", foreign_keys=[user_id])
    resolved_by = db.relationship("User", foreign_keys=[resolved_by_id])
    evidence = db.relationship("IncidentEvent", backref="incident", cascade="all, delete-orphan")
    activity = db.relationship(
        "IncidentActivity", back_populates="incident", cascade="all, delete-orphan",
        order_by="(IncidentActivity.created_at, IncidentActivity.id)",
    )

    @property
    def ref(self) -> str:
        return f"INC-{self.id:04d}"

    def to_dict(self):
        return {
            "id": self.id,
            "ref": self.ref,
            "title": self.title,
            "summary": self.summary,
            "severity": self.severity,
            "status": self.status,
            "ruleId": self.rule_id,
            "mitreTactic": self.mitre_tactic,
            "mitreTechnique": self.mitre_technique,
            "subject": self.subject,
            "sourceIp": self.source_ip,
            "riskScore": self.risk_score,
            "evidenceCount": len(self.evidence),
            "openedAt": iso(self.opened_at),
            "updatedAt": iso(self.updated_at),
            "resolvedAt": iso(self.resolved_at),
            "resolvedBy": self.resolved_by.username if self.resolved_by else None,
        }


class IncidentEvent(db.Model):
    """Correlation link: which evidence supports which incident."""

    __tablename__ = "incident_events"

    incident_id = db.Column(BigInt, db.ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True)
    event_id = db.Column(BigInt, db.ForeignKey("security_events.id", ondelete="CASCADE"), primary_key=True)
    linked_at = db.Column(UTCDateTime, nullable=False, default=utcnow, server_default=db.func.now())

    event = db.relationship("SecurityEvent", lazy="joined")


class IncidentActivity(db.Model):
    """An incident's own audit trail. actor NULL means the system acted."""

    __tablename__ = "incident_activity"
    __table_args__ = (
        CheckConstraint(_in("kind", ACTIVITY_KINDS), name="kind_valid"),
        Index("ix_incident_activity_incident_time", "incident_id", "created_at"),
    )

    id = db.Column(BigInt, primary_key=True)
    incident_id = db.Column(BigInt, db.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    actor_id = db.Column(BigInt, db.ForeignKey("users.id", ondelete="SET NULL"))
    kind = db.Column(db.String(20), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(UTCDateTime, nullable=False, default=utcnow, server_default=db.func.now())

    incident = db.relationship("Incident", back_populates="activity")
    actor = db.relationship("User", lazy="joined")

    def to_dict(self):
        return {
            "timestamp": iso(self.created_at),
            "kind": self.kind,
            "message": self.message,
            "actor": self.actor.username if self.actor else "system",
        }
