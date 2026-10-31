"""Detection rules. Each rule is small, stateless and tagged with its MITRE ATT&CK technique.

Rules look *backwards from the event being evaluated* (never at wall-clock time), which makes them
deterministic and lets the demo seed replay history through exactly the same code that runs live.
"""
from dataclasses import dataclass, field
from datetime import timedelta

from flask import current_app

from ...models import SecurityEvent, User
from .. import risk


@dataclass
class Finding:
    rule: "Rule"
    title: str
    summary: str
    severity: str
    subject: str
    dedupe_key: str
    evidence: list = field(default_factory=list)
    user: User | None = None
    source_ip: str | None = None


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    description: str
    severity: str
    tactic: str
    technique: str          # e.g. T1110.001
    technique_name: str
    triggers: tuple         # event types that cause this rule to be evaluated

    def meta(self) -> dict:
        return {"id": self.id, "name": self.name, "description": self.description, "severity": self.severity,
                "mitreTactic": self.tactic, "mitreTechnique": self.technique,
                "mitreTechniqueName": self.technique_name, "triggers": list(self.triggers)}

    def evaluate(self, event: SecurityEvent) -> Finding | None:  # pragma: no cover - overridden
        raise NotImplementedError


def _cfg(key):
    return current_app.config[key]


def _window(event, minutes):
    return event.occurred_at - timedelta(minutes=minutes), event.occurred_at


def _failed_logins(event, **match):
    start, end = _window(event, _cfg("DETECTION_WINDOW_MINUTES"))
    q = SecurityEvent.query.filter(
        SecurityEvent.event_type == "login_failed",
        SecurityEvent.occurred_at >= start, SecurityEvent.occurred_at <= end,
    )
    for column, value in match.items():
        q = q.filter(getattr(SecurityEvent, column) == value)
    return q.order_by(SecurityEvent.occurred_at, SecurityEvent.id).all()


def _user(username):
    return User.query.filter_by(username=username).first()


class BruteForce(Rule):
    def evaluate(self, event):
        failures = _failed_logins(event, username=event.username, source_ip=event.source_ip)
        threshold = _cfg("LOGIN_MAX_FAILURES")
        user = _user(event.username)
        if len(failures) < threshold or user is None:
            return None
        minutes = _cfg("DETECTION_WINDOW_MINUTES")
        return Finding(
            rule=self, user=user, source_ip=event.source_ip, subject=user.username, evidence=failures,
            severity=self.severity, dedupe_key=f"{self.id}:{user.username}:{event.source_ip}",
            title=f"Brute-force attack against {user.username}",
            summary=f"{len(failures)} failed logins for {user.username} from {event.source_ip} within {minutes} minutes.",
        )


class PasswordSpraying(Rule):
    def evaluate(self, event):
        if not event.source_ip:
            return None
        failures = _failed_logins(event, source_ip=event.source_ip)
        usernames = {f.username for f in failures}
        if len(usernames) < _cfg("RULE_SPRAY_DISTINCT_USERS"):
            return None
        return Finding(
            rule=self, source_ip=event.source_ip, subject=event.source_ip, evidence=failures,
            severity=self.severity, dedupe_key=f"{self.id}:{event.source_ip}",
            title=f"Password spraying from {event.source_ip}",
            summary=f"{len(failures)} failed logins across {len(usernames)} different accounts from {event.source_ip}.",
        )


class CredentialCompromise(Rule):
    def evaluate(self, event):
        failures = _failed_logins(event, username=event.username, source_ip=event.source_ip)
        user = _user(event.username)
        if len(failures) < _cfg("RULE_CRED_FAILURES") or user is None:
            return None
        return Finding(
            rule=self, user=user, source_ip=event.source_ip, subject=user.username,
            evidence=failures + [event], severity=self.severity,
            dedupe_key=f"{self.id}:{user.username}:{event.source_ip}",
            title=f"Successful login after repeated failures: {user.username}",
            summary=(f"{user.username} logged in from {event.source_ip} right after {len(failures)} failed attempts "
                     "from the same address. The password may have been guessed."),
        )


class HoneypotAccess(Rule):
    def evaluate(self, event):
        user = _user(event.username)
        if user is None:
            return None
        return Finding(
            rule=self, user=user, source_ip=event.source_ip, subject=user.username, evidence=[event],
            severity=self.severity, dedupe_key=f"{self.id}:{user.username}",
            title=f"Honeypot triggered by {user.username}",
            summary=(f"{user.username} ({user.role}) opened decoy file '{event.resource_name}'. "
                     "No legitimate workflow touches honeypots."),
        )


class RepeatedDenied(Rule):
    def evaluate(self, event):
        user = _user(event.username)
        if user is None:
            return None
        start, end = _window(event, _cfg("RULE_DENIED_WINDOW_MINUTES"))
        denied = SecurityEvent.query.filter(
            SecurityEvent.user_id == user.id, SecurityEvent.event_type == "access_denied",
            SecurityEvent.occurred_at >= start, SecurityEvent.occurred_at <= end,
        ).order_by(SecurityEvent.occurred_at, SecurityEvent.id).all()
        if len(denied) < _cfg("RULE_DENIED_COUNT"):
            return None
        names = ", ".join(sorted({d.resource_name for d in denied if d.resource_name}))
        return Finding(
            rule=self, user=user, source_ip=event.source_ip, subject=user.username, evidence=denied,
            severity=self.severity, dedupe_key=f"{self.id}:{user.username}",
            title=f"Repeated denied access by {user.username}",
            summary=f"{len(denied)} denied attempts within {_cfg('RULE_DENIED_WINDOW_MINUTES')} minutes: {names}.",
        )


class RiskThreshold(Rule):
    def evaluate(self, event):
        user = _user(event.username)
        if user is None:
            return None
        score = risk.effective_score(user, event.occurred_at)
        if score <= _cfg("RISK_INCIDENT_THRESHOLD"):
            return None
        recent = SecurityEvent.query.filter(
            SecurityEvent.user_id == user.id, SecurityEvent.outcome != "success",
            SecurityEvent.occurred_at >= event.occurred_at - timedelta(days=1),
            SecurityEvent.occurred_at <= event.occurred_at,
        ).order_by(SecurityEvent.occurred_at, SecurityEvent.id).all()
        return Finding(
            rule=self, user=user, source_ip=event.source_ip, subject=user.username, evidence=recent,
            severity=self.severity, dedupe_key=f"{self.id}:{user.username}",
            title=f"Risk threshold exceeded: {user.username}",
            summary=f"{user.username} ({user.role}) reached risk score {score}/100 after {len(recent)} policy violations in 24h.",
        )


RULES: tuple[Rule, ...] = (
    BruteForce("R-BF-001", "Brute-force login attempts",
               "Repeated failed logins for one account from one source address.",
               "high", "Credential Access", "T1110.001", "Brute Force: Password Guessing", ("login_failed",)),
    PasswordSpraying("R-SPRAY-001", "Password spraying",
                     "One source address failing logins across many different accounts.",
                     "high", "Credential Access", "T1110.003", "Brute Force: Password Spraying", ("login_failed",)),
    CredentialCompromise("R-CRED-001", "Login success after repeated failures",
                         "A login succeeds shortly after several failures from the same address.",
                         "critical", "Initial Access", "T1078", "Valid Accounts", ("login_success",)),
    HoneypotAccess("R-HP-001", "Honeypot resource accessed",
                   "Any access to a decoy file. Legitimate users never touch these.",
                   "high", "Discovery", "T1083", "File and Directory Discovery", ("honeypot_access",)),
    RepeatedDenied("R-ACC-001", "Repeated denied access",
                   "Several permission denials in a short period: probing for data outside the user's role.",
                   "medium", "Discovery", "T1083", "File and Directory Discovery", ("access_denied",)),
    RiskThreshold("R-RISK-001", "Risk threshold exceeded",
                  "Accumulated risk score passes the configured threshold.",
                  "high", "Collection", "T1005", "Data from Local System", ("access_denied", "honeypot_access")),
)
