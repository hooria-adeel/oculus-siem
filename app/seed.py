"""Demo data generator:  flask --app run seed [--reset]

Instead of hand-written INSERTs, history is *replayed through the real ingest + detection pipeline*:
a week of ordinary activity plus four scripted incidents. Every incident you see in the demo was opened by
a detection rule, with its evidence linked, exactly as it would be live.
"""
import random
from datetime import datetime, timedelta

import click
from flask.cli import with_appcontext

from .extensions import db
from .models import (Incident, IncidentActivity, IncidentEvent, Resource, ResourcePermission, SecurityEvent,
                     User, utcnow)
from .seed_data import ADMIN_PASSWORD, DEMO_PASSWORD, RESOURCES, USERS
from .services import incidents as incident_svc
from .services.auth import hash_password
from .services.ingest import record_event

UA_CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36"
UA_FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
UA_HYDRA = "Mozilla/5.0 (Hydra v9.5)"
UA_CURL = "curl/8.5.0"

ATTACKER_BF = "203.0.113.45"       # TEST-NET-3 documentation ranges: safe, never real hosts
ATTACKER_SPRAY = "198.51.100.23"   # TEST-NET-2


def wipe():
    for model in (IncidentActivity, IncidentEvent, Incident, SecurityEvent, ResourcePermission, Resource, User):
        db.session.execute(db.delete(model))
    db.session.commit()


def _create_users_and_resources(now):
    employee_hash = hash_password(DEMO_PASSWORD)     # one hash reused: demo accounts only, keeps seeding fast
    admin_hash = hash_password(ADMIN_PASSWORD)
    users = {}
    for i, (username, name, emp_id, role) in enumerate(USERS):
        created = now - timedelta(days=400 - i * 17)
        users[username] = User(username=username, full_name=name, employee_id=emp_id, role=role, risk_score=0,
                               password_hash=admin_hash if role == "Admin" else employee_hash,
                               created_at=created, risk_updated_at=created)
    db.session.add_all(users.values())

    resources = {}
    for name, honeypot, desc, content, roles in RESOURCES:
        r = Resource(name=name, is_honeypot=honeypot, description=desc, content=content)
        r.permissions = [ResourcePermission(role=role) for role in roles]
        resources[name] = r
    db.session.add_all(resources.values())
    db.session.flush()
    return users, resources


def _baseline(rng, now, users, resources):
    """A week of unremarkable office activity."""
    specs = []
    employees = [u for u in users.values() if u.role != "Admin"]
    by_role = {}
    for r in resources.values():
        if not r.is_honeypot:
            for role in r.allowed_roles():
                by_role.setdefault(role, []).append(r)
    dept_idx = {role: i + 1 for i, role in enumerate(sorted({u.role for u in employees}))}

    for day in range(7, -1, -1):
        midnight = (now - timedelta(days=day)).replace(hour=0, minute=0, second=0, microsecond=0)
        for idx, user in enumerate(employees):
            if rng.random() < 0.25:
                continue
            ip = f"10.0.{dept_idx[user.role]}.{10 + idx}"
            ua = rng.choice([UA_CHROME, UA_FIREFOX])
            t = midnight + timedelta(hours=3, minutes=rng.randint(0, 100))   # ~08:00-09:40 Karachi
            if rng.random() < 0.10:                                          # fat-fingered password once
                specs.append(dict(t=t, type="login_failed", user=user, username=user.username, ip=ip, ua=ua))
                t += timedelta(seconds=rng.randint(8, 25))
            specs.append(dict(t=t, type="login_success", user=user, ip=ip, ua=ua))
            for _ in range(rng.randint(1, 4)):
                t += timedelta(minutes=rng.randint(5, 80))
                res = rng.choice(by_role[user.role])
                specs.append(dict(t=t, type="access_granted", user=user, resource=res, ip=ip, ua=ua,
                                  details={"reason": "role_permitted", "role": user.role}))
            if rng.random() < 0.03:                                          # an isolated honest mistake
                other = rng.choice([r for r in resources.values() if not r.is_honeypot and user.role not in r.allowed_roles()])
                specs.append(dict(t=t + timedelta(minutes=3), type="access_denied", user=user, resource=other, ip=ip,
                                  ua=ua, details={"reason": "role_not_permitted", "role": user.role}))
            specs.append(dict(t=midnight + timedelta(hours=12, minutes=rng.randint(0, 90)), type="logout",
                              user=user, ip=ip, ua=ua))
    return [s for s in specs if s["t"] < now - timedelta(minutes=10)]


def _scenario_credential_compromise(now, users, resources):
    """A: external brute force -> success -> attacker explores with the stolen Finance account."""
    sara = users["sara.malik@oculus.com"]
    t0, specs = now - timedelta(hours=52), []
    for i in range(9):
        specs.append(dict(t=t0 + timedelta(seconds=40 * i), type="login_failed", user=sara, username=sara.username,
                          ip=ATTACKER_BF, ua=UA_HYDRA))
    t = t0 + timedelta(seconds=40 * 9 + 20)
    specs.append(dict(t=t, type="login_success", user=sara, ip=ATTACKER_BF, ua=UA_CHROME))
    steps = [("access_granted", "Payroll.xlsx", 2), ("access_granted", "Budget_2026.xlsx", 3),
             ("access_denied", "Firewall.config", 4), ("honeypot_access", "Passwords.txt", 6),
             ("honeypot_access", "IT_Admin_Credentials.docx", 8)]
    for etype, res, minutes in steps:
        specs.append(dict(t=t + timedelta(minutes=minutes), type=etype, user=sara, resource=resources[res],
                          ip=ATTACKER_BF, ua=UA_CHROME, details={"role": sara.role}))
    return specs


def _scenario_insider(now, users, resources):
    """B: an IT employee probes Finance/HR data, then opens decoys."""
    hassan = users["hassan.raza@oculus.com"]
    t0, ip, specs = now - timedelta(hours=27), "10.0.2.12", []
    steps = [("access_denied", "Payroll.xlsx", 0), ("access_denied", "HR_Records.pdf", 4),
             ("access_denied", "Budget_2026.xlsx", 9), ("honeypot_access", "Client_Database_Export.sql", 14),
             ("honeypot_access", "CEO_Salary.xlsx", 19)]
    specs.append(dict(t=t0 - timedelta(minutes=12), type="login_success", user=hassan, ip=ip, ua=UA_CHROME))
    for etype, res, minutes in steps:
        specs.append(dict(t=t0 + timedelta(minutes=minutes), type=etype, user=hassan, resource=resources[res],
                          ip=ip, ua=UA_CHROME, details={"role": hassan.role}))
    return specs


def _scenario_spraying(now, users):
    """C: one address tries a few common accounts, including ones that don't exist."""
    t0, specs = now - timedelta(hours=20), []
    names = ["ahmed.khan@oculus.com", "sara.malik@oculus.com", "administrator@oculus.com", "ali.hassan@oculus.com",
             "admin@oculus.com", "omar.farooq@oculus.com", "root@oculus.com", "usman.tariq@oculus.com"]
    for i, name in enumerate(names):
        specs.append(dict(t=t0 + timedelta(seconds=70 * i), type="login_failed", user=users.get(name), username=name,
                          ip=ATTACKER_SPRAY, ua=UA_CURL))
    return specs


def _scenario_single_honeypot(now, users, resources):
    """D (5 days ago): one honeypot touch that analysts later closed as accidental."""
    m = users["mahnoor.baig@oculus.com"]
    t = now - timedelta(days=5)
    return [dict(t=t, type="honeypot_access", user=m, resource=resources["Confidential_Project_Phoenix.pdf"],
                 ip="10.0.3.20", ua=UA_CHROME, details={"role": m.role})]


def _scenario_minor(now, users, resources):
    """E: two denials: below every threshold, so correctly produces no incident."""
    d = users["danish.iqbal@oculus.com"]
    t = now - timedelta(hours=3)
    return [dict(t=t, type="access_denied", user=d, resource=resources["Payroll.xlsx"], ip="10.0.4.14", ua=UA_CHROME,
                 details={"role": d.role}),
            dict(t=t + timedelta(minutes=6), type="access_denied", user=d, resource=resources["Budget_2026.xlsx"],
                 ip="10.0.4.14", ua=UA_CHROME, details={"role": d.role})]


def _analyst_actions(now, users):
    admin = users["imran.shah@oculus.com"]
    by_rule = lambda rule, who: Incident.query.filter(Incident.rule_id == rule, Incident.subject == who).first()  # noqa: E731
    cred = by_rule("R-CRED-001", "sara.malik@oculus.com")
    if cred:
        incident_svc.set_status(cred, "investigating", admin, when=now - timedelta(hours=49),
                                note="Forced a password reset for sara.malik and revoked active sessions. "
                                     "Reviewing VPN logs for 203.0.113.45.")
    old = by_rule("R-HP-001", "mahnoor.baig@oculus.com")
    if old:
        incident_svc.set_status(old, "resolved", admin, when=now - timedelta(days=5) + timedelta(hours=6),
                                note="Confirmed with the Marketing lead: opened by mistake from a shared drive listing. "
                                     "User reminded of the file access policy.")


def seed_demo(now: datetime | None = None, rng_seed: int = 7) -> dict:
    now = now or utcnow()
    rng = random.Random(rng_seed)
    users, resources = _create_users_and_resources(now)

    specs = _baseline(rng, now, users, resources)
    specs += _scenario_credential_compromise(now, users, resources)
    specs += _scenario_insider(now, users, resources)
    specs += _scenario_spraying(now, users)
    specs += _scenario_single_honeypot(now, users, resources)
    specs += _scenario_minor(now, users, resources)
    specs.sort(key=lambda s: s["t"])

    for i, s in enumerate(specs, 1):
        record_event(s["type"], user=s.get("user"), username=s.get("username"), resource=s.get("resource"),
                     source_ip=s["ip"], user_agent=s["ua"], details=s.get("details"), occurred_at=s["t"], commit=False)
        if i % 100 == 0:
            db.session.commit()
    db.session.commit()

    _analyst_actions(now, users)
    db.session.commit()
    return {"users": len(users), "resources": len(resources), "events": len(specs),
            "incidents": Incident.query.count()}


@click.command("seed")
@click.option("--reset", is_flag=True, help="Delete ALL existing data first.")
@with_appcontext
def seed_command(reset):
    """Load the demo company and a replayed week of security activity."""
    if User.query.first() is not None:
        if not reset:
            raise click.ClickException("Database already contains data. Re-run with --reset to wipe and re-seed.")
        wipe()
    summary = seed_demo()
    click.echo("Seeded: " + ", ".join(f"{v} {k}" for k, v in summary.items()))
    click.echo(f"Demo logins -> admin: imran.shah@oculus.com / {ADMIN_PASSWORD}   employees: <username> / {DEMO_PASSWORD}")
