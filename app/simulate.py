"""Live traffic simulator:  flask --app run simulate

Feeds the *real* ingest pipeline in real time (ordinary office activity plus periodic attacks), so the console's
live stream moves and incidents open exactly as they would in production. Useful for demos and for recording
screenshots; nothing here bypasses detection.

    flask --app run simulate                    # normal traffic + an attack every ~40 s
    flask --app run simulate --attacks 0        # normal traffic only
    flask --app run simulate --duration 120     # stop by itself after two minutes
"""
import random
import time
from datetime import datetime

import click
from flask.cli import with_appcontext

from .models import Resource, User
from .services.ingest import record_event

UA_BROWSER = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/141.0 Safari/537.36",
              "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"]
UA_TOOL = ["Mozilla/5.0 (Hydra v9.5)", "python-requests/2.32.3", "curl/8.5.0"]
EXTERNAL_RANGES = ("203.0.113", "198.51.100", "192.0.2")     # RFC 5737 documentation addresses: never real hosts
COMMON_GUESSES = ["administrator", "admin", "root", "test", "support", "backup", "hr", "finance"]


def office_ip(user: User, employees: list[User]) -> str:
    dept = sorted({u.role for u in employees}).index(user.role) + 1
    return f"10.0.{dept}.{10 + employees.index(user)}"


def normal_event(rng: random.Random, employees, files) -> dict:
    """One unremarkable thing an employee does."""
    user = rng.choice(employees)
    ip, ua = office_ip(user, employees), rng.choice(UA_BROWSER)
    roll = rng.random()
    if roll < 0.12:
        return dict(type="login_success", user=user, ip=ip, ua=ua)
    if roll < 0.15:
        return dict(type="login_failed", user=user, username=user.username, ip=ip, ua=ua)   # fat-finger
    if roll < 0.20:
        return dict(type="logout", user=user, ip=ip, ua=ua)
    allowed = [f for f in files if not f.is_honeypot and user.role in f.allowed_roles()]
    return dict(type="access_granted", user=user, resource=rng.choice(allowed), ip=ip, ua=ua,
                details={"reason": "role_permitted", "role": user.role})


def _attacker(rng) -> str:
    return f"{rng.choice(EXTERNAL_RANGES)}.{rng.randint(2, 250)}"


def scenario_brute_force(rng, employees, files) -> list[dict]:
    """Guess one account's password, then get in. Fires R-BF-001, then R-CRED-001."""
    victim, ip, ua = rng.choice(employees), _attacker(rng), rng.choice(UA_TOOL)
    steps = [dict(delay=0.6, type="login_failed", user=victim, username=victim.username, ip=ip, ua=ua) for _ in range(6)]
    steps.append(dict(delay=1.5, type="login_success", user=victim, ip=ip, ua=rng.choice(UA_BROWSER)))
    return steps


def scenario_spraying(rng, employees, files) -> list[dict]:
    """One address, a handful of common usernames. Fires R-SPRAY-001."""
    ip, ua = _attacker(rng), rng.choice(UA_TOOL)
    names = rng.sample(COMMON_GUESSES, 4) + [u.username for u in rng.sample(employees, 2)]
    return [dict(delay=0.8, type="login_failed", user=next((u for u in employees if u.username == n), None),
                 username=n if "@" in n else f"{n}@oculus.com", ip=ip, ua=ua) for n in names]


def scenario_honeypot(rng, employees, files) -> list[dict]:
    """An employee opens a decoy file. Fires R-HP-001 immediately."""
    user = rng.choice(employees)
    decoy = rng.choice([f for f in files if f.is_honeypot])
    return [dict(delay=0.5, type="honeypot_access", user=user, resource=decoy, ip=office_ip(user, employees),
                 ua=rng.choice(UA_BROWSER), details={"reason": "decoy_resource", "role": user.role})]


def scenario_snooping(rng, employees, files) -> list[dict]:
    """An employee tries files outside their role. Fires R-ACC-001 and raises insider risk."""
    user = rng.choice(employees)
    forbidden = [f for f in files if not f.is_honeypot and user.role not in f.allowed_roles()]
    ip, ua = office_ip(user, employees), rng.choice(UA_BROWSER)
    return [dict(delay=1.2, type="access_denied", user=user, resource=f, ip=ip, ua=ua,
                 details={"reason": "role_not_permitted", "role": user.role}) for f in rng.choices(forbidden, k=3)]   # repeats allowed: a snooper retries


SCENARIOS = (scenario_brute_force, scenario_spraying, scenario_honeypot, scenario_snooping)


def emit(spec: dict, now: datetime | None = None):
    return record_event(spec["type"], user=spec.get("user"), username=spec.get("username"), resource=spec.get("resource"),
                        source_ip=spec["ip"], user_agent=spec["ua"], details=spec.get("details"), occurred_at=now)


def run(duration: float, rate: float, attack_every: float, rng: random.Random, echo=click.echo,
        sleep=time.sleep, clock=time.monotonic) -> int:
    employees = User.query.filter(User.role != "Admin").order_by(User.employee_id).all()
    files = Resource.query.all()
    if not employees or not files:
        raise click.ClickException("No data found. Run `flask --app run seed` first.")

    start = clock()
    next_attack = start + (attack_every if attack_every else float("inf"))
    queue: list[tuple[float, dict]] = []      # (due time, event spec) for multi-step attacks
    count = 0
    while duration <= 0 or clock() - start < duration:
        now = clock()
        if now >= next_attack:
            t = now
            for spec in rng.choice(SCENARIOS)(rng, employees, files):
                t += spec["delay"]
                queue.append((t, spec))
            next_attack = now + attack_every * rng.uniform(0.7, 1.3)
        due = [item for item in queue if item[0] <= now]
        queue = [item for item in queue if item[0] > now]
        specs = [spec for _, spec in sorted(due, key=lambda i: i[0])]
        if rng.random() < rate * 0.25:         # loop ticks every 0.25 s
            specs.append(normal_event(rng, employees, files))
        for spec in specs:
            event = emit(spec)
            count += 1
            flag = " " if event.severity in ("info", "low") else "!"
            echo(f"{event.occurred_at:%H:%M:%S} {flag} {event.event_type:<16} {event.username:<30} {event.source_ip or '-'}"
                 + (f"  {event.resource_name}" if event.resource_name else ""))
        sleep(0.25)
    return count


@click.command("simulate")
@click.option("--rate", default=0.8, show_default=True, help="Average ordinary events per second.")
@click.option("--attacks", "attack_every", default=40.0, show_default=True, help="Seconds between attacks (0 = none).")
@click.option("--duration", default=0.0, help="Stop after N seconds (0 = run until Ctrl+C).")
@click.option("--seed", type=int, default=None, help="Random seed, for repeatable runs.")
@with_appcontext
def simulate_command(rate, attack_every, duration, seed):
    """Stream live activity and attacks through the real detection pipeline."""
    click.echo("Streaming events. Press Ctrl+C to stop.\n")
    try:
        total = run(duration, rate, attack_every, random.Random(seed))
    except KeyboardInterrupt:
        click.echo("\nStopped.")
        return
    click.echo(f"\nDone: {total} events.")
