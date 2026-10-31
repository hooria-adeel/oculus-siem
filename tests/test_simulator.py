"""The simulator must drive the real detection pipeline: each attack scenario has to open its incident."""
import random

import pytest

from app.models import Incident, Resource, User
from app.services.ingest import record_event  # noqa: F401  (pipeline entry point used by emit)
from app import simulate as sim
from tests.conftest import ADMIN


@pytest.fixture()
def world(app):
    employees = User.query.filter(User.role != "Admin").order_by(User.employee_id).all()
    return random.Random(3), employees, Resource.query.all()


def play(steps):
    for s in steps:
        sim.emit(s)


def rules():
    return {i.rule_id for i in Incident.query}


def test_brute_force_scenario_opens_brute_force_then_credential_compromise(world):
    play(sim.scenario_brute_force(*world))
    assert {"R-BF-001", "R-CRED-001"} <= rules()


def test_honeypot_scenario_opens_honeypot_incident(world):
    play(sim.scenario_honeypot(*world))
    assert "R-HP-001" in rules()


def test_snooping_scenario_opens_reconnaissance_incident(world):
    play(sim.scenario_snooping(*world))
    assert "R-ACC-001" in rules()


def test_spraying_scenario_opens_spraying_incident(world):
    rng, employees, files = world
    play(sim.scenario_spraying(rng, employees, files))
    assert "R-SPRAY-001" in rules()


def test_attackers_use_documentation_ranges_only(world):
    for scenario in (sim.scenario_brute_force, sim.scenario_spraying):
        assert all(s["ip"].startswith(sim.EXTERNAL_RANGES) for s in scenario(*world))


def test_normal_traffic_never_touches_decoys_or_forbidden_files(world):
    rng, employees, files = world
    for _ in range(300):
        s = sim.normal_event(rng, employees, files)
        if s["type"] == "access_granted":
            assert not s["resource"].is_honeypot and s["user"].role in s["resource"].allowed_roles()


def test_run_loop_emits_events_and_stops(app):
    ticks = iter(range(10_000))
    count = sim.run(duration=5, rate=4, attack_every=1, rng=random.Random(1), echo=lambda _: None,
                    sleep=lambda _: None, clock=lambda: next(ticks) * 0.25)
    assert count > 5


def test_cli_refuses_to_run_without_seed_data(app):
    from app.extensions import db
    db.session.execute(db.delete(User)); db.session.commit()
    result = app.test_cli_runner().invoke(args=["simulate", "--duration", "1"])
    assert result.exit_code != 0 and "seed" in result.output
