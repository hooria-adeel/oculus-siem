from .rules import RULES


def evaluate(event) -> list:
    """Run every rule whose trigger matches this event; each Finding is raised as/merged into an incident."""
    from .. import incidents  # local import: incidents -> models only, but keeps import graph one-directional

    raised = []
    for rule in RULES:
        if event.event_type not in rule.triggers:
            continue
        finding = rule.evaluate(event)
        if finding is not None:
            raised.append(incidents.raise_finding(finding, event))
    return raised
