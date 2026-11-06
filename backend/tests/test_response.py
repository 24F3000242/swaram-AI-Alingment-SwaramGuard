from app.modules.detection.rules import run_rules
from app.modules.response.policy import DEFAULT_POLICY, respond

from .conftest import normalize, simulate


def _run(gateway: str, mode: str, scenario: str = "unauthorized_access"):
    sim = simulate(scenario, gateway=gateway)
    events = normalize(sim)
    alerts = run_rules(sim.run.run_id, events, sim.agents)
    return alerts, respond(alerts, events, DEFAULT_POLICY.model_copy(update={"mode": mode}))


def test_simulate_mode_never_claims_blocked():
    for gateway in ("monitor", "enforce"):
        _, actions = _run(gateway, "simulate")
        assert actions and all(a.outcome in ("would_block", "would_pause") and not a.enforced and a.mode == "simulated"
                               for a in actions)


def test_enforce_without_gateway_evidence_is_still_would_block():
    # Monitor-mode gateway let all 3 reads complete -> escalated to critical -> pause.
    _, actions = _run("monitor", "enforce")
    assert all(a.outcome == "would_pause" and not a.enforced for a in actions)
    assert "cannot be retroactively prevented" in actions[0].note


def test_enforce_with_gateway_denial_is_blocked():
    alerts, actions = _run("enforce", "enforce")
    assert all(a.outcome == "blocked" and a.enforced and a.mode == "enforced" for a in actions)
    assert all(a.gateway_event_ids for a in actions)
    assert {a.alert_id for a in actions} == {al.alert_id for al in alerts}


def test_pause_and_overrides():
    sim = simulate("coordinated_leakage")
    events = normalize(sim)
    alerts = run_rules(sim.run.run_id, events, sim.agents)
    actions = {a.alert_id: a for a in respond(alerts, events)}
    chain = next(a for a in alerts if a.rule_id == "SG-003")
    assert actions[chain.alert_id].decision == "pause" and actions[chain.alert_id].outcome == "would_pause"

    policy = DEFAULT_POLICY.model_copy(update={"rule_overrides": {"SG-003": "alert", "SG-002": "allow"}})
    outcomes = {a.alert_id: a.outcome for a in respond(alerts, events, policy)}
    assert outcomes[chain.alert_id] == "alerted"
    assert "allowed" in outcomes.values()
