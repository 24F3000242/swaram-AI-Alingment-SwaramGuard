import pytest

from app.modules.simulator.gateway import PolicyGateway
from app.schemas import Agent

from .conftest import simulate


@pytest.mark.parametrize("count", [3, 5, 10, 20])
@pytest.mark.parametrize("scenario", ["normal_collaboration", "unauthorized_access", "coordinated_leakage"])
def test_ids_unique_and_consistent(scenario, count):
    sim = simulate(scenario, agents=count)
    assert len(sim.agents) == count
    ids = [e.event_id for e in sim.events]
    assert len(ids) == len(set(ids))
    agent_ids = {a.agent_id for a in sim.agents}
    assert all(e.run_id == sim.run.run_id for e in sim.events)
    assert all(e.agent_id in agent_ids for e in sim.events)
    assert set(sim.run.labels.malicious_agent_ids) <= agent_ids


def test_deterministic_given_seed():
    a, b = simulate("coordinated_leakage"), simulate("coordinated_leakage")
    assert [e.model_dump() for e in a.events] == [e.model_dump() for e in b.events]
    c = simulate("coordinated_leakage", seed=99)
    assert [e.model_dump() for e in a.events] != [e.model_dump() for e in c.events]


def test_normal_has_no_labels():
    sim = simulate("normal_collaboration")
    assert sim.run.labels.malicious_agent_ids == []
    assert all(e.gateway_decision in (None, "not_checked", "allow") for e in sim.events)


def test_monitor_mode_never_blocks():
    sim = simulate("unauthorized_access", gateway="monitor")
    decisions = {e.gateway_decision for e in sim.events}
    assert "would_block" in decisions and "blocked" not in decisions
    assert all(e.status != "denied" for e in sim.events)


def test_enforce_mode_denies_before_execution():
    sim = simulate("unauthorized_access", gateway="enforce")
    blocked = [e for e in sim.events if e.gateway_decision == "blocked"]
    assert len(blocked) == 3
    assert all(e.status == "denied" for e in blocked)


def test_leakage_relay_for_large_swarms():
    assert len(simulate("coordinated_leakage", agents=5).run.labels.malicious_agent_ids) == 2
    assert len(simulate("coordinated_leakage", agents=10).run.labels.malicious_agent_ids) == 3


def test_drop_rate_removes_events():
    full, dropped = simulate("normal_collaboration"), simulate("normal_collaboration", drop=0.3)
    assert len(dropped.events) + len(dropped.run.dropped_event_ids) == len(full.events)
    assert 0 < len(dropped.run.dropped_event_ids) < len(full.events)


def test_gateway_decisions():
    coder = Agent(agent_id="a", run_id="r", name="c", role="coder", permissions=["repo/src"])
    assert PolicyGateway("monitor").check(coder, resource="repo/src").decision == "not_checked"
    assert PolicyGateway("monitor").check(coder, resource="secrets/api_keys").decision == "would_block"
    assert PolicyGateway("enforce").check(coder, resource="secrets/api_keys").decision == "blocked"
    assert PolicyGateway("enforce").check(coder, target="external:approved-partner-api").decision == "allow"
    assert PolicyGateway("off").check(coder, resource="secrets/api_keys").decision == "not_checked"


def test_unknown_scenario():
    with pytest.raises(ValueError):
        simulate("nope")
