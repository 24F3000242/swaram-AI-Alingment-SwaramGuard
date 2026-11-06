"""Per-agent baselines (SG-025): compare each agent with its OWN history, not only its role."""
import copy

import pytest

from app.modules.detection import baseline
from app.modules.detection.risk import assess
from app.modules.detection.rules import run_rules
from app.schemas import BaselineTrainRequest, ScenarioConfig

from .conftest import inject, normalize, simulate


@pytest.fixture(scope="module")
def trained():
    from app.services.pipeline import Pipeline
    from app.storage.sqlite_store import SQLiteStore

    return Pipeline(SQLiteStore(":memory:")).rules()


def only(alerts, rule_id):
    return [a for a in alerts if a.rule_id == rule_id]


def access(role, action, resource, **kw):
    return {"role": role, "event_type": "resource_access", "action": action, "resource": resource, **kw}


def with_history(rules, identity, edit):
    """Rules whose baseline gives `identity` a specialised history (real agents specialise; our simulator's don't)."""
    rules = copy.deepcopy(rules)
    prof = next(r for r in rules if r.rule_id == "SG-004").params["profile"]
    edit(prof["identities"][identity])
    return rules


def test_identities_are_learned(trained):
    prof = next(r for r in trained if r.rule_id == "SG-004").params["profile"]
    assert prof["version"] == baseline.PROFILE_VERSION and "Analyst 1" in prof["identities"]
    a1 = prof["identities"]["Analyst 1"]
    assert a1["role"] == "analyst" and a1["runs"] >= 30 and "resource_access:read:data/customer_pii" in a1["behaviors"]


def test_takeover_new_sensitive_behavior_for_this_agent(trained):
    """An analyst that never touches PII starts reading it: normal for analysts, abnormal for this one."""
    rules = with_history(trained, "Analyst 1", lambda h: h["behaviors"].pop("resource_access:read:data/customer_pii"))
    sim, events, ids = inject([access("analyst", "read", "data/public")])
    alerts = run_rules(sim.run.run_id, events, sim.agents, rules)
    hit = only(alerts, "SG-025")
    analyst = next(a.agent_id for a in sim.agents if a.name == "Analyst 1")
    assert len(hit) == 1 and hit[0].agent_ids == [analyst] and "never did resource_access:read:data/customer_pii" in hit[0].reason
    assert not only(alerts, "SG-004")  # the role baseline sees nothing unusual
    verdict = next(v for v in assess(sim.run.run_id, events, sim.agents, alerts, rules) if v.agent_id == analyst)
    assert verdict.hypotheses[0].hypothesis == "takeover"


def test_volume_spike_below_fixed_budget(trained):
    sim, events, _ = inject([access("analyst", "read", "data/customer_pii")] * 4)
    alerts = run_rules(sim.run.run_id, events, sim.agents, trained)
    assert not only(alerts, "SG-016")  # under the fixed budget of 6
    hit = only(alerts, "SG-025")
    assert len(hit) == 1 and "usually" in hit[0].reason


def test_new_peers_alone_do_not_alert(trained):
    rules = with_history(trained, "Coder 1", lambda h: h["peers"].clear())
    sim = simulate("normal_collaboration")
    assert not only(run_rules(sim.run.run_id, normalize(sim), sim.agents, rules), "SG-025")


def test_new_peers_are_reported_as_context(trained):
    def edit(h):
        h["behaviors"].pop("resource_access:read:data/customer_pii")
        h["peers"].clear()
    rules = with_history(trained, "Analyst 1", edit)
    sim, events, _ = inject([])
    hit = only(run_rules(sim.run.run_id, events, sim.agents, rules), "SG-025")
    assert hit and "new peers" in hit[0].reason


def test_too_little_history_is_not_judged(trained):
    rules = with_history(trained, "Analyst 1", lambda h: (h["behaviors"].pop("resource_access:read:data/customer_pii"),
                                                         h.update(runs=3)))
    sim, events, _ = inject([])
    assert not only(run_rules(sim.run.run_id, events, sim.agents, rules), "SG-025")


def test_role_rare_behaviour_stays_with_sg004(trained):
    """Secrets reads are rare for coders: that's SG-004/SG-001's finding, not drift."""
    sim, events, _ = inject([access("coder", "read", "secrets/api_keys")])
    assert not only(run_rules(sim.run.run_id, events, sim.agents, trained), "SG-025")


def test_continual_learning_updates_identities(pipeline):
    before = baseline.summary(next(r for r in pipeline.rules() if r.rule_id == "SG-004").params["profile"])
    run_id = pipeline.simulate(ScenarioConfig(scenario_id="normal_collaboration", agent_count=5)).run.run_id
    pipeline.collect(run_id)
    pipeline.detect(run_id)
    prof_before = next(r for r in pipeline.rules() if r.rule_id == "SG-004").params["profile"]
    runs_before = prof_before["identities"]["Coder 1"]["runs"]
    after = pipeline.train_baseline(BaselineTrainRequest(source="run", run_id=run_id))
    prof = next(r for r in pipeline.rules() if r.rule_id == "SG-004").params["profile"]
    assert after["identities_learned"] == before["identities_learned"]
    assert prof["identities"]["Coder 1"]["runs"] == runs_before + 1


@pytest.mark.parametrize("scenario", ["normal_collaboration", "unauthorized_access", "coordinated_leakage"])
@pytest.mark.parametrize("count", [3, 5, 10, 20])
def test_no_drift_alerts_on_unseen_runs(trained, scenario, count):
    for seed in range(300, 305):
        sim = simulate(scenario, agents=count, seed=seed)
        assert not only(run_rules(sim.run.run_id, normalize(sim), sim.agents, trained), "SG-025")
