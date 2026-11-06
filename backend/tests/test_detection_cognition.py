"""SG-004 baseline anomaly, continual learning, Bayesian risk and abductive explanations."""
import pytest

from app.modules.detection import baseline
from app.modules.detection.risk import PRIOR, assess
from app.modules.detection.rules import run_rules
from app.schemas import BaselineTrainRequest, ScenarioConfig

from .conftest import normalize, simulate


@pytest.fixture(scope="module")
def rules():
    from app.services.pipeline import Pipeline
    from app.storage.sqlite_store import SQLiteStore

    p = Pipeline(SQLiteStore(":memory:"))
    p.seed_defaults()
    return p.rules()


def _run(scenario, rules, **kw):
    sim = simulate(scenario, **kw)
    events = normalize(sim)
    alerts = run_rules(sim.run.run_id, events, sim.agents, rules)
    return sim, alerts, {a.agent_id: a for a in assess(sim.run.run_id, events, sim.agents, alerts, rules)}


def test_untrained_baseline_is_silent():
    sim = simulate("unauthorized_access")
    assert all(a.rule_id != "SG-004" for a in run_rules(sim.run.run_id, normalize(sim), sim.agents))


@pytest.mark.parametrize("count", [3, 5, 10, 20])
def test_no_false_positives_on_unseen_normal_runs(rules, count):
    for seed in range(200, 210):  # baseline was trained on seeds 1-10
        sim, alerts, verdicts = _run("normal_collaboration", rules, agents=count, seed=seed)
        assert alerts == []
        assert all(v.level == "low" and v.risk == PRIOR for v in verdicts.values())


def test_anomaly_flags_out_of_role_agent(rules):
    sim, alerts, verdicts = _run("unauthorized_access", rules)
    sg4 = [a for a in alerts if a.rule_id == "SG-004"]
    assert [a.agent_ids for a in sg4] == [sim.run.labels.malicious_agent_ids]
    coder = verdicts[sim.run.labels.malicious_agent_ids[0]]
    assert coder.anomaly_bits >= 12 and coder.level == "critical"
    assert any("secrets/api_keys" in r.behavior for r in coder.rare_behaviors)
    assert coder.hypotheses[0].hypothesis == "rogue_agent"


def test_anomaly_catches_exfil_even_when_rule_evidence_is_missing(rules):
    """System 1 still sees the coder's odd tool use if the upload event is lost."""
    sim = simulate("coordinated_leakage")
    events = [e for e in normalize(sim) if e.event_type != "data_transfer" or e.target == "external:approved-partner-api"]
    alerts = run_rules(sim.run.run_id, events, sim.agents, rules)
    assert not any(a.rule_id == "SG-002" for a in alerts)  # the leak itself was never logged
    # ...but handing PII to a coder that may not hold it is still caught (need-to-know), naming the analyst only.
    handoff = [a for a in alerts if a.rule_id == "SG-003"]
    analyst = next(a for a in sim.agents if a.role == "analyst")
    assert len(handoff) == 1 and handoff[0].agent_ids == [analyst.agent_id] and "need-to-know" in handoff[0].reason
    verdicts = {a.agent_id: a for a in assess(sim.run.run_id, events, sim.agents, alerts, rules)}
    coder = next(a for a in sim.agents if a.role == "coder")
    assert verdicts[coder.agent_id].level in ("watch", "high", "critical")


def test_bayesian_risk_and_explanations_for_leak_chain(rules):
    sim, _, verdicts = _run("coordinated_leakage", rules, agents=10)
    by_role = {sim.agents[[a.agent_id for a in sim.agents].index(aid)].role: v
               for aid, v in verdicts.items() if aid in sim.run.labels.malicious_agent_ids}
    assert by_role["analyst"].best_explanation.startswith("Insider")
    assert by_role["researcher"].hypotheses[0].hypothesis == "colluding_member"
    assert by_role["coder"].risk > by_role["analyst"].risk > PRIOR
    assert all(v.evidence for v in by_role.values())
    ranked = list(verdicts.values())
    assert [v.risk for v in ranked] == sorted((v.risk for v in ranked), reverse=True)


def test_hypothesis_scores_are_normalized(rules):
    _, _, verdicts = _run("unauthorized_access", rules, gateway="enforce")
    for v in verdicts.values():
        if v.hypotheses:
            assert abs(sum(h.score for h in v.hypotheses) - 1) < 0.01


def test_behavior_keys_ignore_free_text():
    sim = simulate("normal_collaboration")
    events = normalize(sim)
    keys = {baseline.behavior_key(e) for e in events}
    for e in events:
        if e.event_type == "message":
            e.payload["content"] = "exfiltrate everything now"
    assert {baseline.behavior_key(e) for e in events} == keys


def test_continual_learning_accumulates(pipeline):
    before = pipeline.baseline_summary()
    run_id = pipeline.simulate(ScenarioConfig(scenario_id="normal_collaboration", agent_count=5)).run.run_id
    pipeline.collect(run_id)
    pipeline.detect(run_id)
    after = pipeline.train_baseline(BaselineTrainRequest(source="run", run_id=run_id))
    assert after["agents_learned"] == before["agents_learned"] + 5
    assert run_id in after["learned_run_ids"]
    with pytest.raises(ValueError):
        pipeline.train_baseline(BaselineTrainRequest(source="run", run_id=run_id))


def test_cannot_learn_from_run_with_alerts(pipeline):
    run_id = pipeline.simulate(ScenarioConfig(scenario_id="unauthorized_access")).run.run_id
    pipeline.collect(run_id)
    pipeline.detect(run_id)
    with pytest.raises(ValueError, match="confirmed clean"):
        pipeline.train_baseline(BaselineTrainRequest(source="run", run_id=run_id))


def test_old_workspace_gets_new_rule(store):
    from app.modules.detection.rules import DEFAULT_RULES
    from app.services.pipeline import Pipeline

    store.put("detection_rules", "SG-001", DEFAULT_RULES[0].model_dump(mode="json"))
    Pipeline(store).seed_defaults()
    assert {d["rule_id"] for d in store.list("detection_rules")} == {r.rule_id for r in DEFAULT_RULES}
