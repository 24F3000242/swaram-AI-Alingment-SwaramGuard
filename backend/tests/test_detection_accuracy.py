"""Accuracy work: evidence-aware rules, inference under missing data, and benchmark floors.

The floors below were measured with scripts/benchmark_detection.py; if a change pushes accuracy
under them, this test fails and the change needs a justification (or a better fix).
"""
import pytest

from app.modules.detection.benchmark import ALL_CASES, ATTACKS, BENIGN, build_trial, run_benchmark, score_trial
from app.modules.detection.evidence import LogCoverage
from app.modules.detection.rules import run_rules

from .conftest import inject, normalize, simulate


@pytest.fixture(scope="module")
def trained():
    from app.services.pipeline import Pipeline
    from app.storage.sqlite_store import SQLiteStore

    return Pipeline(SQLiteStore(":memory:")).rules()


def only(alerts, rule_id):
    return [a for a in alerts if a.rule_id == rule_id]


def agent(sim, role):
    return next(a.agent_id for a in sim.agents if a.role == role)


def access(role, action, resource, **kw):
    return {"role": role, "event_type": "resource_access", "action": action, "resource": resource, **kw}


def drop(events, event_ids):
    return [e for e in events if e.event_id not in set(event_ids)]


# ------------------------------------------------------------ LogCoverage
def test_log_coverage():
    sim = simulate("normal_collaboration")
    events = normalize(sim)
    full = LogCoverage(events)
    assert full.ratio == 1.0 and full.missing_between(events[3], events[9]) == 0
    holed = [e for e in events if e.sequence not in (5, 6, 7)]
    cov = LogCoverage(holed)
    assert cov.missing_between(events[2], events[9]) == 3 and cov.missing_between(events[9], events[12]) == 0
    assert cov.missing_around(events[5], 3) > 0 and round(cov.ratio, 3) == round((len(events) - 3) / len(events), 3)
    assert cov.estimate(7) == pytest.approx(7 / cov.ratio)
    assert cov.local_ratio(events[2], events[9]) == pytest.approx(5 / 8)  # bursty loss shows up locally
    assert cov.estimate(5, span=(events[2], events[9])) == pytest.approx(8)
    assert LogCoverage([e for e in events if e.sequence % 2]).estimate(4) == 4  # coverage < 60%: no extrapolation


# ------------------------------------------------------------ inference when hand-off evidence is missing
def test_leak_source_inferred_when_message_lost():
    sim, events, ids = inject([access("analyst", "read", "data/customer_pii"),
                               {"role": "analyst", "event_type": "message", "action": "send", "target": None,
                                "payload": {"data_ref": "data/customer_pii"}},
                               {"role": "coder", "event_type": "data_transfer", "action": "upload",
                                "resource": "data/customer_pii", "target": "external:paste-site"}])
    alerts = run_rules(sim.run.run_id, drop(events, [ids[1]]), sim.agents)
    inferred = [a for a in only(alerts, "SG-003") if "Inferred" in a.reason]
    assert len(inferred) == 1 and inferred[0].agent_ids == [agent(sim, "analyst"), agent(sim, "coder")]
    assert inferred[0].severity == "high"  # below the 'critical' of a fully evidenced chain


def test_no_inference_on_complete_log():
    """Without a gap, the absence of a hand-off is real evidence: don't invent a source."""
    sim, events, _ = inject([access("analyst", "read", "data/customer_pii"),
                             {"role": "coder", "event_type": "data_transfer", "action": "upload",
                              "resource": "data/customer_pii", "target": "external:paste-site"}])
    assert not [a for a in only(run_rules(sim.run.run_id, events, sim.agents), "SG-003") if "Inferred" in a.reason]


def test_dead_drop_pickup_inferred_when_read_lost():
    sim, events, ids = inject([access("analyst", "read", "data/customer_pii"), access("analyst", "write", "db/scratch_7"),
                               access("coder", "read", "db/scratch_7"),
                               {"role": "coder", "event_type": "data_transfer", "action": "upload", "resource": "db/scratch_7",
                                "target": "external:paste-site"}])
    hit = only(run_rules(sim.run.run_id, drop(events, [ids[2]]), sim.agents), "SG-005")
    assert len(hit) == 1 and hit[0].agent_ids == [agent(sim, "analyst"), agent(sim, "coder")]
    assert "log gap" in hit[0].reason and hit[0].severity == "high"


# ------------------------------------------------------------ absence of evidence across a gap is not evidence
def test_lost_review_is_unverifiable_not_blamed():
    sim, events, ids = inject([access("coder", "write", "repo/src"), access("reviewer", "approve", "repo/src"),
                               access("coder", "write", "repo/main", payload={"source": "repo/src"})])
    hit = only(run_rules(sim.run.run_id, drop(events, [ids[1]]), sim.agents), "SG-023")
    assert len(hit) == 1 and hit[0].agent_ids == [] and hit[0].severity == "medium" and "may have been lost" in hit[0].reason


def test_lost_gateway_record_is_unverifiable_not_blamed():
    sim, events, ids = inject([access("coder", "write", "repo/src"),
                               {"role": "coder", "event_type": "observation", "action": "write", "resource": "repo/src",
                                "payload": {"source": "git-audit"}}])
    hit = only(run_rules(sim.run.run_id, drop(events, [ids[0]]), sim.agents), "SG-021")
    assert len(hit) == 1 and hit[0].agent_ids == [] and "can't be confirmed" in hit[0].reason


def test_coverage_adjusted_salami(trained):
    sim, events, ids = inject([access("analyst", "read", "data/customer_pii")] * 8, gap_s=30)
    analyst = agent(sim, "analyst")
    thinned = drop(events, [ids[1], ids[3], ids[5]])  # lost inside the burst, so the gaps can be bracketed
    visible = sum(e.agent_id == analyst and e.resource == "data/customer_pii" and e.event_type == "resource_access"
                  and e.timestamp >= events[-8].timestamp for e in thinned)
    assert visible <= 6  # under the raw budget: only extrapolating for the gaps can catch it
    assert only(run_rules(sim.run.run_id, thinned, sim.agents, trained), "SG-016")


# ------------------------------------------------------------ benchmark harness + accuracy floors
def test_benchmark_plants_and_scores():
    case = next(c for c in ATTACKS if c.name == "leak chain via message")
    trial = build_trial(case, 10, 1, 0.0)
    assert len(trial.injected) == 3 and all(eid in {e.event_id for e in trial.events} for eid in trial.injected)
    assert [e.sequence for e in trial.events] == sorted(e.sequence for e in trial.events)
    s = score_trial(trial, run_rules("r", trial.events, trial.agents))
    assert s.detected == 1 and s.fp == 0


def test_every_threat_has_a_case_and_benign_lookalikes_exist():
    assert len(ATTACKS) >= 26 and len(BENIGN) >= 10
    assert len({c.name for c in ALL_CASES}) == len(ALL_CASES)


def test_accuracy_floors(trained):
    res = run_benchmark(trained, run_rules, drop_rates=(0.0, 0.3), agent_counts=(5, 10), seeds=range(1, 3))
    clean, gappy = res["rows"]
    assert clean["precision"] == 1.0 and clean["false_positive_rate"] == 0.0
    assert clean["threat_detection_rate"] == 1.0 and clean["right_rule_rate"] == 1.0
    assert clean["benign_alarm_rate"] == 0.0 and gappy["benign_alarm_rate"] == 0.0
    assert gappy["precision"] == 1.0
    assert gappy["detection_given_evidence"] >= 0.8
