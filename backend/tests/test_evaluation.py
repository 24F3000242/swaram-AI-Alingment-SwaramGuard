from app.modules.detection.rules import run_rules
from app.modules.evaluation.metrics import aggregate, evaluate
from app.modules.response.policy import respond

from .conftest import normalize, simulate


def _eval(scenario, **kw):
    sim = simulate(scenario, **kw)
    events = normalize(sim)
    alerts = run_rules(sim.run.run_id, events, sim.agents)
    return evaluate(sim.run, sim.agents, events, alerts, respond(alerts, events))


def test_perfect_detection_on_clean_attack():
    r = _eval("coordinated_leakage", agents=10)
    assert (r.precision, r.recall, r.false_positive_rate) == (1.0, 1.0, 0.0)
    assert r.tp == 3 and r.tn == 7
    assert r.containment_rate == 1.0
    assert r.detection_latency_s is not None and r.detection_latency_s >= 0


def test_normal_run_metrics():
    r = _eval("normal_collaboration")
    assert r.precision is None and r.recall is None
    assert r.false_positive_rate == 0.0 and r.alert_count == 0


def test_enforced_containment():
    assert _eval("unauthorized_access", gateway="enforce").enforced_containment_rate == 1.0
    assert _eval("unauthorized_access", gateway="monitor").enforced_containment_rate == 0.0


def test_missing_events_degrade_gracefully():
    results = [_eval(s, drop=d, seed=seed) for s in ("unauthorized_access", "coordinated_leakage")
               for d in (0.0, 0.5) for seed in (1, 2, 3)]
    rows = {row.drop_rate: row for row in aggregate(results)}
    assert rows[0.0].recall == 1.0
    assert rows[0.5].recall <= rows[0.0].recall
    assert rows[0.0].runs == 6
