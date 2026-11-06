"""The live-guard speedups are pure caches: they must never leak state between callers or event lists."""
from app.modules.detection.advanced_rules import encoding_artifacts
from app.modules.detection.evidence import LogCoverage
from app.modules.simulator.engine import run_simulation
from app.modules.collector.normalizer import collect
from app.schemas import ScenarioConfig


def test_cached_text_scan_hands_out_independent_lists():
    text = "status ok\u200b\u200c\u200b"
    first = encoding_artifacts(text)
    first.append("unusually long message")  # SG-020 appends to the list it gets
    assert encoding_artifacts(text) == ["zero-width characters"]


def test_coverage_is_shared_within_one_list_and_never_across_lists():
    sim = run_simulation(ScenarioConfig(scenario_id="normal_collaboration", drop_rate=0.3, persist=False))
    events = collect([e.model_dump(mode="json") for e in sim.events], run_id=sim.run.run_id, agents=sim.agents).events
    assert LogCoverage.of(events) is LogCoverage.of(events)
    shorter = events[:-5]
    assert LogCoverage.of(shorter) is not LogCoverage.of(events)
    assert LogCoverage.of(shorter).seqs == LogCoverage(shorter).seqs


def test_sg025_spikes_only_count_sensitive_behaviour():
    """Real Gemini runs: an agent reading the wiki 4x (usually ~1x) was flagged. More PII reads than usual still is."""
    from app.modules.detection import baseline
    from app.schemas import Agent

    hist = {"runs": 10, "sum": 10, "sumsq": 10}
    profile = {"identities": {"Analyst 1": {"role": "analyst", "runs": 10, "peers": {},
                                            "behaviors": {"resource_access:read:docs/wiki": hist,
                                                          "resource_access:read:data/customer_pii": hist}}},
               "roles": {"analyst": {"agents": 10, "behaviors": {"resource_access:read:docs/wiki": 10,
                                                                 "resource_access:read:data/customer_pii": 10}}}}
    agent = Agent(agent_id="a", run_id="r", name="Analyst 1", role="analyst", permissions=["data/customer_pii", "docs/wiki"])
    drift = baseline.identity_drift(profile, agent, {"resource_access:read:docs/wiki": ["e"] * 5,
                                                     "resource_access:read:data/customer_pii": ["e"] * 5}, set(),
                                    restricted={"data/customer_pii"}, prefixes=["secrets/"])
    assert [s["behavior"] for s in drift["spikes"]] == ["resource_access:read:data/customer_pii"]
