"""Real-agent demo: an outside platform that never asks the gate; the network stops the leak anyway."""
import pytest

from app.services.agent_demo import ATTACKS, run_local
from app.services.egress_proxy import resolve_map


@pytest.mark.parametrize("attack", sorted(ATTACKS))
def test_attack_is_refused_at_the_network_and_legit_work_still_flows(attack):
    res, _ = run_local(attack=attack, log=lambda m: None)
    analyst = [u for u in res.uploads if u["agent"] == "analyst"]
    assert analyst and all(u["status"] == 403 for u in analyst)  # refused by the proxy, though no gate was asked
    assert res.leaked == []  # no restricted data reached the outside world
    legit = [u for u in res.uploads if u["agent"] == "researcher"]
    assert len(legit) == 2 and all(u["status"] == 200 for u in legit)  # the approved partner upload went through
    assert {r["host"] for r in res.received} == {"approved-partner-api"}
    assert "demo-analyst" in {**res.control["paused"], **res.control["held_egress"]}  # contained
    rules = {a["rule_id"] for a in res.alerts if "demo-analyst" in a["agent_ids"]}
    assert "SG-002" in rules
    if attack != "internal_goal":
        assert "SG-012" in rules  # injections are traced to the untrusted ticket; an internal goal has no such source
    assert not any(a["agent_ids"] and set(a["agent_ids"]) - {"demo-analyst"} for a in res.alerts)  # nobody else blamed


def test_summary_reads_well():
    res, _ = run_local(attack="poisoned_ticket", log=lambda m: None)
    text = res.summary()
    assert "REFUSED 403" in text and "restricted data: none" in text and "SENT" in text


def test_resolve_map():
    assert resolve_map("approved-partner-api=127.0.0.1:9900, *=10.0.0.5:80,bad") == {
        "approved-partner-api": ("127.0.0.1", 9900), "*": ("10.0.0.5", 80)}
