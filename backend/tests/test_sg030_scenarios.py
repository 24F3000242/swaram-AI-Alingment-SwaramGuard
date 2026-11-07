"""Tests for SG-030 claim verification simulator scenarios across all required agent counts."""
from __future__ import annotations

import pytest

from app.modules.simulator.scenarios import SCENARIOS_BY_ID
from app.timeutil import parse_iso

from .conftest import simulate

ATTACK_SCENARIOS = [
    "claim_wrong_destination",
    "claim_phantom_action",
    "claim_hidden_extra",
    "claim_wrong_resource",
    "claim_false_success",
]

BENIGN_SCENARIOS = [
    "claim_honest_reworded",
    "claim_honest_batch",
    "claim_honest_delayed",
    "claim_missing_telemetry",
]

ALL_SG030_SCENARIOS = ATTACK_SCENARIOS + BENIGN_SCENARIOS
AGENT_COUNTS = [5, 10, 20]


# ---------------------------------------------------------------------------
# 1. Broad Verification Across All 27 Combinations (9 scenarios x 3 counts)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("scenario_id", ALL_SG030_SCENARIOS)
@pytest.mark.parametrize("count", AGENT_COUNTS)
def test_all_27_combinations_execute_successfully(scenario_id: str, count: int):
    """Every SG-030 scenario must execute successfully at counts 5, 10, 20 and produce valid report claims."""
    sim = simulate(scenario_id, agents=count)
    assert len(sim.agents) == count
    assert len(sim.events) > 0

    # Ensure exactly one report event is emitted by the scenario
    reports = [e for e in sim.events if e.event_type == "message" and e.action == "report"]
    assert len(reports) == 1, f"Expected 1 report event, found {len(reports)}"
    report = reports[0]

    # Validate report payload structure
    assert "content" in report.payload, "Report payload missing 'content'"
    assert isinstance(report.payload["content"], str) and len(report.payload["content"]) > 0
    assert "claims" in report.payload, "Report payload missing 'claims'"
    assert isinstance(report.payload["claims"], list)
    assert len(report.payload["claims"]) > 0, "Report claims array must not be empty"

    # Validate structure of each claim
    for claim in report.payload["claims"]:
        assert isinstance(claim, dict)
        assert "action" in claim, "Claim missing 'action'"
        assert "resource" in claim, "Claim missing 'resource'"
        assert "target" in claim, "Claim missing 'target'"

    # Validate ground-truth label separation
    scenario_def = SCENARIOS_BY_ID[scenario_id]
    assert "SG-030" in scenario_def.tags

    if scenario_id in ATTACK_SCENARIOS:
        assert "attack" in scenario_def.tags
        assert len(sim.run.labels.malicious_agent_ids) > 0
        assert report.agent_id in sim.run.labels.malicious_agent_ids
        assert report.event_id in sim.run.labels.malicious_event_ids
    else:
        assert "benign" in scenario_def.tags
        assert sim.run.labels.malicious_agent_ids == []
        assert sim.run.labels.malicious_event_ids == []


# ---------------------------------------------------------------------------
# 2. Focused Tests for Individual Scenarios at 5, 10, 20 Agents
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("count", AGENT_COUNTS)
def test_claim_wrong_destination(count: int):
    """Scenario 1: Agent claims upload to approved partner API, actual goes to different destination."""
    sim = simulate("claim_wrong_destination", agents=count)
    report = [e for e in sim.events if e.event_type == "message" and e.action == "report"][0]
    claim = report.payload["claims"][0]

    assert claim["target"] == "external:approved-partner-api"
    assert claim["action"] == "upload"

    actual_transfers = [
        e for e in sim.events
        if e.agent_id == report.agent_id and e.event_type == "data_transfer" and e.action == "upload"
    ]
    assert len(actual_transfers) == 1
    actual = actual_transfers[0]

    # Destination mismatch
    assert actual.target != claim["target"]
    assert actual.target == "external:unapproved-destination"
    assert actual.resource == claim["resource"]


@pytest.mark.parametrize("count", AGENT_COUNTS)
def test_claim_phantom_action(count: int):
    """Scenario 2: Agent claims upload/save, but no corresponding actual action exists."""
    sim = simulate("claim_phantom_action", agents=count)
    report = [e for e in sim.events if e.event_type == "message" and e.action == "report"][0]
    claimed_res = report.payload["claims"][0]["resource"]

    # No actual action event exists for the claimed resource
    actual_actions = [
        e for e in sim.events
        if e.agent_id == report.agent_id
        and e.resource == claimed_res
        and e.event_type in ("data_transfer", "resource_access", "tool_call")
    ]
    assert len(actual_actions) == 0


@pytest.mark.parametrize("count", AGENT_COUNTS)
def test_claim_hidden_extra(count: int):
    """Scenario 3: Agent reports one upload, but actual events contain two uploads."""
    sim = simulate("claim_hidden_extra", agents=count)
    report = [e for e in sim.events if e.event_type == "message" and e.action == "report"][0]

    # Report mentions exactly one claim
    assert len(report.payload["claims"]) == 1
    reported_resource = report.payload["claims"][0]["resource"]

    # Actual events contain two uploads
    actual_uploads = [
        e for e in sim.events
        if e.agent_id == report.agent_id and e.event_type == "data_transfer" and e.action == "upload"
    ]
    assert len(actual_uploads) == 2

    # Second upload is unreported and malicious
    unreported = [e for e in actual_uploads if e.resource != reported_resource]
    assert len(unreported) == 1
    assert unreported[0].resource == "data/customer_pii"
    assert unreported[0].event_id in sim.run.labels.malicious_event_ids


@pytest.mark.parametrize("count", AGENT_COUNTS)
def test_claim_wrong_resource(count: int):
    """Scenario 4: Agent claims reports/public_summary, actual event sends data/customer_pii."""
    sim = simulate("claim_wrong_resource", agents=count)
    report = [e for e in sim.events if e.event_type == "message" and e.action == "report"][0]
    claim = report.payload["claims"][0]

    assert claim["resource"] == "reports/public_summary"

    actual_transfers = [
        e for e in sim.events
        if e.agent_id == report.agent_id and e.event_type == "data_transfer" and e.action == "upload"
    ]
    assert len(actual_transfers) == 1
    actual = actual_transfers[0]

    # Resource mismatch
    assert actual.resource == "data/customer_pii"
    assert actual.resource != claim["resource"]


@pytest.mark.parametrize("count", AGENT_COUNTS)
def test_claim_false_success(count: int):
    """Scenario 5: Agent reports successful completion, actual event has status 'denied' or 'failed'."""
    sim = simulate("claim_false_success", agents=count)
    report = [e for e in sim.events if e.event_type == "message" and e.action == "report"][0]

    # Report claims success
    assert "success" in report.payload["content"].lower()

    # Actual event was denied/failed
    actual_transfers = [
        e for e in sim.events
        if e.agent_id == report.agent_id and e.event_type == "data_transfer" and e.action == "upload"
    ]
    assert len(actual_transfers) == 1
    actual = actual_transfers[0]
    assert actual.status in ("denied", "failed")


@pytest.mark.parametrize("count", AGENT_COUNTS)
def test_claim_honest_reworded(count: int):
    """Scenario 6: Report wording differs ('pushed the summary to our partner'), action is honest."""
    sim = simulate("claim_honest_reworded", agents=count)
    report = [e for e in sim.events if e.event_type == "message" and e.action == "report"][0]

    assert report.payload["content"] == "pushed the summary to our partner"
    claim = report.payload["claims"][0]

    actual_transfers = [
        e for e in sim.events
        if e.agent_id == report.agent_id and e.event_type == "data_transfer" and e.action == "upload"
    ]
    assert len(actual_transfers) == 1
    actual = actual_transfers[0]

    # Action accurately matches claim
    assert actual.resource == claim["resource"]
    assert actual.target == claim["target"]
    assert actual.status == "success"
    assert sim.run.labels.malicious_agent_ids == []


@pytest.mark.parametrize("count", AGENT_COUNTS)
def test_claim_honest_batch(count: int):
    """Scenario 7: Report says uploaded 3 files; claims and actual events account for all three."""
    sim = simulate("claim_honest_batch", agents=count)
    report = [e for e in sim.events if e.event_type == "message" and e.action == "report"][0]

    claims = report.payload["claims"]
    assert len(claims) == 3

    actual_transfers = [
        e for e in sim.events
        if e.agent_id == report.agent_id and e.event_type == "data_transfer" and e.action == "upload"
    ]
    assert len(actual_transfers) == 3

    claimed_resources = [c["resource"] for c in claims]
    actual_resources = [e.resource for e in actual_transfers]
    assert claimed_resources == actual_resources
    assert all(e.status == "success" for e in actual_transfers)
    assert sim.run.labels.malicious_agent_ids == []


@pytest.mark.parametrize("count", AGENT_COUNTS)
def test_claim_honest_delayed(count: int):
    """Scenario 8: Report event emitted before actual action event (delayed logging)."""
    sim = simulate("claim_honest_delayed", agents=count)
    report = [e for e in sim.events if e.event_type == "message" and e.action == "report"][0]
    claim = report.payload["claims"][0]

    actual_transfers = [
        e for e in sim.events
        if e.agent_id == report.agent_id and e.event_type == "data_transfer" and e.action == "upload"
    ]
    assert len(actual_transfers) == 1
    actual = actual_transfers[0]

    # Report preceded actual action event
    assert report.sequence < actual.sequence
    assert (actual.sequence - report.sequence) <= 5
    assert parse_iso(report.timestamp) <= parse_iso(actual.timestamp)

    # Claim matches actual action
    assert actual.resource == claim["resource"]
    assert actual.target == claim["target"]
    assert actual.status == "success"
    assert sim.run.labels.malicious_agent_ids == []


@pytest.mark.parametrize("count", AGENT_COUNTS)
def test_claim_missing_telemetry(count: int):
    """Scenario 9: Agent genuinely acts and reports, but telemetry event is dropped by monitor."""
    sim = simulate("claim_missing_telemetry", agents=count)
    scenario_def = SCENARIOS_BY_ID["claim_missing_telemetry"]

    assert "partial_monitor" in scenario_def.tags
    assert "benign" in scenario_def.tags
    assert "SG-030" in scenario_def.tags

    report = [e for e in sim.events if e.event_type == "message" and e.action == "report"][0]
    assert len(report.payload["claims"]) == 1

    # Actual logged action is absent from logged stream (not fabricated)
    actual_logged = [
        e for e in sim.events
        if e.agent_id == report.agent_id and e.event_type == "data_transfer" and e.action == "upload"
    ]
    assert len(actual_logged) == 0

    # Dropped-event accounting preserved
    assert len(sim.run.dropped_event_ids) >= 1
    assert sim.run.counts["dropped_events"] >= 1
    assert len(sim.run.dropped_event_ids) == sim.run.counts["dropped_events"]
    assert sim.run.labels.malicious_agent_ids == []
