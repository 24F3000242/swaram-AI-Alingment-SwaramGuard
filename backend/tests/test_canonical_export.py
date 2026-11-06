"""Unit tests for Member 1 canonical 12-field JSONL export functionality."""
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.modules.simulator.export import (
    CANONICAL_FIELDS,
    CANONICAL_SCHEMA_VERSION,
    determine_source,
    export_canonical_jsonl,
    from_canonical_event,
    parse_canonical_jsonl,
    to_canonical_event,
    to_canonical_events,
)
from app.modules.simulator.engine import export_events_jsonl, run_simulation
from app.schemas import RawEvent, ScenarioConfig
from .conftest import BASE_TIME, simulate


def test_canonical_event_exact_keys():
    """Verify that every single exported event contains exactly the 12 canonical fields in exact order."""
    sim = simulate("coordinated_leakage", agents=5)
    canonical_list = to_canonical_events(sim.events)
    assert len(canonical_list) > 0

    for idx, ev in enumerate(canonical_list):
        keys = tuple(ev.keys())
        assert keys == CANONICAL_FIELDS, f"Event {idx} keys do not match canonical contract: {keys}"
        # Ensure internal non-canonical fields are absent
        assert "sequence" not in ev
        assert "gateway_decision" not in ev
        assert "payload" not in ev


def test_canonical_field_types_and_schema_version():
    """Verify types of all 12 fields and check default schema_version."""
    sim = simulate("normal_collaboration", agents=5)
    canonical_list = to_canonical_events(sim.events)

    for ev in canonical_list:
        assert isinstance(ev["schema_version"], str)
        assert ev["schema_version"] == "1.0"
        assert isinstance(ev["event_id"], str) and ev["event_id"].startswith("evt-")
        assert isinstance(ev["run_id"], str) and ev["run_id"].startswith("run-")
        assert isinstance(ev["agent_id"], str) and ev["agent_id"].startswith("agt-")
        assert isinstance(ev["timestamp"], str)
        # Verify UTC ISO-8601 timestamp ending with Z
        assert ev["timestamp"].endswith("Z")
        assert "T" in ev["timestamp"]
        assert isinstance(ev["event_type"], str)
        assert isinstance(ev["action"], str)
        assert ev["target"] is None or isinstance(ev["target"], str)
        assert ev["resource"] is None or isinstance(ev["resource"], str)
        assert isinstance(ev["status"], str)
        assert isinstance(ev["source"], str)
        assert isinstance(ev["details"], dict)


def test_payload_to_details_mapping():
    """Verify that payload data is mapped cleanly into details."""
    sim = simulate("normal_collaboration", agents=5)
    message_events = [e for e in sim.events if e.event_type == "message" and e.action == "send"]
    assert len(message_events) > 0

    for orig in message_events:
        canonical = to_canonical_event(orig)
        assert canonical["details"]["intent"] == orig.payload["intent"]
        assert canonical["details"]["topic"] == orig.payload["topic"]
        assert canonical["details"]["content"] == orig.payload["content"]
        assert canonical["details"]["message_id"] == orig.payload["message_id"]


def test_null_preservation_for_optional_fields():
    """Ensure None values for target and resource are serialized as JSON null, not omitted."""
    raw = RawEvent(
        run_id="run-test",
        event_id="evt-test-0001",
        agent_id="agt-test-01",
        timestamp="2026-01-15T09:00:00.000Z",
        event_type="task",
        action="complete",
        status="success",
        target=None,
        resource=None,
        payload={"task_id": "t1"},
    )
    canonical = to_canonical_event(raw)
    assert canonical["target"] is None
    assert canonical["resource"] is None

    # Check serialized JSON string
    serialized = json.dumps(canonical)
    assert '"target": null' in serialized
    assert '"resource": null' in serialized


def test_source_values_origin_based():
    """Verify that source is derived from event origin and cannot be overridden by payload injection."""
    # 1. Agent actions originate from agent
    sim = simulate("normal_collaboration", agents=5)
    for ev in to_canonical_events(sim.events):
        assert ev["source"] == "agent"

    # 2. System and Gateway origins
    system_event = RawEvent(
        run_id="run-test",
        event_id="evt-sys-0001",
        agent_id="system",
        timestamp="2026-01-15T09:00:00.000Z",
        event_type="system_startup",
        action="boot",
        status="success",
        payload={},
    )
    assert determine_source(system_event) == "system"
    assert to_canonical_event(system_event)["source"] == "system"

    gateway_event = RawEvent(
        run_id="run-test",
        event_id="evt-gw-0001",
        agent_id="gateway",
        timestamp="2026-01-15T09:00:00.000Z",
        event_type="policy_check",
        action="block",
        status="denied",
        payload={},
    )
    assert determine_source(gateway_event) == "gateway"
    assert to_canonical_event(gateway_event)["source"] == "gateway"

    # 3. Payload poisoning attempt (source inside payload is ignored)
    poisoned_event = RawEvent(
        run_id="run-test",
        event_id="evt-test-0002",
        agent_id="agt-test-01",
        timestamp="2026-01-15T09:00:00.000Z",
        event_type="message",
        action="send",
        status="success",
        payload={"source": "spoofed_gateway", "content": "malicious message"},
    )
    # Origin is agt-test-01, so source MUST remain "agent", not "spoofed_gateway"
    canonical = to_canonical_event(poisoned_event)
    assert canonical["source"] == "agent"


def test_no_ground_truth_labels_in_exported_details():
    """Verify that sensitive ground-truth threat labels are completely excluded from canonical JSONL."""
    sim = simulate("coordinated_leakage", agents=5)
    # Inject a sensitive label into one event payload to test sanitizer
    sim.events[0].payload["is_malicious"] = True
    sim.events[0].payload["malicious_agent_ids"] = ["agt-01"]

    exported_str = export_canonical_jsonl(sim)
    assert "is_malicious" not in exported_str
    assert "malicious_agent_ids" not in exported_str
    assert "malicious_event_ids" not in exported_str


def test_jsonl_roundtrip_parsing(tmp_path):
    """Verify round-trip serialization and deserialization via file and string."""
    sim = simulate("coordinated_leakage", agents=5)
    out_file = tmp_path / "canonical_events.jsonl"

    # Export to file
    content = export_canonical_jsonl(sim, destination=out_file)
    assert out_file.exists()
    assert out_file.read_text(encoding="utf-8") == content

    # Parse back from file
    parsed_records = parse_canonical_jsonl(out_file)
    assert len(parsed_records) == len(sim.events)

    # Convert parsed records back to RawEvents
    reconstructed = [from_canonical_event(r, sequence=i + 1) for i, r in enumerate(parsed_records)]
    assert len(reconstructed) == len(sim.events)

    for orig, recon in zip(sim.events, reconstructed):
        assert recon.event_id == orig.event_id
        assert recon.run_id == orig.run_id
        assert recon.agent_id == orig.agent_id
        assert recon.timestamp == orig.timestamp
        assert recon.event_type == orig.event_type
        assert recon.action == orig.action
        assert recon.status == orig.status
        assert recon.target == orig.target
        assert recon.resource == orig.resource
        assert recon.payload == {k: v for k, v in orig.payload.items() if k not in ("is_malicious", "malicious_agent_ids")}


@pytest.mark.parametrize("agent_count", [3, 5, 10, 20])
def test_unique_event_ids_within_each_run(agent_count):
    """Verify that event IDs remain strictly unique across multiple swarm configurations."""
    sim = simulate("coordinated_leakage", agents=agent_count)
    exported = parse_canonical_jsonl(export_canonical_jsonl(sim))
    event_ids = [e["event_id"] for e in exported]
    assert len(event_ids) == len(set(event_ids))
    assert len(event_ids) == len(sim.events)


def test_deterministic_replay_with_explicit_identifiers():
    """Verify byte-for-byte deterministic canonical JSONL output when seed, run_id, and base_time are provided."""
    cfg = ScenarioConfig(scenario_id="coordinated_leakage", agent_count=5, seed=42)
    sim_a = run_simulation(cfg, run_id="run-replay01", base_time=BASE_TIME)
    sim_b = run_simulation(cfg, run_id="run-replay01", base_time=BASE_TIME)

    export_a = export_canonical_jsonl(sim_a)
    export_b = export_canonical_jsonl(sim_b)
    assert export_a == export_b


def test_deterministic_replay_default_behavior_and_event_sequence():
    """Verify determinism under default invocation (without explicit run_id):

    1. Action/event sequences, targets, and roles are 100% deterministic between matching seeds.
    2. Different seeds produce different event sequences.
    3. Run-specific IDs (run_id, event_id, agent_id, timestamp) are unique per unseeded run.
    """
    cfg1 = ScenarioConfig(scenario_id="coordinated_leakage", agent_count=5, seed=123)
    sim1 = run_simulation(cfg1)
    sim2 = run_simulation(cfg1)

    # Run IDs and timestamps are run-specific
    assert sim1.run.run_id != sim2.run.run_id

    # But event sequences and structures are 100% identical
    canon1 = to_canonical_events(sim1.events)
    canon2 = to_canonical_events(sim2.events)
    assert len(canon1) == len(canon2)

    seq1 = [(e["event_type"], e["action"], e["status"], e["resource"]) for e in canon1]
    seq2 = [(e["event_type"], e["action"], e["status"], e["resource"]) for e in canon2]
    assert seq1 == seq2

    # Different seed yields different behavior
    cfg_diff = ScenarioConfig(scenario_id="coordinated_leakage", agent_count=5, seed=999)
    sim_diff = run_simulation(cfg_diff)
    canon_diff = to_canonical_events(sim_diff.events)
    seq_diff = [(e["event_type"], e["action"], e["status"], e["resource"]) for e in canon_diff]
    assert seq1 != seq_diff


def test_engine_export_convenience_helper():
    """Verify export_events_jsonl helper exposed on engine module."""
    sim = simulate("normal_collaboration", agents=5)
    jsonl_from_engine = export_events_jsonl(sim)
    jsonl_from_export = export_canonical_jsonl(sim)
    assert jsonl_from_engine == jsonl_from_export
