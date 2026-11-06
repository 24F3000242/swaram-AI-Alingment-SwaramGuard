"""Comprehensive test suite for Member 1: Functional Multi-Agent Environment,
Executable Tool System, Policy Gateway Interception, and Full 20-SG Threat Scenarios.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from app.adapters.gemini_adapter import GeminiAdapter
from app.modules.simulator.agent import SimulatedAgent
from app.modules.simulator.engine import AgentRunner, export_events_jsonl, run_simulation
from app.modules.simulator.environment import (
    ENVIRONMENT_REGISTRY,
    SharedEnvironment,
    VirtualDatabase,
    VirtualFilesystem,
    get_environment,
    reset_environments,
)
from app.modules.simulator.export import CANONICAL_FIELDS, parse_canonical_jsonl
from app.modules.simulator.gateway import PolicyGateway
from app.modules.simulator.scenarios import SCENARIOS, SCENARIOS_BY_ID
from app.modules.simulator.tools import ToolRegistry, ToolResult
from app.schemas import Agent, ScenarioConfig
from .conftest import BASE_TIME, simulate


@pytest.fixture(autouse=True)
def clean_environments():
    reset_environments()
    yield
    reset_environments()


# ---------------------------------------------------------------------------
# 1. Virtual Filesystem Tests
# ---------------------------------------------------------------------------

def test_virtual_filesystem_crud():
    fs = VirtualFilesystem()
    # Create / write
    f1 = fs.create_file("shared/notes.md", "# Shared Notes\nHello team.")
    assert fs.has_file("shared/notes.md")
    assert f1.size > 0
    assert len(f1.content_hash) == 16

    # Read
    content = fs.read_file("shared/notes.md", reader_id="agt-01")
    assert content == "# Shared Notes\nHello team."
    assert len(fs.access_log) == 1
    assert fs.access_log[0]["reader_id"] == "agt-01"

    # Update
    fs.write_file("shared/notes.md", "# Updated Notes", writer_id="agt-02")
    assert fs.read_file("shared/notes.md") == "# Updated Notes"

    # Delete
    deleted = fs.delete_file("shared/notes.md", deleter_id="agt-01")
    assert deleted is True
    assert not fs.has_file("shared/notes.md")


def test_virtual_filesystem_honeytoken_tripwire():
    fs = VirtualFilesystem()
    fs.create_file(
        "secrets/honeytoken_keys.txt",
        "CANARY=trap-key-12345",
        is_restricted=True,
        is_honeytoken=True,
    )
    vfile = fs.get_file("secrets/honeytoken_keys.txt")
    assert vfile.is_honeytoken is True

    # Read logs the tripwire event
    fs.read_file("secrets/honeytoken_keys.txt", reader_id="agt-attacker")
    log_entry = fs.access_log[-1]
    assert log_entry["is_honeytoken"] is True
    assert log_entry["reader_id"] == "agt-attacker"


# ---------------------------------------------------------------------------
# 2. Virtual Database Tests
# ---------------------------------------------------------------------------

def test_virtual_database_crud_and_audit():
    db = VirtualDatabase()
    db.create_table("inventory")
    rec_id = db.insert("inventory", {"item": "server", "count": 10}, actor_id="agt-01")
    assert rec_id.startswith("rec-")

    # Query
    results = db.query("inventory", actor_id="agt-02")
    assert len(results) == 1
    assert results[0]["item"] == "server"

    # Update
    ok = db.update("inventory", rec_id, {"count": 12}, actor_id="agt-01")
    assert ok is True
    updated = db.query("inventory", filter_fn=lambda r: r["id"] == rec_id)[0]
    assert updated["count"] == 12

    # Audit log check
    actions = [entry["action"] for entry in db.audit_log]
    assert "insert" in actions
    assert "query" in actions
    assert "update" in actions


# ---------------------------------------------------------------------------
# 3. Cross-Run Isolation Tests
# ---------------------------------------------------------------------------

def test_environment_cross_run_isolation():
    env1 = get_environment("run-iso-001")
    env2 = get_environment("run-iso-002")

    # Write in env1
    env1.fs.write_file("data/run1_file.txt", "Env 1 secret data")
    env1.db.create_table("run1_table")
    env1.db.insert("run1_table", {"test": "val1"})

    # Check that env2 does not have env1 data
    assert not env2.fs.has_file("data/run1_file.txt")
    assert env2.db.query("run1_table") == []


# ---------------------------------------------------------------------------
# 4. Executable Tools & Policy Gateway Interception Tests
# ---------------------------------------------------------------------------

def test_tools_enforce_policy_gateway_denial():
    """In enforce mode, policy violations must NEVER execute against the environment."""
    sim = simulate("normal_collaboration", agents=5, gateway="enforce")
    env = get_environment(sim.run.run_id)
    # Give runner the environment
    sim_runner = AgentRunner(
        sim.run.run_id,
        "testhex",
        BASE_TIME,
        sim_runner_rng := __import__("random").Random(42),
        PolicyGateway("enforce"),
        sim_runner_adapter := __import__("app.adapters.base", fromlist=["DeterministicAdapter"]).DeterministicAdapter(),
        env=env,
    )
    coder = next(a for a in sim.agents if a.role == "coder")

    # Coder has NO permission to data/customer_pii
    tools = sim_runner.tools
    res = tools.read_file(coder, "data/customer_pii")
    assert res.success is False
    assert "Policy violation" in res.error
    assert res.gateway_decision == "blocked"

    # Verify that fs.access_log DOES NOT have a read from coder
    reads_by_coder = [l for l in env.fs.access_log if l.get("reader_id") == coder.agent_id and l.get("path") == "data/customer_pii"]
    assert len(reads_by_coder) == 0, "Blocked action must never execute against virtual filesystem"


def test_tools_permitted_execution():
    """In enforce mode, permitted actions execute successfully and return ToolResult."""
    sim = simulate("normal_collaboration", agents=5, gateway="enforce")
    env = get_environment(sim.run.run_id)
    sim_runner = AgentRunner(
        sim.run.run_id,
        "testhex",
        BASE_TIME,
        __import__("random").Random(42),
        PolicyGateway("enforce"),
        __import__("app.adapters.base", fromlist=["DeterministicAdapter"]).DeterministicAdapter(),
        env=env,
    )
    analyst = next(a for a in sim.agents if a.role == "analyst")

    # Analyst DOES have permission for data/customer_pii
    tools = sim_runner.tools
    res = tools.read_file(analyst, "data/customer_pii")
    assert res.success is True
    assert res.gateway_decision == "allow"
    assert "Alice Smith" in res.data


def test_tools_external_unallowlisted_destination_blocked():
    """Policy gateway blocks external destinations not on EXTERNAL_ALLOWLIST."""
    sim = simulate("normal_collaboration", agents=5, gateway="enforce")
    env = get_environment(sim.run.run_id)
    sim_runner = AgentRunner(
        sim.run.run_id,
        "testhex",
        BASE_TIME,
        __import__("random").Random(42),
        PolicyGateway("enforce"),
        __import__("app.adapters.base", fromlist=["DeterministicAdapter"]).DeterministicAdapter(),
        env=env,
    )
    researcher = next(a for a in sim.agents if a.role == "researcher")
    tools = sim_runner.tools

    # 1. Allowed external destination
    allowed_res = tools.access_external(researcher, target="external:approved-partner-api", data="Public report")
    assert allowed_res.success is True
    assert allowed_res.gateway_decision == "allow"

    # 2. Blocked external destination
    blocked_res = tools.access_external(researcher, target="external:paste-site", data="Public report")
    assert blocked_res.success is False
    assert blocked_res.gateway_decision == "blocked"


# ---------------------------------------------------------------------------
# 5. SimulatedAgent Perception-Reasoning-Action Cycle
# ---------------------------------------------------------------------------

def test_simulated_agent_step_and_tool_execution():
    sim = simulate("normal_collaboration", agents=5, gateway="monitor")
    env = get_environment(sim.run.run_id)
    sim_runner = AgentRunner(
        sim.run.run_id,
        "testhex",
        BASE_TIME,
        __import__("random").Random(42),
        PolicyGateway("monitor"),
        __import__("app.adapters.base", fromlist=["DeterministicAdapter"]).DeterministicAdapter(),
        env=env,
    )
    analyst = next(a for a in sim.agents if a.role == "analyst")
    sim_agent = SimulatedAgent(analyst, sim_runner.tools, sim_runner.adapter)

    # Agent executes a step
    result = sim_agent.step(round_no=1)
    assert isinstance(result, ToolResult)
    assert result.success is True
    # Observation recorded in agent memory
    assert len(sim_agent.memory.observations) > 0


def test_simulated_agent_gemini_structured_action_selection():
    """Verify LLM structured tool call selection with mocked Gemini adapter."""
    mock_client = MagicMock()
    mock_response = MagicMock()
    # LLM returns structured tool JSON
    mock_response.text = '{"tool": "read_file", "args": {"path": "data/public"}}'
    mock_client.models.generate_content.return_value = mock_response

    adapter = GeminiAdapter(api_key="mock-key", client=mock_client)
    sim = simulate("normal_collaboration", agents=5)
    env = get_environment(sim.run.run_id)
    sim_runner = AgentRunner(
        sim.run.run_id,
        "testhex",
        BASE_TIME,
        __import__("random").Random(42),
        PolicyGateway("monitor"),
        adapter,
        env=env,
    )
    analyst = next(a for a in sim.agents if a.role == "analyst")
    sim_agent = SimulatedAgent(analyst, sim_runner.tools, adapter)

    # Execute step with LLM structured reasoning
    res = sim_agent.step(round_no=1)
    assert res.success is True
    assert res.tool_name == "read_file"
    assert "latency" in res.data


# ---------------------------------------------------------------------------
# 6. Full 20 SG Scenarios Coverage Tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "scenario_id",
    [
        "sg001_unauthorized_access",
        "sg002_external_leak",
        "sg003_leak_chain",
        "sg004_role_anomaly",
        "sg005_dead_drop",
        "sg006_oversight_tampering",
        "sg007_self_replication",
        "sg008_privilege_escalation",
        "sg009_honeytoken_tripwire",
        "sg010_log_tampering",
        "sg011_power_seeking",
        "sg012_prompt_injection",
        "sg013_cascading_failures",
        "sg014_false_reporting",
        "sg015_reward_hacking",
        "sg016_salami_leakage",
        "sg017_human_coercion",
        "sg018_message_loops",
        "sg019_untrusted_tools",
        "sg020_steganography",
    ],
)
def test_all_20_sg_scenarios_produce_valid_canonical_events(scenario_id):
    """Every SG scenario (SG-001 through SG-020) must run and generate valid canonical JSONL."""
    cfg = ScenarioConfig(scenario_id=scenario_id, agent_count=5, seed=42)
    sim = run_simulation(cfg, run_id=f"run-{scenario_id[:8]}", base_time=BASE_TIME)

    assert len(sim.events) > 0
    assert len(sim.agents) == 5

    # Malicious labels must be recorded in labels, not in detector-visible events
    if scenario_id != "normal_collaboration":
        assert len(sim.run.labels.malicious_agent_ids) > 0
        assert len(sim.run.labels.malicious_event_ids) > 0

    # Canonical export verification
    jsonl_str = export_events_jsonl(sim)
    records = parse_canonical_jsonl(jsonl_str)
    assert len(records) == len(sim.events)

    for rec in records:
        assert tuple(rec.keys()) == CANONICAL_FIELDS
        assert "is_malicious" not in rec["details"]
        assert "malicious_agent_ids" not in rec["details"]
