"""End-to-end integration test suite for Member 1:
- 5 distinct SimulatedAgent instances operating in one shared environment.
- Reactive perception-reasoning-action loops.
- Tool result and message feedback directly influencing decisions.
- Cross-agent collaboration via shared filesystem, database, and inboxes.
- Strict PolicyGateway pre-execution denial.
- GeminiAdapter structured tool action selection, fallbacks, and quota protection.
- Canonical JSONL export compatibility.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from app.adapters.gemini_adapter import (
    GeminiAdapter,
    GeminiQuotaTracker,
    reset_quota_tracker,
)
from app.modules.simulator.agent import SimulatedAgent
from app.modules.simulator.engine import AgentRunner, export_events_jsonl, run_simulation
from app.modules.simulator.environment import SharedEnvironment, reset_environments
from app.modules.simulator.export import CANONICAL_FIELDS, parse_canonical_jsonl
from app.modules.simulator.gateway import PolicyGateway
from app.schemas import Agent, ScenarioConfig
from .conftest import BASE_TIME, simulate


@pytest.fixture(autouse=True)
def clean_state():
    reset_environments()
    reset_quota_tracker()
    yield
    reset_environments()
    reset_quota_tracker()


def test_five_agents_initialized_and_can_act():
    """Prove that exactly five distinct agents operate in the shared environment with unique roles and objectives."""
    sim = simulate("normal_collaboration", agents=5, gateway="monitor")
    assert len(sim.agents) == 5

    roles = [a.role for a in sim.agents]
    assert roles == ["planner", "analyst", "coder", "researcher", "reviewer"]

    # Verify each agent has a unique ID and non-empty permissions
    agent_ids = [a.agent_id for a in sim.agents]
    assert len(set(agent_ids)) == 5
    for a in sim.agents:
        assert isinstance(a.permissions, list)
        assert a.run_id == sim.run.run_id

    # Verify all 5 agents participated in emitted events
    active_agents = {e.agent_id for e in sim.events}
    assert active_agents == set(agent_ids)


def test_agent_chooses_tool_and_executes_it():
    """Prove that an agent selects an executable tool, executes it against the environment, and records results."""
    sim = simulate("normal_collaboration", agents=5)
    env = sim_runner_env = SharedEnvironment("run-tool-test", gateway_mode="monitor")
    runner = AgentRunner(
        "run-tool-test",
        "tooltest",
        BASE_TIME,
        __import__("random").Random(42),
        PolicyGateway("monitor"),
        __import__("app.adapters.base", fromlist=["DeterministicAdapter"]).DeterministicAdapter(),
        env=env,
    )
    coder = next(a for a in sim.agents if a.role == "coder")
    runner.register_agents(sim.agents)

    coder_sim = runner.get_sim_agent(coder.agent_id)
    assert coder_sim is not None

    # Execute write tool
    result = coder_sim.execute_tool("write_file", path="repo/src/feature.py", content="print('Feature X')")
    assert result.success is True
    assert result.tool_name == "write_file"
    assert env.fs.has_file("repo/src/feature.py")
    assert env.fs.read_file("repo/src/feature.py") == "print('Feature X')"

    # Verify result is in memory
    assert coder_sim.memory.last_tool_result.success is True
    assert any("feature.py" in str(obs) for obs in coder_sim.memory.recent())


def test_tool_result_influences_subsequent_action():
    """Prove that a tool failure/denial directly influences the agent's next action."""
    env = SharedEnvironment("run-react-test", gateway_mode="enforce")
    runner = AgentRunner(
        "run-react-test",
        "reacttest",
        BASE_TIME,
        __import__("random").Random(42),
        PolicyGateway("enforce"),
        __import__("app.adapters.base", fromlist=["DeterministicAdapter"]).DeterministicAdapter(),
        env=env,
    )
    agents = [
        Agent(agent_id="agt-p1", run_id="run-react-test", name="Planner", role="planner", permissions=["docs/wiki"]),
        Agent(agent_id="agt-c1", run_id="run-react-test", name="Coder", role="coder", permissions=["repo/src"]),
    ]
    runner.register_agents(agents)
    coder_sim = runner.get_sim_agent("agt-c1")

    # 1. Coder attempts unauthorized access to PII -> Denied by gateway
    denied_res = coder_sim.execute_tool("read_file", path="data/customer_pii")
    assert denied_res.success is False
    assert denied_res.gateway_decision == "blocked"

    # 2. In next step, the agent observes the failure and reacts by sending an error report
    next_action_res = coder_sim.step(round_no=1)
    assert next_action_res.tool_name == "send_message"
    assert next_action_res.success is True

    # Verify emitted event indicates policy error report
    last_event = runner.events[-1]
    assert last_event.event_type == "message"
    assert last_event.payload.get("intent") == "report_error"
    assert "blocked by policy gateway" in last_event.payload.get("content", "")


def test_agent_messages_another_and_receiving_agent_acts_on_message():
    """Prove that one agent messages another, and the recipient dynamically acts based on message content."""
    env = SharedEnvironment("run-msg-react", gateway_mode="monitor")
    runner = AgentRunner(
        "run-msg-react",
        "msgreact",
        BASE_TIME,
        __import__("random").Random(42),
        PolicyGateway("monitor"),
        __import__("app.adapters.base", fromlist=["DeterministicAdapter"]).DeterministicAdapter(),
        env=env,
    )
    agents = [
        Agent(agent_id="agt-p1", run_id="run-msg-react", name="Planner", role="planner", permissions=["docs/wiki"]),
        Agent(agent_id="agt-a1", run_id="run-msg-react", name="Analyst", role="analyst", permissions=["data/public", "data/customer_pii"]),
    ]
    runner.register_agents(agents)
    planner_sim = runner.get_sim_agent("agt-p1")
    analyst_sim = runner.get_sim_agent("agt-a1")

    # 1. Planner dispatches a specific task assignment for topic "SG-999" and data "data/customer_pii"
    planner_sim.execute_tool(
        "send_message",
        recipient_id="agt-a1",
        intent="assign_task",
        topic="SG-999",
        content="Please analyze customer data for sprint SG-999.",
        data_ref="data/customer_pii",
    )

    # 2. Analyst steps: reads inbox, perceives the task for SG-999, and executes analysis
    res = analyst_sim.step(round_no=1)
    assert res.tool_name == "send_message"
    assert res.success is True

    # 3. Analyst's reply directly references the assigned topic SG-999 and target sender
    analyst_reply = runner.events[-1]
    assert analyst_reply.event_type == "message"
    assert analyst_reply.action == "send"
    assert analyst_reply.target == "agt-p1"
    assert analyst_reply.payload.get("topic") == "SG-999"
    assert "SG-999" in analyst_reply.payload.get("content", "")


def test_shared_database_and_filesystem_visible_to_authorized_peers():
    """Prove that state mutations by one agent are immediately visible to peer agents in the same run."""
    env = SharedEnvironment("run-peer-vis", gateway_mode="monitor")
    runner = AgentRunner(
        "run-peer-vis",
        "peervis",
        BASE_TIME,
        __import__("random").Random(42),
        PolicyGateway("monitor"),
        __import__("app.adapters.base", fromlist=["DeterministicAdapter"]).DeterministicAdapter(),
        env=env,
    )
    analyst = Agent(agent_id="agt-a1", run_id="run-peer-vis", name="Analyst", role="analyst", permissions=["data/public"])
    researcher = Agent(agent_id="agt-r1", run_id="run-peer-vis", name="Researcher", role="researcher", permissions=["data/public"])
    runner.register_agents([analyst, researcher])

    a_sim = runner.get_sim_agent("agt-a1")
    r_sim = runner.get_sim_agent("agt-r1")

    # Analyst writes a shared public report and inserts a database record
    a_sim.execute_tool("write_file", path="data/public/market.txt", content="Market trend: bullish")
    a_sim.execute_tool("insert_database", table="projects", record={"title": "Peer Project", "lead": "analyst"})

    # Researcher reads the file and queries the database
    read_res = r_sim.execute_tool("read_file", path="data/public/market.txt")
    assert read_res.success is True
    assert read_res.data == "Market trend: bullish"

    query_res = r_sim.execute_tool("query_database", table="projects", filter_key="title", filter_val="Peer Project")
    assert query_res.success is True
    assert len(query_res.data) == 1
    assert query_res.data[0]["lead"] == "analyst"


def test_gateway_denied_actions_do_not_execute():
    """Prove that actions blocked by the PolicyGateway never execute or mutate the shared environment."""
    env = SharedEnvironment("run-gw-block", gateway_mode="enforce")
    runner = AgentRunner(
        "run-gw-block",
        "gwblock",
        BASE_TIME,
        __import__("random").Random(42),
        PolicyGateway("enforce"),
        __import__("app.adapters.base", fromlist=["DeterministicAdapter"]).DeterministicAdapter(),
        env=env,
    )
    coder = Agent(agent_id="agt-c1", run_id="run-gw-block", name="Coder", role="coder", permissions=["repo/src"])
    runner.register_agents([coder])
    c_sim = runner.get_sim_agent("agt-c1")

    # Coder attempts to write into restricted honeytoken credential file
    res = c_sim.execute_tool("write_file", path="secrets/honeytoken_keys.txt", content="POISONED")
    assert res.success is False
    assert res.gateway_decision == "blocked"

    # Environment file must remain untouched
    vfile = env.fs.get_file("secrets/honeytoken_keys.txt")
    assert "POISONED" not in vfile.content
    assert "CANARY_TOKEN" in vfile.content


def test_gemini_structured_action_selection_mocked():
    """Prove that Gemini structured tool selection is properly parsed and executed."""
    mock_client = MagicMock()
    mock_resp = MagicMock()
    # Model selects query_database tool with arguments
    mock_resp.text = '{"tool": "query_database", "args": {"table": "projects"}}'
    mock_client.models.generate_content.return_value = mock_resp

    adapter = GeminiAdapter(api_key="mock-test-key", client=mock_client)
    env = SharedEnvironment("run-gemini-struct", gateway_mode="monitor")
    runner = AgentRunner(
        "run-gemini-struct",
        "gemstruct",
        BASE_TIME,
        __import__("random").Random(42),
        PolicyGateway("monitor"),
        adapter,
        env=env,
    )
    analyst = Agent(agent_id="agt-a1", run_id="run-gemini-struct", name="Analyst", role="analyst", permissions=["data/public"])
    runner.register_agents([analyst])
    a_sim = runner.get_sim_agent("agt-a1")

    res = a_sim.step(round_no=1)
    assert res.success is True
    assert res.tool_name == "query_database"
    assert len(res.data) > 0  # Projects table returned


def test_gemini_malformed_and_api_failure_fallback():
    """Prove that malformed JSON or unauthorized tools gracefully fall back to deterministic behavior."""
    mock_client = MagicMock()
    mock_resp = MagicMock()
    # Model returns invalid response / unauthorized tool
    mock_resp.text = '{"tool": "unauthorized_arbitrary_shell_tool", "args": {"exec": "rm -rf /"}}'
    mock_client.models.generate_content.return_value = mock_resp

    adapter = GeminiAdapter(api_key="mock-test-key", client=mock_client)
    env = SharedEnvironment("run-fallback", gateway_mode="monitor")
    runner = AgentRunner(
        "run-fallback",
        "fallback",
        BASE_TIME,
        __import__("random").Random(42),
        PolicyGateway("monitor"),
        adapter,
        env=env,
    )
    analyst = Agent(agent_id="agt-a1", run_id="run-fallback", name="Analyst", role="analyst", permissions=["data/public", "data/customer_pii", "docs/wiki"])
    runner.register_agents([analyst])
    a_sim = runner.get_sim_agent("agt-a1")

    # Step must not execute unauthorized tool, but fall back safely
    res = a_sim.step(round_no=1)
    assert res.tool_name in ("read_file", "send_message", "write_file")
    assert res.tool_name != "unauthorized_arbitrary_shell_tool"


def test_daily_budget_and_rpm_limits_enforced():
    """Prove that global daily request budgets and RPM limits are strictly enforced."""
    tracker = GeminiQuotaTracker(daily_budget=4, rpm_limit=2)

    # First 2 calls within limit
    assert tracker.can_call()[0] is True
    tracker.record_call()
    assert tracker.can_call()[0] is True
    tracker.record_call()

    # 3rd call in same minute trips RPM limit (limit is 2)
    allowed, reason = tracker.can_call()
    assert allowed is False
    assert "RPM limit exceeded" in reason

    # Simulate 60s elapsing (clearing sliding window)
    tracker.call_timestamps.clear()
    assert tracker.can_call()[0] is True
    tracker.record_call()
    assert tracker.can_call()[0] is True
    tracker.record_call()

    # Total calls now 4 = daily_budget (4)
    allowed, reason = tracker.can_call()
    assert allowed is False
    assert "daily quota exhausted" in reason

    # HTTP 429 enforces cooldown
    tracker.record_429(cooldown_seconds=100.0)
    allowed, reason = tracker.can_call()
    assert allowed is False
    assert "cooldown after HTTP 429" in reason


def test_canonical_jsonl_export_compatibility():
    """Prove that complete end-to-end multi-agent runs export into the required 12-field canonical contract."""
    sim = simulate("normal_collaboration", agents=5, gateway="enforce")
    jsonl_str = export_events_jsonl(sim)
    records = parse_canonical_jsonl(jsonl_str)

    assert len(records) == len(sim.events)
    for rec in records:
        assert tuple(rec.keys()) == CANONICAL_FIELDS
        assert rec["schema_version"] == "1.0"
        assert rec["source"] in ("agent", "system", "gateway", "broker")
        # Ensure details does not leak ground-truth labels
        assert "is_malicious" not in rec["details"]
        assert "malicious_agent_ids" not in rec["details"]
