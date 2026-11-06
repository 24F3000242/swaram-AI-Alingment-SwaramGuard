"""Tests for the user-directed autonomous multi-agent simulation."""
from __future__ import annotations

import json
from pathlib import Path
import pytest

from app.adapters.base import DeterministicAdapter
from app.modules.simulator.engine import export_events_jsonl, run_simulation
from app.modules.simulator.environment import SharedEnvironment, get_environment
from app.modules.simulator.tools import ToolRegistry
from app.schemas import Agent, ScenarioConfig


def test_scenario_config_user_task():
    cfg = ScenarioConfig(
        scenario_id="user_directed",
        user_task="Build a resilient cache manager with TTL support",
        gateway_mode="enforce",
    )
    assert cfg.user_task == "Build a resilient cache manager with TTL support"
    assert cfg.scenario_id == "user_directed"
    assert cfg.agent_count == 5


def test_user_directed_deterministic_run(tmp_path: Path):
    workspace = tmp_path / "test_workspace"
    cfg = ScenarioConfig(
        scenario_id="user_directed",
        user_task="Implement a rate-limiting algorithm",
        agent_backend="deterministic",
        gateway_mode="enforce",
        workspace_dir=str(workspace),
    )
    result = run_simulation(cfg)
    assert result.run.scenario_id == "user_directed"
    assert len(result.agents) == 5
    assert len(result.events) > 15

    # Check that disk workspace contains all expected files
    expected_files = [
        "docs/wiki/plan.md",
        "docs/wiki/research_notes.md",
        "data/public/analysis_report.json",
        "repo/src/solution.py",
        "repo/src/test_solution.py",
        "docs/wiki/review_report.md",
        "docs/wiki/final_summary.md",
    ]
    for rel_path in expected_files:
        disk_file = workspace / rel_path
        assert disk_file.is_file(), f"Expected {rel_path} to exist on disk"
        content = disk_file.read_text(encoding="utf-8")
        assert len(content) > 10, f"File {rel_path} was empty"

    # Verify canonical export
    export_file = tmp_path / "canonical.jsonl"
    export_events_jsonl(result, export_file)
    assert export_file.is_file()
    with open(export_file, "r", encoding="utf-8") as f:
        lines = [json.loads(line) for line in f]
    assert len(lines) == len(result.events)
    for evt in lines:
        assert "run_id" in evt
        assert "event_id" in evt
        assert "timestamp" in evt
        assert "event_type" in evt


def test_tool_registry_list_files_and_delete_db():
    env = SharedEnvironment("test-env-tools")
    from app.modules.simulator.engine import AgentRunner
    from app.timeutil import utcnow
    import random
    from app.adapters.base import DeterministicAdapter
    from app.modules.simulator.gateway import PolicyGateway

    agent = Agent(
        agent_id="agt-coder-01",
        run_id="test-env-tools",
        name="Coder 1",
        role="coder",
        permissions=["repo/src", "docs/wiki", "data/projects"],
    )
    runner = AgentRunner(
        "test-env-tools",
        "tools01",
        utcnow(),
        random.Random(42),
        PolicyGateway("monitor"),
        DeterministicAdapter(),
        env=env,
    )

    # 1. Test list_files
    list_res = runner.tools.list_files(agent, prefix="docs")
    assert list_res.success is True
    assert isinstance(list_res.data, list)

    # 2. Test insert and delete database
    ins_res = runner.tools.insert_database(agent, "projects", {"title": "Test Project"})
    assert ins_res.success is True
    rec_id = ins_res.data["record_id"]
    del_res = runner.tools.delete_database(agent, "projects", rec_id)
    assert del_res.success is True
    assert del_res.data["deleted"] is True


def test_disk_mirroring_reads_and_deletes(tmp_path: Path):
    env = SharedEnvironment("test-mirror", workspace_dir=tmp_path)
    # File write should write to disk
    env.fs.write_file("repo/src/test_mod.py", "X = 1\n")
    disk_file = tmp_path / "repo/src/test_mod.py"
    assert disk_file.is_file()
    assert disk_file.read_text(encoding="utf-8") == "X = 1\n"

    # Delete should delete from disk
    env.fs.delete_file("repo/src/test_mod.py")
    assert not disk_file.exists()


# =============================================================================
# REGRESSION TESTS FOR REVIEW / REVISION LOOP & AUDIT QUALITY GATES
# =============================================================================

class MockCodeAdapter(DeterministicAdapter):
    def __init__(self, mock_code: str | list | None = None) -> None:
        super().__init__()
        self.mock_solution_code = mock_code


def test_placeholder_implementation_is_rejected():
    """Prove that a dummy/placeholder return {'status': 'success'} is rejected by the Reviewer."""
    placeholder_code = (
        "def execute_task():\n"
        "    return {'task': 'demo', 'status': 'success', 'verified': True}\n"
    )
    adapter = MockCodeAdapter(placeholder_code)
    cfg = ScenarioConfig(
        scenario_id="user_directed",
        user_task="Build a resilient cache manager",
        agent_backend="deterministic",
    )
    res = run_simulation(cfg, adapter=adapter)

    # Check that reviewer emitted REVISE on complete events
    review_complete_events = [e for e in res.events if e.action == "complete" and e.payload.get("phase") == "review"]
    assert len(review_complete_events) >= 1
    assert all(e.payload.get("verdict") == "REVISE" for e in review_complete_events)

    # Check review report file
    report_file = get_environment(res.run.run_id).fs.get_file("docs/wiki/review_report.md")
    assert report_file is not None
    assert "REVISE" in report_file.content
    assert "hardcoded success stub" in report_file.content.lower()


def test_invalid_python_is_rejected():
    """Prove that invalid Python syntax is caught by AST parser and rejected."""
    broken_code = "def syntax_error(\n    print('unclosed paren'\n"
    adapter = MockCodeAdapter(broken_code)
    cfg = ScenarioConfig(
        scenario_id="user_directed",
        user_task="Implement a math parser",
        agent_backend="deterministic",
    )
    res = run_simulation(cfg, adapter=adapter)

    review_complete_events = [e for e in res.events if e.action == "complete" and e.payload.get("phase") == "review"]
    assert all(e.payload.get("verdict") == "REVISE" for e in review_complete_events)

    report_file = get_environment(res.run.run_id).fs.get_file("docs/wiki/review_report.md")
    assert report_file is not None
    assert "Invalid Python syntax" in report_file.content


def test_failing_implementation_is_rejected():
    """Prove that code that crashes or raises an exception during execution is rejected."""
    failing_code = (
        "def run():\n"
        "    raise RuntimeError('Fatal runtime initialization error')\n\n"
        "if __name__ == '__main__':\n"
        "    run()\n"
    )
    adapter = MockCodeAdapter(failing_code)
    cfg = ScenarioConfig(
        scenario_id="user_directed",
        user_task="Create an HTTP client wrapper",
        agent_backend="deterministic",
    )
    res = run_simulation(cfg, adapter=adapter)

    review_complete_events = [e for e in res.events if e.action == "complete" and e.payload.get("phase") == "review"]
    assert all(e.payload.get("verdict") == "REVISE" for e in review_complete_events)

    report_file = get_environment(res.run.run_id).fs.get_file("docs/wiki/review_report.md")
    assert report_file is not None
    assert "Execution verification failed" in report_file.content


def test_working_implementation_is_approved():
    """Prove that a valid, working, complete Python implementation is APPROVED."""
    adapter = MockCodeAdapter(None)  # Uses _generate_deterministic_solution
    cfg = ScenarioConfig(
        scenario_id="user_directed",
        user_task="Implement a thread-safe LRU cache",
        agent_backend="deterministic",
    )
    res = run_simulation(cfg, adapter=adapter)

    review_complete_events = [e for e in res.events if e.action == "complete" and e.payload.get("phase") == "review"]
    assert any(e.payload.get("verdict") == "APPROVED" for e in review_complete_events)

    report_file = get_environment(res.run.run_id).fs.get_file("docs/wiki/review_report.md")
    assert report_file is not None
    assert "APPROVED" in report_file.content


def test_rejected_work_triggers_revision():
    """Prove that an initial rejection triggers a revision round that Coder fixes."""
    broken_code = "def broken():\n    pass  # todo: implement\n"
    working_sol = (
        "class TokenBucket:\n"
        "    def __init__(self, rate: int = 10):\n"
        "        self.rate = rate\n"
        "    def allow(self) -> bool:\n"
        "        return True\n"
    )
    working_test = (
        "import unittest\n"
        "from solution import TokenBucket\n\n"
        "class TestBucket(unittest.TestCase):\n"
        "    def test_bucket(self):\n"
        "        b = TokenBucket()\n"
        "        self.assertTrue(b.allow())\n\n"
        "if __name__ == '__main__':\n"
        "    unittest.main()\n"
    )
    adapter = MockCodeAdapter([broken_code, (working_sol, working_test)])
    cfg = ScenarioConfig(
        scenario_id="user_directed",
        user_task="Build token bucket rate limiter",
        agent_backend="deterministic",
    )
    res = run_simulation(cfg, adapter=adapter)

    # Must have feedback event from planner
    feedback_events = [e for e in res.events if e.action == "feedback"]
    assert len(feedback_events) == 1
    assert feedback_events[0].payload.get("attempt") == 1

    # Attempt 1 was REVISE, Attempt 2 was APPROVED
    review_complete_events = [e for e in res.events if e.action == "complete" and e.payload.get("phase") == "review"]
    assert len(review_complete_events) == 2
    assert review_complete_events[0].payload.get("verdict") == "REVISE"
    assert review_complete_events[1].payload.get("verdict") == "APPROVED"

    # Final planner task completion
    final_event = [e for e in res.events if e.agent_id.startswith("agt-") and "deliverables" in e.payload][0]
    assert final_event.payload.get("status") == "completed"
    assert final_event.payload.get("attempts") == 2


def test_planner_cannot_mark_failed_work_completed():
    """Prove that if work cannot pass review after 3 attempts, Planner marks it failed."""
    placeholder_code = (
        "def execute_task():\n"
        "    return {'status': 'success'}\n"
    )
    adapter = MockCodeAdapter(placeholder_code)
    cfg = ScenarioConfig(
        scenario_id="user_directed",
        user_task="Build distributed lock manager",
        agent_backend="deterministic",
    )
    res = run_simulation(cfg, adapter=adapter)

    # 3 review attempts, all REVISE
    review_complete_events = [e for e in res.events if e.action == "complete" and e.payload.get("phase") == "review"]
    assert len(review_complete_events) == 3
    assert all(e.payload.get("verdict") == "REVISE" for e in review_complete_events)

    # Planner must record failed, NOT completed
    final_events = [e for e in res.events if "deliverables" in e.payload]
    assert len(final_events) == 1
    final_event = final_events[0]
    assert final_event.payload.get("status") == "failed"
    assert final_event.payload.get("verdict") == "REVISE"
    assert final_event.payload.get("attempts") == 3
    assert final_event.action == "failed"

    # Database records failed
    db_records = get_environment(res.run.run_id).db.query("projects", lambda r: r.get("status") == "failed")
    assert len(db_records) >= 1
    assert db_records[0]["verdict"] == "REVISE"
