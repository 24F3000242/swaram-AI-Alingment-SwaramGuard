"""Gemini quota for the app: estimate what a run needs and refuse up front instead of degrading mid-run.

Without this, a run started with too little quota quietly falls back to scripted text part-way through, which mixes
model-written and template behavior in one run and corrupts AI-mode results.
"""
from __future__ import annotations

from app.schemas import ScenarioConfig

AGENT_COUNTS = (3, 5, 10, 20)


def estimate_calls(agent_count: int, agent_mode: str = "scripted", user_task: bool = False, rounds: int = 2) -> int:
    """Model calls one run makes with a model backend (AI mode, 5 agents, 2 rounds: 10 calls)."""
    workers = max(1, agent_count - 1)
    if user_task:
        return 40  # the user-task team iterates; this is a generous upper bound
    if agent_mode == "autonomous":
        return rounds * (workers + 1)  # per round: one planner call + one decision per worker
    return -(-5 * workers * rounds // 2)  # scripted: assignments, reports and some peer notes are model-written


def estimate_for(config: ScenarioConfig) -> int:
    from app.modules.simulator.world import SCENARIOS_BY_ID

    scenario = SCENARIOS_BY_ID.get(config.scenario_id)
    rounds = max(config.rounds, scenario.min_rounds if scenario else 2)
    return estimate_calls(config.agent_count, config.agent_mode,
                          bool(config.user_task or config.scenario_id == "user_directed"), rounds)


def quota_status() -> dict:
    from app.adapters.gemini_adapter import get_quota_tracker
    from app.config import get_settings

    s = get_settings()
    return {"configured": bool(s.gemini_api_key), "model": s.gemini_model, **get_quota_tracker().status(),
            "calls_per_run": {str(n): {"scripted": estimate_calls(n), "autonomous": estimate_calls(n, "autonomous")}
                              for n in AGENT_COUNTS}}


def require(calls: int, what: str = "this run") -> None:
    """Raise a clear error if today's Gemini quota can't cover `calls` model calls."""
    from app.adapters.gemini_adapter import get_quota_tracker, humanize_seconds

    st = get_quota_tracker().status()
    if calls <= st["remaining_today"]:
        return
    raise ValueError(
        f"Not enough Gemini quota for {what}: it needs about {calls} model calls and {st['remaining_today']} are left "
        f"today ({st['calls_today']}/{st['daily_limit']} used). "
        f"{st['blocked_reason'] or 'Quota resets in ' + humanize_seconds(st['resets_in_s'])}. "
        f"Use the deterministic backend, fewer agents, or wait for the reset.")


def check_run(config: ScenarioConfig) -> None:
    if config.agent_backend == "gemini":
        require(estimate_for(config))
