"""Deterministic and autonomous multi-agent simulator with real broker communication and shared environment.

Same (scenario, agent_count, seed, base_time) -> same events, apart from the run id

that prefixes every agent/event id."""
from __future__ import annotations

import random
import tempfile
import uuid
from datetime import datetime
from pathlib import Path
from app.adapters import get_adapter
from app.adapters.base import AgentAdapter
from app.modules.simulator.broker import BROKER_REGISTRY, MessageBroker
from app.modules.simulator.environment import ENVIRONMENT_REGISTRY, SharedEnvironment
from app.modules.simulator.export import export_canonical_jsonl
from app.modules.simulator.gateway import PolicyGateway
from app.modules.simulator.scenarios import SCENARIO_ATTACKS
from app.modules.simulator.world import ROLE_OUTPUT, ROLE_TOOLS, SCENARIOS_BY_ID, TOPICS
from app.schemas import Agent, RawEvent, Run, RunLabels, ScenarioConfig, SimulationResult
from app.timeutil import iso, now_iso, utcnow

# Re-exported so existing `from app.modules.simulator.engine import ...` keeps working.
from app.modules.simulator.runner import AgentRunner, _make_agents, _first  # noqa: F401
from app.modules.simulator.codework import _clean_json_or_text, _extract_code_block, _extract_solution_and_tests, _validate_python_syntax, _audit_code_implementation, _generate_deterministic_solution  # noqa: F401
from app.modules.simulator.sandbox import CODE_EXEC_FLAG, _code_exec_allowed, _child_env, _execute_code_safely  # noqa: F401
from app.modules.simulator.collaboration import _autonomous_user_task_collaboration  # noqa: F401
from app.modules.simulator.autonomous import autonomous_round


ROUNDS = 2


def _normal_round(r: AgentRunner, agents: list[Agent], round_no: int) -> None:
    planner, workers = agents[0], agents[1:]
    for w in workers:
        r.message(planner, w, "assign_task", r.rng.choice(TOPICS))
        received_events = r.receive_messages(w)
        # Update simulated agent perceptions
        w_sim = r.sim_agents_by_id.get(w.agent_id)
        if w_sim:
            for rev in received_events:
                w_sim.perceive({
                    "type": "message_received",
                    "sender_id": rev.payload.get("sender_id"),
                    "intent": rev.payload.get("intent"),
                    "topic": rev.payload.get("topic"),
                    "content": rev.payload.get("content"),
                    "data_ref": rev.payload.get("data_ref"),
                })
                w_sim.memory.add_pending_task(rev.payload)
    for w in workers:
        topic = r.rng.choice(TOPICS)
        r.emit(w, "task", "start", payload={"round": round_no, "topic": topic})
        if w.role == "analyst" and round_no == 1:
            source = "data/customer_pii"  # legitimate, permitted PII access
        else:
            source = r.rng.choice(w.permissions)
        r.access(w, source, "read")
        r.emit(w, "tool_call", "run", resource=ROLE_TOOLS[w.role])
        r.access(w, ROLE_OUTPUT[w.role], "write")
        if w.role == "researcher" and round_no == 1:
            r.protected(w, "data_transfer", "upload", resource="data/public", target="external:approved-partner-api")
        if len(workers) > 1 and r.rng.random() < 0.3:
            peer = r.rng.choice([x for x in workers if x is not w])
            r.message(w, peer, "share_notes", topic)
            r.receive_messages(peer)
        r.message(w, planner, "report", topic)
        r.receive_messages(planner)
        r.emit(w, "task", "complete", payload={"round": round_no, "topic": topic})


ATTACKS = SCENARIO_ATTACKS


def run_simulation(
    config: ScenarioConfig,
    *,
    run_id: str | None = None,
    base_time: datetime | None = None,
    adapter: AgentAdapter | None = None,
    broker: MessageBroker | None = None,
    env: SharedEnvironment | None = None,
    live=None,
) -> SimulationResult:
    if config.scenario_id not in SCENARIOS_BY_ID:
        raise ValueError(f"Unknown scenario: {config.scenario_id}")
    run_hex = run_id.removeprefix("run-") if run_id else uuid.uuid4().hex[:8]
    run_id = f"run-{run_hex}"
    base_time = base_time or utcnow().replace(microsecond=0)
    rng = random.Random(config.seed)
    agents = _make_agents(run_id, run_hex, config.agent_count)
    if live:
        live.start(run_id, agents)
    workspace_dir = config.workspace_dir or (Path(tempfile.gettempdir()) / "swarmguard-runs" / run_id / "workspace" if (config.user_task or config.scenario_id == "user_directed") else None)
    active_env = env or ENVIRONMENT_REGISTRY.create(run_id, gateway_mode=config.gateway_mode, workspace_dir=workspace_dir)
    active_broker = broker or BROKER_REGISTRY.create(run_id)
    active_broker.register_agents(a.agent_id for a in agents)
    active_env.broker = active_broker
    active_env.gateway = PolicyGateway(config.gateway_mode)
    runner = AgentRunner(
        run_id,
        run_hex,
        base_time,
        rng,
        active_env.gateway,
        adapter or get_adapter(config.agent_backend),
        broker=active_broker,
        env=active_env,
        live=live,
    )
    runner.register_agents(agents)
    if config.user_task or config.scenario_id == "user_directed":
        task_text = config.user_task or "Collaboratively design and implement a secure data pipeline."
        _autonomous_user_task_collaboration(runner, agents, task_text)
        malicious_ids = set()
    else:
        work_round = autonomous_round if config.agent_mode == "autonomous" else _normal_round
        rounds = max(config.rounds, SCENARIOS_BY_ID[config.scenario_id].min_rounds)
        work_round(runner, agents, 1)
        attack_fn = ATTACKS.get(config.scenario_id, lambda r, agts: [])
        malicious_agents = attack_fn(runner, agents)
        for round_no in range(2, rounds + 1):  # the attack lands after round 1; later rounds show what follows
            work_round(runner, agents, round_no)
        malicious_ids = {a.agent_id for a in malicious_agents}
        stats = getattr(runner, "ai_stats", None)
        if stats is not None:  # outcome-based labels: an AI agent that broke policy is a culprit, whatever made it
            malicious_ids |= stats.violators
        for a in agents:
            a.is_malicious = a.agent_id in malicious_ids
    events, dropped = runner.events, []
    if config.sensors:  # an independent second record of each executed action (lost independently below)
        from app.modules.detection.evidence import sensor_record

        with_sensors = []
        for e in events:
            with_sensors.append(e)
            rec = sensor_record(e.model_dump(mode="json"))
            if rec:
                with_sensors.append(RawEvent.model_validate(rec))
        events = with_sensors
    if config.drop_rate > 0:
        drop_rng = random.Random(config.seed * 7919 + 1)
        kept = []
        for e in events:
            (dropped if drop_rng.random() < config.drop_rate else kept).append(e)
        events, dropped = kept, [e.event_id for e in dropped]
    run = Run(
        run_id=run_id,
        scenario_id=config.scenario_id,
        agent_count=config.agent_count,
        seed=config.seed,
        gateway_mode=config.gateway_mode,
        drop_rate=config.drop_rate,
        agent_backend=config.agent_backend,
        agent_mode=config.agent_mode,
        created_at=now_iso(),
        base_time=iso(base_time),
        stages={"simulated": now_iso()},
        counts={"agents": len(agents), "raw_events": len(events), "dropped_events": len(dropped),
                **(runner.ai_stats.counts() if hasattr(runner, "ai_stats") else {})},
        labels=RunLabels(malicious_agent_ids=sorted(malicious_ids), malicious_event_ids=runner.malicious_event_ids),
        dropped_event_ids=dropped,
    )
    return SimulationResult(run=run, agents=agents, events=events)


def export_events_jsonl(
    sim_or_events: SimulationResult | list[RawEvent],
    destination: Path | str | None = None,
    *,
    schema_version: str = "1.0",
) -> str:
    """Convenience helper to export canonical 12-field JSONL for SwarmGuard."""
    return export_canonical_jsonl(sim_or_events, destination, schema_version=schema_version)
