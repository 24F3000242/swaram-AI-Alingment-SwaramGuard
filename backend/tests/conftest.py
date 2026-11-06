from __future__ import annotations

import os

os.environ["GEMINI_QUOTA_FILE"] = "off"  # tests must never touch the real Gemini usage file
os.environ["SWARMGUARD_API_KEYS"] = ""  # auth off unless a test turns it on (a developer's .env may set keys)

import json
from datetime import datetime, timezone

import pytest

from app.config import FIXTURES_DIR
from app.modules.collector.normalizer import collect
from app.modules.simulator.engine import run_simulation
from app.schemas import ScenarioConfig
from app.services.pipeline import Pipeline
from app.storage.sqlite_store import SQLiteStore

BASE_TIME = datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)


def simulate(scenario: str, agents: int = 5, seed: int = 7, gateway: str = "monitor", drop: float = 0.0, run_id: str = "run-test0001"):
    cfg = ScenarioConfig(scenario_id=scenario, agent_count=agents, seed=seed, gateway_mode=gateway, drop_rate=drop, persist=False)
    return run_simulation(cfg, run_id=run_id, base_time=BASE_TIME)


def normalize(sim):
    return collect([e.model_dump(mode="json") for e in sim.events], run_id=sim.run.run_id, agents=sim.agents).events


def inject(steps: list[dict], scenario: str = "normal_collaboration", agents: int = 5, seed: int = 7, gap_s: float = 5.0):
    """A clean simulated run plus synthetic events appended after it, then normalized.

    Each step: {"role", "event_type", "action", "resource"?, "target"?, "status"?, "payload"?}. Roles map to the
    first agent with that role. Returns (sim, normalized_events, injected_event_ids).
    """
    from datetime import timedelta

    from app.timeutil import iso, parse_iso

    sim = simulate(scenario, agents=agents, seed=seed)
    raw = [e.model_dump(mode="json") for e in sim.events]
    t = parse_iso(raw[-1]["timestamp"])
    hexid = sim.run.run_id.removeprefix("run-")
    role_of = {}
    for a in sim.agents:
        role_of.setdefault(a.role, a.agent_id)
    injected = []
    for step in steps:
        t += timedelta(seconds=gap_s)
        seq = len(raw) + 1
        ev = {"run_id": sim.run.run_id, "event_id": f"evt-{hexid}-{seq:04d}", "agent_id": role_of[step["role"]],
              "timestamp": iso(t), "event_type": step["event_type"], "action": step["action"],
              "status": step.get("status", "success"), "resource": step.get("resource"), "target": step.get("target"),
              "sequence": seq, "payload": step.get("payload", {})}
        raw.append(ev)
        injected.append(ev["event_id"])
    return sim, collect(raw, run_id=sim.run.run_id, agents=sim.agents).events, injected


def load_jsonl(name: str) -> list:
    return [json.loads(line) for line in (FIXTURES_DIR / name).read_text(encoding="utf-8").splitlines() if line.strip()]


@pytest.fixture
def store():
    return SQLiteStore(":memory:")


@pytest.fixture
def pipeline(store):
    p = Pipeline(store)
    p.seed_defaults()
    return p
