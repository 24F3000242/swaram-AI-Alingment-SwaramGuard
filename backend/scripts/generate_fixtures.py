"""Regenerate the sample fixtures in /fixtures from the real modules.

    python scripts/generate_fixtures.py

Uses a fixed run id, seed and base time so the output is stable across machines.
`raw_events_messy.jsonl` is hand-written and is not touched.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import FIXTURES_DIR  # noqa: E402
from app.modules.collector.normalizer import collect  # noqa: E402
from app.modules.detection.rules import DEFAULT_RULES, run_rules  # noqa: E402
from app.modules.evaluation.metrics import evaluate  # noqa: E402
from app.modules.response.policy import DEFAULT_POLICY, respond  # noqa: E402
from app.modules.simulator.engine import run_simulation  # noqa: E402
from app.modules.simulator.world import SCENARIOS  # noqa: E402
from app.schemas import ScenarioConfig  # noqa: E402

BASE_TIME = datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)


def dump(model):
    return model.model_dump(mode="json")


def write_json(name: str, data) -> None:
    (FIXTURES_DIR / name).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def write_jsonl(name: str, rows) -> None:
    (FIXTURES_DIR / name).write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


def main() -> None:
    FIXTURES_DIR.mkdir(exist_ok=True)
    config = ScenarioConfig(scenario_id="coordinated_leakage", agent_count=5, seed=7, gateway_mode="enforce", persist=False)
    sim = run_simulation(config, run_id="run-fixture1", base_time=BASE_TIME)
    normalized = collect([dump(e) for e in sim.events], run_id=sim.run.run_id, agents=sim.agents)
    alerts = run_rules(sim.run.run_id, normalized.events, sim.agents)
    enforce_policy = DEFAULT_POLICY.model_copy(update={"mode": "enforce"})
    actions = respond(alerts, normalized.events, enforce_policy)
    evaluation = evaluate(sim.run, sim.agents, normalized.events, alerts, actions)

    write_json("scenarios.json", [dump(s) for s in SCENARIOS])
    write_json("scenario_config.json", dump(config))
    write_json("run.json", dump(sim.run))
    write_json("agents.json", [dump(a) for a in sim.agents])
    write_jsonl("raw_events.jsonl", [dump(e) for e in sim.events])
    write_jsonl("normalized_events.jsonl", [dump(e) for e in normalized.events])
    write_json("collection_report.json", dump(normalized.report))
    write_json("detection_rules.json", [dump(r) for r in DEFAULT_RULES])
    write_json("alerts.json", [dump(a) for a in alerts])
    write_json("response_policy.json", dump(enforce_policy))
    write_json("response_actions.json", [dump(a) for a in actions])
    write_json("evaluation.json", dump(evaluation))
    print(f"events={len(sim.events)} alerts={len(alerts)} actions={len(actions)} "
          f"precision={evaluation.precision} recall={evaluation.recall}")


if __name__ == "__main__":
    main()
