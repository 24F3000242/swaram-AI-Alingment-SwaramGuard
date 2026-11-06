"""Bulk import of a dataset batch (scripts/generate_dataset.py output) into the workspace.

Each run in labels.jsonl becomes a stored run (agents, raw events from events/<run_id>.jsonl, ground-truth labels),
then goes through the whole pipeline (collect, detect, respond, evaluate) so it shows up in the app like any run.
Runs already in the workspace are skipped, so importing twice is safe.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from app.modules.simulator.export import from_canonical_event, parse_canonical_jsonl
from app.schemas import Agent, Run, RunLabels
from app.timeutil import now_iso


def import_dataset(pipeline, folder: str | Path, include_degraded: bool = False,
                   log: Callable[[str], None] = lambda m: None) -> dict:
    folder = Path(folder)
    labels_path = folder / "labels.jsonl"
    if not labels_path.exists():
        raise ValueError(f"{folder} has no labels.jsonl (is it a dataset batch folder?)")
    done = {"imported": 0, "skipped_existing": 0, "skipped_degraded": 0, "missing_events": 0, "run_ids": []}
    for line in labels_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        lab = json.loads(line)
        run_id = lab["run_id"]
        if lab.get("degraded") and not include_degraded:
            done["skipped_degraded"] += 1
            continue
        if pipeline.store.get("runs", run_id):
            done["skipped_existing"] += 1
            continue
        events_path = folder / "events" / f"{run_id}.jsonl"
        if not events_path.exists():
            done["missing_events"] += 1
            continue
        records = parse_canonical_jsonl(events_path)
        events = [from_canonical_event(r, sequence=i + 1) for i, r in enumerate(records)]
        agents = [Agent(run_id=run_id, **a, is_malicious=a["agent_id"] in lab["malicious_agent_ids"]) for a in lab["agents"]]
        created = events[0].timestamp if events else now_iso()
        run = Run(run_id=run_id, scenario_id=lab["scenario_id"], agent_count=len(agents), seed=lab.get("seed", 0),
                  gateway_mode="monitor", drop_rate=0.0, agent_backend=lab.get("backend") or "imported",
                  agent_mode="autonomous", created_at=now_iso(), base_time=str(created),
                  stages={"simulated": now_iso()}, counts={**lab.get("counts", {}), "agents": len(agents), "raw_events": len(events)},
                  labels=RunLabels(malicious_agent_ids=lab["malicious_agent_ids"],
                                   malicious_event_ids=lab.get("malicious_event_ids", [])))
        pipeline.store.put("runs", run_id, run.model_dump(mode="json"))
        pipeline.store.put_many("agents", [(a.agent_id, a.model_dump(mode="json")) for a in agents])
        pipeline.store.put_many("raw_events", [(e.event_id, e.model_dump(mode="json")) for e in events])
        pipeline.run_all(run_id)
        done["imported"] += 1
        done["run_ids"].append(run_id)
        log(f"imported {run_id} ({lab['scenario_id']}, {len(events)} events)")
    return done
