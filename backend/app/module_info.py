"""Schema + sample JSON shown behind each page's info button."""
from __future__ import annotations

import json
from typing import Any

from app.config import FIXTURES_DIR
from app.schemas import (
    Alert, CollectionReport, Dashboard, EvaluationResult, NormalizedEvent, RawEvent, ResponseAction, ResponsePolicy,
    ScenarioConfig, SuiteRequest,
)

MODULES: dict[str, dict[str, Any]] = {
    "simulator": {"input": (ScenarioConfig, "scenario_config.json"), "output": (RawEvent, "raw_events.jsonl")},
    "collector": {"input": (RawEvent, "raw_events_messy.jsonl"), "output": (NormalizedEvent, "normalized_events.jsonl"),
                  "extra": (CollectionReport, None)},
    "detection": {"input": (NormalizedEvent, "normalized_events.jsonl"), "output": (Alert, "alerts.json")},
    "response": {"input": (ResponsePolicy, "response_policy.json"), "output": (ResponseAction, "response_actions.json")},
    "evaluation": {"input": (SuiteRequest, "suite_request.json"), "output": (EvaluationResult, "evaluation.json"), "extra": (Dashboard, None)},
}


def _sample(filename: str | None, limit: int = 2) -> Any:
    if not filename:
        return None
    path = FIXTURES_DIR / filename
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8")
    if filename.endswith(".jsonl"):
        return [json.loads(line) for line in text.splitlines() if line.strip()][:limit]
    data = json.loads(text)
    return data[:limit] if isinstance(data, list) else data


def module_info(name: str) -> dict[str, Any]:
    spec = MODULES[name]
    info: dict[str, Any] = {"module": name}
    for key in ("input", "output", "extra"):
        if key in spec:
            model, fixture = spec[key]
            info[key] = {"model": model.__name__, "schema": model.model_json_schema(), "fixture": fixture, "sample": _sample(fixture)}
    return info
