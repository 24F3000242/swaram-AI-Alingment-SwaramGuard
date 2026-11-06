"""Canonical JSONL export module for Member 1 (Agent Simulation Engineer).

Implements the official 12-field SwarmGuard JSONL event contract:
1. schema_version (str, default "1.0")
2. event_id (str)
3. run_id (str)
4. agent_id (str)
5. timestamp (str, ISO-8601 UTC)
6. event_type (str)
7. action (str)
8. target (str | None)
9. resource (str | None)
10. status (str)
11. source (str)
12. details (dict[str, Any])
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Sequence

from app.schemas import RawEvent, SimulationResult

CANONICAL_SCHEMA_VERSION = "1.0"
TELEMETRY_KEY = "telemetry"

CANONICAL_FIELDS: tuple[str, ...] = (
    "schema_version",
    "event_id",
    "run_id",
    "agent_id",
    "timestamp",
    "event_type",
    "action",
    "target",
    "resource",
    "status",
    "source",
    "details",
)

SENSITIVE_LABEL_KEYS: frozenset[str] = frozenset({
    "is_malicious",
    "malicious",
    "malicious_event_ids",
    "malicious_agent_ids",
    "ground_truth",
})


def determine_source(event: RawEvent) -> str:
    """Determine a consistent, meaningful event source based on origin.

    - "system": System or simulator runtime events.
    - "gateway": Policy gateway enforcement checks.
    - "broker": Message broker infrastructure events.
    - "agent": Agent activities, tool executions, communications, and resource accesses.

    Crucially, this is determined from event origin metadata rather than
    blindly inferred from untrusted or arbitrary payload content.
    """
    explicit_source = getattr(event, "source", None)
    if isinstance(explicit_source, str) and explicit_source.strip():
        return explicit_source.strip()

    agent_id = (event.agent_id or "").lower()
    event_type = (event.event_type or "").lower()

    if agent_id in ("system", "simulator", "host") or agent_id.startswith("sys-"):
        return "system"
    if agent_id in ("gateway", "policy_gateway") or event_type in ("policy_check", "gateway_decision"):
        return "gateway"
    if agent_id in ("broker", "message_broker"):
        return "broker"

    # All simulated agent actions (tasks, tool calls, accesses, messages)
    return "agent"


def to_canonical_event(
    event: RawEvent,
    *,
    schema_version: str = CANONICAL_SCHEMA_VERSION,
    source: str | None = None,
) -> dict[str, Any]:
    """Convert an internal RawEvent into the official 12-field canonical event dict.

    - Enforces exact canonical field keys and order.
    - Maps internal `payload` -> `details`.
    - Preserves nulls for target and resource.
    - Strips any ground-truth threat labels from details.
    """
    event_source = source if source is not None else determine_source(event)

    raw_payload = event.payload if isinstance(event.payload, dict) else {}
    details: dict[str, Any] = {
        k: v for k, v in raw_payload.items() if k not in SENSITIVE_LABEL_KEYS
    }
    # Detection needs ordering (log-gap checks) and the gateway's verdict (proof of a real block); both ride in
    # details.telemetry so the 12-field contract stays intact.
    telemetry = {"sequence": event.sequence}
    if event.gateway_decision is not None:
        telemetry["gateway_decision"] = event.gateway_decision
    details[TELEMETRY_KEY] = telemetry

    canonical: dict[str, Any] = {
        "schema_version": str(schema_version),
        "event_id": str(event.event_id),
        "run_id": str(event.run_id),
        "agent_id": str(event.agent_id),
        "timestamp": str(event.timestamp),
        "event_type": str(event.event_type),
        "action": str(event.action),
        "target": str(event.target) if event.target is not None else None,
        "resource": str(event.resource) if event.resource is not None else None,
        "status": str(event.status),
        "source": str(event_source),
        "details": details,
    }
    return canonical


def to_canonical_events(
    events: Sequence[RawEvent],
    *,
    schema_version: str = CANONICAL_SCHEMA_VERSION,
) -> list[dict[str, Any]]:
    """Convert a sequence of RawEvent instances into a list of canonical event dicts."""
    return [to_canonical_event(e, schema_version=schema_version) for e in events]


def export_canonical_jsonl(
    events_or_sim: Sequence[RawEvent] | SimulationResult,
    destination: Path | str | None = None,
    *,
    schema_version: str = CANONICAL_SCHEMA_VERSION,
) -> str:
    """Export events as canonical JSONL.

    Parameters:
    - events_or_sim: Either a list of RawEvent objects or a SimulationResult instance.
    - destination: Optional Path or file path string. If provided, writes the JSONL to disk.
    - schema_version: Version string for the schema header (default "1.0").

    Returns:
    - The serialized JSONL string with trailing newline.
    """
    if hasattr(events_or_sim, "events"):
        events = events_or_sim.events
    else:
        events = events_or_sim

    lines = [
        json.dumps(to_canonical_event(e, schema_version=schema_version), ensure_ascii=False)
        for e in events
    ]
    content = "\n".join(lines) + ("\n" if lines else "")

    if destination is not None:
        target_path = Path(destination)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(content, encoding="utf-8")

    return content


def parse_canonical_jsonl(source: str | Path) -> list[dict[str, Any]]:
    """Parse canonical JSONL text or file into a list of canonical event dictionaries.

    Validates that every row contains exactly the 12 canonical keys in valid format.
    """
    if isinstance(source, Path) or (isinstance(source, str) and "\n" not in source and Path(source).exists()):
        text = Path(source).read_text(encoding="utf-8")
    else:
        text = str(source)

    records: list[dict[str, Any]] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        record = json.loads(line)
        keys = tuple(record.keys())
        if keys != CANONICAL_FIELDS:
            missing = set(CANONICAL_FIELDS) - set(keys)
            extra = set(keys) - set(CANONICAL_FIELDS)
            raise ValueError(
                f"Line {idx} invalid canonical event schema. Missing: {missing}, Extra: {extra}"
            )
        records.append(record)
    return records


def from_canonical_event(record: dict[str, Any], *, sequence: int = 0) -> RawEvent:
    """Convert a canonical 12-field event dictionary back into an internal RawEvent.

    Maps `details` back to `payload`, and `details.telemetry` back to sequence / gateway_decision.
    """
    payload = dict(record.get("details", {}))
    telemetry = payload.pop(TELEMETRY_KEY, {}) or {}
    return RawEvent(
        run_id=record["run_id"],
        event_id=record["event_id"],
        agent_id=record["agent_id"],
        timestamp=record["timestamp"],
        event_type=record["event_type"],
        action=record["action"],
        status=record["status"],
        target=record.get("target"),
        resource=record.get("resource"),
        sequence=telemetry.get("sequence", sequence),
        gateway_decision=telemetry.get("gateway_decision"),
        payload=payload,
    )
