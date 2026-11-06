"""Event Collector: validate, de-duplicate and normalize raw events."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

from pydantic import ValidationError

from app.modules.collector import integrity, privacy
from app.schemas import Agent, CollectionReport, CollectionResult, CollectorIssue, NormalizedEvent, RawEvent
from app.timeutil import iso, now_iso, parse_iso

CANONICAL_EVENT_TYPES = {"message", "tool_call", "resource_access", "data_transfer", "task"}
EVENT_TYPE_ALIASES = {
    "msg": "message", "chat": "message", "message_sent": "message", "send_message": "message",
    "tool": "tool_call", "tool_use": "tool_call", "function_call": "tool_call",
    "access": "resource_access", "file_read": "resource_access", "file_write": "resource_access",
    "read_resource": "resource_access", "resource": "resource_access",
    "transfer": "data_transfer", "upload": "data_transfer", "exfil": "data_transfer", "send_external": "data_transfer",
    "task_start": "task", "task_complete": "task",
}
STATUS_ALIASES = {
    "ok": "success", "succeeded": "success", "completed": "success", "done": "success", "allowed": "success",
    "deny": "denied", "blocked": "denied", "rejected": "denied", "forbidden": "denied",
    "error": "failed", "fail": "failed", "failure": "failed",
    "queued": "pending", "in_progress": "pending",
}
GATEWAY_DECISIONS = {"not_checked", "allow", "would_block", "blocked"}
REQUIRED_FIELDS = ("run_id", "event_id", "agent_id", "timestamp", "event_type", "action", "status")


def _snake(value: str) -> str:
    value = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value.strip())
    return re.sub(r"[\s\-./]+", "_", value).lower()


def normalize_timestamp(value: Any) -> str:
    """Accept ISO-8601 (with or without zone) or epoch seconds/milliseconds."""
    if isinstance(value, bool):
        raise ValueError("boolean is not a timestamp")
    if isinstance(value, str) and re.fullmatch(r"\d+(\.\d+)?", value.strip()):
        value = float(value)
    if isinstance(value, (int, float)):
        seconds = float(value) / 1000 if value > 1e12 else float(value)
        return iso(datetime.fromtimestamp(seconds, tz=timezone.utc))
    if isinstance(value, str):
        return iso(parse_iso(value))
    raise ValueError(f"unsupported timestamp: {value!r}")


def normalize_event_type(value: str) -> tuple[str, bool]:
    key = _snake(value)
    key = EVENT_TYPE_ALIASES.get(key, key)
    return key, key in CANONICAL_EVENT_TYPES


def normalize_status(value: str) -> str | None:
    key = _snake(value)
    key = STATUS_ALIASES.get(key, key)
    return key if key in {"success", "denied", "failed", "pending"} else None


def raw_hash(raw: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(raw, sort_keys=True, default=str).encode()).hexdigest()


def summarize(e: dict[str, Any], role: str | None) -> str:
    who = f"{e['agent_id']}" + (f" ({role})" if role else "")
    et, action, status = e["event_type"], e["action"], e["status"]
    if et == "message":
        ref = f" [data_ref={e['payload']['data_ref']}]" if e["payload"].get("data_ref") else ""
        return f"{who} -> {e.get('target')}: {e['payload'].get('intent', action)}{ref}"
    if et == "data_transfer":
        return f"{who} {action} {e.get('resource')} -> {e.get('target')} [{status}]"
    if et == "resource_access":
        return f"{who} {action} {e.get('resource')} [{status}]"
    if et == "tool_call":
        return f"{who} ran {e.get('resource') or action} [{status}]"
    return f"{who} {et}:{action} [{status}]"


def from_canonical(raw: dict[str, Any]) -> dict[str, Any]:
    """Accept the simulator's canonical 12-field export: `details` is the payload, and `details.telemetry` carries
    sequence + gateway_decision. Internal-format events pass through unchanged."""
    if "payload" in raw or not isinstance(raw.get("details"), dict):
        return raw
    details = dict(raw["details"])
    telemetry = details.pop("telemetry", None) or {}
    out = {k: v for k, v in raw.items() if k not in ("details", "schema_version", "source")}
    out["payload"] = details
    out.setdefault("sequence", telemetry.get("sequence", 0))
    if "gateway_decision" in telemetry:
        out.setdefault("gateway_decision", telemetry["gateway_decision"])
    return out


def collect(raw_events: list[Any], *, run_id: str | None = None, agents: list[Agent] | None = None) -> CollectionResult:
    registry = {a.agent_id: a for a in agents or []}
    errors: list[CollectorIssue] = []
    warnings: list[CollectorIssue] = []
    seen_ids: dict[str, str] = {}
    seen_content: set[tuple] = set()
    duplicates = 0
    normalized: list[NormalizedEvent] = []
    stamp = now_iso()
    redact = privacy.enabled()
    redactions = 0
    ai = {"model_decisions": 0, "fallbacks": 0, "refusals": 0, "exposed_to_untrusted": 0}
    traced: set[tuple] = set()

    for idx, raw in enumerate(raw_events):
        if not isinstance(raw, dict):
            errors.append(CollectorIssue(index=idx, code="not_an_object", message="event must be a JSON object"))
            continue
        event_id = raw.get("event_id") if isinstance(raw.get("event_id"), str) else None
        missing = [f for f in REQUIRED_FIELDS if raw.get(f) in (None, "")]
        if missing:
            errors.append(CollectorIssue(index=idx, event_id=event_id, code="missing_field", message=f"missing required field(s): {', '.join(missing)}"))
            continue
        try:
            ev = RawEvent.model_validate(from_canonical(raw))
        except ValidationError as exc:
            errors.append(CollectorIssue(index=idx, event_id=event_id, code="schema_error", message=exc.errors()[0]["msg"]))
            continue
        try:
            ts = normalize_timestamp(ev.timestamp)
        except (ValueError, OverflowError, OSError) as exc:
            errors.append(CollectorIssue(index=idx, event_id=ev.event_id, code="invalid_timestamp", message=str(exc)))
            continue
        if run_id and ev.run_id != run_id:
            errors.append(CollectorIssue(index=idx, event_id=ev.event_id, code="run_mismatch", message=f"event run_id {ev.run_id} != {run_id}"))
            continue
        status = normalize_status(ev.status)
        if status is None:
            errors.append(CollectorIssue(index=idx, event_id=ev.event_id, code="invalid_status", message=f"unknown status {ev.status!r}"))
            continue

        h = raw_hash(raw)
        if ev.event_id in seen_ids:
            duplicates += 1
            if seen_ids[ev.event_id] == h:
                warnings.append(CollectorIssue(index=idx, event_id=ev.event_id, code="duplicate_event", message="exact duplicate dropped"))
            else:
                errors.append(CollectorIssue(index=idx, event_id=ev.event_id, code="conflicting_duplicate", message="same event_id with different content; first copy kept"))
            continue

        event_type, known_type = normalize_event_type(ev.event_type)
        action = _snake(ev.action)
        content_key = (ev.agent_id, event_type, action, ev.target, ev.resource, ts)
        if content_key in seen_content:
            duplicates += 1
            warnings.append(CollectorIssue(index=idx, event_id=ev.event_id, code="duplicate_content", message="same agent/action/target/time as an earlier event; dropped"))
            continue
        seen_ids[ev.event_id] = h
        seen_content.add(content_key)

        issues: list[str] = []
        if not known_type:
            issues.append("unknown_event_type")
            warnings.append(CollectorIssue(index=idx, event_id=ev.event_id, code="unknown_event_type", message=f"event_type {ev.event_type!r} kept as {event_type!r}"))
        agent = registry.get(ev.agent_id)
        if registry and agent is None:
            issues.append("unknown_agent")
            warnings.append(CollectorIssue(index=idx, event_id=ev.event_id, code="unknown_agent", message=f"{ev.agent_id} is not registered for this run"))
        if registry and event_type == "message" and ev.target and ev.target.startswith("agt-") and ev.target not in registry:
            issues.append("unknown_target_agent")
            warnings.append(CollectorIssue(index=idx, event_id=ev.event_id, code="unknown_target_agent", message=f"message target {ev.target} is not registered"))
        if agent is not None and agent.run_id != ev.run_id:
            issues.append("agent_run_mismatch")
            warnings.append(CollectorIssue(index=idx, event_id=ev.event_id, code="agent_run_mismatch", message=f"{ev.agent_id} belongs to {agent.run_id}"))
        gateway = ev.gateway_decision if ev.gateway_decision in GATEWAY_DECISIONS else "not_checked"
        payload, stored_raw = ev.payload, raw
        if redact:
            payload, n = privacy.redact(ev.payload)
            if n:
                redactions += n
                key = "details" if "details" in raw and "payload" not in raw else "payload"
                stored_raw = {**raw, key: privacy.redact(raw.get(key) or {})[0]}
        trace = payload.get("ai_trace") if isinstance(payload.get("ai_trace"), dict) else None
        if trace and (ev.agent_id, trace.get("round")) not in traced:  # one decision per agent turn
            traced.add((ev.agent_id, trace.get("round")))
            ai["model_decisions" if trace.get("source") == "model" else "fallbacks"] += 1
            ai["refusals"] += bool(trace.get("refused"))
            ai["exposed_to_untrusted"] += bool(trace.get("exposed_to_untrusted"))

        fields = {
            "run_id": ev.run_id, "event_id": ev.event_id, "agent_id": ev.agent_id,
            "event_type": event_type, "action": action, "status": status,
            "target": ev.target, "resource": ev.resource, "payload": payload,
        }
        normalized.append(NormalizedEvent(
            **fields,
            agent_role=agent.role if agent else None,
            timestamp=ts,
            sequence=ev.sequence,
            gateway_decision=gateway,
            summary=summarize(fields, agent.role if agent else None),
            issues=issues,
            raw_hash=h,
            raw=stored_raw,
            normalized_at=stamp,
        ))

    normalized.sort(key=lambda e: (e.timestamp, e.sequence, e.event_id))
    anchor = integrity.chain(normalized) if normalized else None
    report = CollectionReport(
        run_id=run_id or (normalized[0].run_id if normalized else None),
        total_input=len(raw_events),
        valid=len(normalized),
        invalid=len(raw_events) - len(normalized) - duplicates,
        duplicates=duplicates,
        warnings=warnings,
        errors=errors,
        redactions=redactions,
        ai=ai if traced else {},
        log_anchor=anchor,
    )
    return CollectionResult(report=report, events=normalized)
