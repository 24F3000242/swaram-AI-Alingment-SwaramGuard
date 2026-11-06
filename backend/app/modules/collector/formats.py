"""Import real agent logs: OpenTelemetry GenAI traces and LangSmith runs become SwarmGuard raw events.

OpenTelemetry (OTLP JSON, GenAI semantic conventions): spans with `gen_ai.operation.name` = `invoke_agent` become
`task:start` for that agent, `execute_tool` becomes a `tool_call` on `tool/<gen_ai.tool.name>`. The agent is
`gen_ai.agent.id` (or `gen_ai.agent.name`), inherited from the parent `invoke_agent` span when a tool span doesn't
say. Model calls (`chat`, `text_completion`, `embeddings`) are not agent actions and are skipped. An integration can
describe protected actions precisely with optional attributes: `swarmguard.event_type`, `swarmguard.action`,
`swarmguard.resource`, `swarmguard.target`, `swarmguard.data_ref`, `swarmguard.role`.

LangSmith (exported runs): `tool` runs become `tool_call`, `retriever` runs become a `resource_access` read; the agent
is `extra.metadata.agent_id`, else the LangGraph node, else the nearest named parent chain. LLM, prompt and parser
runs are skipped.

Both return (raw events, agents seen) ready for the collector or the live ingest API.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

MODEL_OPS = {"chat", "text_completion", "generate_content", "embeddings"}


def _iso_from_nanos(n: Any) -> str:
    t = datetime.fromtimestamp(int(n) / 1e9, tz=timezone.utc)
    return t.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _attr_value(v: dict) -> Any:
    for k in ("stringValue", "intValue", "doubleValue", "boolValue"):
        if k in v:
            return v[k]
    if "arrayValue" in v:
        return [_attr_value(x) for x in v["arrayValue"].get("values", [])]
    return None


def _attrs(span: dict) -> dict[str, Any]:
    a = span.get("attributes") or {}
    if isinstance(a, dict):  # simplified form
        return a
    return {x["key"]: _attr_value(x.get("value") or {}) for x in a}


def _spans(doc: Any) -> list[dict]:
    if isinstance(doc, list):
        return doc
    out = []
    for rs in doc.get("resourceSpans", []):
        service = _attrs(rs.get("resource") or {}).get("service.name")
        for ss in rs.get("scopeSpans", []) or rs.get("instrumentationLibrarySpans", []):
            for sp in ss.get("spans", []):
                out.append({**sp, "_service": service})
    return out


def from_otel(doc: Any, run_id: str) -> tuple[list[dict], list[dict]]:
    spans = _spans(doc)
    by_id = {s.get("spanId"): s for s in spans}

    def agent_of(span: dict) -> str | None:
        seen = set()
        while span and span.get("spanId") not in seen:
            seen.add(span.get("spanId"))
            a = _attrs(span)
            if a.get("gen_ai.agent.id") or a.get("gen_ai.agent.name"):
                return str(a.get("gen_ai.agent.id") or a.get("gen_ai.agent.name"))
            span = by_id.get(span.get("parentSpanId"))
        return None

    events, agents = [], {}
    for sp in sorted(spans, key=lambda s: int(s.get("startTimeUnixNano") or 0)):
        a = _attrs(sp)
        op = a.get("gen_ai.operation.name")
        if op in MODEL_OPS or (not op and "swarmguard.event_type" not in a):
            continue
        agent = agent_of(sp) or sp.get("_service") or "unknown-agent"
        agents.setdefault(agent, {"agent_id": agent, "name": str(a.get("gen_ai.agent.name") or agent),
                                  "role": a.get("swarmguard.role") or "agent", "permissions": []})
        if a.get("swarmguard.role"):
            agents[agent]["role"] = a["swarmguard.role"]
        failed = (sp.get("status") or {}).get("code") in (2, "STATUS_CODE_ERROR")
        if op == "invoke_agent" and "swarmguard.event_type" not in a:
            et, action, resource = "task", "start", None
        elif op == "execute_tool" and "swarmguard.event_type" not in a:
            tool = a.get("gen_ai.tool.name") or str(sp.get("name", "")).removeprefix("execute_tool ").strip() or "unknown"
            et, action, resource = "tool_call", "run", f"tool/{tool}"
        else:
            et, action, resource = a.get("swarmguard.event_type"), a.get("swarmguard.action") or "run", a.get("swarmguard.resource")
        payload = {k: a[f"swarmguard.{k}"] for k in ("data_ref", "content") if f"swarmguard.{k}" in a}
        if a.get("gen_ai.tool.call.id"):
            payload["tool_call_id"] = a["gen_ai.tool.call.id"]
        payload["source"] = "otel"
        events.append({"run_id": run_id, "event_id": f"otel-{sp.get('spanId')}", "agent_id": agent,
                       "timestamp": _iso_from_nanos(sp.get("startTimeUnixNano") or 0), "event_type": et, "action": action,
                       "status": "failed" if failed else "success", "resource": resource or a.get("swarmguard.resource"),
                       "target": a.get("swarmguard.target"), "payload": payload})
    return events, list(agents.values())


def from_langsmith(runs: list[dict], run_id: str) -> tuple[list[dict], list[dict]]:
    by_id = {r.get("id"): r for r in runs}

    def agent_of(r: dict) -> str:
        seen = set()
        cur = r
        while cur and cur.get("id") not in seen:
            seen.add(cur.get("id"))
            meta = ((cur.get("extra") or {}).get("metadata") or {})
            if meta.get("agent_id") or meta.get("langgraph_node"):
                return str(meta.get("agent_id") or meta.get("langgraph_node"))
            cur = by_id.get(cur.get("parent_run_id"))
        parent = by_id.get(r.get("parent_run_id"))
        return str((parent or r).get("name") or "unknown-agent")

    events, agents = [], {}
    for r in sorted(runs, key=lambda x: str(x.get("start_time") or "")):
        kind = r.get("run_type")
        if kind not in ("tool", "retriever"):
            continue
        agent = agent_of(r)
        meta = ((r.get("extra") or {}).get("metadata") or {})
        agents.setdefault(agent, {"agent_id": agent, "name": agent, "role": meta.get("role") or "agent", "permissions": []})
        et, action, resource = (("tool_call", "run", f"tool/{r.get('name')}") if kind == "tool"
                                else ("resource_access", "read", f"retriever/{r.get('name')}"))
        ts = str(r.get("start_time") or "")
        events.append({"run_id": run_id, "event_id": f"ls-{r.get('id')}", "agent_id": agent,
                       "timestamp": ts if ts.endswith("Z") or "+" in ts[10:] else ts + "Z", "event_type": et,
                       "action": action, "status": "failed" if r.get("error") else "success", "resource": resource,
                       "target": None, "payload": {"source": "langsmith", "trace_id": r.get("trace_id")}})
    return events, list(agents.values())


# ---------------------------------------------------------------- real sensor feeds (a second evidence source)
# Records from systems the agents don't control. They become `observation` events with payload.mirrors, which
# detection fuses with the agent log (evidence.fuse) and reconciles in SG-021: an action a sensor saw but the agent
# log never recorded, with no log gap to explain it, is a gateway bypass.

def _sensor(run_id: str, kind: str, i: int, rec: dict, *, agent: str, mirrors: str, action: str, resource=None,
            target=None, extra: dict | None = None) -> dict:
    import hashlib
    import json as _json

    h = hashlib.sha1(_json.dumps(rec, sort_keys=True, default=str).encode()).hexdigest()[:8]
    return {"run_id": run_id, "event_id": f"sensor-{kind}-{i:05d}-{h}", "agent_id": agent,
            "timestamp": rec.get("timestamp") or rec.get("ts") or rec.get("time"), "event_type": "observation",
            "action": action, "status": "success", "resource": resource, "target": target, "sequence": 0,
            "payload": {"source": kind, "mirrors": mirrors, **(extra or {})}}


def from_egress(records: list[dict], run_id: str) -> tuple[list[dict], list[dict]]:
    """Egress proxy log: {timestamp, agent_id|client, destination|host, method?, resource?, bytes?}."""
    out = []
    for i, r in enumerate(records):
        dest = str(r.get("destination") or r.get("host") or "")
        dest = dest if dest.startswith("external:") else f"external:{dest}"
        action = "download" if str(r.get("method", "POST")).upper() == "GET" else "upload"
        out.append(_sensor(run_id, "egress-proxy", i, r, agent=r.get("agent_id") or r.get("client"), mirrors="data_transfer",
                           action=action, resource=r.get("resource"), target=dest, extra={"bytes": r.get("bytes")}))
    return out, []


def from_file_audit(records: list[dict], run_id: str) -> tuple[list[dict], list[dict]]:
    """File / DB audit log: {timestamp, agent_id|actor, path|table, operation}."""
    return [_sensor(run_id, "resource-audit", i, r, agent=r.get("agent_id") or r.get("actor"), mirrors="resource_access",
                    action=str(r.get("operation") or "read").lower(), resource=r.get("path") or r.get("table"))
            for i, r in enumerate(records)], []


def from_broker(records: list[dict], run_id: str) -> tuple[list[dict], list[dict]]:
    """Message broker log: {timestamp, sender, recipient, message_id, data_ref?, content?}."""
    return [_sensor(run_id, "broker-log", i, r, agent=r.get("sender"), mirrors="message", action="send",
                    target=r.get("recipient"),
                    extra={k: r[k] for k in ("message_id", "data_ref", "content") if r.get(k) is not None})
            for i, r in enumerate(records)], []


FORMATS = {"otel": from_otel, "langsmith": from_langsmith, "egress": from_egress, "file_audit": from_file_audit,
           "broker": from_broker}


def convert(fmt: str, doc: Any, run_id: str) -> tuple[list[dict], list[dict]]:
    if fmt not in FORMATS:
        raise ValueError(f"unknown format {fmt!r}; use one of {sorted(FORMATS)}")
    return FORMATS[fmt](doc, run_id)
