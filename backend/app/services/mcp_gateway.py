"""MCP gateway: SwarmGuard between an agent and its MCP tool server (Model Context Protocol, streamable HTTP).

The agent's MCP client points at SwarmGuard instead of the tool server:

    POST /api/ingest/{run_id}/mcp/{agent_id}     (JSON-RPC 2.0, same body the tool server would get)

and the session says where the real server is:

    POST /api/ingest/sessions  {..., "mcp": {"upstream": "http://tools:9000/mcp",
                                            "tools": {"a1": ["search", "read_ticket"]},   # optional allowlist per agent
                                            "untrusted_results": true}}                  # scan tool output (default)

What the gateway does, per JSON-RPC message:
- `tools/list`: forwarded; tools not on the agent's allowlist are removed from the answer (it never sees them).
- `tools/call`: an unlisted tool is refused; otherwise the live guard's gate decides (paused agent, held egress, hijack
  tripwire, pre-execution policy check on the arguments' resource / destination). A refusal is answered the way MCP
  reports tool errors (`isError: true`), so the agent's framework handles it normally, and is logged as denied.
  Allowed calls go to the real server; the call is reported, and the tool's output is reported as untrusted content,
  so the injection classifier (SG-028) scores it and the hijack tripwire arms.
- everything else (initialize, notifications, resources, prompts) is passed through unchanged.
"""
from __future__ import annotations

import json
import re
from typing import Any

import httpx

from app.services import ingest

PASS_HEADERS = ("mcp-session-id", "mcp-protocol-version", "authorization")
RESOURCE_KEYS = ("resource", "path", "file", "table", "dataset", "uri")
DEST_KEYS = ("destination", "url", "endpoint", "to", "target")
WRITE_TOOL = re.compile(r"write|update|create|delete|put|save|edit|append", re.I)


def _tool_error(msg_id, text: str) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "result": {"content": [{"type": "text", "text": text}], "isError": True}}


def _pick(args: dict, keys: tuple[str, ...]) -> str | None:
    for k in keys:
        v = args.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def describe_call(name: str, args: dict) -> dict:
    """The SwarmGuard event a tool call amounts to: an upload if it names an outside destination, else a tool run
    (with the resource its arguments name, so restricted data is checked)."""
    resource, dest = _pick(args, RESOURCE_KEYS), _pick(args, DEST_KEYS)
    if dest and (dest.startswith(("http://", "https://")) or dest.startswith("external:")):
        host = dest.split("://", 1)[-1].split("/", 1)[0] if "://" in dest else dest.removeprefix("external:")
        return {"event_type": "data_transfer", "action": "upload", "resource": resource, "target": f"external:{host}",
                "payload": {"tool": name}}
    if resource:  # a tool that reads or writes a named resource is an access to it (restricted data is checked)
        action = "write" if WRITE_TOOL.search(name) else "read"
        return {"event_type": "resource_access", "action": action, "resource": resource,
                "payload": {"tool": name, "arguments": json.dumps(args)[:1000]}}
    return {"event_type": "tool_call", "action": "run", "resource": f"tool/{name}",
            "payload": {"tool": name, "arguments": json.dumps(args)[:1000]}}


def _upstream(url: str, msg: Any, headers: dict) -> tuple[Any, dict]:
    fwd = {k: v for k, v in headers.items() if k.lower() in PASS_HEADERS}
    fwd["accept"] = "application/json, text/event-stream"
    r = httpx.post(url, json=msg, headers=fwd, timeout=60)
    back = {k: v for k, v in r.headers.items() if k.lower() in ("mcp-session-id",)}
    if r.status_code == 202 or not r.content:
        return None, back
    if r.headers.get("content-type", "").startswith("text/event-stream"):  # streamable HTTP may answer as SSE
        last = None
        for line in r.text.splitlines():
            if line.startswith("data:"):
                try:
                    last = json.loads(line[5:].strip())
                except ValueError:
                    continue
        return last, back
    return r.json(), back


def handle(pipeline, run_id: str, agent_id: str, msg: Any, headers: dict) -> tuple[Any, dict]:
    """Process one JSON-RPC message (or a batch) from `agent_id`. Returns (response body or None, headers)."""
    s = ingest.session(run_id)
    cfg = getattr(s, "mcp", None) or {}
    if not cfg.get("upstream"):
        raise ValueError("this session has no MCP upstream (open it with \"mcp\": {\"upstream\": ...})")
    if agent_id not in {a.agent_id for a in s.agents}:
        raise ValueError(f"{agent_id} is not registered in {run_id}")
    allowed = (cfg.get("tools") or {}).get(agent_id)  # None: no allowlist for this agent
    if isinstance(msg, list):
        out, hdrs = [], {}
        for m in msg:
            r, hdrs = handle(pipeline, run_id, agent_id, m, headers)
            if r is not None:
                out.append(r)
        return (out or None), hdrs
    method, params, msg_id = msg.get("method"), msg.get("params") or {}, msg.get("id")

    if method == "tools/call":
        name, args = str(params.get("name") or ""), params.get("arguments") or {}
        ev = {"agent_id": agent_id, **describe_call(name, args if isinstance(args, dict) else {})}
        if allowed is not None and name not in allowed:
            ingest.add_events(pipeline, run_id, [{**ev, "status": "denied", "gateway_decision": "blocked",
                                                  "payload": {**ev["payload"], "gateway_reason": "tool not allowed"}}])
            return _tool_error(msg_id, f"SwarmGuard: tool {name!r} is not allowed for {agent_id}"), {}
        reason = s.gate(ev)["reason"]
        if reason:
            ingest.add_events(pipeline, run_id, [{**ev, "status": "denied", "gateway_decision": "blocked",
                                                  "payload": {**ev["payload"], "gateway_reason": reason}}])
            return _tool_error(msg_id, f"SwarmGuard blocked this call: {reason}"), {}
        resp, back = _upstream(cfg["upstream"], msg, headers)
        failed = not isinstance(resp, dict) or "error" in resp or (resp.get("result") or {}).get("isError")
        text = ""
        if isinstance(resp, dict):
            text = "\n".join(str(c.get("text", "")) for c in (resp.get("result") or {}).get("content", [])
                             if isinstance(c, dict))
        report = {**ev, "status": "failed" if failed else "success",
                  "payload": {**ev["payload"], **({"untrusted": True, "content": text[:4000]}
                                                  if text and cfg.get("untrusted_results", True) else {})}}
        ingest.add_events(pipeline, run_id, [report])
        return resp, back

    resp, back = _upstream(cfg["upstream"], msg, headers)
    if method == "tools/list" and allowed is not None and isinstance(resp, dict) and "result" in resp:
        tools = (resp["result"] or {}).get("tools") or []
        resp = {**resp, "result": {**resp["result"], "tools": [t for t in tools if t.get("name") in allowed]}}
    return resp, back
