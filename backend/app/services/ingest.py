"""Live ingest: real agents outside our simulator report what they do, as they do it.

An agent platform (LangChain, CrewAI, a custom swarm) opens a session with its agents, asks the gate before each
protected action ("may this agent do X?"), and sends each event right after. Events go through the same collector,
live guard and streaming as simulated runs, so an attacker in a real swarm shows up in the live UI the moment it
acts, and in `contain` mode its next actions are denied before they execute. `finish` runs the full pipeline
(collect, detect, respond, evaluate) on the session.

    POST /api/ingest/sessions                 {"name": "...", "agents": [...], "live_guard": "contain"}
    POST /api/ingest/{run_id}/gate            {"agent_id", "event_type", "action", "target", "resource", "payload"}
    POST /api/ingest/{run_id}/events          [raw event, ...]   (event_id / sequence / timestamp optional)
    POST /api/ingest/{run_id}/finish

Agent identity: every agent in a session gets its own token (HMAC-SHA256 of run and agent id under a server secret).
With `"require_agent_identity": true`, an event, gate call or proxied request for an agent must carry that agent's
token, so one agent (or a compromised process holding the platform's key) can't report or act as another.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import threading
import time
import uuid
from typing import Any

from app.modules.detection.live import LiveGuard
from app.schemas import Agent, RawEvent, Run
from app.services.live_hub import LiveStream, get_hub
from app.timeutil import now_iso

SESSIONS: dict[str, "IngestSession"] = {}
_SECRET = (os.getenv("SWARMGUARD_IDENTITY_SECRET") or "").encode() or secrets.token_bytes(32)


def _mac(msg: str) -> str:
    return base64.urlsafe_b64encode(hmac.new(_SECRET, msg.encode(), hashlib.sha256).digest()).decode().rstrip("=")


def agent_token(run_id: str, agent_id: str, expires_at: int | None = None) -> str:
    """A token proving the holder is this agent. With expires_at (unix seconds) it is scoped to that lifetime:
    `<exp>.<mac>`; otherwise it lasts the session. Nothing but the holder of the secret can forge one."""
    if expires_at is None:
        return _mac(f"{run_id}/{agent_id}")
    return f"{expires_at}.{_mac(f'{run_id}/{agent_id}/{expires_at}')}"


def token_valid(run_id: str, agent_id: str, token: str, now: int) -> bool:
    if token and "." in token:
        exp_s, _, _ = token.partition(".")
        if exp_s.isdigit():
            exp = int(exp_s)
            return exp >= now and hmac.compare_digest(agent_token(run_id, agent_id, exp), token)
        return False
    return bool(token) and hmac.compare_digest(agent_token(run_id, agent_id), token)


class IngestSession:
    def __init__(self, run_id: str, agents: list[Agent], guard: LiveGuard | None, on_contained=None,
                 require_identity: bool = False):
        self.run_id, self.agents, self.guard = run_id, agents, guard
        self.require_identity = require_identity
        self.stream = LiveStream(get_hub(), guard, on_contained)
        self.lock = threading.Lock()
        self.seq = 0
        self.stream.start(run_id, agents)

    def verify(self, agent_id: str | None, token: str | None) -> bool:
        """True if identity isn't required, or `token` is this agent's own token and not expired."""
        if not self.require_identity:
            return True
        return bool(agent_id and token) and token_valid(self.run_id, agent_id, token, int(time.time()))

    def gate(self, req: dict) -> dict:
        with self.lock:
            reason = self.stream.gate(req["agent_id"], req.get("event_type"), req.get("target"), action=req.get("action"),
                                      resource=req.get("resource"), payload=req.get("payload") or {},
                                      sequence=self.seq + 1, timestamp=now_iso(),
                                      policy_check=req.get("policy_check", True))
        return {"allow": reason is None, "reason": reason}

    def add(self, raw: dict) -> RawEvent:
        with self.lock:
            sensor = raw.get("event_type") == "observation"  # a separate source: it has no place in the agent log's order
            self.seq += 0 if sensor else 1
            ev = RawEvent.model_validate({
                "event_id": raw.get("event_id") or f"evt-{self.run_id.removeprefix('run-')}-{self.seq:05d}{'-s' if sensor else ''}",
                "timestamp": raw.get("timestamp") or now_iso(), "status": raw.get("status") or "success",
                **{k: v for k, v in raw.items()
                   if k not in ("event_id", "timestamp", "status", "run_id", "sequence", "agent_token")},
                "run_id": self.run_id, "sequence": 0 if sensor else self.seq})
            self.stream.observe(ev)
        return ev


def open_session(pipeline, name: str, agents: list[dict], live_guard: str = "contain", pause_at: float = 0.6,
                 require_identity: bool = False, token_ttl: int | None = None) -> dict:
    if not agents:
        raise ValueError("a session needs at least one agent (agent_id, role, permissions)")
    run_id = f"run-{uuid.uuid4().hex[:8]}"
    regs = [Agent.model_validate({"name": a.get("name") or a["agent_id"], "permissions": a.get("permissions") or [],
                                  **{k: v for k, v in a.items() if k in ("agent_id", "role")}, "run_id": run_id})
            for a in agents]
    guard = LiveGuard(pipeline.rules(), live_guard, pause_at, policy=pipeline.policy()) if live_guard != "off" else None
    now = now_iso()
    run = Run(run_id=run_id, scenario_id=f"ingest:{name}", agent_count=len(regs), seed=0, gateway_mode="monitor",
              drop_rate=0.0, agent_backend="external", agent_mode="external", created_at=now, base_time=now,
              stages={"ingesting": now}, counts={"agents": len(regs), "raw_events": 0})
    pipeline.store.put("runs", run_id, run.model_dump(mode="json"))
    pipeline.store.put_many("agents", [(a.agent_id, a.model_dump(mode="json")) for a in regs])
    get_hub().publish("run_started", {"config": {"scenario_id": run.scenario_id, "source": "ingest",
                                                 "live_guard": live_guard, "agent_count": len(regs)}}, run_id)
    from app.services import review

    SESSIONS[run_id] = IngestSession(run_id, regs, guard, review.recorder(pipeline.store, run_id), require_identity)
    exp = int(time.time()) + token_ttl if token_ttl else None  # scoped tokens expire; re-open or re-issue to renew
    return {"run_id": run_id, "stream": f"/api/live?run_id={run_id}", "require_agent_identity": require_identity,
            "token_ttl": token_ttl,
            "agent_tokens": {a.agent_id: agent_token(run_id, a.agent_id, exp) for a in regs}}


def session(run_id: str) -> IngestSession:
    s = SESSIONS.get(run_id)
    if s is None:
        raise ValueError(f"no open ingest session {run_id} (open one with POST /api/ingest/sessions)")
    return s


def control(run_id: str) -> dict[str, Any]:
    """What the guard has decided about each agent right now, for a platform to poll and act on (no push needed)."""
    s = session(run_id)
    g = s.guard
    if g is None:
        return {"run_id": run_id, "mode": "off", "paused": {}, "held_egress": {}, "quarantined": []}
    def why(c):
        return {"trigger": c.trigger, "since_event": c.paused_at_sequence, "explanation": c.explanation}
    return {"run_id": run_id, "mode": g.mode, "paused": {a: why(c) for a, c in g.paused.items()},
            "held_egress": {a: why(c) for a, c in g.held.items()}, "quarantined": list(g.quarantined)}


def add_events(pipeline, run_id: str, events: list[dict]) -> dict[str, Any]:
    s = session(run_id)
    before = len(s.guard.detections) if s.guard else 0
    added = [s.add(e) for e in events]
    pipeline.store.put_many("raw_events", [(e.event_id, e.model_dump(mode="json")) for e in added])
    g = s.guard
    return {"accepted": len(added), "event_ids": [e.event_id for e in added],
            "denied": [e.event_id for e in added if e.status == "denied"],
            "new_detections": [d.model_dump(mode="json") for d in g.detections[before:]] if g else [],
            "paused_agents": sorted(g.paused) if g else [], "held_egress": sorted(g.held) if g else []}


def finish(pipeline, run_id: str) -> dict[str, Any]:
    s = SESSIONS.pop(run_id, None) or session(run_id)
    s.stream.close()
    run = pipeline.get_run(run_id)
    events = pipeline.raw_events(run_id)
    run.counts["raw_events"] = len(events)
    run.stages.pop("ingesting", None)
    run.stages["simulated"] = now_iso()  # the pipeline's first stage: events exist
    pipeline.store.put("runs", run_id, run.model_dump(mode="json"))
    report = s.guard.report(run) if s.guard else None
    if report:
        pipeline.store.put("evaluations", f"live-{run_id}", {**report.model_dump(mode="json"), "kind": "live"})
    pipeline.run_all(run_id)
    done = {"persisted": True, "counts": run.counts, "alerts": len(pipeline.alerts(run_id)),
            "live_metrics": report.metrics if report else None}
    get_hub().publish("run_finished", done, run_id)
    return {"run_id": run_id, **done}
