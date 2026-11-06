"""Live hub: pushes what happens in a run to connected UIs the moment it happens.

Runs execute in worker threads; UIs listen on a WebSocket (asyncio). The hub bridges the two: `publish()` can be
called from any thread, and every subscriber gets each message through its own event loop. Recent messages are kept
so a UI that connects mid-run (or refreshes) can catch up.

Message envelope (see docs/live-stream.md for every type):
    {"type": "event", "seq": 42, "ts": "2026-11-05T12:00:00.123Z", "run_id": "run-…", "data": {...}}
"""
from __future__ import annotations

import asyncio
import itertools
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from app.timeutil import now_iso

HISTORY = 2000  # recent messages kept for late joiners


@dataclass
class Subscriber:
    loop: asyncio.AbstractEventLoop
    queue: asyncio.Queue
    run_id: str | None = None  # None = every run

    def wants(self, msg: dict) -> bool:
        return self.run_id is None or msg.get("run_id") in (None, self.run_id)


@dataclass
class LiveHub:
    history: deque = field(default_factory=lambda: deque(maxlen=HISTORY))
    _subs: list[Subscriber] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _seq: Any = field(default_factory=lambda: itertools.count(1))
    taps: list = field(default_factory=list)  # callables(msg) run on every publish, e.g. notifications

    def publish(self, type_: str, data: dict | None = None, run_id: str | None = None) -> dict:
        with self._lock:
            msg = {"type": type_, "seq": next(self._seq), "ts": now_iso(), "run_id": run_id, "data": data or {}}
            self.history.append(msg)
            subs = list(self._subs)
        for tap in list(self.taps):
            try:
                tap(msg)
            except Exception:  # a tap must never break a run
                pass
        for s in subs:
            if s.wants(msg):
                try:
                    s.loop.call_soon_threadsafe(s.queue.put_nowait, msg)
                except RuntimeError:  # that subscriber's loop is gone
                    self.unsubscribe(s)
        return msg

    def subscribe(self, loop: asyncio.AbstractEventLoop, run_id: str | None = None) -> Subscriber:
        sub = Subscriber(loop, asyncio.Queue(), run_id)
        with self._lock:
            self._subs.append(sub)
        return sub

    def unsubscribe(self, sub: Subscriber) -> None:
        with self._lock:
            if sub in self._subs:
                self._subs.remove(sub)

    def replay(self, run_id: str | None = None, since: int = 0) -> list[dict]:
        with self._lock:
            return [m for m in self.history if m["seq"] > since and (run_id is None or m.get("run_id") in (None, run_id))]

    @property
    def subscribers(self) -> int:
        return len(self._subs)


HUB = LiveHub()
ACTIVE_GUARDS: dict[str, object] = {}  # run_id -> live guard of a run still in progress
ACTIVE_STREAMS: dict[str, "LiveStream"] = {}  # run_id -> its stream (operator actions publish through it)


def get_hub() -> LiveHub:
    return HUB


def active_guard(run_id: str):
    return ACTIVE_GUARDS.get(run_id)


def active_stream(run_id: str) -> "LiveStream | None":
    return ACTIVE_STREAMS.get(run_id)


# ---------------------------------------------------------------- run instrumentation
def _event_view(raw) -> dict:
    d = raw.model_dump(mode="json") if hasattr(raw, "model_dump") else dict(raw)
    payload = d.get("payload") or {}
    keep = {k: payload[k] for k in ("content", "data_ref", "intent", "topic", "claimed_sender", "untrusted", "quarantined",
                                    "gateway_reason", "ai_trace") if k in payload}
    return {k: d.get(k) for k in ("event_id", "agent_id", "timestamp", "event_type", "action", "status", "target",
                                  "resource", "sequence", "gateway_decision")} | {"payload": keep}


class LiveStream:
    """Wraps the live guard (if any) with the runner's duck-typed hook, and publishes everything as it happens.

    The runner calls start() once, gate() before every action and observe() after; with no guard, gate() never
    denies, so streaming alone never changes a run.
    """

    def __init__(self, hub: LiveHub, guard=None, on_contained=None):
        self.hub, self.guard, self.run_id = hub, guard, None
        self.on_contained = on_contained  # callback(kind, data) for each containment / quarantine (review queue)
        self._seen = {"detections": 0, "quarantined": 0, "responses": 0}
        self._published: set[tuple[str, str]] = set()  # containments already announced (agent, scope)
        import threading as _t

        self._lock = _t.RLock()  # operator actions (API thread) vs the run (worker thread)

    def start(self, run_id: str, agents) -> None:
        self.run_id = run_id
        if self.guard:
            self.guard.start(run_id, agents)
            ACTIVE_GUARDS[run_id] = self.guard
            ACTIVE_STREAMS[run_id] = self
        self.hub.publish("run_agents", {"agents": [{"agent_id": a.agent_id, "name": a.name, "role": a.role,
                                                    "permissions": a.permissions} for a in agents]}, run_id)

    def gate(self, agent_id, event_type=None, target=None, **kw):
        with self._lock:
            reason = self.guard.gate(agent_id, event_type, target, **kw) if self.guard else None
            self._flush()
        return reason

    def observe(self, raw) -> None:
        self.hub.publish("event", _event_view(raw), self.run_id)
        with self._lock:
            if self.guard:
                self.guard.observe(raw)
            self._flush()

    def _flush(self) -> None:
        """Publish whatever the guard concluded since the last check (detections, pauses, holds, quarantines)."""
        g = self.guard
        if not g:
            return
        for d in g.detections[self._seen["detections"]:]:
            self.hub.publish("detection", d.model_dump(mode="json"), self.run_id)
        self._seen["detections"] = len(g.detections)
        for r in getattr(g, "responses", [])[self._seen["responses"]:]:
            self.hub.publish("response", dict(r), self.run_id)
        self._seen["responses"] = len(getattr(g, "responses", []))
        for c in [*g.held.values(), *g.paused.values()]:
            key = (c.agent_id, c.scope)
            if key not in self._published:
                self._published.add(key)
                data = c.model_dump(mode="json")
                self.hub.publish("containment", data, self.run_id)
                if self.on_contained:
                    self.on_contained("containment", data)
        for q in g.quarantined[self._seen["quarantined"]:]:
            self.hub.publish("quarantine", dict(q), self.run_id)
            if self.on_contained:
                self.on_contained("quarantine", dict(q))
        self._seen["quarantined"] = len(g.quarantined)

    def operator(self, agent_id: str, action: str, note: str | None = None) -> str:
        """Operator action from the live UI; published (and queued for review) immediately."""
        if not self.guard or self.guard.mode != "contain":
            raise ValueError("this run isn't contained live; start it with live_guard='contain'")
        with self._lock:
            result = self.guard.operator(agent_id, action, note)
            self._flush()
        self.hub.publish("operator", {"agent_id": agent_id, "action": action, "result": result, "note": note}, self.run_id)
        return result

    def close(self) -> None:
        """The run is over: nothing left to release."""
        ACTIVE_GUARDS.pop(self.run_id, None)
        ACTIVE_STREAMS.pop(self.run_id, None)

    def report(self, run):
        return self.guard.report(run) if self.guard else None
