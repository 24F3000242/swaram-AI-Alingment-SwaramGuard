"""SwarmGuard SDK: connect any agent platform to SwarmGuard in a few lines.

    from swarmguard_sdk import SwarmGuard

    sg = SwarmGuard("http://guard:8000", api_key="...")              # an `agent` key when auth is on
    s = sg.open_session("crew-demo", [{"agent_id": "a1", "role": "analyst", "permissions": ["data/public"]}])

    @s.guarded("a1", resource="tool/sql_query")                       # ask the gate first, report after
    def run_query(sql): ...

    s.report("a1", "resource_access", "read", resource="inbox/email_1", content=email_text, untrusted=True)
    os.environ["HTTPS_PROXY"] = s.proxy_url("a1", "http://guard:8899")  # network enforcement, no cooperation needed
    s.finish()

Framework adapters: `swarmguard_sdk.langchain.SwarmGuardCallbackHandler`. Only needs `httpx`.
"""
from __future__ import annotations

import functools
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import quote

import httpx

__all__ = ["SwarmGuard", "Session", "Decision", "Blocked"]


class Blocked(Exception):
    """SwarmGuard denied the action: the agent must not do it."""

    def __init__(self, agent_id: str, reason: str | None):
        super().__init__(f"SwarmGuard blocked {agent_id}: {reason}")
        self.agent_id, self.reason = agent_id, reason


@dataclass
class Decision:
    allow: bool
    reason: str | None = None


class SwarmGuard:
    def __init__(self, base_url: str = "http://127.0.0.1:8000", api_key: str | None = None, client=None,
                 timeout: float = 30):
        self.http = client or httpx.Client(base_url=base_url, timeout=timeout)
        self.headers = {"X-API-Key": api_key} if api_key else {}

    def _call(self, method: str, path: str, body: Any = None) -> Any:
        r = self.http.request(method, path, json=body, headers=self.headers)
        if r.status_code >= 400:
            raise RuntimeError(f"SwarmGuard {method} {path}: {r.status_code} {r.text[:200]}")
        return r.json()

    def open_session(self, name: str, agents: list[dict], live_guard: str = "contain",
                     require_agent_identity: bool = False) -> "Session":
        """Register the agents (agent_id, role, permissions) and start watching. Returns a Session."""
        out = self._call("POST", "/api/ingest/sessions", {"name": name, "agents": agents, "live_guard": live_guard,
                                                           "require_agent_identity": require_agent_identity})
        return Session(self, out["run_id"], out.get("stream"), out.get("agent_tokens") or {})


class Session:
    def __init__(self, sg: SwarmGuard, run_id: str, stream: str | None, tokens: dict[str, str]):
        self.sg, self.run_id, self.stream, self.tokens = sg, run_id, stream, tokens

    def _event(self, agent_id: str, event_type: str, action: str, resource: str | None = None,
               target: str | None = None, content: str | None = None, untrusted: bool = False,
               status: str | None = None, payload: dict | None = None) -> dict:
        p = dict(payload or {})
        if content is not None:
            p["content"] = content
        if untrusted:
            p["untrusted"] = True
        ev = {"agent_id": agent_id, "event_type": event_type, "action": action, "payload": p}
        for k, v in (("resource", resource), ("target", target), ("status", status)):
            if v is not None:
                ev[k] = v
        if agent_id in self.tokens:
            ev["agent_token"] = self.tokens[agent_id]
        return ev

    def gate(self, agent_id: str, event_type: str, action: str, **kw) -> Decision:
        """Ask BEFORE acting. allow=False means: don't do it."""
        out = self.sg._call("POST", f"/api/ingest/{self.run_id}/gate", self._event(agent_id, event_type, action, **kw))
        return Decision(bool(out["allow"]), out.get("reason"))

    def report(self, agent_id: str, event_type: str, action: str, **kw) -> dict:
        """Report what an agent did (right after it did it)."""
        return self.sg._call("POST", f"/api/ingest/{self.run_id}/events", [self._event(agent_id, event_type, action, **kw)])

    def control(self) -> dict:
        """Which agents are paused / have outbound transfers held right now, and why."""
        return self.sg._call("GET", f"/api/ingest/{self.run_id}/control")

    def finish(self) -> dict:
        return self.sg._call("POST", f"/api/ingest/{self.run_id}/finish", {})

    def proxy_url(self, agent_id: str, proxy: str = "http://127.0.0.1:8899", key: str | None = None) -> str:
        """HTTP(S)_PROXY value for this agent: its traffic is then checked at the network."""
        secret = self.tokens.get(agent_id) or key or "no-auth"
        host = proxy.split("://", 1)[-1]
        return f"http://{quote(f'{self.run_id}/{agent_id}', safe='')}:{quote(secret, safe='')}@{host}"

    def guarded(self, agent_id: str, event_type: str = "tool_call", action: str = "run", resource: str | None = None,
                target: str | None = None) -> Callable:
        """Decorator: gate before the call (raise Blocked if denied), report success or failure after."""
        def wrap(fn: Callable) -> Callable:
            @functools.wraps(fn)
            def inner(*args, **kwargs):
                d = self.gate(agent_id, event_type, action, resource=resource, target=target)
                if not d.allow:
                    self.report(agent_id, event_type, action, resource=resource, target=target, status="denied",
                                payload={"gateway_reason": d.reason})
                    raise Blocked(agent_id, d.reason)
                try:
                    result = fn(*args, **kwargs)
                except Exception:
                    self.report(agent_id, event_type, action, resource=resource, target=target, status="failed")
                    raise
                self.report(agent_id, event_type, action, resource=resource, target=target)
                return result
            return inner
        return wrap
