"""LangChain integration: every tool call an agent makes is gated and reported, tool output is scanned.

    from swarmguard_sdk.langchain import SwarmGuardCallbackHandler

    handler = SwarmGuardCallbackHandler(session, agent_id="a1", untrusted_tools={"web_search", "read_email"})
    agent_executor.invoke({"input": "..."}, config={"callbacks": [handler]})

- on_tool_start asks the gate; if SwarmGuard says no, it raises `Blocked` and the tool never runs
  (`raise_error = True` makes LangChain propagate it).
- on_tool_end reports the call; output of tools in `untrusted_tools` is sent as untrusted content, so SwarmGuard's
  prompt-injection classifier (SG-028) scores it and the hijack tripwire arms.
- on_tool_error reports the failure.
Works with langchain-core's BaseCallbackHandler when installed; the handler itself only needs the SDK.
"""
from __future__ import annotations

from typing import Any

from swarmguard_sdk import Blocked, Session

try:  # inherit LangChain's base class when available (it is duck-typed either way)
    from langchain_core.callbacks import BaseCallbackHandler as _Base
except Exception:  # pragma: no cover - langchain not installed
    _Base = object


class SwarmGuardCallbackHandler(_Base):
    raise_error = True  # LangChain re-raises exceptions from this handler: a Blocked tool call stops

    def __init__(self, session: Session, agent_id: str, untrusted_tools: set[str] | None = None, block: bool = True):
        self.session, self.agent_id, self.block = session, agent_id, block
        self.untrusted_tools = set(untrusted_tools or ())
        self._running: dict[Any, str] = {}

    @staticmethod
    def _tool(serialized: dict | None, kw: dict) -> str:
        return str((serialized or {}).get("name") or kw.get("name") or "tool")

    def on_tool_start(self, serialized: dict, input_str: str, *, run_id=None, **kw: Any) -> None:
        name = self._tool(serialized, kw)
        self._running[run_id] = name
        d = self.session.gate(self.agent_id, "tool_call", "run", resource=f"tool/{name}", payload={"input": input_str[:2000]})
        if not d.allow and self.block:
            self.session.report(self.agent_id, "tool_call", "run", resource=f"tool/{name}", status="denied",
                                payload={"gateway_reason": d.reason})
            raise Blocked(self.agent_id, d.reason)

    def on_tool_end(self, output: Any, *, run_id=None, **kw: Any) -> None:
        name = self._running.pop(run_id, None) or self._tool(None, kw)
        text = str(getattr(output, "content", output))
        untrusted = name in self.untrusted_tools
        self.session.report(self.agent_id, "tool_call", "run", resource=f"tool/{name}",
                            content=text[:4000] if untrusted else None, untrusted=untrusted)

    def on_tool_error(self, error: BaseException, *, run_id=None, **kw: Any) -> None:
        name = self._running.pop(run_id, None) or self._tool(None, kw)
        if not isinstance(error, Blocked):
            self.session.report(self.agent_id, "tool_call", "run", resource=f"tool/{name}", status="failed",
                                payload={"error": str(error)[:300]})
