# SwarmGuard Python SDK

Connects an agent platform to SwarmGuard. It only needs `httpx`.

```bash
pip install httpx
export PYTHONPATH=sdk/python   # or copy the swarmguard_sdk folder into your project
```

## Any platform

```python
from swarmguard_sdk import SwarmGuard, Blocked

sg = SwarmGuard("http://guard:8000", api_key="<agent key>")    # api_key only when SWARMGUARD_API_KEYS is on
s = sg.open_session("crew-demo", [
    {"agent_id": "a1", "role": "analyst", "permissions": ["data/public", "data/customer_pii"]},
], require_agent_identity=True)                                  # each agent proves who it is (own token)

@s.guarded("a1", resource="tool/sql_query")                      # gate first; raises Blocked if denied
def run_query(sql): ...

# Untrusted input is scanned by the prompt-injection classifier (SG-028) and arms the hijack tripwire.
s.report("a1", "resource_access", "read", resource="inbox/email_1", content=email_text, untrusted=True)

# Network enforcement: the agent's traffic is checked even if your code never asks the gate.
os.environ["HTTPS_PROXY"] = s.proxy_url("a1", "http://guard:8899")

s.control()   # {"paused": {...}, "held_egress": {...}}: poll and act on it
s.finish()    # runs the full pipeline: alerts, response, evaluation
```

## LangChain

```python
from swarmguard_sdk.langchain import SwarmGuardCallbackHandler

handler = SwarmGuardCallbackHandler(s, agent_id="a1", untrusted_tools={"web_search", "read_email"})
executor.invoke({"input": "..."}, config={"callbacks": [handler]})
```

Every tool call goes through the gate before it runs. A denied call raises `Blocked`, and the tool never runs.
Output from tools listed in `untrusted_tools` is sent to SwarmGuard as untrusted content, so it gets scanned for
injections.

## MCP

Agents that use MCP tool servers need no SDK: point the MCP client at
`/api/ingest/{run_id}/mcp/{agent_id}` (see the MCP gateway in `docs/live-stream.md`).

## Other frameworks

CrewAI, AutoGen and the OpenAI Agents SDK all let you run code before and after a tool call. Call `s.gate(...)`
before and `s.report(...)` after, the same way `guarded` does. Platforms that already export OpenTelemetry spans or
LangSmith runs can send them as they are: `POST /api/ingest/{run_id}/events?format=otel|langsmith`.
