# Real LangChain and MCP integrations

Branch: `pranav/real-integration-tests`, based on hackathon repository
`controlledai9-stack/swaram-AI-Alingment-SwaramGuard` at `01ea96e`.
Only tests, optional requirements, and this document are added; application and SDK code are unchanged.

## Versions and running

Verified on Windows with Python 3.12.10. `backend/requirements-integration.txt` pins:

| Package | Version |
| --- | --- |
| langchain-core | 0.3.79 |
| langchain | 0.3.27 |
| mcp (official Python SDK) | 1.29.0 |
| uvicorn | 0.38.0 |

From `backend/`, in a fresh virtual environment:

```sh
pip install -r requirements.txt
pip install -r requirements-integration.txt && python -m pytest tests/test_real_langchain.py tests/test_real_mcp.py -v
```

For the ordinary suite, install only `requirements.txt` and run `python -m pytest`.
Both integration modules skip during collection if their framework packages are absent.
The LangChain module also skips if `langchain-core` is present without `langchain`.
Dependency resolution was checked with `python -m pip check` (no broken requirements).

## What runs

LangChain uses its real `AgentExecutor`, tool-message scratchpad, tool-call parser,
`FakeMessagesListChatModel`, and two real `@tool` functions. The fake model scripts
tool calls; it does not prove whether a live model would follow an injection.
The production callback and SwarmGuard SDK talk to a real localhost FastAPI server.

MCP uses the official `FastMCP` server, Streamable HTTP client, and `ClientSession`,
pointed at SwarmGuard's gateway. Every MCP case runs twice: upstream SSE and JSON
responses, with real initialization and stateful MCP session headers.

Servers bind to reserved ephemeral ports on `127.0.0.1`. Fixtures stop and join
server threads, close HTTP clients, remove their ingest sessions, restore dependency
overrides, and close their temporary SQLite database. Backend lifespan is disabled
to avoid starting deployment services or opening the developer's configured store;
the real routes, middleware, SDK, gateway, policy, and detection logic execute.
Fixtures disable dotenv loading, paid providers, external injection scoring, and
LangSmith tracing; quota persistence is off. Tool side effects are in-memory records.
No API keys or model calls are required.

## Results

| Test | Result |
| --- | --- |
| LangChain: allowed file read and approved-partner upload; API events | PASS |
| LangChain: attacker-destination upload stopped before tool execution | XFAIL (SG-LC-001) |
| LangChain: operator pause prevents execution and records denial | PASS |
| LangChain: injected file output recorded as untrusted through API | PASS |
| LangChain: upload after injected output stopped before execution | XFAIL (SG-LC-001) |
| MCP: initialize through gateway | PASS (SSE + JSON) |
| MCP: tool list hides send_email | PASS (SSE + JSON) |
| MCP: search returns real server result and records success | PASS (SSE + JSON) |
| MCP: send_email returns isError and server receives zero calls | PASS (SSE + JSON) |
| MCP: injected ticket is untrusted and has an SG-028 alert referencing its event and classifier score | PASS (SSE + JSON) |
| MCP: pause refuses a previously allowed call before server execution | PASS (SSE + JSON) |

The focused integration command completed with **15 passed, 2 xfailed**.
Without optional packages, the full suite completed with **933 passed, 2 skipped**.
With optional packages installed, the final full suite completed with
**948 passed, 2 xfailed** (13 upstream SDK warnings, no errors or unexpected failures).
Earlier runs observed intermittent failures in existing `test_agent_demo.py`
network tests (including `test_summary_reads_well` with optional packages installed).
All five tests in that file passed on rerun, and the full baseline rerun passed.
These existing tests have not been modified or marked xfail.

## Bug report for Aarya: SG-LC-001

The callback sends every tool start as `tool_call/run`, resource `tool/<name>`,
and serializes the arguments into `payload.input`. It does not expose an upload's
resource or external destination to the policy gate. Consequently an upload to
`external:attacker-site` runs, even after untrusted injected file content was reported.
The untrusted-output recording and operator pause features work.

Reproduce from `backend/` after installing both requirements files:

```sh
python -m pytest tests/test_real_langchain.py -k "out_of_policy or injection_followed" --runxfail -v
```

Both tests fail because the upload function's side-effect record is present.
Without `--runxfail`, these are strict expected failures with an explicit reason;
only assertion failures qualify, so unrelated infrastructure errors still fail.
Once the adapter is fixed, an unexpected pass fails the suite until the markers
are removed. No application workaround is installed by these tests.
