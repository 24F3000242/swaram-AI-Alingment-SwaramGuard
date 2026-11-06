# Live stream: contract for the live UI

Everything that happens in a run is pushed to the UI the moment it happens: each agent action, each detection, each
pause or hold, each quarantined input. It works the same for simulated runs and for real agents reporting through the
ingest API. A reference page lives at **Live monitor** (`frontend/src/pages/LivePage.tsx`), with a reusable hook in
`frontend/src/lib/live.ts`.

## Connect

```
WebSocket  /api/live                 every run
WebSocket  /api/live?run_id=run-…    one run
WebSocket  /api/live?since=<seq>     replay everything after <seq> (resume after a reconnect)
```

On connect you get `hello`, then the recent history (up to 2000 messages), then live messages. Use `seq` to drop
duplicates after a reconnect (`useLiveStream()` does this for you).

```ts
import { useLiveStream } from "../lib/live";
const { messages, connected } = useLiveStream(runId); // runId optional
```

In dev the Vite proxy forwards WebSockets (`ws: true` in `vite.config.ts`).

## Start a run without waiting

```
POST /api/runs/start      body: ScenarioConfig (same as /api/simulate)  ->  {"run_id": "run-…", "stream": "/api/live"}
GET  /api/live/active     runs in progress
```

The call returns at once; the run streams. Use `live_guard: "contain"` to see attackers being stopped, and
`auto_pipeline: true` to have alerts, response and evaluation ready when it finishes. Gemini runs are refused up front
if today's quota can't cover them (`GET /api/gemini/quota`).

## Message envelope

```json
{"type": "event", "seq": 42, "ts": "2026-11-05T12:00:00.123Z", "run_id": "run-1a2b3c4d", "data": {}}
```

`seq` is global and strictly increasing. `run_id` is null only for messages about the whole system (`quota`).

| type | when | `data` |
|---|---|---|
| `hello` | on connect | `{subscribers}` |
| `run_started` | a run begins | `{config}`: the ScenarioConfig, or `{scenario_id, source: "ingest", live_guard, agent_count}` |
| `run_agents` | right after | `{agents: [{agent_id, name, role, permissions}]}` |
| `event` | every agent action, as it happens | `{event_id, agent_id, timestamp, event_type, action, status, target, resource, sequence, gateway_decision, payload}`. `status: "denied"` with `payload.quarantined` means it was **blocked before it ran**. `payload.ai_trace` says why a model-driven agent acted. |
| `detection` | a rule fires for the first time on some agents | `{sequence, timestamp, event_id, rule_id, rule_name, severity, agent_ids, reason}` (empty `agent_ids` = run-level, e.g. SG-026) |
| `containment` | an agent is paused, or its outbound transfers held | `{agent_id, role, scope: "agent"\|"egress", trigger: "risk"\|"hijack_tripwire"\|"need_to_know"\|"policy_check"\|"policy"\|"operator", paused_at_sequence, risk, explanation, blocked_actions}` |
| `quarantine` | an untrusted input was withheld before the agent read it | `{agent_id, resource, claimed_sender, sequence}` |
| `response` | the response policy acted on a new alert, live | `{sequence, rule_id, rule_name, severity, decision, agent_ids, applied}`; `applied` is e.g. `["paused"]`, `["egress held"]`, `["recorded"]`, or `["would_pause"]` in detect mode |
| `operator` | a person paused an agent / held its egress from the UI | `{agent_id, action, result, note}` |
| `review` | a review item was created or decided | `{action: "created"\|"decided", item}` (see the review queue) |
| `quota` | after a Gemini run | the `/api/gemini/quota` object |
| `run_finished` | the run is done (and saved, and processed if `auto_pipeline`) | `{persisted, counts, stages, live_metrics, alerts, ground_truth}`. `live_metrics.data_left_the_system` is the headline. `ground_truth` is for demo scoring only. |
| `run_failed` | the run crashed | `{error}` |

Suggested UI: an agent grid that turns amber on `detection` and red on `containment`; a feed of `event`s where
`status: "denied"` is shown as blocked; toasts for `detection`, `containment` and `quarantine`; a banner on
`run_finished` with whether data left the system.

**Pre-execution policy check.** In `contain` mode the live guard refuses any action outside the agent's own policy
*before it runs*: a restricted resource it may not read, an upload to an unapproved destination, or handing restricted
data to a teammate who may not hold it. It applies to every agent, whatever the cause (an injection, a goal of its
own, a bug). The refused action is logged as `denied` and the agent's outbound transfers are held for review
(`containment` with trigger `policy_check`). Honest work is never refused. It covers everything that goes through the
gate: simulated runs, and platforms that call `/gate` (or use the SDK). Platforms that don't call the gate are covered
at the network by the egress proxy. Turn it off with `LiveGuard(..., policy_gate=False)`.

## Operator controls (while a run is live)

```
POST /api/live/{run_id}/agents/{agent_id}   {"action": "pause" | "hold_egress", "note": "..."}  -> {"result": "paused"}
POST /api/live/{run_id}/stop                {"note": "..."}  -> pauses every agent (kill switch)
```

Only for runs started with `live_guard: "contain"` that are still running (409 otherwise). Each action is published
as `containment` + `operator`, and lands in the review queue (`GET /api/reviews`, release / confirm).

## Real agents (live ingest)

An external agent platform reports into the same pipeline and stream:

```
POST /api/ingest/sessions     {"name": "crew-demo", "live_guard": "contain",
                               "agents": [{"agent_id": "a1", "role": "analyst", "permissions": ["data/customer_pii"]}]}
                              -> {"run_id": "run-…", "stream": "/api/live?run_id=run-…"}
POST /api/ingest/{run_id}/gate    {"agent_id", "event_type", "action", "resource", "target", "payload"}
                              -> {"allow": false, "reason": "egress held since event #3: …"}   (ask BEFORE acting)
POST /api/ingest/{run_id}/events  [{"agent_id", "event_type", "action", "resource", "target", "payload"}, …]
                              -> {"accepted", "denied", "new_detections", "paused_agents", "held_egress"}
POST /api/ingest/{run_id}/finish  -> runs collect, detect, respond, evaluate; publishes run_finished
```

`event_type` is one of `message`, `tool_call`, `resource_access`, `data_transfer`, `task`. `event_id`, `timestamp` and
`sequence` are filled in if missing.

```
GET  /api/ingest/{run_id}/control  -> {"paused": {agent: {trigger, since_event, explanation}}, "held_egress": {...},
                                       "quarantined": [...]}   (poll this to act on the guard's decisions)
```

Every session also returns `agent_tokens`: one token per agent (HMAC-SHA256 of the run and agent id). Open the
session with `"require_agent_identity": true` and every event and gate call must include that agent's own
`agent_token` (403 otherwise), and the egress proxy takes it as the agent's password. One agent, or a compromised
process holding the platform's key, then can't report or act as another. Tokens are never stored with events.

Platforms in Python can use the SDK instead of raw HTTP (`sdk/python`, with a LangChain callback handler).

## Enforcement when the platform doesn't ask the gate: the egress proxy

The gate only stops what a platform asks about. A hijacked agent, or a platform that only reports, won't ask. Data
theft still has to leave over the network, so SwarmGuard can sit on that path: start the app with
`SWARMGUARD_EGRESS_PROXY_PORT=8899` and run each agent with

```
HTTP_PROXY=http://<run_id>%2F<agent_id>:<agent api key>@guard-host:8899
HTTPS_PROXY=http://<run_id>%2F<agent_id>:<agent api key>@guard-host:8899
```

(and block direct outbound traffic at the firewall, so the proxy is the only way out). Every request is then checked
whether or not the agent cooperates:

| Situation | Proxy answer | Recorded as |
|---|---|---|
| Agent paused (live detection, policy, operator, tripwire) | 403 | blocked `data_transfer` (a real block) |
| Agent's outbound transfers held (need-to-know) | 403 | blocked `data_transfer` |
| Destination not in `SWARMGUARD_EGRESS_ALLOW` (enforce mode) | 403 | blocked `data_transfer` |
| Allowed | forwarded | egress sensor record; if the agent never reports it, SG-021 flags a gateway bypass |
| No / wrong credentials | 407 | nothing |

HTTPS goes through a CONNECT tunnel: the proxy sees the host, not the content (no TLS interception). With
`SWARMGUARD_EGRESS_MODE=monitor` off-allowlist hosts are forwarded but flagged; guard decisions are always enforced.
If the proxy can't reach a decision it refuses (fails closed). `GET /api/egress-proxy` shows its settings and recent
decisions.

## Performance

The live guard re-checks every rule over the run so far after each event, so its cost grows with the square of the
run length. Four caches remove the repeated work without changing any result (all 206 snapshotted outputs, alerts,
risk scores, live decisions and benchmark numbers, are identical before and after): timestamp parsing, SG-020's text
scan, one log-coverage index per detection pass, and one-pass per-agent facts in risk scoring.

| Live guard, `sg003_leak_chain` | Before | After |
|---|---|---|
| 5 agents (80 events) | 405 ms | 104 ms |
| 10 agents (177 events) | 1.7 s | 0.41 s |
| 20 agents (369 events) | 7.6 s | 1.6 s |

Very long sessions (thousands of events) would still slow down; the next step would be evaluating the heavy rules over
a recent window, which trades exactness on whole-run rules (e.g. SG-016 salami) and so is not done yet.

## MCP gateway

Agents that reach their tools over MCP (Model Context Protocol, streamable HTTP) can go through SwarmGuard without
any code change. Point the agent's MCP client at `POST /api/ingest/{run_id}/mcp/{agent_id}` instead of the tool server,
and open the session with:

```json
"mcp": {"upstream": "http://tools:9000/mcp", "tools": {"a1": ["search", "read_ticket"]}, "untrusted_results": true}
```

What the gateway does:
- **`tools/list`**: tools outside the agent's allowlist are removed from the answer.
- **`tools/call`**: an unlisted tool is refused. Every other call goes through the live guard's gate: pause, egress
  hold, hijack tripwire and the pre-execution policy check.
  - A call naming a resource (`path`, `file`, `resource`, ...) is checked as an access to that resource.
  - A call naming a URL or `external:` destination is checked as an upload.
  - A refusal comes back as an MCP tool error (`isError: true`), so the agent's framework handles it normally.
  - Allowed calls go to the real server. Their output is reported as untrusted content, so the injection classifier
    scores it.
- **Everything else** passes through unchanged: initialize, notifications, resources, prompts.
- **Identity:** with `require_agent_identity`, the agent sends its token in `X-Agent-Token`.

## SIEM export (OCSF)

`GET /api/runs/{run_id}/alerts?format=ocsf` returns the alerts as **OCSF Detection Findings** (class 2004). That's the
open schema Splunk, Microsoft Sentinel, AWS Security Lake and QRadar ingest. Each finding carries:
- the rule and severity;
- the agents, as resources;
- the evidence event ids and the recommended action;
- its OWASP Agentic Top 10 risk IDs.

Set `SWARMGUARD_SIEM_URL` (plus `SWARMGUARD_SIEM_AUTH` for an Authorization header) to push every finished run's
findings automatically.
