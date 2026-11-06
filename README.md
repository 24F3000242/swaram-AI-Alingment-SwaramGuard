# SwarmGuard

A small web simulator for a multi-agent security pipeline: agents act, events are
collected and normalized, threats are detected with evidence, responses are decided
(honestly: simulated vs. enforced), and results are evaluated against labeled
synthetic scenarios.

Five modules, one shared dataset. Each teammate can own one module and work on it
alone, because modules only talk through the shared data contracts and the store.

| # | Module | Backend code | UI page | Reads | Writes |
|---|--------|--------------|---------|-------|--------|
| 1 | Agent Simulator | `backend/app/modules/simulator/` | `SimulatorPage.tsx` | scenario config | `runs`, `agents`, `raw_events` |
| 2 | Event Collector | `backend/app/modules/collector/` | `CollectorPage.tsx` | `raw_events` (or an upload) | `normalized_events` |
| 3 | Threat Detection | `backend/app/modules/detection/` | `DetectionPage.tsx` | `normalized_events`, `agents`, `detection_rules` | `alerts` |
| 4 | Security Response | `backend/app/modules/response/` | `ResponsePage.tsx` | `alerts`, `normalized_events`, `response_policies` | `response_actions`, alert status |
| 5 | Dashboard & Evaluation | `backend/app/modules/evaluation/` | `DashboardPage.tsx` | all of the above | `evaluations` |

The stack is React + Vite + TypeScript + Tailwind for the frontend, FastAPI + Pydantic + NetworkX for the backend, and Firestore with a SQLite fallback for storage.
No model is needed: everything runs offline with scripted agents, and real models are optional.

## What it does today

- **AI mode**: each agent's model (Gemini, any OpenAI-compatible API, or a local Ollama model) plans and acts on
  its own; an AI planner assigns the work; agents remember earlier rounds. Attacks are never asked of a model: they are
  scripted, or planted as prompt injections (16 of them, from phishing to a self-spreading worm, a poisoned memory and a sleeper note);
  internal-goal cases test agents with a goal of their own and no attacker.
- **Threat Detection**: 29 rules (SG-001 to SG-029), a learned behavioural baseline, Bayesian risk with explanations,
  and an accuracy benchmark (30 attacks, 14 benign look-alikes; precision 1.0). A second, independent evidence source
  (egress proxy, audit and broker logs) keeps detection working when the agent log loses events.
- **Live guard**: detection while a run happens. It refuses any out-of-policy action before it runs (whatever the
  cause: injection, a goal of the agent's own, a bug), blocks a hijacked agent before its first harmful action,
  quarantines impersonated messages, applies the response policy as alerts fire, trips a swarm circuit breaker on a
  cascade, and pushes everything to the UI over a WebSocket (`docs/live-stream.md`).
- **Security Response**: a review queue (release / confirm, escalation, who decided), operator controls (pause an agent,
  stop a run), webhook notifications, honest records (`blocked` only when an action was really denied), and an egress
  proxy that enforces pauses and holds at the network even when the agent platform doesn't cooperate.
- **Real agents**: a live ingest API with a pre-execution gate, an MCP gateway, a Python SDK and LangChain handler (`sdk/python`),
  per-agent identity tokens, OpenTelemetry and LangSmith importers, personal-data redaction, and a tamper-evident
  hash-chained log.
- **Injection classifier** (SG-028): a model trained on public datasets scores every untrusted input; measured on
  datasets it never saw (`docs/injection-classifier.md`).
- **Operations**: OCSF alert export for SIEMs, OWASP Agentic Top 10 coverage map, API keys with roles, a Gemini quota meter that refuses runs that won't fit, a dataset generator, an
  adaptive injection fuzzer, an internal-goal fuzzer (agents breaking policy for a goal of their own, no attacker), a
  real-agent demo enforced at the network (`scripts/demo_real_agents.py`), and CI on every pull request.

| Doc | What's in it |
|---|---|
| `docs/threat-model.md` | Every threat, rule and measured result |
| `docs/live-stream.md` | The live stream contract, operator controls, ingest API |
| `docs/owasp-agentic.md` | Coverage of the OWASP Top 10 for Agentic Applications |
| `docs/swarm-traces.md` | Results on a real multi-agent incident and the AgentDojo benchmark |
| `docs/injection-classifier.md` | The trained injection classifier: data, licenses, measured results |
| `sdk/python/README.md` | Connecting an agent platform (SDK, LangChain) |
| `docs/collector-and-response.md` | Collector and response features |
| `docs/dataset-generator.md` | Generating AI-mode datasets |
| `backend/app/modules/simulator/README.md` | Simulator, AI mode, injections, providers, quota |

## Setup

You need Python 3.12+ (development and CI use 3.14) and Node 20+ (CI uses 24).

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate          # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

```bash
cd frontend
npm ci
npm run dev                      # http://localhost:5173 (proxies /api to :8000)
```

Without any configuration the backend uses SQLite at `backend/data/swarmguard.db`, so the app works offline straight away.

## Environment variables

Copy `.env.example` to `backend/.env`. Every variable is optional.

| Variable | Default | Purpose |
|----------|---------|---------|
| `SWARMGUARD_STORAGE` | `auto` | `auto` uses Firestore if `FIREBASE_CREDENTIALS` is set, otherwise SQLite. You can also set `sqlite`, `firestore` or `memory`. |
| `SWARMGUARD_WORKSPACE` | `default` | Shared workspace namespace. |
| `SWARMGUARD_SQLITE_PATH` | `backend/data/swarmguard.db` | Location of the SQLite fallback database. |
| `FIREBASE_CREDENTIALS` | none | Path to a service-account JSON file. Server-side only. |
| `FIREBASE_PROJECT_ID` | none | Firebase project id. |
| `SWARMGUARD_API_KEYS` | none | **Login.** `name:key:role,...` with roles `viewer`, `operator`, `admin`, `agent`. Unset = no login (local only). See `backend/app/auth.py`. |
| `GEMINI_API_KEY` / `GEMINI_MODEL` | none / `gemini-3.5-flash-lite` | The `gemini` agent backend. |
| `GEMINI_DAILY_BUDGET` / `GEMINI_MAX_RPM` | `480` / `14` | Local caps under Google's free tier (500/day, 15/min). Usage is shared across processes in `backend/data/gemini_quota.json`. |
| `OPENAI_API_KEY` / `OPENAI_MODEL` / `OPENAI_BASE_URL` | none | The `openai` backend: any OpenAI-compatible API (OpenAI, Groq, OpenRouter). |
| `OLLAMA_MODEL` / `OLLAMA_BASE_URL` | `ministral-3:3b-...` / `http://localhost:11434/v1` | The `ollama` backend: local models, no key, no quota. |
| `ANTHROPIC_API_KEY` | none | Turns on the optional `anthropic` agent backend. |
| `SWARMGUARD_LLM_MODEL` | `claude-haiku-5-5` | Model used by the `anthropic` backend. |
| `SWARMGUARD_LLM_MAX_CALLS` | `80` | Maximum model calls per run. After that, agents fall back to scripted work. |
| `SWARMGUARD_WEBHOOK_URL` | none | Slack / Discord / Teams webhook for containments, quarantines and overdue reviews. |
| `SWARMGUARD_REVIEW_ESCALATE_MIN` | `15` | Minutes before a pending review is escalated. |
| `SWARMGUARD_REDACT_PII` | `1` | Replace emails, phones, cards and SSNs in stored events with pseudonyms. |
| `SWARMGUARD_EGRESS_PROXY_PORT` | none | Start the egress proxy: blocks paused / held agents and off-allowlist hosts at the network, no agent cooperation needed (`docs/live-stream.md`). |
| `SWARMGUARD_EGRESS_ALLOW` / `SWARMGUARD_EGRESS_MODE` | none / `enforce` | Hosts agents may reach; `monitor` flags instead of refusing. |
| `SWARMGUARD_SIEM_URL` / `SWARMGUARD_SIEM_AUTH` | none | Push each finished run's alerts as OCSF findings to a SIEM. |
| `SWARMGUARD_CODE_EXEC` | `sandbox` | `off` never runs agent-written code. |
| `SWARMGUARD_CORS_ORIGINS` | `http://localhost:5173,…` | Allowed browser origins. |

### Enabling Firestore later

1. Create a Firebase project with a Firestore database, then create a service-account key (Project settings → Service accounts).
2. Run `pip install -r requirements-firestore.txt`.
3. Set `FIREBASE_CREDENTIALS=<path to key>` and `FIREBASE_PROJECT_ID=<id>` in `backend/.env`, then restart the backend. The sidebar footer should show `Storage: firestore`.
4. Deploy `firestore.rules`. It denies all direct client access, so all writes go through FastAPI using the Admin SDK and credentials never reach the browser.

Data lives under `workspaces/{SWARMGUARD_WORKSPACE}/{collection}/{doc_id}` in these collections:
`scenarios, runs, agents, raw_events, normalized_events, alerts, response_actions, detection_rules, response_policies, evaluations, reviews`.
Every run-scoped document carries `run_id`, which is how the modules index and query data.

## Tests

```bash
cd backend
.venv\Scripts\python -m pytest -q
```

```bash
cd frontend
npm test
```

```bash
cd frontend
npm run typecheck
```

There are about 700 backend tests (simulator, AI mode with fake models, injections, collector, detection, the
benchmark, live guard, streaming, ingest, response, auth and the API) and frontend tests for helpers and components.
GitHub Actions runs all of them, plus the typecheck and a production build, on every pull request
(`.github/workflows/ci.yml`). No test calls a real model.

Detection accuracy: `python scripts/benchmark_detection.py` (add `--sensors` for the two-source setup).

To regenerate fixtures from the real modules:

```bash
cd backend
.venv\Scripts\python scripts/generate_fixtures.py
```

## Exact data flow

```
ScenarioConfig ──► [1] Simulator ──► raw_events (+ runs, agents with ground-truth labels)
                     │  AgentRunner calls PolicyGateway.check() BEFORE every protected tool
                     │  (restricted resource / external destination):
                     │    off → not_checked, monitor → would_block (runs), enforce → blocked (status=denied, never runs)
                     ▼
raw_events ──► [2] Collector ──► normalized_events  (+ CollectionReport: errors, warnings, duplicates)
                 validate required fields → parse/normalize timestamp (ISO, offsets, epoch s/ms → UTC ms Z)
                 → run_id match → status/event_type aliases → duplicate id / duplicate content
                 → agent & target identity vs run registry → keep `raw` + sha256 `raw_hash` → summary
                     ▼
normalized_events ──► [3] Detection ──► alerts (+ NetworkX agent graph)
                 SG-001 unauthorized restricted access (uses agent permissions)
                 SG-002 transfer to a non-allowlisted external destination
                 SG-003 leakage chain: restricted read → message(data_ref) → … → external transfer
                 SG-004 behavioral anomaly (System 1): surprise in bits vs a learned per-role baseline
                 Per-agent risk: Bayesian posterior from a 2% prior × one likelihood ratio per rule + anomaly
                 Best explanation: ranked hypotheses (insider, rogue, colluding member, misconfiguration, benign)
                 Every alert lists event_ids + evidence. Message text is never evidence.
                     ▼
alerts + policy ──► [4] Response ──► response_actions (linked by alert_id), alert.status updated
                 decision = rule_override or severity_actions[severity]
                 outcome  = blocked ONLY if policy.mode=enforce AND the gateway denied an alert event
                            (gateway_event_ids lists them); otherwise would_block / would_pause / alerted / allowed
                     ▼
everything ──► [5] Dashboard & Evaluation ──► evaluations
                 totals, outcomes, graph, timeline, flagged agents with supporting event IDs,
                 precision / recall / FPR / latency / containment / evidence coverage,
                 and a suite across scenarios × seeds × missing-event rates
```

Re-running a stage replaces that run's output and clears downstream outputs. For example, re-collecting deletes the run's alerts and responses, so references never point at stale events.
IDs are `run-<hex>`, `agt-<hex>-NN`, `evt-<hex>-NNNN`, `alt-<sha1>` and `rsp-<sha1>`. Alert and response IDs are content hashes, so re-running gives the same IDs.

## Threat Detection: two-layer design

These ideas come from cognitive science: dual-process thinking, Bayesian belief updating, abductive reasoning and continual learning.

- **System 1, fast (`detection/baseline.py`, rule SG-004):** each agent's behaviors (for example `tool_call:tool/shell`) are scored by how rarely agents in the same role show them in a baseline learned from benign runs. The score is `-log2 p` with Laplace smoothing, and only behaviors seen in fewer than 10% of same-role agents count. At 12 or more bits it raises a medium alert; at 6 or more the agent goes on watch.
- **System 2, slow (`detection/rules.py`, rules SG-001 to SG-003):** explicit, auditable rules.
- **Risk (`detection/risk.py`):** a Bayesian posterior per agent. Agents are ranked by risk so the riskiest are reviewed first.
- **Best explanation:** each agent at watch level or above gets ranked hypotheses with the facts that support them.
- **Continual learning:** the baseline trains itself from synthetic normal runs the first time it's needed. After that, `POST /api/detection/baseline` folds in any run confirmed clean (runs with alerts are refused).
- **Checks:** across 120 normal runs that weren't in the training data there were 0 false alerts. Every attacker scores high or critical risk. If the upload event is missing, the exfiltrating agent is still put on watch.

- **Hidden channels (SG-005):** restricted data passed through shared storage (a database, file or wiki) with no message, then leaked. Writes to an agent's own sanctioned workspace don't spread taint unless a `data_ref` or `content_hash` proves restricted data is in them, which stops normal teamwork from tainting the whole swarm.
- **Loss of control (SG-006 to SG-010, `detection/control_rules.py`):** Phase 1 of [docs/threat-model.md](docs/threat-model.md).
  - SG-006, oversight and shutdown tampering: monitoring, logs, policy, gateway, prompts, model deployment, and commands such as `sed -i … oversight` or `chattr +i`.
  - SG-007, self-exfiltration and replication: copying `model/` weights, and spawn/schedule/deploy tools such as `crontab`, `nohup` and `scp`.
  - SG-008, privilege escalation and impersonation: `iam/` grants, and `on_behalf_of` set to another agent.
  - SG-009, honeytoken tripwires.
  - SG-010, log integrity: sequence gaps or reordering. This alert is never attributed to an agent.

- **Phase 2 (SG-011 to SG-020, `detection/advanced_rules.py`):**
  - SG-011, power seeking.
  - SG-012, goal hijack and memory poisoning. Provenance-tracked: untrusted input leads to an out-of-policy action, directly or through poisoned `memory/`.
  - SG-013, cascading failure.
  - SG-014, deceptive reporting: `payload.claims` compared with the agent's actual logged actions.
  - SG-015, reward hacking and result manipulation: tests, graders, CI, `inputs/`, or rewriting finalized outputs.
  - SG-016, salami exfiltration budget.
  - SG-017, coercion of humans.
  - SG-018, loops.
  - SG-019, untrusted tooling.
  - SG-020, steganographic collusion indicators. This is the only rule that reads message text, and only for encoding artifacts: zero-width characters, encoded blobs, mixed-alphabet look-alikes and odd whitespace. It also flags first-contact trigger messages, repeated trigger patterns (signals hidden in action choice) and message-length outliers.
- **Phase 3 (SG-021 to SG-024, `detection/assurance_rules.py`):** checks on the assumptions the other rules rely on.
  - SG-021, gateway bypass and enforcement failure. Resource-side `observation` events (file-integrity or DB audit) are reconciled with the agent log.
  - SG-022, monitoring-dependent behavior: a compliance gap when the agent believes it is unmonitored, and lower scores on evaluations than on normal work.
  - SG-023, unreviewed merges into protected targets.
  - SG-024, unregistered agents acting in the swarm.
- **Audit queue:** not an alert. It's a risk-ranked sample of actions for human or trusted-model review, capped by an audit budget, in the AI-control style.

The full threat catalogue covers 32 threats in 5 families, with sources, signals, detectability, coverage and build order, in [docs/threat-model.md](docs/threat-model.md). Current coverage is 27 built, 4 partial and 1 out of scope.

- **Agent Simulator (member 1)** (`backend/app/modules/simulator/`): a multi-agent environment with message broker, virtual filesystem/database, real tools behind the pre-execution gateway, optional Gemini agents and 29 scenarios covering SG-001 to SG-025. See `backend/app/modules/simulator/README.md`, including §11 integration notes.
- **Live guard** (`detection/live.py`, the Live guard card on the Detection page): detection runs *while* agents act. In `contain` mode it pauses an agent at 60% risk and holds outbound transfers for any agent handed restricted data it may not hold, denying their next actions before they execute. In the leakage scenario the data never leaves, even with the static gateway only monitoring, and no innocent agent is paused. Enable it with `live_guard: "contain"` on `POST /api/simulate` and read results at `GET /api/runs/{id}/live-report`. Details are in [docs/threat-model.md](docs/threat-model.md) §11. The simulator only has an optional hook, and it's inert when off.
- **Attack replay** (`POST /api/detection/replay`, and the picker on the Live guard card): plant any of the 38 benchmark cases (attacks and benign look-alikes) into a fresh realistic run and watch the live guard catch and contain it. Every threat is demoable without new simulator scenarios.
- **Accuracy benchmark** (`detection/benchmark.py`, `scripts/benchmark_detection.py`, and the Detection page): 26 planted attacks plus 12 benign look-alikes inside realistic runs, with 0–50% of events missing. Precision is 1.0 with 0 benign false alarms at every level. It catches 100% / 91% / 72% / 51% of attacks at 0 / 10 / 30 / 50% missing (97% / 87% / 75% when some attack evidence survived). Rules don't blame agents for an absence that falls in a log gap (`detection/evidence.py`). Details are in [docs/threat-model.md](docs/threat-model.md) §10.

Endpoints: `GET /api/runs/{id}/assessments`, `GET /api/runs/{id}/audit-queue`, `GET|POST /api/detection/baseline`, `POST /api/detection/benchmark`.

The collector currently keeps `observation` events with an `unknown_event_type` warning. Adding `observation` to its canonical types is a small follow-up for the collector owner.

## Definition of Done walkthrough

1. Open http://localhost:5173.
2. In **Agent Simulator**, pick *Coordinated data leakage* with 5 agents. Set gateway mode to `enforce` to see real blocks, then click **Run simulation**.
3. Inspect the raw events in the table or JSON view, and export them.
4. In **Event Collector**, click **Normalize events**.
5. In **Threat Detection**, click **Run detection**. Click an alert to see its evidence chain and the graph.
6. In **Security Response**, set the policy mode to `enforce` and click **Apply policy**. The outcome is `blocked`, with gateway event IDs. With gateway `monitor` you get `would_block` / `would_pause` instead.
7. **Dashboard & Evaluation** shows the full result and metrics. Run the suite to see robustness when events are missing.
8. Reload the page. The selected run is restored from `localStorage`, and all of its data is reloaded from the store.

Shortcuts: tick *Auto-run* in the Simulator, or click **Run full pipeline** on the Dashboard (`POST /api/runs/{run_id}/pipeline`).

## API

Interactive docs are at http://localhost:8000/docs. The main endpoints are:
`POST /api/simulate`, `POST /api/collect`, `POST /api/detect`, `POST /api/respond`, `POST /api/evaluate`,
`POST /api/evaluate/suite`, `GET /api/runs[/{id}[/raw-events|normalized-events|alerts|graph|responses|dashboard]]`,
`GET|PUT /api/detection-rules/{id}`, `GET|PUT /api/response-policies/{id}`, `GET /api/modules/{name}` (schema + sample shown behind each page's info button).

## Shared contracts & fixtures

- `backend/app/schemas.py` is the source of truth. `frontend/src/types.ts` mirrors it, so update both together.
- `fixtures/` holds sample JSON/JSONL for every module: `scenario_config.json`, `raw_events.jsonl`, `raw_events_messy.jsonl` (hand-written invalid and duplicate cases), `normalized_events.jsonl`, `collection_report.json`, `detection_rules.json`, `alerts.json`, `response_policy.json`, `response_actions.json`, `evaluation.json`, `suite_request.json`, `agents.json`, `run.json`, `scenarios.json`.

## Guardrails

- All attack data is synthetic. Simulations are limited to 3/5/10/20 agents, and suites to 60 in-memory runs.
- No API keys are in the code. Model calls are capped per run and fall back to templates on error or when the cap is reached.
- LLM text only fills message `content`. Detection uses structured fields only (a test enforces this).
- In simulation mode, outcomes are `would_*`. `blocked` requires a recorded gateway denial that happened before execution.

## Team workflow

- Each teammate owns one module folder, its page and its tests. Modules exchange data only through the store and the schemas.
- Point everyone's backend at the same Firestore workspace to share runs. Use separate `SWARMGUARD_WORKSPACE` values for sandboxes.
- To add a detection rule, write a function in `detection/rules.py`, register it in `RULE_IMPLS`, add it to `DEFAULT_RULES` and add a test. Rules are seeded into `detection_rules` the first time the backend starts.
