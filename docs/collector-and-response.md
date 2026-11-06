# Event Collector and Security Response: what was added

Members 2 (collector) and 4 (response) were covered by member 3 in this round. Streaming for the live UI is in
`docs/live-stream.md`.

## Event Collector (member 2)

| Feature | What it does | Where |
|---|---|---|
| **Personal-data redaction** | Emails, phone numbers (10–15 digits), Luhn-valid card numbers and SSNs anywhere in an event's payload become stable pseudonyms like `<email:3f9a2c>` before storage. Same value, same pseudonym, so copy detection (SG-027) still works. `raw_hash` is still the hash of the event as received. On by default; `SWARMGUARD_REDACT_PII=0` turns it off. | `collector/privacy.py` |
| **Tamper-evident log** | Every collected event gets `chain_hash = sha256(previous + content)`; the last one is the run's `log_anchor`. `GET /api/runs/{id}/integrity` re-checks the stored log: edited, deleted or reordered events break the chain; a log that no longer ends at the anchor was truncated. Sequence gaps from collection are reported separately as lost telemetry. Keep the anchor outside this database to make truncation provable. | `collector/integrity.py` |
| **AI-trace summary** | The collection report counts model decisions, fallbacks, refusals and exposures to untrusted input (`report.ai`). | `collector/normalizer.py` |
| **Real log formats** | OpenTelemetry GenAI traces (`invoke_agent` → task start, `execute_tool` → `tool_call`; model calls skipped; optional `swarmguard.*` attributes for protected actions) and LangSmith runs (`tool`, `retriever`). Preview with `POST /api/convert?format=otel\|langsmith`, or send live with `POST /api/ingest/{run_id}/events?format=…`. | `collector/formats.py` |
| **Real sensor feeds** | Egress-proxy, file/DB-audit and message-broker logs become sensor records (`format=egress\|file_audit\|broker` on `POST /api/ingest/{run_id}/events` or `/api/convert`). They are fused with the agent log: an action a sensor saw but the agent log never recorded, with no log gap to explain it, is flagged by SG-021 as a gateway bypass. A sensor that can't see a field (a proxy doesn't know which file) matches on the rest. | `collector/formats.py` |
| **Dataset import** | `python scripts/import_dataset.py ../datasets/<batch>` loads a generator batch into the workspace and runs the full pipeline on every run (skips degraded and already-imported runs). | `services/dataset_import.py` |

## Security Response (member 4)

| Feature | What it does | Where |
|---|---|---|
| **Review queue** | Every live-guard pause, egress hold and quarantined input becomes a pending review item, pushed on the live stream. **Release** lets a still-running agent continue at once (the guard won't re-pause it for risk alone; the hijack tripwire and an `enforce` gateway still apply). **Confirm** keeps it contained. After a run ends, decisions are recorded honestly ("nothing was running to release"). UI: Security Response → Review queue. API: `GET /api/reviews?status=pending`, `POST /api/reviews/{id}` `{"decision": "release"\|"confirm", "note"}`. | `services/review.py`, `pages/ReviewQueueCard.tsx` |
| **Policy applied live** | The live guard now applies the response policy as each alert fires: `pause` pauses the agents it names, `block` holds their outbound transfers, `alert` / `allow` only record. In `detect` mode it records what it *would* do. Each decision is a `response` message on the stream. Change the policy and the live behaviour follows. | `detection/live.py` |
| **Operator controls** | From the live UI: pause an agent, hold its egress, or stop the whole run (pause everyone). Published live and queued for review. | `POST /api/live/{run_id}/agents/{agent_id}`, `POST /api/live/{run_id}/stop`; Live page buttons |
| **Live containment in response records** | After a run, every pause / hold the live guard made becomes a response record (`rsp-live-…`), linked to the alert that explains it. Outcome `blocked` only if later actions were actually denied, otherwise the new `contained`; alerts are marked `contained`. The UI shows "Paused live" / "Egress held live" and never says "blocked" without a denial. | `response/policy.respond_live` |
| **Policy for newer rules** | Default overrides: SG-012 (goal hijack) → pause; SG-026 (impersonated sender) and SG-027 (worm relay) → block. | `schemas.ResponsePolicy` |
| **Escalation and who decided** | Pending reviews older than `SWARMGUARD_REVIEW_ESCALATE_MIN` (15) are marked overdue and announced once more (stream + webhook), checked every minute; `POST /api/reviews/escalate` runs it on demand. Each decision records `decided_by` (the reviewer's name, entered on the Responses page). | `services/review.py` |
| **Notifications** | Opt-in webhook (`SWARMGUARD_WEBHOOK_URL`, Slack / Discord / Teams `text` format): containments, quarantines, critical detections and new review items, sent from a background thread so a failing webhook never slows a run. | `services/notify.py` |

Live-guard denials already count as real gateway blocks in responses (they are recorded as `blocked` before the action
runs), so `blocked` outcomes cover both the static gateway and the live guard.

## Also fixed

`Pipeline.rules()` saved only SG-004 the first time it ran, so any pipeline that wasn't seeded at app startup (scripts,
ingest sessions, tests) silently ran with SG-004 alone afterwards. Missing default rules are now always filled in.
