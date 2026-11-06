"""SwarmGuard FastAPI application."""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import Body, Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.adapters import available_adapters
from app.config import get_settings
from app.module_info import MODULES, module_info
from app.modules.simulator.world import SCENARIOS
from app.schemas import (
    AGENT_COUNTS, BaselineTrainRequest, CollectRequest, ReplayRequest, DetectionRule, DetectRequest, EvaluateRequest, RespondRequest, ResponsePolicy,
    ScenarioConfig, SuiteRequest,
)
from app.services.pipeline import NotFound, Pipeline
from app.storage import get_store


def get_pipeline() -> Pipeline:
    return Pipeline(get_store())


@asynccontextmanager
async def lifespan(app: FastAPI):
    from app.services import notify
    from app.services.live_hub import get_hub

    get_pipeline().seed_defaults()
    notify.install(get_hub())  # opt-in: SWARMGUARD_WEBHOOK_URL
    from app.services import siem

    siem.install(get_hub(), lambda run_id: get_pipeline().alerts(run_id))  # opt-in: SWARMGUARD_SIEM_URL
    from app.services import review

    review.start_escalation_loop(get_store)  # overdue reviews are announced again
    from app.services import egress_proxy

    proxy = egress_proxy.start_from_env(get_pipeline())  # opt-in: SWARMGUARD_EGRESS_PROXY_PORT
    yield
    if proxy:
        proxy.stop()


app = FastAPI(title="SwarmGuard", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def require_api_key(request: Request, call_next):
    """Role check for every API call when SWARMGUARD_API_KEYS is set (see app/auth.py)."""
    from app import auth

    request.state.principal = None
    if auth.enabled():
        need = auth.required_role(request.method, request.url.path)
        who = auth.identify(auth.key_from(request.headers, request.query_params))
        if not auth.allowed(who, need):
            status = 401 if who is None else 403
            msg = ("Missing or unknown API key: send 'Authorization: Bearer <key>'." if who is None
                   else f"The {who.role} key '{who.name}' can't do this (needs {need}).")
            return JSONResponse(status_code=status, content={"detail": msg})
        request.state.principal = who
    return await call_next(request)


@app.exception_handler(NotFound)
async def not_found(_: Request, exc: NotFound):
    return JSONResponse(status_code=404, content={"detail": str(exc)})


@app.exception_handler(ValueError)
async def bad_request(_: Request, exc: ValueError):
    return JSONResponse(status_code=400, content={"detail": str(exc)})


P = Depends(get_pipeline)


# ------------------------------------------------------------------ meta
@app.get("/api/health")
def health(p: Pipeline = P) -> dict[str, Any]:
    from app import auth

    return {"ok": True, "storage": p.store.backend, "workspace": p.store.workspace,
            "auth": "on" if auth.enabled() else "off"}


@app.get("/api/whoami")
def whoami(request: Request) -> dict[str, Any]:
    who = request.state.principal
    return {"auth": who is not None, "name": who.name if who else None, "role": who.role if who else "local"}


@app.get("/api/gemini/quota")
def gemini_quota() -> dict[str, Any]:
    """Gemini calls used today, what's left, when Google resets it, and what a run costs."""
    from app.services.quota import quota_status

    return quota_status()


@app.get("/api/meta")
def meta() -> dict[str, Any]:
    return {"scenarios": [s.model_dump() for s in SCENARIOS], "agent_counts": list(AGENT_COUNTS),
            "agent_backends": available_adapters()}


@app.get("/api/modules/{name}")
def get_module_info(name: str) -> dict[str, Any]:
    if name not in MODULES:
        raise HTTPException(404, f"unknown module {name}")
    return module_info(name)


# ------------------------------------------------------------------ runs
@app.get("/api/runs")
def list_runs(limit: int = 50, p: Pipeline = P):
    return p.list_runs(limit)


@app.get("/api/runs/{run_id}")
def get_run(run_id: str, p: Pipeline = P):
    return p.get_run(run_id)


@app.get("/api/runs/{run_id}/agents")
def run_agents(run_id: str, p: Pipeline = P):
    return p.agents(run_id)


@app.get("/api/runs/{run_id}/raw-events")
def run_raw_events(run_id: str, p: Pipeline = P):
    return p.raw_events(run_id)


@app.get("/api/runs/{run_id}/normalized-events")
def run_normalized_events(run_id: str, p: Pipeline = P):
    return p.normalized_events(run_id)


@app.get("/api/runs/{run_id}/alerts")
def run_alerts(run_id: str, format: str | None = None, p: Pipeline = P):
    """The run's alerts; ?format=ocsf returns them as OCSF Detection Findings for a SIEM."""
    if format == "ocsf":
        from app.services import siem

        return siem.findings(p.alerts(run_id))
    return p.alerts(run_id)


@app.get("/api/runs/{run_id}/graph")
def run_graph(run_id: str, p: Pipeline = P):
    return p.graph(run_id).graph


@app.get("/api/runs/{run_id}/responses")
def run_responses(run_id: str, p: Pipeline = P):
    return p.responses(run_id)


@app.get("/api/runs/{run_id}/dashboard")
def run_dashboard(run_id: str, p: Pipeline = P):
    return p.dashboard(run_id)


@app.post("/api/runs/{run_id}/pipeline")
def run_pipeline(run_id: str, p: Pipeline = P):
    """Automatic trigger: collect -> detect -> respond -> evaluate."""
    return p.run_all(run_id)


# ------------------------------------------------------------------ modules
# ------------------------------------------------------------------ live streaming (for the live UI)
@app.post("/api/runs/start")
def start_run(config: ScenarioConfig, p: Pipeline = P) -> dict[str, Any]:
    """Start a run in the background; watch it on the /api/live WebSocket. Returns at once."""
    if config.workspace_dir:
        raise HTTPException(400, "workspace_dir can't be set through the API")
    return {"run_id": p.start_run(config), "stream": "/api/live"}


@app.get("/api/live/active")
def active_runs() -> list[dict[str, Any]]:
    from app.services.pipeline import ACTIVE_RUNS

    return list(ACTIVE_RUNS.values())


@app.websocket("/api/live")
async def live(ws: WebSocket):
    """Every event, detection, containment and quarantine, pushed as it happens.

    Query: ?run_id=… to follow one run; ?since=<seq> to replay what you missed (default: the recent history).
    """
    import asyncio

    from app.services.live_hub import get_hub

    from app import auth

    if auth.enabled() and not auth.allowed(auth.identify(ws.query_params.get("key")), "viewer"):
        await ws.close(code=1008)  # policy violation: no or wrong key
        return
    await ws.accept()
    hub = get_hub()
    run_id = ws.query_params.get("run_id") or None
    since = int(ws.query_params.get("since") or 0)
    sub = hub.subscribe(asyncio.get_running_loop(), run_id)
    try:
        await ws.send_json({"type": "hello", "seq": 0, "run_id": run_id, "data": {"subscribers": hub.subscribers}})
        for msg in hub.replay(run_id, since):
            await ws.send_json(msg)
        while True:
            await ws.send_json(await sub.queue.get())
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        hub.unsubscribe(sub)


# ------------------------------------------------------------------ live ingest (real agents outside the simulator)
@app.post("/api/ingest/sessions")
def ingest_open(body: dict[str, Any], p: Pipeline = P) -> dict[str, Any]:
    from app.services import ingest

    out = ingest.open_session(p, body.get("name") or "external", body.get("agents") or [],
                              body.get("live_guard", "contain"), float(body.get("pause_at", 0.6)),
                              require_identity=bool(body.get("require_agent_identity")),
                              token_ttl=body.get("token_ttl"))
    if body.get("mcp"):
        ingest.SESSIONS[out["run_id"]].mcp = dict(body["mcp"])  # MCP gateway settings (services/mcp_gateway.py)
        out["mcp"] = {a["agent_id"]: f"/api/ingest/{out['run_id']}/mcp/{a['agent_id']}" for a in body.get("agents") or []}
    return out


@app.post("/api/ingest/{run_id}/mcp/{agent_id}")
async def ingest_mcp(run_id: str, agent_id: str, request: Request, p: Pipeline = P):
    """MCP gateway: the agent's MCP client talks to this URL; tool calls are gated, then sent to the real server."""
    import asyncio

    from fastapi.responses import JSONResponse, Response

    from app.services import ingest, mcp_gateway

    s = ingest.session(run_id)
    if not s.verify(agent_id, request.headers.get("x-agent-token")):
        raise HTTPException(403, f"X-Agent-Token does not prove the caller is {agent_id}")
    msg = await request.json()
    body, headers = await asyncio.to_thread(mcp_gateway.handle, p, run_id, agent_id, msg, dict(request.headers))
    if body is None:
        return Response(status_code=202, headers=headers)
    return JSONResponse(body, headers=headers)


@app.post("/api/ingest/{run_id}/gate")
def ingest_gate(run_id: str, body: dict[str, Any]) -> dict[str, Any]:
    """Ask BEFORE acting: {"allow": false, "reason": ...} means the agent must not do it."""
    from app.services import ingest

    if not body.get("agent_id"):
        raise HTTPException(400, "agent_id is required")
    s = ingest.session(run_id)
    if not s.verify(body["agent_id"], body.get("agent_token")):
        raise HTTPException(403, f"agent_token does not prove the caller is {body['agent_id']}")
    return s.gate(body)


@app.get("/api/ingest/{run_id}/control")
def ingest_control(run_id: str) -> dict[str, Any]:
    """Poll this: which agents are paused or have outbound transfers held right now, and why."""
    from app.services import ingest

    return ingest.control(run_id)


@app.get("/api/egress-proxy")
def egress_proxy_status() -> dict[str, Any]:
    from app.services import egress_proxy

    px = egress_proxy.PROXY
    if px is None:
        return {"running": False, "hint": "set SWARMGUARD_EGRESS_PROXY_PORT (and SWARMGUARD_EGRESS_ALLOW) to start it"}
    return {"running": True, "host": px.host, "port": px.port, "mode": px.mode, "allow": sorted(px.allow),
            "recent": px.decisions[-50:]}


@app.post("/api/ingest/{run_id}/events")
def ingest_events(run_id: str, body: Any = Body(...), format: str | None = None, p: Pipeline = P) -> dict[str, Any]:
    """Raw events (a list or one object), or ?format=otel|langsmith to send OpenTelemetry spans / LangSmith runs."""
    from app.modules.collector.formats import convert
    from app.services import ingest

    if format:
        events, _ = convert(format, body, run_id)
    else:
        events = body if isinstance(body, list) else [body]
    s = ingest.session(run_id)
    bad = sorted({str(e.get("agent_id")) for e in events if not s.verify(e.get("agent_id"), e.get("agent_token"))})
    if bad:
        raise HTTPException(403, f"agent_token missing or wrong for {', '.join(bad)}: events rejected")
    return ingest.add_events(p, run_id, events)


@app.post("/api/convert")
def convert_logs(body: Any = Body(...), format: str = "otel", run_id: str = "run-imported") -> dict[str, Any]:
    """Preview how OpenTelemetry spans (format=otel) or LangSmith runs (format=langsmith) map to SwarmGuard events."""
    from app.modules.collector.formats import convert

    events, agents = convert(format, body, run_id)
    return {"events": events, "agents": agents}


@app.post("/api/ingest/{run_id}/finish")
def ingest_finish(run_id: str, p: Pipeline = P) -> dict[str, Any]:
    from app.services import ingest

    return ingest.finish(p, run_id)


# ------------------------------------------------------------------ review queue (Security Response)
@app.get("/api/reviews")
def reviews(status: str | None = None, run_id: str | None = None, p: Pipeline = P) -> list[dict[str, Any]]:
    from app.services import review

    return review.items(p.store, status, run_id)


@app.post("/api/reviews/escalate")
def escalate_reviews(minutes: float = 15.0, p: Pipeline = P) -> list[dict[str, Any]]:
    """Mark pending reviews older than `minutes` as overdue and announce them (also runs every minute on its own)."""
    from app.services import review

    return review.escalate(p.store, minutes)


@app.post("/api/reviews/{review_id}")
def decide_review(review_id: str, body: dict[str, Any], request: Request, p: Pipeline = P) -> dict[str, Any]:
    """{"decision": "release" | "confirm", "note": "..."}. With API keys on, the key's name is recorded as who decided."""
    from app.services import review

    who = request.state.principal
    return review.decide(p.store, review_id, body.get("decision", ""), body.get("note"), who.name if who else body.get("by"))


@app.get("/api/runs/{run_id}/integrity")
def run_integrity(run_id: str, p: Pipeline = P) -> dict[str, Any]:
    """Tamper evidence: was any stored event edited, deleted or reordered since collection?"""
    return p.integrity(run_id)


@app.post("/api/live/{run_id}/agents/{agent_id}")
def operate_agent(run_id: str, agent_id: str, body: dict[str, Any] = Body(default={})) -> dict[str, Any]:
    """Operator control while a run is live: {"action": "pause" | "hold_egress", "note": "..."}."""
    from app.services.live_hub import active_stream

    stream = active_stream(run_id)
    if stream is None:
        raise HTTPException(409, f"{run_id} isn't running live (it finished, or wasn't started with the live guard)")
    return {"run_id": run_id, "agent_id": agent_id, "result": stream.operator(agent_id, body.get("action", "pause"), body.get("note"))}


@app.post("/api/live/{run_id}/stop")
def stop_run(run_id: str, body: dict[str, Any] = Body(default={})) -> dict[str, Any]:
    """Kill switch: pause every agent of a live run. Pending items appear in the review queue."""
    from app.services.live_hub import active_stream

    stream = active_stream(run_id)
    if stream is None:
        raise HTTPException(409, f"{run_id} isn't running live")
    note = body.get("note") or "kill switch: all agents paused"
    return {"run_id": run_id, "paused": {a: stream.operator(a, "pause", note) for a in list(stream.guard.registry)}}


@app.post("/api/simulate")
def simulate(config: ScenarioConfig, p: Pipeline = P):
    if config.workspace_dir:
        # Agents write files into the workspace; only local scripts may choose where that is on disk.
        raise HTTPException(400, "workspace_dir can't be set through the API")
    return p.simulate(config)


@app.post("/api/collect")
def collect(req: CollectRequest, p: Pipeline = P):
    if not req.run_id and req.events is None:
        raise HTTPException(400, "provide run_id or events")
    return p.collect(req.run_id, req.events, req.persist)


@app.post("/api/detect")
def detect(req: DetectRequest, p: Pipeline = P):
    return p.detect(req.run_id, req.persist)


@app.get("/api/runs/{run_id}/assessments")
def run_assessments(run_id: str, p: Pipeline = P):
    """Per-agent Bayesian risk + best explanation, ranked by risk."""
    return p.assessments(run_id)


@app.get("/api/runs/{run_id}/audit-queue")
def run_audit_queue(run_id: str, p: Pipeline = P):
    """Risk-ranked sample of actions for human / trusted-model review (not alerts)."""
    return p.audit_queue(run_id)


@app.get("/api/runs/{run_id}/live-report")
def run_live_report(run_id: str, p: Pipeline = P):
    """What the live guard saw and stopped while the run was happening."""
    return p.live_report(run_id)


@app.get("/api/detection/replay-cases")
def replay_cases():
    """The 26 labeled attacks and 12 benign look-alikes that can be replayed into a live run."""
    from app.modules.detection.benchmark import case_catalog

    return case_catalog()


@app.post("/api/detection/replay")
def replay(req: ReplayRequest, p: Pipeline = P):
    """Plant one case into a fresh realistic run, stream it through the live guard, save it and run the pipeline."""
    return p.replay(req)


@app.post("/api/detection/benchmark")
def detection_benchmark(full: bool = False, p: Pipeline = P):
    """Accuracy on planted attacks + benign look-alikes. Quick by default (~150 trials); full=true runs ~1,400."""
    from app.modules.detection.benchmark import ALL_CASES, run_benchmark
    from app.modules.detection.rules import run_rules

    res = run_benchmark(p.rules(), run_rules, drop_rates=(0.0, 0.1, 0.3, 0.5) if full else (0.0, 0.3),
                        agent_counts=(5, 10, 20) if full else (5,), seeds=range(1, 4) if full else range(1, 3))
    res["cases_info"] = {c.name: {"threat": c.threat, "benign": c.benign} for c in ALL_CASES}
    return res


@app.get("/api/detection/baseline")
def detection_baseline(p: Pipeline = P):
    return p.baseline_summary()


@app.post("/api/detection/baseline")
def train_detection_baseline(req: BaselineTrainRequest, p: Pipeline = P):
    """Retrain from synthetic normal runs, or fold in one run confirmed clean (continual learning)."""
    return p.train_baseline(req)


@app.get("/api/coverage/owasp")
def owasp_coverage() -> dict[str, Any]:
    """How SwarmGuard's rules and controls cover the OWASP Top 10 for Agentic Applications."""
    from app.modules.detection.owasp import coverage

    return coverage()


@app.get("/api/detection-rules")
def detection_rules(p: Pipeline = P):
    return p.rules()


@app.put("/api/detection-rules/{rule_id}")
def update_rule(rule_id: str, rule: DetectionRule, p: Pipeline = P):
    if rule.rule_id != rule_id:
        raise HTTPException(400, "rule_id mismatch")
    return p.save_rule(rule)


@app.post("/api/respond")
def respond(req: RespondRequest, p: Pipeline = P):
    return p.respond(req.run_id, req.policy, req.persist)


@app.get("/api/response-policies/{policy_id}")
def get_policy(policy_id: str, p: Pipeline = P):
    return p.policy(policy_id)


@app.put("/api/response-policies/{policy_id}")
def put_policy(policy_id: str, policy: ResponsePolicy, p: Pipeline = P):
    if policy.policy_id != policy_id:
        raise HTTPException(400, "policy_id mismatch")
    return p.save_policy(policy)


@app.post("/api/evaluate")
def evaluate(req: EvaluateRequest, p: Pipeline = P):
    return p.evaluate(req.run_id, req.persist)


@app.post("/api/evaluate/suite")
def evaluate_suite(req: SuiteRequest, p: Pipeline = P):
    return p.suite(req)


@app.get("/api/evaluations")
def evaluations(p: Pipeline = P):
    return p.evaluations()
