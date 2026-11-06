"""Orchestrates the five modules against the shared store.

Each stage reads its input dataset from the store (keyed by run_id), writes its
output dataset back, and stamps `run.stages`. Re-running a stage replaces that
run's previous output so references stay consistent.
"""
from __future__ import annotations

import hashlib
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from app.modules.collector.normalizer import collect
from app.modules.detection import baseline
from app.modules.detection.graph import build_graph
from app.modules.detection.live import LiveGuard
from app.modules.detection.risk import assess, audit_queue
from app.modules.detection.rules import DEFAULT_RULES, run_rules
from app.modules.evaluation.metrics import aggregate, evaluate
from app.modules.response.policy import DEFAULT_POLICY, alert_status_after, respond
from app.modules.simulator.engine import run_simulation
from app.modules.simulator.world import SCENARIOS
from app.schemas import (
    AGENT_COUNTS, Agent, AgentAssessment, Alert, AuditItem, LiveReport, ReplayRequest, RunLabels, BaselineTrainRequest, CollectionResult, Dashboard, DetectionResult, DetectionRule, EvaluationResult, NormalizedEvent,
    RawEvent, ResponseAction, ResponsePolicy, ResponseResult, Run, ScenarioConfig, SimulationResult, SuiteRequest,
    SuiteResult,
)
from app.storage.base import Store
from app.timeutil import now_iso

ACTIVE_RUNS: dict[str, dict] = {}  # background runs in progress

# Downstream outputs invalidated when an upstream stage re-runs.
DOWNSTREAM = {
    "collected": ("normalized_events", "alerts", "response_actions"),
    "detected": ("alerts", "response_actions"),
    "responded": ("response_actions",),
}
STAGE_ORDER = ["simulated", "collected", "detected", "responded", "evaluated"]
BASELINE_SEEDS = range(1, 11)
BASELINE_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)


class NotFound(Exception):
    pass


def _dump(model) -> dict[str, Any]:
    return model.model_dump(mode="json")


class Pipeline:
    def __init__(self, store: Store):
        self.store = store

    # ---------------------------------------------------------------- seeds
    def seed_defaults(self) -> None:
        if not self.store.list("scenarios", limit=1):
            self.store.put_many("scenarios", [(s.scenario_id, _dump(s)) for s in SCENARIOS])
        existing = {d["rule_id"] for d in self.store.list("detection_rules")}
        missing = [r for r in DEFAULT_RULES if r.rule_id not in existing]  # new rules reach old workspaces too
        if missing:
            self.store.put_many("detection_rules", [(r.rule_id, _dump(r)) for r in missing])
        if self.store.get("response_policies", DEFAULT_POLICY.policy_id) is None:
            self.store.put("response_policies", DEFAULT_POLICY.policy_id, _dump(DEFAULT_POLICY))

    # ---------------------------------------------------------------- reads
    def get_run(self, run_id: str) -> Run:
        doc = self.store.get("runs", run_id)
        if doc is None:
            raise NotFound(f"run {run_id} not found")
        return Run.model_validate(doc)

    def list_runs(self, limit: int = 50) -> list[Run]:
        runs = [Run.model_validate(d) for d in self.store.list("runs")]
        return sorted(runs, key=lambda r: r.created_at, reverse=True)[:limit]

    def agents(self, run_id: str) -> list[Agent]:
        return [Agent.model_validate(d) for d in self.store.list("agents", run_id=run_id)]

    def raw_events(self, run_id: str) -> list[RawEvent]:
        return sorted((RawEvent.model_validate(d) for d in self.store.list("raw_events", run_id=run_id)), key=lambda e: e.sequence)

    def normalized_events(self, run_id: str) -> list[NormalizedEvent]:
        evs = [NormalizedEvent.model_validate(d) for d in self.store.list("normalized_events", run_id=run_id)]
        return sorted(evs, key=lambda e: (e.timestamp, e.sequence))

    def alerts(self, run_id: str) -> list[Alert]:
        return [Alert.model_validate(d) for d in self.store.list("alerts", run_id=run_id)]

    def responses(self, run_id: str) -> list[ResponseAction]:
        return [ResponseAction.model_validate(d) for d in self.store.list("response_actions", run_id=run_id)]

    def rules(self) -> list[DetectionRule]:
        docs = self.store.list("detection_rules")
        rules = [DetectionRule.model_validate(d) for d in docs]
        # Saved rules override defaults; any default not saved yet (never seeded, or added in a newer version) still
        # applies. Without this, the first call saved only SG-004 and every later call silently ran SG-004 alone.
        have = {r.rule_id for r in rules}
        rules += [r.model_copy(deep=True) for r in DEFAULT_RULES if r.rule_id not in have]
        anomaly = next((r for r in rules if r.rule_id == "SG-004"), None)
        if anomaly and not baseline.is_current(anomaly.params.get("profile")):
            anomaly.params["profile"] = self._synthetic_profile()  # train once, lazily (or upgrade an old version)
            self.save_rule(anomaly)
        return rules

    # ---------------------------------------------------------------- detection baseline
    def _synthetic_profile(self) -> dict:
        """Baseline from labeled-benign synthetic runs across seeds and swarm sizes."""
        profile = baseline.empty_profile()
        for seed in BASELINE_SEEDS:
            for count in AGENT_COUNTS:
                sim = run_simulation(ScenarioConfig(scenario_id="normal_collaboration", agent_count=count, seed=seed, persist=False),
                                     run_id=f"run-base{seed:02d}{count:02d}", base_time=BASELINE_TIME)
                events = collect([_dump(e) for e in sim.events], run_id=sim.run.run_id, agents=sim.agents).events
                profile = baseline.learn(profile, events, sim.agents)
        return profile

    def baseline_summary(self) -> dict:
        anomaly = next((r for r in self.rules() if r.rule_id == "SG-004"), None)
        return baseline.summary(anomaly.params.get("profile") if anomaly else None)

    def train_baseline(self, req: BaselineTrainRequest) -> dict:
        anomaly = next((r for r in self.rules() if r.rule_id == "SG-004"), None)
        if anomaly is None:
            raise ValueError("SG-004 is not configured in this workspace")
        taught = None
        if req.source == "synthetic":
            anomaly.params["profile"] = self._synthetic_profile()
        elif req.source == "ai":
            anomaly.params["profile"], taught = self._teach_ai(anomaly.params.get("profile"), req)
        else:
            if not req.run_id:
                raise ValueError("run_id is required to learn from a run")
            self.get_run(req.run_id)
            if self.alerts(req.run_id) and not req.confirm_clean:
                raise ValueError("this run has alerts; only runs confirmed clean can be learned "
                                 "(set confirm_clean if a reviewer found them to be false positives)")
            events = self.normalized_events(req.run_id)
            if not events:
                raise ValueError("no normalized events for this run; run the Event Collector first")
            anomaly.params["profile"] = baseline.learn(anomaly.params.get("profile"), events, self.agents(req.run_id), req.run_id)
        self.save_rule(anomaly)
        out = baseline.summary(anomaly.params["profile"])
        if taught is not None:
            out["taught"] = taught
        return out

    def _teach_ai(self, profile: dict | None, req: BaselineTrainRequest) -> tuple[dict, list[dict]]:
        """Generate clean AI-mode normal runs and learn them, so model-written behaviour stops looking anomalous.

        A run is learned only if no agent broke policy (simulator ground truth) and every agent decision came from the
        model (no quota fallback). Runs are not stored; each takes ~16 model calls with 5 agents.
        """
        from app.adapters import get_adapter

        if req.agent_backend == "gemini":
            from app.services import quota

            quota.require(req.runs * quota.estimate_calls(5, "autonomous"), f"teaching {req.runs} AI run(s)")
        taught = []
        for i in range(req.runs):
            adapter = get_adapter(req.agent_backend)  # fresh per run: each adapter has a per-run call cap
            sim = run_simulation(ScenarioConfig(scenario_id="normal_collaboration", agent_count=5, seed=5000 + i,
                                                agent_mode="autonomous", agent_backend=req.agent_backend, persist=False),
                                 adapter=adapter)
            c = sim.run.counts
            if sim.run.labels.malicious_agent_ids:
                reason = "an agent broke policy, so this run is not normal behaviour"
            elif c.get("ai_fallbacks"):
                reason = f"{c['ai_fallbacks']} agent turn(s) fell back to scripted work (model quota or error)"
            else:
                events = collect([_dump(e) for e in sim.events], run_id=sim.run.run_id, agents=sim.agents).events
                profile = baseline.learn(profile, events, sim.agents, sim.run.run_id)
                reason = None
            taught.append({"run_id": sim.run.run_id, "learned": reason is None, "skipped_because": reason,
                           "ai_decisions": c.get("ai_decisions", 0)})
            if c.get("ai_fallbacks") and not c.get("ai_decisions"):
                break  # the model isn't answering at all; stop spending time
        return profile or baseline.empty_profile(), taught

    def assessments(self, run_id: str) -> list[AgentAssessment]:
        self.get_run(run_id)
        return assess(run_id, self.normalized_events(run_id), self.agents(run_id), self.alerts(run_id), self.rules())

    def replay(self, req: ReplayRequest) -> SimulationResult:
        """Plant a benchmark case into a fresh run, stream it through the live guard, save it, run the pipeline."""
        from app.modules.detection.benchmark import CASES_BY_NAME, plant

        case = CASES_BY_NAME.get(req.case)
        if case is None:
            raise ValueError(f"unknown replay case {req.case!r}")
        run_id = f"run-{uuid.uuid4().hex[:8]}"
        planted = plant(case, req.agent_count, req.seed, run_id=run_id, salt="replay")
        sim, timeline = planted.sim, planted.raw
        live = LiveGuard(self.rules(), req.live_guard, req.pause_at) if req.live_guard != "off" else None
        if live:
            live.start(run_id, sim.agents)
            timeline = live.replay(timeline)
        events = [RawEvent.model_validate(e) for e in timeline]
        bad_agents = sorted({planted.slots[s] for s in case.flagged})
        for a in sim.agents:
            a.is_malicious = a.agent_id in bad_agents
        run = sim.run.model_copy(update={
            "scenario_id": f"replay:{case.name}", "gateway_mode": "monitor", "created_at": now_iso(),
            "stages": {"simulated": now_iso()}, "counts": {"agents": len(sim.agents), "raw_events": len(events), "dropped_events": 0},
            "labels": RunLabels(malicious_agent_ids=bad_agents, malicious_event_ids=planted.injected if bad_agents else []),
        })
        result = SimulationResult(run=run, agents=sim.agents, events=events, live_report=live.report(run) if live else None)
        self.store.put_many("agents", [(a.agent_id, _dump(a)) for a in result.agents])
        self.store.put_many("raw_events", [(e.event_id, _dump(e)) for e in events])
        self.store.put("runs", run_id, _dump(run))
        if result.live_report:
            self.store.put("evaluations", f"live-{run_id}", {**_dump(result.live_report), "kind": "live"})
        self.run_all(run_id)
        result.run = self.get_run(run_id)
        return result

    def live_report(self, run_id: str) -> LiveReport | None:
        """None when the run was simulated without the live guard (a normal case, not an error)."""
        self.get_run(run_id)
        doc = self.store.get("evaluations", f"live-{run_id}")
        return LiveReport.model_validate(doc) if doc else None

    def audit_queue(self, run_id: str) -> list[AuditItem]:
        self.get_run(run_id)
        events, agents, alerts, rules = self.normalized_events(run_id), self.agents(run_id), self.alerts(run_id), self.rules()
        return audit_queue(events, agents, alerts, assess(run_id, events, agents, alerts, rules), rules)

    def policy(self, policy_id: str = "default") -> ResponsePolicy:
        doc = self.store.get("response_policies", policy_id)
        return ResponsePolicy.model_validate(doc) if doc else DEFAULT_POLICY

    def save_policy(self, policy: ResponsePolicy) -> ResponsePolicy:
        self.store.put("response_policies", policy.policy_id, _dump(policy))
        return policy

    def save_rule(self, rule: DetectionRule) -> DetectionRule:
        self.store.put("detection_rules", rule.rule_id, _dump(rule))
        return rule

    # ---------------------------------------------------------------- helpers
    def _mark(self, run: Run, stage: str, **counts: int) -> Run:
        run.stages[stage] = now_iso()
        idx = STAGE_ORDER.index(stage)
        for later in STAGE_ORDER[idx + 1:]:
            run.stages.pop(later, None)
        run.counts.update(counts)
        self.store.put("runs", run.run_id, _dump(run))
        return run

    def _replace(self, collection: str, run_id: str, docs: list[tuple[str, dict]]) -> None:
        self.store.delete_run_docs(collection, run_id)
        if docs:
            self.store.put_many(collection, docs)

    def _invalidate(self, stage: str, run_id: str) -> None:
        for col in DOWNSTREAM.get(stage, ()):
            self.store.delete_run_docs(col, run_id)

    # ---------------------------------------------------------------- stages
    def simulate(self, config: ScenarioConfig, run_id: str | None = None) -> SimulationResult:
        """Run a scenario; every event, detection and containment is also pushed to live UIs as it happens."""
        from app.services import quota
        from app.services.live_hub import LiveStream, get_hub

        quota.check_run(config)  # refuse up front rather than fall back to scripted text mid-run
        hub = get_hub()
        run_id = run_id or f"run-{uuid.uuid4().hex[:8]}"
        hub.publish("run_started", {"config": config.model_dump(mode="json")}, run_id)
        before = quota.quota_status()["calls_today"] if config.agent_backend == "gemini" else None
        guard = (LiveGuard(self.rules(), config.live_guard, config.pause_at, policy=self.policy())
                 if config.live_guard != "off" else None)
        from app.services import review

        stream = LiveStream(hub, guard, review.recorder(self.store, run_id) if config.persist else None)
        try:
            result = run_simulation(config, run_id=run_id, live=stream)
        except Exception as exc:
            hub.publish("run_failed", {"error": str(exc)}, run_id)
            raise
        finally:
            stream.close()
        if before is not None:
            result.run.counts["model_calls"] = max(0, quota.quota_status()["calls_today"] - before)
            hub.publish("quota", quota.quota_status())
        if guard:
            result.live_report = guard.report(result.run)
        if config.persist:
            run_id = result.run.run_id
            self.store.put_many("agents", [(a.agent_id, _dump(a)) for a in result.agents])
            self.store.put_many("raw_events", [(e.event_id, _dump(e)) for e in result.events])
            self.store.put("runs", run_id, _dump(result.run))
            if result.live_report:
                self.store.put("evaluations", f"live-{run_id}", {**_dump(result.live_report), "kind": "live"})
            if config.auto_pipeline:
                self.run_all(run_id)
                result.run = self.get_run(run_id)
        hub.publish("run_finished", {
            "persisted": config.persist, "counts": result.run.counts, "stages": result.run.stages,
            "live_metrics": result.live_report.metrics if result.live_report else None,
            "alerts": len(self.alerts(run_id)) if config.persist and config.auto_pipeline else None,
            # Ground truth, for demo scoring only: detection never sees it.
            "ground_truth": {"malicious_agent_ids": result.run.labels.malicious_agent_ids},
        }, run_id)
        return result

    # ---------------------------------------------------------------- background runs (watch them live)
    def start_run(self, config: ScenarioConfig) -> str:
        """Start a run in the background and return its id at once; progress streams on /api/live."""
        import threading

        from app.modules.simulator.world import SCENARIOS_BY_ID
        from app.services import quota

        if config.scenario_id not in SCENARIOS_BY_ID:
            raise ValueError(f"Unknown scenario: {config.scenario_id}")
        quota.check_run(config)
        run_id = f"run-{uuid.uuid4().hex[:8]}"
        ACTIVE_RUNS[run_id] = {"run_id": run_id, "scenario_id": config.scenario_id, "started_at": now_iso()}

        def work() -> None:
            try:
                self.simulate(config, run_id=run_id)
            except Exception:  # already published as run_failed
                pass
            finally:
                ACTIVE_RUNS.pop(run_id, None)

        threading.Thread(target=work, name=f"swarmguard-{run_id}", daemon=True).start()
        return run_id

    def collect(self, run_id: str | None, events: list[Any] | None = None, persist: bool = True) -> CollectionResult:
        run = self.get_run(run_id) if run_id else None
        agents = self.agents(run_id) if run_id else []
        raw = events if events is not None else [_dump(e) for e in self.raw_events(run_id)] if run_id else []
        result = collect(raw, run_id=run_id, agents=agents)
        if persist and run is not None:
            self._invalidate("collected", run_id)
            self._replace("normalized_events", run_id, [(e.event_id, _dump(e)) for e in result.events])
            run.log_anchor = result.report.log_anchor
            self._mark(run, "collected", normalized_events=len(result.events), collector_errors=len(result.report.errors),
                       duplicates=result.report.duplicates, alerts=0, responses=0)
        return result

    def integrity(self, run_id: str) -> dict[str, Any]:
        """Re-check the stored log against its hash chain and the run's anchor (tamper evidence)."""
        from app.modules.collector import integrity

        run = self.get_run(run_id)
        events = self.normalized_events(run_id)
        if not events:
            raise ValueError("no normalized events for this run; run the Event Collector first")
        return {"run_id": run_id, **integrity.verify(events, run.log_anchor)}

    def detect(self, run_id: str, persist: bool = True) -> DetectionResult:
        run = self.get_run(run_id)
        events = self.normalized_events(run_id)
        if not events:
            raise ValueError("no normalized events for this run; run the Event Collector first")
        agents = self.agents(run_id)
        rules = self.rules()
        alerts = run_rules(run_id, events, agents, rules)
        graph = build_graph(run_id, events, agents, alerts)
        if persist:
            self._invalidate("detected", run_id)
            self._replace("alerts", run_id, [(a.alert_id, _dump(a)) for a in alerts])
            self._mark(run, "detected", alerts=len(alerts), responses=0)
        return DetectionResult(run_id=run_id, alerts=alerts, graph=graph, assessments=assess(run_id, events, agents, alerts, rules))

    def graph(self, run_id: str) -> DetectionResult:
        events, alerts = self.normalized_events(run_id), self.alerts(run_id)
        return DetectionResult(run_id=run_id, alerts=alerts, graph=build_graph(run_id, events, self.agents(run_id), alerts))

    def respond(self, run_id: str, policy: ResponsePolicy | None = None, persist: bool = True) -> ResponseResult:
        run = self.get_run(run_id)
        if "detected" not in run.stages:
            raise ValueError("no detection results for this run; run Threat Detection first")
        policy = policy or self.policy()
        alerts = self.alerts(run_id)
        actions = respond(alerts, self.normalized_events(run_id), policy)
        live = self.live_report(run_id)
        if live and live.containment:  # what the live guard already did mid-run, as auditable responses
            from app.modules.response.policy import respond_live

            live_actions = respond_live(live.containment, alerts, policy)
            for a in live_actions:
                a.run_id = run_id
            actions += live_actions
        if persist:
            self._replace("response_actions", run_id, [(a.response_id, _dump(a)) for a in actions])
            status: dict[str, str] = {}
            for a in actions:  # a live containment outranks a post-run "responded"
                if a.alert_id and status.get(a.alert_id) != "contained":
                    status[a.alert_id] = alert_status_after(a)
            for al in alerts:
                al.status = status.get(al.alert_id, al.status)
            if alerts:
                self.store.put_many("alerts", [(a.alert_id, _dump(a)) for a in alerts])
            self._mark(run, "responded", responses=len(actions))
        return ResponseResult(run_id=run_id, policy=policy, actions=actions)

    def evaluate(self, run_id: str, persist: bool = True) -> EvaluationResult:
        run = self.get_run(run_id)
        result = evaluate(run, self.agents(run_id), self.normalized_events(run_id), self.alerts(run_id), self.responses(run_id))
        if persist:
            self.store.put("evaluations", result.evaluation_id, _dump(result))
            run.stages["evaluated"] = now_iso()
            self.store.put("runs", run.run_id, _dump(run))
        return result

    def run_all(self, run_id: str) -> Run:
        self.collect(run_id)
        self.detect(run_id)
        self.respond(run_id)
        self.evaluate(run_id)
        return self.get_run(run_id)

    def suite(self, req: SuiteRequest) -> SuiteResult:
        """Run labeled scenarios in memory across drop rates; only the summary is persisted."""
        if len(req.scenario_ids) * len(req.drop_rates) * len(req.seeds) > 60:
            raise ValueError("suite too large: limit scenarios x drop_rates x seeds to 60 runs")
        policy = self.policy()
        rules = self.rules()
        results = []
        for scenario_id in req.scenario_ids:
            for drop in req.drop_rates:
                for seed in req.seeds:
                    sim = run_simulation(ScenarioConfig(scenario_id=scenario_id, agent_count=req.agent_count, seed=seed,
                                                        gateway_mode=req.gateway_mode, drop_rate=drop, persist=False))
                    events = collect([_dump(e) for e in sim.events], run_id=sim.run.run_id, agents=sim.agents).events
                    alerts = run_rules(sim.run.run_id, events, sim.agents, rules)
                    actions = respond(alerts, events, policy)
                    results.append(evaluate(sim.run, sim.agents, events, alerts, actions))
        created = now_iso()
        suite = SuiteResult(
            evaluation_id="suite-" + hashlib.sha1(created.encode()).hexdigest()[:10],
            created_at=created,
            config=req,
            rows=aggregate(results),
            results=results,
        )
        if req.persist:
            self.store.put("evaluations", suite.evaluation_id, {**_dump(suite), "run_id": None, "kind": "suite"})
        return suite

    def evaluations(self) -> list[dict[str, Any]]:
        return sorted(self.store.list("evaluations"), key=lambda d: d.get("created_at", ""), reverse=True)

    def dashboard(self, run_id: str) -> Dashboard:
        run = self.get_run(run_id)
        agents = self.agents(run_id)
        events = self.normalized_events(run_id)
        alerts = self.alerts(run_id)
        responses = self.responses(run_id)
        graph = build_graph(run_id, events, agents, alerts)
        flagged_events: dict[str, set[str]] = {}
        flagged_rules: dict[str, set[str]] = {}
        for al in alerts:
            for aid in al.agent_ids:
                flagged_events.setdefault(aid, set()).update(al.event_ids)
                flagged_rules.setdefault(aid, set()).add(al.rule_id)
        roles = {a.agent_id: a.role for a in agents}
        alerted_events = {eid for al in alerts for eid in al.event_ids}
        timeline = [
            {"event_id": e.event_id, "agent_id": e.agent_id, "timestamp": e.timestamp, "event_type": e.event_type,
             "status": e.status, "summary": e.summary, "flagged": e.event_id in alerted_events}
            for e in events
        ]
        evaluation = evaluate(run, agents, events, alerts, responses) if events else None
        return Dashboard(
            run=run,
            totals={"agents": len(agents), "raw_events": run.counts.get("raw_events", 0), "events": len(events),
                    "threats": len(alerts), "responses": len(responses), "flagged_agents": len(flagged_events)},
            response_outcomes=dict(Counter(r.outcome for r in responses)),
            severity_counts=dict(Counter(a.severity for a in alerts)),
            graph=graph,
            timeline=timeline,
            flagged_agents=[{"agent_id": aid, "role": roles.get(aid), "rule_ids": sorted(flagged_rules[aid]),
                             "event_ids": sorted(eids)} for aid, eids in sorted(flagged_events.items())],
            evaluation=evaluation,
        )
