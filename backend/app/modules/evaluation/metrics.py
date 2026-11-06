"""Evaluation against labeled synthetic scenarios (agent-level confusion matrix)."""
from __future__ import annotations

import hashlib
from statistics import mean

from app.schemas import Agent, Alert, EvaluationResult, NormalizedEvent, ResponseAction, Run, SuiteRow
from app.timeutil import now_iso, parse_iso


def _ratio(num: int | float, den: int | float) -> float | None:
    return round(num / den, 4) if den else None


def evaluate(run: Run, agents: list[Agent], events: list[NormalizedEvent], alerts: list[Alert],
             responses: list[ResponseAction]) -> EvaluationResult:
    all_agents = {a.agent_id for a in agents}
    truth = set(run.labels.malicious_agent_ids)
    predicted = {aid for al in alerts for aid in al.agent_ids if aid in all_agents}
    tp, fp = len(predicted & truth), len(predicted - truth)
    fn = len(truth - predicted)
    tn = len(all_agents) - tp - fp - fn
    precision, recall = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    f1 = round(2 * precision * recall / (precision + recall), 4) if precision and recall else (0.0 if truth else None)

    by_id = {e.event_id: e for e in events}
    mal_events = [by_id[eid] for eid in run.labels.malicious_event_ids if eid in by_id]
    cited = {eid for al in alerts for eid in al.event_ids}
    evidence_coverage = _ratio(sum(1 for e in mal_events if e.event_id in cited), len(mal_events))

    latencies = []
    for aid in truth & predicted:
        own = [parse_iso(e.timestamp) for e in mal_events if e.agent_id == aid]
        if not own:
            continue
        # An alert is "detectable" once its last evidence event has happened.
        ready = [max(parse_iso(by_id[eid].timestamp) for eid in al.event_ids if eid in by_id)
                 for al in alerts if aid in al.agent_ids and any(eid in by_id for eid in al.event_ids)]
        if ready:
            latencies.append(max(0.0, (min(ready) - min(own)).total_seconds()))

    contained = {aid for r in responses if r.outcome in ("would_block", "would_pause", "blocked", "contained")
                 for aid in r.agent_ids}
    containment = _ratio(len(truth & contained), len(truth))
    gated = [e for e in mal_events if e.gateway_decision in ("would_block", "blocked")]
    enforced = _ratio(sum(1 for e in gated if e.status == "denied"), len(gated))

    eid = hashlib.sha1(f"{run.run_id}|{len(alerts)}|{len(responses)}".encode()).hexdigest()[:10]
    return EvaluationResult(
        evaluation_id=f"eval-{eid}",
        run_id=run.run_id,
        scenario_id=run.scenario_id,
        agent_count=run.agent_count,
        drop_rate=run.drop_rate,
        tp=tp, fp=fp, fn=fn, tn=tn,
        precision=precision,
        recall=recall,
        false_positive_rate=_ratio(fp, fp + tn),
        f1=f1,
        evidence_coverage=evidence_coverage,
        detection_latency_s=round(mean(latencies), 3) if latencies else None,
        containment_rate=containment,
        enforced_containment_rate=enforced,
        alert_count=len(alerts),
        created_at=now_iso(),
    )


def aggregate(results: list[EvaluationResult]) -> list[SuiteRow]:
    """Micro-averaged metrics per drop rate (performance under missing events)."""
    rows = []
    for drop in sorted({r.drop_rate for r in results}):
        group = [r for r in results if r.drop_rate == drop]
        tp, fp, fn, tn = (sum(getattr(r, k) for r in group) for k in ("tp", "fp", "fn", "tn"))
        lat = [r.detection_latency_s for r in group if r.detection_latency_s is not None]
        cont = [r.containment_rate for r in group if r.containment_rate is not None]
        rows.append(SuiteRow(
            drop_rate=drop, runs=len(group), tp=tp, fp=fp, fn=fn, tn=tn,
            precision=_ratio(tp, tp + fp), recall=_ratio(tp, tp + fn), false_positive_rate=_ratio(fp, fp + tn),
            mean_latency_s=round(mean(lat), 3) if lat else None,
            containment_rate=round(mean(cont), 4) if cont else None,
        ))
    return rows
