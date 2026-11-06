"""Where is the event log incomplete?

Rules that conclude from the *absence* of an event (no review, no matching gateway record)
must not trust that absence across a log gap, and count-based rules should account for
events they never saw. This uses the monotonic `sequence` numbers to locate gaps.
"""
from __future__ import annotations

from bisect import bisect_left, bisect_right
from datetime import timedelta

from app.schemas import NormalizedEvent
from app.timeutil import parse_iso


_COVERAGE_CACHE: dict[tuple, "LogCoverage"] = {}


class LogCoverage:
    @classmethod
    def of(cls, events: list[NormalizedEvent]) -> "LogCoverage":
        """Shared coverage for one event list: every rule in a detection pass gets the same list object."""
        key = (id(events), len(events), events[0].event_id if events else None, events[-1].event_id if events else None)
        hit = _COVERAGE_CACHE.get(key)
        if hit is None:
            if len(_COVERAGE_CACHE) > 8:
                _COVERAGE_CACHE.clear()
            hit = _COVERAGE_CACHE[key] = cls(events)
        return hit

    def __init__(self, events: list[NormalizedEvent]):
        ordered = sorted((e for e in events if e.sequence > 0), key=lambda e: e.sequence)
        self.seqs = [e.sequence for e in ordered]
        self.times = [parse_iso(e.timestamp) for e in ordered]
        self.known = len(self.seqs) >= 2

    @property
    def ratio(self) -> float:
        """Share of expected events actually present (1.0 when sequences are absent or complete)."""
        if not self.known:
            return 1.0
        span = self.seqs[-1] - self.seqs[0] + 1
        return len(self.seqs) / span if span else 1.0

    def _span(self, e: NormalizedEvent) -> tuple[int, int] | None:
        """Where an event sits in the agent log's numbering. A rebuilt event (no sequence) is placed by time between
        its logged neighbours, so a gap next to it still counts as a gap."""
        if e.sequence > 0:
            return e.sequence, e.sequence
        if not self.known:
            return None
        i = bisect_left(self.times, parse_iso(e.timestamp))
        return self.seqs[max(0, i - 1)], self.seqs[min(i, len(self.seqs) - 1)]

    def outside(self, e: NormalizedEvent) -> bool:
        """Before the first or after the last logged event: a loss there leaves no sequence gap to see."""
        if not self.known:
            return False
        t = parse_iso(e.timestamp)
        return t < self.times[0] or t > self.times[-1]

    def missing_between(self, a: NormalizedEvent, b: NormalizedEvent) -> int:
        """Events missing strictly between two events (by sequence; rebuilt events placed conservatively by time)."""
        sa, sb = self._span(a), self._span(b)
        if not self.known or sa is None or sb is None:
            return 0
        lo, hi = min(sa[0], sb[0]), max(sa[1], sb[1])
        present = bisect_left(self.seqs, hi) - bisect_right(self.seqs, lo)
        return max(0, hi - lo - 1 - present)

    def missing_around(self, event: NormalizedEvent, seconds: float) -> int:
        """Events missing in the time window event ± seconds, bracketed by the nearest logged neighbours."""
        if not self.known:
            return 0
        t, window = parse_iso(event.timestamp), timedelta(seconds=seconds)
        lo_i = max(0, bisect_left(self.times, t - window) - 1)
        hi_i = min(len(self.seqs) - 1, bisect_right(self.times, t + window))
        if hi_i <= lo_i:
            return 0
        return max(0, (self.seqs[hi_i] - self.seqs[lo_i] + 1) - (hi_i - lo_i + 1))

    def local_ratio(self, a: NormalizedEvent, b: NormalizedEvent) -> float:
        """Coverage between two logged events. Loss is often bursty, so this beats the run-wide average."""
        if not self.known or a.sequence <= 0 or b.sequence <= 0:
            return 1.0
        lo, hi = sorted((a.sequence, b.sequence))
        present = bisect_right(self.seqs, hi) - bisect_left(self.seqs, lo)
        return present / (hi - lo + 1)

    def estimate(self, observed: int, min_ratio: float = 0.6, span: tuple[NormalizedEvent, NormalizedEvent] | None = None) -> float:
        """Estimated true count of something seen `observed` times, if coverage is good enough to extrapolate.

        With `span`, coverage is measured locally between those two events. Losses before the first or after the last
        seen occurrence can't be bracketed and are not extrapolated.
        """
        r = self.local_ratio(*span) if span else self.ratio
        return observed / r if r >= min_ratio else float(observed)


# ---------------------------------------------------------------- second, independent evidence source
# One log is one point of failure: in the benchmark, 30% event loss erases every trace of ~22% of attacks. Mature
# deployments also keep resource-side records written by systems the agent doesn't control (egress proxy, broker
# log, file/DB audit, tool audit). A loss in one source is then usually covered by the other, as long as the two
# are lost independently. Sensor records are `observation` events with payload.mirrors = the action type they saw.
SENSOR_FOR = {"data_transfer": "egress-proxy", "message": "broker-log", "resource_access": "resource-audit",
              "tool_call": "tool-audit"}
_MIRRORED_PAYLOAD = ("data_ref", "content", "claims", "message_id", "intent", "topic", "untrusted", "claimed_sender",
                     "operation", "command", "query")


def sensor_record(raw: dict) -> dict | None:
    """The resource-side record of an executed action (raw-event dict), or None if no sensor would see it.

    Denied actions never happened, so only the gateway log knows them; inbox reads are the recipient's own log.
    """
    et = raw.get("event_type")
    if et not in SENSOR_FOR or raw.get("status") != "success" or (et == "message" and raw.get("action") == "receive"):
        return None
    payload = {k: v for k, v in (raw.get("payload") or {}).items() if k in _MIRRORED_PAYLOAD}
    return {**raw, "event_id": f"{raw['event_id']}-s", "event_type": "observation", "sequence": 0,
            "gateway_decision": None, "payload": {**payload, "source": SENSOR_FOR[et], "mirrors": et}}


def _secs_apart(a: NormalizedEvent, b: NormalizedEvent) -> float:
    return abs((parse_iso(a.timestamp) - parse_iso(b.timestamp)).total_seconds())


def logged_index(events: list[NormalizedEvent]) -> dict[tuple[str, str], list[NormalizedEvent]]:
    """Agent-log actions by (agent, type), excluding sensor records and anything rebuilt from them."""
    index: dict[tuple[str, str], list[NormalizedEvent]] = {}
    for e in events:
        if e.event_type != "observation" and "reconstructed_from" not in e.payload:
            index.setdefault((e.agent_id, e.event_type), []).append(e)
    return index


def sensor_match(o: NormalizedEvent, index: dict, tol: float = 30.0) -> NormalizedEvent | None:
    """The agent-log record of the action a sensor saw, if the agent log has it."""
    mid = o.payload.get("message_id")
    for x in index.get((o.agent_id, o.payload.get("mirrors")), []):
        # A sensor that can't see a field (e.g. a proxy doesn't know which file was uploaded) matches on the rest.
        if (x.action == o.action and o.resource in (None, x.resource) and o.target in (None, x.target)
                and _secs_apart(x, o) <= tol
                and (not mid or x.payload.get("message_id") == mid)):
            return x
    return None


def fuse(events: list[NormalizedEvent], tol: float = 30.0) -> list[NormalizedEvent]:
    """Rebuild agent-log records the log lost but a sensor saw, so rules can still use the evidence.

    Rebuilt events are marked (`payload.reconstructed_from`, `evidence_source`, summary prefix) and are never used to
    decide that the gateway was bypassed: SG-021 reconciles the two sources itself.
    """
    sensors = [e for e in events if e.event_type == "observation" and e.payload.get("mirrors")]
    if not sensors:
        return events
    index = logged_index(events)
    rebuilt = []
    for o in sensors:
        if sensor_match(o, index, tol) is not None:
            continue
        payload = {k: v for k, v in o.payload.items() if k not in ("source", "mirrors")}
        rebuilt.append(o.model_copy(update={
            "event_id": f"{o.event_id}:rebuilt", "event_type": o.payload["mirrors"], "status": "success",
            "payload": {**payload, "reconstructed_from": o.event_id, "evidence_source": o.payload["source"]},
            "summary": f"[rebuilt from {o.payload['source']}] {o.summary}"}))
    return events + rebuilt
