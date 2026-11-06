"""Tamper-evident event log: a hash chain over the stored events, verifiable later.

Each normalized event gets `chain_hash = sha256(previous chain_hash + content_hash)`, in log (sequence) order; the
last one is the run's **log anchor**. Later, `verify()` recomputes everything from what is stored:

- an edited event no longer matches its own content hash;
- a deleted or reordered event breaks the chain at that point;
- truncated tail events are only provable against an anchor kept somewhere else (the chain alone can't prove absence),
  so record the anchor outside this database (e.g. in a ticket or a signed export).

Sequence gaps that were already there at collection time are reported separately: that is lost telemetry, not
tampering.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

GENESIS = "0" * 64
FIELDS = ("event_id", "run_id", "agent_id", "timestamp", "event_type", "action", "status", "target", "resource",
          "sequence", "gateway_decision", "payload")


def content_hash(e: Any) -> str:
    d = e if isinstance(e, dict) else e.model_dump(mode="json")
    return hashlib.sha256(json.dumps({k: d.get(k) for k in FIELDS}, sort_keys=True, default=str).encode()).hexdigest()


def link(prev: str, content: str) -> str:
    return hashlib.sha256((prev + content).encode()).hexdigest()


def log_order(events: list) -> list:
    return sorted(events, key=lambda e: ((e.sequence if e.sequence > 0 else 10 ** 12), e.timestamp, e.event_id))


def chain(events: list) -> str:
    """Set chain_hash on every event (in log order) and return the anchor."""
    prev = GENESIS
    for e in log_order(events):
        prev = link(prev, content_hash(e))
        e.chain_hash = prev
    return prev


def verify(events: list, anchor: str | None) -> dict[str, Any]:
    ordered = log_order(events)
    prev, problems = GENESIS, []
    for e in ordered:
        expected = link(prev, content_hash(e))
        if e.chain_hash != expected:
            problems.append({"event_id": e.event_id, "sequence": e.sequence,
                             "problem": "edited, deleted or reordered at or before this event"})
            prev = e.chain_hash or expected  # resync so one break is reported once
        else:
            prev = expected
    seqs = sorted(e.sequence for e in ordered if e.sequence > 0)
    gaps = [{"after": a, "before": b, "missing": b - a - 1} for a, b in zip(seqs, seqs[1:]) if b - a > 1]
    anchor_ok = anchor is None or (bool(ordered) and ordered[-1].chain_hash == anchor and not problems)
    if anchor is not None and not anchor_ok and not problems:
        problems.append({"event_id": None, "sequence": None, "problem": "log does not end at the recorded anchor (truncated?)"})
    return {"events": len(ordered), "intact": not problems and anchor_ok, "anchor": anchor,
            "computed_anchor": prev if ordered else None, "problems": problems[:50], "telemetry_gaps": gaps[:50]}
