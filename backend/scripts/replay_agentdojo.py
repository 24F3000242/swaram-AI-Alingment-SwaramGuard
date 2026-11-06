"""Outside proof for the injection classifier: replay real AgentDojo traces through SG-028.

    python scripts/fetch_agentdojo_runs.py       # once
    python scripts/replay_agentdojo.py           # -> prints a report, writes datasets/agentdojo/report.json

Each AgentDojo trace is a real model's tool-using conversation. In an "important_instructions" run an attacker's text
was planted in one tool result; in a "none" run nothing was. We take the text the agent read back from tools and ask
the SG-028 classifier whether it is an injection:
- recall = fraction of attacked tool results the classifier flags (its job is to warn before the agent acts);
- false-positive rate = fraction of clean "none"-run tool results it flags.
These are held-out real traces across five models; the classifier never trained on any of them.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.modules.detection import injection_classifier as clf  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
RUNS = REPO / "datasets" / "agentdojo"


def tool_texts(trace: dict) -> list[str]:
    out = []
    for m in trace.get("messages", []):
        if m.get("role") == "tool":
            c = m.get("content")
            if isinstance(c, str) and c.strip():
                out.append(c)
            elif isinstance(c, list):
                out += [b.get("content", "") for b in c if isinstance(b, dict) and b.get("content")]
    return out


def _norm(s: str) -> str:
    return " ".join(s.split())


def injected_text(trace: dict) -> list[str]:
    """Tool results that actually carry the planted attack (so clean results in an attacked run aren't miscounted)."""
    marks = [_norm(str(v)) for v in (trace.get("injections") or {}).values() if isinstance(v, str) and v.strip()]
    marks = [m[:80] for m in marks if len(m) >= 20]  # a distinctive slice, whitespace-insensitive
    return [t for t in tool_texts(trace) if any(m in _norm(t) for m in marks)]


def main() -> None:
    if not RUNS.exists():
        sys.exit("run scripts/fetch_agentdojo_runs.py first")
    thr = clf.threshold()
    per_model: dict[str, dict] = {}
    att_hit = att_tot = clean_hit = clean_tot = 0
    for f in RUNS.rglob("*.json"):
        if f.name == "report.json":
            continue
        trace = json.loads(f.read_text(encoding="utf-8"))
        if "messages" not in trace:
            continue
        model = trace.get("pipeline_name") or f.relative_to(RUNS).parts[0]
        pm = per_model.setdefault(model, {"attacked": 0, "flagged": 0, "clean": 0, "clean_flagged": 0})
        if trace.get("injection_task_id"):
            for t in injected_text(trace):
                att_tot += 1
                pm["attacked"] += 1
                if clf.score(t) >= thr:
                    att_hit += 1
                    pm["flagged"] += 1
        else:
            for t in tool_texts(trace):
                clean_tot += 1
                pm["clean"] += 1
                if clf.score(t) >= thr:
                    clean_hit += 1
                    pm["clean_flagged"] += 1
    report = {
        "threshold": thr,
        "attacked_tool_results": att_tot, "recall": round(att_hit / att_tot, 3) if att_tot else None,
        "clean_tool_results": clean_tot,
        "false_positive_rate": round(clean_hit / clean_tot, 3) if clean_tot else None,
        "per_model": {m: {"recall": round(v["flagged"] / v["attacked"], 3) if v["attacked"] else None,
                          "fp_rate": round(v["clean_flagged"] / v["clean"], 3) if v["clean"] else None,
                          "attacked": v["attacked"], "clean": v["clean"]} for m, v in sorted(per_model.items())},
    }
    (RUNS / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
