"""Run the detection accuracy benchmark and print a report.

    python scripts/benchmark_detection.py            # full run
    python scripts/benchmark_detection.py --quick    # fewer seeds / sizes
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.modules.detection.benchmark import ATTACKS, BENIGN, run_benchmark  # noqa: E402
from app.modules.detection.rules import run_rules  # noqa: E402
from app.services.pipeline import Pipeline  # noqa: E402
from app.storage.sqlite_store import SQLiteStore  # noqa: E402


def main() -> None:
    quick = "--quick" in sys.argv
    sensors = "--sensors" in sys.argv  # add an independent resource-side record per action
    rules = Pipeline(SQLiteStore(":memory:")).rules()  # trained baseline, as in the app
    res = run_benchmark(rules, run_rules, agent_counts=(5, 10) if quick else (5, 10, 20), seeds=range(1, 3 if quick else 4),
                        sensors=sensors)
    print("Evidence sources: agent log + independent sensors" if sensors else "Evidence source: agent log only")
    print(f"{len(ATTACKS)} attack cases, {len(BENIGN)} benign look-alikes\n")
    print(f"{'missing':>8} {'trials':>7} {'precision':>10} {'recall':>7} {'FPR':>7} {'caught':>7} {'right rule':>11} "
          f"{'evidence':>9} {'caught|ev':>10} {'benign alarms':>14}")
    for r in res["rows"]:
        print(f"{r['drop_rate']:>8.0%} {r['trials']:>7} {r['precision']!s:>10} {r['recall']!s:>7} {r['false_positive_rate']!s:>7} "
              f"{r['threat_detection_rate']!s:>7} {r['right_rule_rate']!s:>11} {r['evidence_survived']!s:>9} "
              f"{r['detection_given_evidence']!s:>10} {r['benign_alarm_rate']!s:>14}")
    print("\nPer-case detection rate (benign: rate of staying quiet):")
    drops = [str(r["drop_rate"]) for r in res["rows"]]
    for name, by_drop in res["cases"].items():
        print(f"  {name:28s} " + "  ".join(f"{by_drop.get(d)!s:>6}" for d in drops))
    if "--json" in sys.argv:
        print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
