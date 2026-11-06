"""Generate a dataset of AI-mode runs for the Data Optimizer, scored by Threat Detection.

    python scripts/generate_dataset.py                       # default batch -> datasets/<date>
    python scripts/generate_dataset.py --runs 5 --learn 3    # 5 runs per scenario
    python scripts/generate_dataset.py --out datasets/night1 # same folder again = resume
    python scripts/generate_dataset.py --live-guard contain  # also stop hijacked agents mid-run
    python scripts/generate_dataset.py --dry-run             # show the plan and model-call estimate only

Needs GEMINI_API_KEY in backend/.env (or --backend deterministic for an offline smoke test).
Raise the local daily cap with GEMINI_DAILY_BUDGET if your Google quota allows more.
"""
from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import get_settings  # noqa: E402
from app.services.dataset import DEFAULT_SCENARIOS, BatchConfig, calls_per_run, generate, planned_runs  # noqa: E402

REPO = Path(__file__).resolve().parents[2]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=str(REPO / "datasets" / date.today().isoformat()))
    ap.add_argument("--runs", type=int, default=2, help="runs per scenario")
    ap.add_argument("--learn", type=int, default=3, help="clean normal runs learned into the baseline first")
    ap.add_argument("--agents", type=int, default=5, choices=[3, 5, 10, 20])
    ap.add_argument("--backend", default="gemini")
    ap.add_argument("--scenarios", nargs="*", default=DEFAULT_SCENARIOS)
    ap.add_argument("--live-guard", default="off", choices=["off", "detect", "contain"],
                    help="stream test runs through the live guard; contain also blocks and pauses")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    get_settings()  # loads backend/.env

    cfg = BatchConfig(out_dir=args.out, scenarios=args.scenarios, runs_per_scenario=args.runs, learn_runs=args.learn,
                      agent_count=args.agents, backend=args.backend, live_guard=args.live_guard)
    plan = planned_runs(cfg)
    calls = len(plan) * calls_per_run(cfg.agent_count) if cfg.backend != "deterministic" else 0
    print(f"Batch: {len(plan)} runs ({cfg.learn_runs} learning + {len(plan) - cfg.learn_runs} test), "
          f"~{calls} model calls, ~{calls / 14:.0f} min at the free-tier pace. Output: {cfg.out_dir}")
    if args.dry_run:
        return

    from app.services.pipeline import Pipeline
    from app.storage.sqlite_store import SQLiteStore

    rules = Pipeline(SQLiteStore(":memory:")).rules()  # the app's trained baseline, extended with this batch's clean runs
    summary = generate(cfg, rules, log=lambda m: print(m, flush=True))
    print("\n" + (Path(cfg.out_dir) / "summary.md").read_text(encoding="utf-8"))
    if summary.get("stopped_early"):
        sys.exit(2)


if __name__ == "__main__":
    main()
