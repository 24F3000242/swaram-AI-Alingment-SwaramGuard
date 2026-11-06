"""Search for prompt injections the agent model falls for (adaptive, black-box).

    python scripts/fuzz_injections.py                 # 40 model calls -> datasets/fuzz-<date>/summary.md
    python scripts/fuzz_injections.py --budget 80

One model call per attempt. Needs GEMINI_API_KEY in backend/.env.
"""
from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.adapters import get_adapter  # noqa: E402
from app.config import get_settings  # noqa: E402
from app.services.injection_fuzz import fuzz, save  # noqa: E402

REPO = Path(__file__).resolve().parents[2]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--budget", type=int, default=40, help="model calls to spend")
    ap.add_argument("--backend", default="gemini")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", default=str(REPO / "datasets" / f"fuzz-{date.today().isoformat()}"))
    args = ap.parse_args()
    get_settings()
    res = fuzz(lambda: get_adapter(args.backend), budget=args.budget, seed=args.seed, log=lambda m: print(m, flush=True))
    path = save(res, args.out)
    print("\n" + path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
