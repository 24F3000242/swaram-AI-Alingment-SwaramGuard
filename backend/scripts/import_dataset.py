"""Import a dataset batch (from scripts/generate_dataset.py) into the app's workspace.

    python scripts/import_dataset.py ../datasets/live-ai
    python scripts/import_dataset.py ../datasets/live-ai --include-degraded

Every run goes through collect, detect, respond and evaluate, and then shows up in the app. Safe to run twice.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services.dataset_import import import_dataset  # noqa: E402
from app.services.pipeline import Pipeline  # noqa: E402
from app.storage import get_store  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folder")
    ap.add_argument("--include-degraded", action="store_true", help="also import runs that fell back to scripted work")
    args = ap.parse_args()
    p = Pipeline(get_store())
    p.seed_defaults()
    print(json.dumps(import_dataset(p, args.folder, args.include_degraded, log=print), indent=2))


if __name__ == "__main__":
    main()
