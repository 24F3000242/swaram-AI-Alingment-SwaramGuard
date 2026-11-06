"""Download the Swarm Traces incident dataset (swarmtraces.org): a real swarm-of-agents intrusion, redacted.

    python scripts/fetch_swarm_traces.py       # -> datasets/swarmtraces/redacted.jsonl.gz (~15 MB)

The publishers redact credentials, PII and infrastructure details. The data is evidence, read as text and never run.
"""
from __future__ import annotations

import sys
from pathlib import Path

import httpx

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "datasets" / "swarmtraces"
URL = "https://swarmtraces.org/data/final/redacted.jsonl.gz"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    dest = OUT / "redacted.jsonl.gz"
    if dest.exists() and "--force" not in sys.argv:
        print(f"{dest} already present ({dest.stat().st_size} bytes)")
        return
    with httpx.stream("GET", URL, timeout=120, follow_redirects=True) as r:
        r.raise_for_status()
        with dest.open("wb") as f:
            for chunk in r.iter_bytes(1 << 16):
                f.write(chunk)
    print(f"downloaded {dest} ({dest.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
