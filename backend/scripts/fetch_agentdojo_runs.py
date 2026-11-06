"""Download published AgentDojo run logs (real model traces, labelled) for the outside evaluation.

    python scripts/fetch_agentdojo_runs.py      # -> datasets/agentdojo/<model>/<suite>/<user_task>/<attack>/<task>.json

AgentDojo (ETH Zurich SPY Lab, MIT license, github.com/ethz-spylab/agentdojo) publishes every run of its benchmark:
each file is one real model's conversation with tool calls and tool results, where an attacker's instructions were
planted in a tool result, and `security` says whether the attack succeeded. We keep only the main attack
("important_instructions") and the attack-free runs ("none") for a few models. The archive is streamed and filtered,
so nothing large is held in memory.
"""
from __future__ import annotations

import sys
import tarfile
from pathlib import Path

import httpx

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "datasets" / "agentdojo"
URL = "https://codeload.github.com/ethz-spylab/agentdojo/tar.gz/refs/heads/main"
MODELS = ["gpt-4o-2024-05-13", "claude-3-5-sonnet-20241022", "gemini-2.0-flash-001",
          "meta-llama_Llama-3.3-70B-Instruct", "gpt-4o-mini-2024-07-18"]
ATTACKS = {"important_instructions", "none"}


class _Stream:
    """File-like wrapper over an httpx byte stream, for tarfile's streaming mode."""

    def __init__(self, it):
        self.it, self.buf = it, b""

    def read(self, n=-1):
        while n < 0 or len(self.buf) < n:
            try:
                self.buf += next(self.it)
            except StopIteration:
                break
        if n < 0:
            out, self.buf = self.buf, b""
        else:
            out, self.buf = self.buf[:n], self.buf[n:]
        return out


def main() -> None:
    kept = 0
    with httpx.stream("GET", URL, timeout=300, follow_redirects=True) as r:
        r.raise_for_status()
        with tarfile.open(fileobj=_Stream(r.iter_bytes(1 << 16)), mode="r|gz") as tar:
            for m in tar:
                parts = Path(m.name).parts  # agentdojo-main/runs/<model>/<suite>/<user_task>/<attack>/<file>.json
                if (not m.isfile() or len(parts) != 7 or parts[1] != "runs" or parts[2] not in MODELS
                        or parts[5] not in ATTACKS or not parts[6].endswith(".json")):
                    continue
                dest = OUT.joinpath(*parts[2:])
                dest.parent.mkdir(parents=True, exist_ok=True)
                f = tar.extractfile(m)
                if f is not None:
                    dest.write_bytes(f.read())
                    kept += 1
                    if kept % 500 == 0:
                        print(f"{kept} traces", flush=True)
    print(f"done: {kept} traces in {OUT}")
    if not kept:
        sys.exit("nothing matched: has the repository layout changed?")


if __name__ == "__main__":
    main()
