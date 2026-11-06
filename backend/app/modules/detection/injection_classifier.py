"""Trained prompt-injection classifier: scores untrusted text (an email, a web page, a tool result) before an agent acts.

Until now SwarmGuard caught injections by what the agent *did* afterwards (SG-012, the live tripwire). This looks at the
text itself. It is a linear model (logistic regression over hashed word and character n-grams) trained on public,
openly licensed injection datasets plus indirect-injection examples in our own workspace's style
(`scripts/train_injection_classifier.py`). No extra packages: scoring is a dictionary lookup per feature, well under a
millisecond per document, and the weights ship as one JSON file.

It is a signal, not a verdict: a linear model can be evaded by paraphrase, which is why the behaviour-based rules stay.
Measured accuracy, including on datasets it never saw, is in docs/injection-classifier.md.
"""
from __future__ import annotations

import json
import logging
import os
import math
import re
import zlib
from functools import lru_cache
from pathlib import Path

log = logging.getLogger(__name__)

MODEL_PATH = Path(__file__).with_name("data") / "injection_model.json"
BUCKETS = 1 << 20
MAX_CHARS = 4000
WORD = re.compile(r"[a-z0-9_:/.\-']+")


def _h(feature: str) -> int:
    return zlib.crc32(feature.encode("utf-8")) & (BUCKETS - 1)  # stable across processes (unlike hash())


DEST = re.compile(r"external:[a-z0-9](?:[a-z0-9_.\-]*[a-z0-9])?")  # no trailing full stop or dash


def structural(t: str) -> set[str]:
    """Signals that don't depend on wording: which destinations the text names, compared with the approved list."""
    from app.modules.simulator.world import EXTERNAL_ALLOWLIST

    dests = set(DEST.findall(t))
    out = set()
    if dests - set(EXTERNAL_ALLOWLIST):
        out.add("s:unapproved_destination")
    if dests & set(EXTERNAL_ALLOWLIST) and dests - set(EXTERNAL_ALLOWLIST):
        out.add("s:approved_and_unapproved")  # e.g. "X moved to Y", "fallback for X is Y"
    return out


def features(text: str) -> dict[int, float]:
    """Hashed word 1-2 grams, character 4-grams and structural signals, L2-normalised presence weights."""
    t = " ".join((text or "").lower().split())[:MAX_CHARS]
    words = WORD.findall(t)
    feats: set[int] = {_h("w:" + w) for w in words}
    feats |= {_h(s) for s in structural(t)}
    feats |= {_h(f"b:{a} {b}") for a, b in zip(words, words[1:])}
    padded = f" {t} "
    feats |= {_h("c:" + padded[i:i + 4]) for i in range(len(padded) - 3)}
    if not feats:
        return {}
    v = 1.0 / math.sqrt(len(feats))
    return {f: v for f in feats}


@lru_cache(maxsize=1)
def load(path: str | None = None) -> dict:
    data = json.loads(Path(path or MODEL_PATH).read_text(encoding="utf-8"))
    data["w"] = {int(k): v for k, v in data["weights"].items()}
    return data


def linear_score(text: str, model: dict | None = None) -> float:
    """The trained model's probability (0..1) that the text contains a prompt injection."""
    m = model or load()
    z = m["bias"] + sum(m["w"].get(f, 0.0) * v for f, v in features(text).items())
    return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))


DESTINATION_SCORE = 0.85  # above the alert threshold, below the default live-quarantine threshold (0.9)


def destination_score(text: str) -> float:
    """Policy-aware second detector: untrusted content naming an outside destination that is not approved. Catches
    injections that read like ordinary policy pages ("uploads now go to X", "retry via X"), which wording-based models
    miss. Uses the deployment's own allowlist, so it is only as good as that list."""
    return DESTINATION_SCORE if "s:unapproved_destination" in structural(" ".join((text or "").lower().split())) else 0.0


def score(text: str, model: dict | None = None) -> float:
    """Injection score (0..1): the higher of the trained model and the destination check."""
    return max(linear_score(text, model), destination_score(text))


def external_score(text: str, url: str | None = None) -> float | None:
    """Optional stronger model run elsewhere (SWARMGUARD_INJECTION_SCORER_URL): POST {"text"} -> {"score": 0..1}.
    Any failure returns None, so the built-in model alone decides."""
    url = url or os.getenv("SWARMGUARD_INJECTION_SCORER_URL")
    if not url:
        return None
    try:
        import httpx

        r = httpx.post(url, json={"text": text[:MAX_CHARS]}, timeout=3)
        return max(0.0, min(1.0, float(r.json()["score"])))
    except Exception as exc:  # never let an outside service break detection
        log.warning("external injection scorer failed: %s", exc)
        return None


@lru_cache(maxsize=4096)
def cached_score(text: str) -> float:
    """Built-in score, or the outside model's if it is configured and higher."""
    s = score(text)
    ext = external_score(text)
    return max(s, ext) if ext is not None else s


def threshold() -> float:
    return float(load().get("threshold", 0.5))


def available() -> bool:
    return MODEL_PATH.exists()
