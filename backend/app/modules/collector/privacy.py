"""Personal data in event text is replaced before anything is stored.

Emails, phone numbers, payment-card numbers (Luhn-checked) and US SSNs found in any string inside an event's payload
become stable pseudonyms such as `<email:3f9a2c>`: the same value always maps to the same pseudonym, so detection
that compares text (e.g. SG-027 spotting a copied email) still works, but the stored events no longer contain the
personal data. On by default; set SWARMGUARD_REDACT_PII=0 to keep text as-is.
"""
from __future__ import annotations

import hashlib
import os
import re
from typing import Any

EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
CARD = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")
PHONE = re.compile(r"(?<![\w-])\+?\(?\d[\d\s().-]{8,}\d(?![\w-])")
SKIP_KEYS = {"message_id", "data_ref", "event_id", "run_id", "sender_id", "telemetry"}  # identifiers, not personal data


def enabled() -> bool:
    return os.getenv("SWARMGUARD_REDACT_PII", "1").strip().lower() not in ("0", "false", "off", "no")


def _luhn(digits: str) -> bool:
    total, parity = 0, len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def _pseudo(kind: str, value: str) -> str:
    return f"<{kind}:{hashlib.sha256(value.strip().lower().encode()).hexdigest()[:6]}>"


def redact_text(text: str) -> tuple[str, int]:
    count = 0

    def sub(kind: str, check=None):
        def repl(m: re.Match) -> str:
            nonlocal count
            value = m.group(0)
            if check and not check(value):
                return value
            count += 1
            return _pseudo(kind, value)
        return repl

    text = EMAIL.sub(sub("email"), text)
    text = SSN.sub(sub("ssn"), text)
    text = CARD.sub(sub("card", lambda v: _luhn(re.sub(r"\D", "", v))), text)
    text = PHONE.sub(sub("phone", lambda v: 10 <= len(re.sub(r"\D", "", v)) <= 15), text)  # E.164: at most 15 digits
    return text, count


def redact(value: Any, key: str | None = None) -> tuple[Any, int]:
    """Redact every string inside a payload (dicts and lists included). Returns (redacted copy, replacements)."""
    if key in SKIP_KEYS:
        return value, 0
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        out, n = {}, 0
        for k, v in value.items():
            out[k], c = redact(v, k)
            n += c
        return out, n
    if isinstance(value, list):
        out_l, n = [], 0
        for v in value:
            r, c = redact(v)
            out_l.append(r)
            n += c
        return out_l, n
    return value, 0
