"""SG-029: covert staged-transfer channels in agent output.

Modelled on the public Swarm Traces incident data (swarmtraces.org), where agents moved content between each other
through chains of short links: each link held one fragment plus the address of the next, and a loader joined the
fragments. The encoded content varies endlessly, so this looks for the *shape* of such a channel instead, which
survives encoding and the dataset's redactions. Each signal is a hint, never proof on its own; `covert_signals`
returns the distinct signals found, and the rule flags content carrying two or more, or sending a credential outside.

Signals:
- fragment_chain: a fragment is appended, then the next hop is fetched ("x+=...; n('//next')", loops over parts);
- script_pull:    a remote script is pulled into a page or loader (script src from a variable, dynamic import of a URL);
- assemble_run:   assembled text is run (eval / new Function / exec / os.system / known template-escape gadgets);
- decode_run:     a decoder sits next to an executor (atob / b64decode / fromCharCode near eval / exec);
- credential_out: an auth header or bearer token is sent to a destination.
"""
from __future__ import annotations

import re
from functools import lru_cache

from app.schemas import Agent, Alert, DetectionRule, NormalizedEvent

_SIGNALS = {
    "fragment_chain": re.compile(r"""\w\s*\+=\s*['"].*?['"]\s*;?\s*\w*\s*\(?\s*['"]?//""", re.S),
    "script_pull": re.compile(r"""<script[^>]*\ssrc\s*=\s*[^>]*[\]`+]|import\s*\(\s*[`'"]?\s*(?:https?:|//|\[)""", re.I),
    "assemble_run": re.compile(r"""\b(?:eval|new\s+Function|exec|os\.system|subprocess|__globals__|cycler\.__init__)\b""", re.I),
    "decode_run": re.compile(r"""\b(?:atob|b64decode|b64_?decode|fromCharCode|unescape|base64)\b""", re.I),
    "credential_out": re.compile(r"""['"]?(?:authorization|x-api-key|x-amz-security-token)['"]?\s*[:,]\s*['"]?\s*(?:bearer\s|\[credential)""", re.I),
}
_NEXT_HOP = re.compile(r"""[`'"]\s*(?://|https?:)""")


@lru_cache(maxsize=16384)
def covert_signals(text: str) -> tuple[str, ...]:
    """The distinct covert-transfer signals a single piece of outbound content carries."""
    if not text:
        return ()
    found = []
    for name, pat in _SIGNALS.items():
        if pat.search(text):
            if name == "decode_run" and not _SIGNALS["assemble_run"].search(text):
                continue  # a decoder alone is ordinary; only a decoder feeding an executor counts
            found.append(name)
    return tuple(found)


def _content(e: NormalizedEvent) -> str:
    p = e.payload or {}
    parts = [p.get("content"), p.get("body"), p.get("script"), p.get("command"), p.get("arguments"), e.resource, e.target]
    return "\n".join(x for x in parts if isinstance(x, str))


def rule_covert_transfer(rule: DetectionRule, run_id: str, events: list[NormalizedEvent], registry: dict[str, Agent]) -> list[Alert]:
    from app.modules.detection.rules import _make_alert

    min_signals = int(rule.params.get("min_signals", 2))
    outbound = {"data_transfer", "tool_call", "message"}
    alerts = []
    for e in events:
        if e.event_type not in outbound:
            continue
        signals = covert_signals(_content(e))
        if len(signals) >= min_signals or "credential_out" in signals:
            sev = "high" if ("credential_out" in signals or len(signals) >= 3) else "medium"
            reason = (f"{e.agent_id} sent content with {len(signals)} covert-transfer signal(s) "
                      f"({', '.join(signals)}): the shape of a staged payload moved through an encoded channel, "
                      f"not ordinary output.")
            alerts.append(_make_alert(rule, run_id, [e.agent_id], [e], e.resource or e.target, reason, severity=sev))
    return alerts


COVERT_RULES = [DetectionRule(
    rule_id="SG-029", name="Covert staged transfer", severity="high", recommended_action="alert",
    description="Outbound content shaped like a staged payload moved through an encoded channel (fragment chains, "
    "remote-script pulls, assemble-and-run, decoder-plus-executor, or a credential sent to a destination). Modelled on "
    "the Swarm Traces incident. Signals only, never proof; two or more, or a credential leaving, raises it.",
    params={"min_signals": 2})]
COVERT_IMPLS = {"SG-029": rule_covert_transfer}
