"""SwarmGuard coverage of the OWASP Top 10 for Agentic Applications (OWASP GenAI Security Project, Dec 2025).

Each risk lists the detection rules that cover it, the controls that act on it (enforcement, not just alerts), and
what is honestly still missing. `coverage` is our own judgement: "strong" = detected and enforced with tests,
"partial" = detected or enforced only in part. GET /api/coverage/owasp serves this; docs/owasp-agentic.md explains it.
"""
from __future__ import annotations

OWASP_AGENTIC = [
    {"id": "ASI01", "name": "Agent Goal Hijack", "coverage": "strong",
     "rules": ["SG-012", "SG-028", "SG-026", "SG-027"],
     "controls": ["hijack tripwire (pause before the first out-of-policy action after untrusted input)",
                  "trained injection classifier, optional live quarantine", "pre-execution policy check",
                  "egress proxy"],
     "gaps": "Injections that look like ordinary policy pages are not caught from text; only from what the agent does next."},
    {"id": "ASI02", "name": "Tool Misuse and Exploitation", "coverage": "strong",
     "rules": ["SG-001", "SG-002", "SG-016", "SG-018", "SG-011", "SG-021"],
     "controls": ["pre-execution gate on every tool call (ingest /gate, SDK, LangChain handler, MCP gateway)",
                  "pre-execution policy check", "egress allowlist at the network (proxy)"],
     "gaps": "Tool arguments are checked against resource policy, not against each tool's own schema."},
    {"id": "ASI03", "name": "Identity and Privilege Abuse", "coverage": "strong",
     "rules": ["SG-008", "SG-024", "SG-026"],
     "controls": ["per-agent identity tokens, optionally scoped with a TTL (events, gate, proxy)",
                  "API keys with roles"],
     "gaps": "Tokens are session- or time-scoped, not scoped to a single task or tool."},
    {"id": "ASI04", "name": "Agentic Supply Chain Vulnerabilities", "coverage": "partial",
     "rules": ["SG-019"],
     "controls": ["unregistered / re-hashed / untrusted-source tools flagged", "MCP gateway tool allowlist"],
     "gaps": "No signature verification of tool or model packages."},
    {"id": "ASI05", "name": "Unexpected Code Execution", "coverage": "partial",
     "rules": ["SG-007", "SG-015", "SG-006", "SG-023"],
     "controls": ["agent-written code runs in a sandbox, or not at all (SWARMGUARD_CODE_EXEC)"],
     "gaps": "The sandbox is a subprocess with limits, not a VM or container."},
    {"id": "ASI06", "name": "Memory and Context Poisoning", "coverage": "strong",
     "rules": ["SG-012", "SG-028"],
     "controls": ["memory provenance: recalling a note that came from untrusted content arms the tripwire",
                  "sleeper and poisoned-memory scenarios tested"],
     "gaps": "Provenance must be reported by the platform; memory written outside SwarmGuard's view is unlabelled."},
    {"id": "ASI07", "name": "Insecure Inter-Agent Communication", "coverage": "strong",
     "rules": ["SG-026", "SG-027", "SG-003", "SG-005", "SG-020", "SG-029"],
     "controls": ["impersonated messages quarantined before delivery", "need-to-know egress hold",
                  "per-agent identity tokens"],
     "gaps": "Messages are not encrypted by SwarmGuard; it relies on the platform's transport."},
    {"id": "ASI08", "name": "Cascading Failures", "coverage": "strong",
     "rules": ["SG-013", "SG-018", "SG-010"],
     "controls": ["automatic swarm circuit breaker (pause the rest once containment spreads to N agents)",
                  "operator kill switch (stop run)", "worm containment at patient zero"],
     "gaps": "The breaker pauses; it does not selectively throttle while keeping healthy agents running."},
    {"id": "ASI09", "name": "Human-Agent Trust Exploitation", "coverage": "partial",
     "rules": ["SG-017", "SG-014", "SG-030"],
     "controls": ["review queue: humans release or confirm every containment",
                  "agent work reports checked claim by claim against recorded actions (SG-030)"],
     "gaps": "Messages to humans are checked for coercion patterns, not for subtle persuasion."},
    {"id": "ASI10", "name": "Rogue Agents", "coverage": "strong",
     "rules": ["SG-004", "SG-025", "SG-006", "SG-007", "SG-009", "SG-011", "SG-014", "SG-015", "SG-022", "SG-030"],
     "controls": ["pre-execution policy check (any cause, incl. a goal of the agent's own)", "risk-based pause",
                  "internal-goal fuzzer measures how often a model goes rogue"],
     "gaps": "Baselines need history (SG-025 needs 5+ runs of the agent)."},
]


def coverage() -> dict:
    from app.modules.detection.rules import DEFAULT_RULES

    names = {r.rule_id: r.name for r in DEFAULT_RULES}
    risks = [{**r, "rules": [{"rule_id": x, "name": names.get(x, "?")} for x in r["rules"]]} for r in OWASP_AGENTIC]
    used = {x for r in OWASP_AGENTIC for x in r["rules"]}
    return {"framework": "OWASP Top 10 for Agentic Applications (2026)",
            "summary": {"strong": sum(r["coverage"] == "strong" for r in OWASP_AGENTIC),
                        "partial": sum(r["coverage"] == "partial" for r in OWASP_AGENTIC), "none": 0},
            "risks": risks, "rules_not_mapped": sorted(set(names) - used)}
