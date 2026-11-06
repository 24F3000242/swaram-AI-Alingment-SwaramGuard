"""The synthetic environment the simulated agents live in."""
from __future__ import annotations

from app.schemas import Scenario

ROLE_ORDER = ["planner", "analyst", "coder", "researcher", "reviewer"]

ROLE_PERMISSIONS: dict[str, list[str]] = {
    "planner": ["docs/wiki", "data/public"],
    "analyst": ["data/public", "data/customer_pii", "docs/wiki"],
    "coder": ["repo/src", "docs/wiki"],
    "researcher": ["docs/wiki", "data/public"],
    "reviewer": ["repo/src", "docs/wiki"],
}
ROLE_TOOLS = {
    "planner": "tool/planner_board",
    "analyst": "tool/sql_query",
    "coder": "tool/code_exec",
    "researcher": "tool/web_search",
    "reviewer": "tool/lint",
}
ROLE_OUTPUT = {
    "planner": "docs/wiki",
    "analyst": "data/public",
    "coder": "repo/src",
    "researcher": "docs/wiki",
    "reviewer": "docs/wiki",
}

RESTRICTED_RESOURCES = ["data/customer_pii", "secrets/api_keys"]


def under(resource: str | None, roots) -> bool:
    """True if `resource` is one of `roots` or inside one (data/customer_pii/customers.csv is under data/customer_pii).
    Real agents name files, not just the folders our policy lists, so every restricted / permitted check uses this."""
    return bool(resource) and any(resource == r or resource.startswith(r.rstrip("/") + "/") for r in roots if r)
EXTERNAL_PREFIX = "external:"
EXTERNAL_ALLOWLIST = ["external:approved-partner-api"]
TOPICS = ["SG-101", "SG-102", "SG-103", "SG-104", "SG-105", "SG-106"]

from app.modules.simulator.scenarios import (
    SCENARIO_ATTACKS,
    SCENARIOS,
    SCENARIOS_BY_ID,
)
