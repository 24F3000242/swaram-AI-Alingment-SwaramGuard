"""API keys with roles: who may watch, who may act, who may change the rules.

Set SWARMGUARD_API_KEYS in backend/.env to switch authentication on:

    SWARMGUARD_API_KEYS=aarya:<long-random-key>:admin,vyom:<key>:operator,demo:<key>:viewer,crew-bot:<key>:agent

Roles (each includes the ones before it, except `agent`):
    viewer    read everything, watch the live stream
    operator  + start runs, run pipeline stages, pause / stop agents, review decisions
    admin     + change detection rules, response policy and baselines
    agent     only the live ingest API (for a real agent platform reporting in)

Send the key as `Authorization: Bearer <key>` or `X-API-Key: <key>`; the WebSocket takes `?key=<key>` (browsers
can't set headers on WebSockets). With no keys configured, authentication is off (local development) and
/api/health says so. Keys are compared in constant time and never logged. Generate one with:
    python -c "import secrets; print(secrets.token_urlsafe(32))"
"""
from __future__ import annotations

import hmac
import os
from dataclasses import dataclass

RANK = {"viewer": 1, "operator": 2, "admin": 3}
OPEN = {"/api/health"}  # liveness check only; says nothing about runs
ADMIN_PREFIXES = ("/api/detection-rules", "/api/response-policies", "/api/detection/baseline")


@dataclass(frozen=True)
class Principal:
    name: str
    role: str


def load_keys(raw: str | None = None) -> dict[str, Principal]:
    raw = os.getenv("SWARMGUARD_API_KEYS", "") if raw is None else raw
    keys = {}
    for part in raw.split(","):
        bits = [b.strip() for b in part.strip().split(":")]
        if len(bits) != 3 or not all(bits):
            continue
        name, key, role = bits
        if role not in (*RANK, "agent"):
            raise ValueError(f"SWARMGUARD_API_KEYS: unknown role {role!r} for {name!r}")
        if len(key) < 16:
            raise ValueError(f"SWARMGUARD_API_KEYS: the key for {name!r} is too short (use 16+ random characters)")
        keys[key] = Principal(name, role)
    return keys


def enabled() -> bool:
    return bool(load_keys())


def identify(key: str | None) -> Principal | None:
    if not key:
        return None
    for known, who in load_keys().items():
        if hmac.compare_digest(known.encode(), key.encode()):
            return who
    return None


def required_role(method: str, path: str) -> str | None:
    """The minimum role for a request, or None if it is open."""
    if path in OPEN or not path.startswith("/api/") or method == "OPTIONS":
        return None  # OPTIONS: CORS pre-flight carries no credentials
    if path.startswith("/api/ingest/") or path == "/api/convert":
        return "agent"
    if method in ("GET", "HEAD", "OPTIONS") or path == "/api/live":
        return "viewer"
    if path.startswith(ADMIN_PREFIXES):
        return "admin"
    return "operator"


def allowed(who: Principal | None, need: str | None) -> bool:
    if need is None:
        return True
    if who is None:
        return False
    if need == "agent":
        return who.role == "agent" or RANK.get(who.role, 0) >= RANK["operator"]
    if who.role == "agent":
        return False  # an agent key only reports in; it can't read results or act
    return RANK[who.role] >= RANK[need]


def key_from(headers, query) -> str | None:
    auth = headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return headers.get("x-api-key") or query.get("key")
