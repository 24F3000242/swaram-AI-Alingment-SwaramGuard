"""System 1: fast behavioral screen against a learned per-role baseline.

Dual-process idea: rules (System 2) reason slowly and explicitly; this screen
cheaply asks "has an agent in this role ever done this before?". Each behavior an
agent shows is scored by its surprise, -log2 P(an agent of this role shows it),
estimated from benign runs with Laplace smoothing. Only rare behaviors count.

The baseline is learned continually: new runs confirmed clean can be folded in
without forgetting earlier ones (counts only ever accumulate).
"""
from __future__ import annotations

import copy
import math
from collections import defaultdict

from app.modules.simulator.world import under
from app.schemas import Agent, NormalizedEvent

RARE_P = 0.1  # behaviors seen in >= 10% of same-role agents are "normal"


def is_send(e: NormalizedEvent) -> bool:
    """A message the agent SENT. Inbox reads ('receive': agent = recipient, target = sender) are not hand-offs."""
    return e.event_type == "message" and e.action != "receive"


def scope(resource: str | None) -> str | None:
    """A resource's area: its first two path levels ('repo/src/auth.py' -> 'repo/src').

    Model-driven agents name individual files; the policy and the baseline reason about areas.
    """
    return "/".join(resource.split("/")[:2]) if resource and "/" in resource else resource


def behavior_key(e: NormalizedEvent) -> str:
    """Structured description of what an agent did. Free text is never used."""
    if e.event_type == "message" and e.action == "receive":
        return "message:receive"
    if e.event_type == "message":
        ref = e.payload.get("data_ref")
        return f"message:send{f':data_ref={ref}' if ref else ''}"
    if e.event_type == "data_transfer":
        return f"data_transfer:{e.action}:{scope(e.resource)}->{e.target}"
    if e.event_type == "resource_access":
        return f"resource_access:{e.action}:{scope(e.resource)}"
    if e.event_type == "tool_call":
        return f"tool_call:{scope(e.resource) or e.action}"
    return f"{e.event_type}:{e.action}"


def agent_behaviors(events: list[NormalizedEvent]) -> dict[str, dict[str, list[str]]]:
    """agent_id -> behavior -> event_ids exhibiting it."""
    out: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for e in events:
        if e.event_type == "observation":  # resource-side telemetry about an agent, not the agent's own action
            continue
        if e.payload.get("untrusted") is True:  # content delivered to the agent (email, ticket): an input, not behavior
            continue
        out[e.agent_id][behavior_key(e)].append(e.event_id)
    return out


# v2: "pairs"; v3: "msg_stats"; v4: "identities" (per-agent history);
# v5: inbox reads keyed as message:receive + member 1's simulator, so baselines saved before must retrain.
# v6: resources keyed by area (scope()) so AI agents naming individual files aren't "never seen before".
PROFILE_VERSION = 6


def empty_profile() -> dict:
    return {"version": PROFILE_VERSION, "roles": {}, "pairs": {}, "msg_stats": {}, "identities": {}, "runs_learned": 0}


def message_length_limit(profile: dict, role: str | None, sigmas: float = 4.0, floor: float = 20.0) -> float | None:
    """Longest 'normal' message for a role: mean + sigmas * max(std, floor). None without enough data."""
    s = profile.get("msg_stats", {}).get(role or "")
    if not s or s["n"] < 10:
        return None
    std = (s["m2"] / (s["n"] - 1)) ** 0.5
    return s["mean"] + sigmas * max(std, floor)


def is_current(profile: dict | None) -> bool:
    return bool(profile and profile.get("roles") and profile.get("version", 1) >= PROFILE_VERSION)


def pair_rate(profile: dict, sender_role: str | None, recipient_role: str | None) -> float | None:
    """Messages per sender agent from role A to role B in the baseline. None when it can't be judged.

    Real swarms have structural channels (planner <-> workers, ~2/agent/run) and incidental ones (<0.25).
    """
    role = profile.get("roles", {}).get(sender_role or "")
    if not recipient_role or "pairs" not in profile or not role or not role["agents"]:
        return None
    return profile["pairs"].get(f"{sender_role}->{recipient_role}", 0) / role["agents"]


def learn(profile: dict | None, events: list[NormalizedEvent], agents: list[Agent], run_id: str | None = None) -> dict:
    """Fold one benign run into the profile (continual learning, no forgetting)."""
    profile = copy.deepcopy(profile) if profile else empty_profile()
    if run_id:
        if run_id in profile.setdefault("learned_run_ids", []):
            raise ValueError(f"{run_id} is already part of the baseline")
        profile["learned_run_ids"].append(run_id)
    seen = agent_behaviors(events)
    for a in agents:
        role = profile["roles"].setdefault(a.role, {"agents": 0, "behaviors": {}})
        role["agents"] += 1
        for b in seen.get(a.agent_id, {}):
            role["behaviors"][b] = role["behaviors"].get(b, 0) + 1
    roles = {a.agent_id: a.role for a in agents}
    pairs = profile.setdefault("pairs", {})
    stats = profile.setdefault("msg_stats", {})
    for e in events:
        if is_send(e) and e.agent_id in roles and e.target in roles:
            key = f"{roles[e.agent_id]}->{roles[e.target]}"
            pairs[key] = pairs.get(key, 0) + 1
        if is_send(e) and e.agent_id in roles and e.payload.get("content"):
            s = stats.setdefault(roles[e.agent_id], {"n": 0, "mean": 0.0, "m2": 0.0})
            x = float(len(str(e.payload["content"])))  # Welford's running mean/variance
            s["n"] += 1
            delta = x - s["mean"]
            s["mean"] += delta / s["n"]
            s["m2"] += delta * (x - s["mean"])
    _learn_identities(profile, events, agents, seen)
    profile["version"] = PROFILE_VERSION
    profile["runs_learned"] += 1
    return profile


# ---------------------------------------------------------------- per-agent (identity) history
# An identity is an agent's stable name ("Analyst 1"); run-scoped agent ids change every run. In production this
# should be the agent's durable identity (service account, deployment name).

def identity_of(agent: Agent) -> str:
    return agent.name


def _learn_identities(profile: dict, events: list[NormalizedEvent], agents: list[Agent], seen: dict) -> None:
    identities = profile.setdefault("identities", {})
    names = {a.agent_id: identity_of(a) for a in agents}
    peers: dict[str, set[str]] = defaultdict(set)
    for e in events:
        if is_send(e) and e.agent_id in names and e.target in names:
            peers[e.agent_id].add(names[e.target])
    for a in agents:
        ident = identities.setdefault(identity_of(a), {"role": a.role, "runs": 0, "behaviors": {}, "peers": {}})
        ident["runs"] += 1
        for b, ids in seen.get(a.agent_id, {}).items():
            s = ident["behaviors"].setdefault(b, {"runs": 0, "sum": 0, "sumsq": 0})
            s["runs"] += 1
            s["sum"] += len(ids)
            s["sumsq"] += len(ids) ** 2
        for p in peers.get(a.agent_id, ()):
            ident["peers"][p] = ident["peers"].get(p, 0) + 1


def is_sensitive(behavior: str, restricted: set[str], prefixes: list[str]) -> bool:
    """Behaviors where 'new for this agent' matters: restricted data, outbound transfers, hand-offs, control plane."""
    if behavior.startswith("data_transfer:") or "data_ref=" in behavior:
        return True
    target = behavior.split(":", 2)[-1]
    return under(target, restricted) or any(target.startswith(p) for p in prefixes)


def identity_drift(profile: dict, agent: Agent, behaviors: dict[str, list[str]], peers: set[str], *, restricted: set[str],
                   prefixes: list[str], min_runs: int = 5, novel_p: float = 0.15, sigmas: float = 3.0) -> dict | None:
    """How this run's behavior departs from this agent's OWN history. None if there is not enough history."""
    ident = profile.get("identities", {}).get(identity_of(agent))
    if not ident or ident["runs"] < min_runs or ident["role"] != agent.role:
        return None
    runs = ident["runs"]
    novel, spikes = [], []
    for b, ids in sorted(behaviors.items()):
        h = ident["behaviors"].get(b, {"runs": 0, "sum": 0, "sumsq": 0})
        p_self = (h["runs"] + 1) / (runs + 2)
        role_p = probability(profile, agent.role, b)
        if p_self < novel_p and is_sensitive(b, restricted, prefixes) and (role_p is None or role_p >= RARE_P):
            # New for THIS agent but normal for its role (role-rare behavior is SG-004's job).
            novel.append({"behavior": b, "p_self": round(p_self, 3), "history_runs": runs, "event_ids": ids})
            continue
        if b.startswith("message:"):
            continue  # message volume scales with swarm size; runaway messaging is SG-018's job
        if not is_sensitive(b, restricted, prefixes):
            continue  # more wiki reads than usual is not a threat (seen with real AI agents); more PII reads is
        mean = h["sum"] / runs
        std = max(0.0, h["sumsq"] / runs - mean * mean) ** 0.5
        if len(ids) >= 3 and len(ids) > mean + sigmas * max(std, 1.0):
            spikes.append({"behavior": b, "count": len(ids), "usual": round(mean, 2), "history_runs": runs, "event_ids": ids})
    new_peers = sorted(p for p in peers if p not in ident["peers"])
    return {"identity": identity_of(agent), "history_runs": runs, "novel": novel, "spikes": spikes, "new_peers": new_peers}


def probability(profile: dict, role: str, behavior: str) -> float | None:
    r = profile.get("roles", {}).get(role)
    if not r or not r["agents"]:
        return None
    return (r["behaviors"].get(behavior, 0) + 1) / (r["agents"] + 2)


def score_agent(profile: dict, role: str | None, behaviors: dict[str, list[str]]) -> tuple[float, list[dict]]:
    """Total surprise in bits and the rare behaviors that produced it."""
    if not role:
        return 0.0, []
    rare = []
    for b, event_ids in sorted(behaviors.items()):
        p = probability(profile, role, b)
        if p is None or p >= RARE_P:
            continue
        rare.append({"behavior": b, "p": round(p, 4), "bits": round(-math.log2(p), 2), "event_ids": event_ids})
    return round(sum(r["bits"] for r in rare), 2), rare


def summary(profile: dict | None) -> dict:
    profile = profile or empty_profile()
    roles = profile.get("roles", {})
    return {
        "trained": bool(roles),
        "runs_learned": profile.get("runs_learned", 0),
        "learned_run_ids": profile.get("learned_run_ids", []),
        "agents_learned": sum(r["agents"] for r in roles.values()),
        "identities_learned": len(profile.get("identities", {})),
        "roles": {k: {"agents": v["agents"], "behaviors": len(v["behaviors"])} for k, v in sorted(roles.items())},
    }
