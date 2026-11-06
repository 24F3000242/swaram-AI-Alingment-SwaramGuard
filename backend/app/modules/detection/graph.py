"""Agent relationship graph built with NetworkX."""
from __future__ import annotations

from collections import Counter

import networkx as nx

from app.modules.detection.baseline import is_send
from app.schemas import Agent, AgentGraph, Alert, GraphEdge, GraphNode, NormalizedEvent


def build_graph(run_id: str, events: list[NormalizedEvent], agents: list[Agent], alerts: list[Alert]) -> AgentGraph:
    g = nx.DiGraph()
    roles = {a.agent_id: a.role for a in agents}
    for a in agents:
        g.add_node(a.agent_id, kind="agent")
    flagged = {aid for al in alerts for aid in al.agent_ids}
    activity = Counter(e.agent_id for e in events)

    for e in events:
        if is_send(e) and e.target:
            kind = "message"
        elif e.event_type == "data_transfer" and e.target:
            kind = "data_transfer"
        else:
            continue
        for node in (e.agent_id, e.target):
            if node not in g:
                g.add_node(node, kind="external" if node.startswith("external:") else "agent")
        if g.has_edge(e.agent_id, e.target):
            g[e.agent_id][e.target]["event_ids"].append(e.event_id)
        else:
            g.add_edge(e.agent_id, e.target, kind=kind, event_ids=[e.event_id])

    # Hidden channels found by SG-005: writer -> reader through a shared resource.
    by_id = {e.event_id: e for e in events}
    for al in alerts:
        if al.rule_id != "SG-005":
            continue
        stores = set((al.resource or "").split(","))
        for src, dst in zip(al.agent_ids, al.agent_ids[1:]):
            hop = [eid for eid in al.event_ids if eid in by_id and by_id[eid].resource in stores
                   and by_id[eid].event_type == "resource_access" and by_id[eid].agent_id in (src, dst)]
            if g.has_edge(src, dst) and g[src][dst]["kind"] == "indirect":
                g[src][dst]["event_ids"].extend(x for x in hop if x not in g[src][dst]["event_ids"])
            elif not g.has_edge(src, dst):
                g.add_edge(src, dst, kind="indirect", event_ids=hop)

    degree = nx.degree_centrality(g) if g.number_of_nodes() > 1 else {}
    between = nx.betweenness_centrality(g) if g.number_of_nodes() > 2 else {}
    nodes = [
        GraphNode(
            id=n,
            kind=data.get("kind", "agent"),
            role=roles.get(n),
            flagged=n in flagged,
            event_count=activity.get(n, 0),
            degree_centrality=round(degree.get(n, 0.0), 4),
            betweenness=round(between.get(n, 0.0), 4),
        )
        for n, data in g.nodes(data=True)
    ]
    edges = [
        GraphEdge(source=u, target=v, kind=d["kind"], count=len(d["event_ids"]), event_ids=d["event_ids"])
        for u, v, d in g.edges(data=True)
    ]
    return AgentGraph(run_id=run_id, nodes=nodes, edges=edges)
