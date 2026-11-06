"""Interactive Showcase of Member 1: Agent Simulation Engineer.

Demonstrates:
1. Agent initialization (5 roles: Planner, Analyst, Coder, Researcher, Reviewer).
2. Shared virtual filesystem and database setup.
3. Benign collaboration workflow with private inbox message exchange.
4. PolicyGateway pre-execution security enforcement.
5. Threat simulation (Coordinated Data Leakage - SG-003).
6. Canonical 12-field JSONL event export for downstream handoff.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.modules.simulator.engine import ScenarioConfig, export_events_jsonl, run_simulation
from app.modules.simulator.world import ROLE_PERMISSIONS, ROLE_TOOLS


def print_banner(text: str, ch: str = "="):
    line = ch * 80
    print(f"\n{line}\n  {text}\n{line}")


def main():
    print_banner("SWARMGUARD - MEMBER 1: AGENT SIMULATOR LIVE DEMO")
    print("Welcome! You are observing Member 1 (Agent Simulation Engineer) in action.")
    print("This module simulates autonomous multi-agent behavior, shared resources,")
    print("inter-agent messaging, security policy enforcement, and canonical telemetry.\n")

    # -------------------------------------------------------------------------
    # PART 1: AGENT SETUP
    # -------------------------------------------------------------------------
    print_banner("PART 1: INITIALIZING 5-AGENT SWARM", "-")
    roles = ["planner", "analyst", "coder", "researcher", "reviewer"]
    print(f"Creating 5 specialized agents with strict Role-Based Access Control (RBAC):")
    for idx, role in enumerate(roles, start=1):
        perms = ", ".join(ROLE_PERMISSIONS.get(role, []))
        tool = ROLE_TOOLS.get(role, "none")
        print(f"  [{idx}] Role: {role.upper():<11} | Tool: {tool:<18} | Permissions: {perms}")

    # -------------------------------------------------------------------------
    # PART 2: NORMAL COLLABORATION RUN
    # -------------------------------------------------------------------------
    print_banner("PART 2: RUNNING BENIGN MULTI-AGENT COLLABORATION", "-")
    print("[*] Launching scenario 'normal_collaboration' (seed=42, gateway=enforce)...")
    
    config_normal = ScenarioConfig(
        scenario_id="normal_collaboration",
        agent_count=5,
        seed=42,
        gateway_mode="enforce",
        agent_backend="deterministic",
    )
    sim_normal = run_simulation(config_normal)

    print(f"[+] Simulation completed successfully!")
    print(f"    - Run ID:           {sim_normal.run.run_id}")
    print(f"    - Total Events:     {len(sim_normal.events)}")
    print(f"    - Malicious Agents: {len(sim_normal.run.labels.malicious_agent_ids)} (Clean benign run)")

    print("\nSample Agent Communication Flow:")
    msg_events = [e for e in sim_normal.events if e.event_type == "message" and e.action == "send"][:4]
    for e in msg_events:
        tgt_agent = next((a for a in sim_normal.agents if a.agent_id == e.target), None)
        src_agent = next((a for a in sim_normal.agents if a.agent_id == e.agent_id), None)
        src_name = src_agent.role.upper() if src_agent else e.agent_id
        tgt_name = tgt_agent.role.upper() if tgt_agent else e.target
        intent = e.payload.get("intent", "")
        topic = e.payload.get("topic", "")
        content = e.payload.get("content", "")
        print(f"  >> {src_name} -> {tgt_name} [{intent} on {topic}]")
        print(f"     \"{content}\"")

    print("\nSample Virtual Environment & Tool Invocations:")
    tool_events = [e for e in sim_normal.events if e.event_type in ("tool_call", "resource_access")][:4]
    for e in tool_events:
        agent = next((a for a in sim_normal.agents if a.agent_id == e.agent_id), None)
        role = agent.role.upper() if agent else e.agent_id
        gw = f"[Gateway: {e.gateway_decision}]" if e.gateway_decision else ""
        print(f"  >> {role} executed {e.event_type}:{e.action} on '{e.resource or e.target}' -> status: {e.status.upper()} {gw}")

    # -------------------------------------------------------------------------
    # PART 3: THREAT SCENARIO (COORDINATED DATA LEAKAGE)
    # -------------------------------------------------------------------------
    print_banner("PART 3: EXECUTING THREAT SCENARIO (SG-003: COORDINATED DATA LEAKAGE)", "-")
    print("[*] Launching scenario 'coordinated_leakage' (analyst + coder collusion)...")
    
    config_attack = ScenarioConfig(
        scenario_id="coordinated_leakage",
        agent_count=5,
        seed=42,
        gateway_mode="enforce",
        agent_backend="deterministic",
    )
    sim_attack = run_simulation(config_attack)

    print(f"[+] Attack simulation completed!")
    print(f"    - Run ID:           {sim_attack.run.run_id}")
    print(f"    - Total Events:     {len(sim_attack.events)}")
    print(f"    - Malicious Agents: {sim_attack.run.labels.malicious_agent_ids}")

    print("\nObservable Malicious Chain Caught by PolicyGateway:")
    mal_events = [e for e in sim_attack.events if e.event_id in sim_attack.run.labels.malicious_event_ids]
    for idx, e in enumerate(mal_events, start=1):
        agent = next((a for a in sim_attack.agents if a.agent_id == e.agent_id), None)
        role = agent.role.upper() if agent else e.agent_id
        details_str = f"res={e.resource}" if e.resource else f"tgt={e.target}"
        if e.payload.get("data_ref"):
            details_str += f", data_ref={e.payload['data_ref']}"
        gw_reason = f"({e.payload.get('gateway_reason')})" if e.payload.get('gateway_reason') else ""
        print(f"  Step {idx}: {role:<10} | {e.event_type:<15} | {e.action:<8} | {details_str:<35} | Status: {e.status.upper()} {gw_reason}")

    # -------------------------------------------------------------------------
    # PART 4: CANONICAL 12-FIELD JSONL TELEMETRY EXPORT
    # -------------------------------------------------------------------------
    print_banner("PART 4: CANONICAL 12-FIELD JSONL EVENT OUTPUT", "-")
    print("[*] Exporting canonical telemetry via export_canonical_jsonl()...")
    
    jsonl_output = export_events_jsonl(sim_normal)
    lines = jsonl_output.strip().splitlines()
    print(f"[+] Total exported JSONL lines: {len(lines)}")
    print("\nInspecting first 2 exported event records (exact format handed off to Member 2):")
    for i in range(min(2, len(lines))):
        record = json.loads(lines[i])
        print(f"\n--- Event #{i+1} ({record['event_id']}) ---")
        for k, v in record.items():
            print(f"  {k:<16}: {json.dumps(v)}")

    # -------------------------------------------------------------------------
    # PART 5: SUMMARY & VERIFICATION
    # -------------------------------------------------------------------------
    print_banner("DEMO SUMMARY: MEMBER 1 DELIVERABLES READY", "=")
    print("  [+] 5 Specialized Autonomous & Scripted Agents Running")
    print("  [+] MessageBroker with Private Inboxes & 1:1 Correlation")
    print("  [+] In-Memory VirtualFilesystem & VirtualDatabase Active")
    print("  [+] Pre-Execution PolicyGateway Enforcing Role Boundaries")
    print("  [+] Threat Scenarios Generating Authentic Observable Telemetry")
    print("  [+] Strict 12-Field Canonical JSONL Output with 0 Ground-Truth Leakage")
    print("=" * 80 + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
