"""Validation script for all scenarios in SwarmGuard Member 1.

Runs normal_collaboration, coordinated_leakage, and sg001..sg020 in deterministic mode.
Validates:
1. Scenario execution and agent roles.
2. Canonical JSONL 12-field schema compliance.
3. Separation of ground truth labels from events.
4. Observable malicious actions vs empty simulations.
5. Ingestion by downstream collector and detection rules.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.modules.collector.normalizer import collect
from app.modules.detection.advanced_rules import ADVANCED_RULES
from app.modules.detection.control_rules import CONTROL_RULES
from app.modules.detection.rules import DEFAULT_RULES, run_rules
from app.modules.simulator.engine import ScenarioConfig, export_events_jsonl, run_simulation
from app.modules.simulator.scenarios import SCENARIO_ATTACKS, SCENARIOS_BY_ID
from app.services.pipeline import Pipeline
from app.storage.sqlite_store import SQLiteStore

ALL_RULES = DEFAULT_RULES + CONTROL_RULES + ADVANCED_RULES

SCENARIO_LIST = [
    "normal_collaboration",
    "coordinated_leakage",
    "sg001_unauthorized_access",
    "sg002_external_leak",
    "sg003_leak_chain",
    "sg004_role_anomaly",
    "sg005_dead_drop",
    "sg006_oversight_tampering",
    "sg007_self_replication",
    "sg008_privilege_escalation",
    "sg009_honeytoken_tripwire",
    "sg010_log_tampering",
    "sg011_power_seeking",
    "sg012_prompt_injection",
    "sg013_cascading_failures",
    "sg014_false_reporting",
    "sg015_reward_hacking",
    "sg016_salami_leakage",
    "sg017_human_coercion",
    "sg018_message_loops",
    "sg019_untrusted_tools",
    "sg020_steganography",
]

REQUIRED_12_FIELDS = [
    "schema_version",
    "event_id",
    "run_id",
    "agent_id",
    "timestamp",
    "event_type",
    "action",
    "target",
    "resource",
    "status",
    "source",
    "details",
]


def test_scenario(sid: str) -> dict:
    config = ScenarioConfig(
        scenario_id=sid,
        agent_count=5,
        seed=42,
        gateway_mode="enforce",
        agent_backend="deterministic",
    )
    sim = run_simulation(config)
    
    # 1. Check agents
    agents = sim.agents
    agent_ids = {a.agent_id for a in agents}
    roles = {a.role for a in agents}
    
    # 2. Check JSONL export
    jsonl_str = export_events_jsonl(sim)
    lines = [json.loads(line) for line in jsonl_str.strip().splitlines() if line.strip()]
    
    schema_ok = True
    ids_ok = True
    timestamps_ok = True
    no_labels_leak = True
    
    seen_ids = set()
    for row in lines:
        if list(row.keys()) != REQUIRED_12_FIELDS:
            schema_ok = False
        if row["event_id"] in seen_ids or not row["event_id"].startswith("evt-"):
            ids_ok = False
        seen_ids.add(row["event_id"])
        if row["run_id"] != sim.run.run_id:
            ids_ok = False
        if "is_malicious" in row or "labels" in row or "malicious_event_ids" in row:
            no_labels_leak = False
        if "details" in row and ("is_malicious" in row["details"] or "malicious" in row["details"]):
            no_labels_leak = False

    # 3. Check ground-truth labels presence in Run
    labels = sim.run.labels
    mal_agents = labels.malicious_agent_ids
    mal_events = labels.malicious_event_ids
    
    # 4. Check observable malicious actions
    malicious_event_objs = [e for e in sim.events if e.event_id in mal_events]
    observable_actions = [
        f"{e.event_type}:{e.action} (res={e.resource}, tgt={e.target}, status={e.status})"
        for e in malicious_event_objs
    ]
    
    # 5. Downstream collector test
    collector_res = collect([e.model_dump() for e in sim.events], run_id=sim.run.run_id, agents=sim.agents)
    collector_errors = len(collector_res.report.errors)
    normalized_events = collector_res.events
    
    # 6. Downstream detector test
    # A) All untuned rules
    alerts_raw = run_rules(sim.run.run_id, normalized_events, sim.agents, ALL_RULES)
    alert_rules_raw = sorted({a.rule_id for a in alerts_raw})
    
    # B) Trained Pipeline rules (includes synthetic baseline for SG-004)
    pipe = Pipeline(SQLiteStore(":memory:"))
    trained_rules = pipe.rules()
    alerts_trained = run_rules(sim.run.run_id, normalized_events, sim.agents, trained_rules)
    alerts_trained_rules = sorted({a.rule_id for a in alerts_trained})
    
    # Combined effective alerts
    combined_alerts = sorted(set(alert_rules_raw) | set(alerts_trained_rules))
    
    # Summary
    has_observable_actions = len(malicious_event_objs) > 0 or sid == "normal_collaboration"
    passed = schema_ok and ids_ok and no_labels_leak and (collector_errors == 0) and has_observable_actions

    return {
        "scenario_id": sid,
        "pass": passed,
        "total_events": len(sim.events),
        "malicious_agents": mal_agents,
        "malicious_events_count": len(mal_events),
        "observable_actions": observable_actions,
        "collector_errors": collector_errors,
        "alerts_fired": combined_alerts,
        "schema_ok": schema_ok,
        "no_labels_leak": no_labels_leak,
    }


def main():
    print("=" * 100)
    print("  SWARMGUARD - Complete Scenario & Downstream Pipeline Validation")
    print("=" * 100)
    
    results = []
    for sid in SCENARIO_LIST:
        res = test_scenario(sid)
        results.append(res)
        status_sym = "[PASS]" if res["pass"] else "[FAIL]"
        alerts_str = ",".join(res["alerts_fired"]) if res["alerts_fired"] else "None"
        print(f"{status_sym} {sid:<28} Events: {res['total_events']:<3} MalAgts: {len(res['malicious_agents']):<2} Alerts: {alerts_str}")
        if not res["pass"]:
            print(f"     FAILED CHECKS: schema={res['schema_ok']}, collector_errs={res['collector_errors']}, no_leak={res['no_labels_leak']}")

    print("=" * 100)
    all_passed = all(r["pass"] for r in results)
    print(f"Overall Scenario Status: {'ALL PASSED' if all_passed else 'SOME FAILED'}")

    # Print markdown table format for final report
    print("\n\n### SCENARIO OBSERVABILITY AND PIPELINE VALIDATION TABLE\n")
    print("| Scenario ID | Name / Threat | Verdict | Total Evts | Malicious Evts | Observable Actions Generated | Downstream Alerts |")
    print("|---|---|---|---|---|---|---|")
    for r in results:
        sid = r["scenario_id"]
        scen_obj = SCENARIOS_BY_ID.get(sid)
        name = scen_obj.name if scen_obj else sid
        obs = "; ".join(r["observable_actions"][:2]) if r["observable_actions"] else "Benign collaborative actions only"
        if len(r["observable_actions"]) > 2:
            obs += f" (+{len(r['observable_actions']) - 2} more)"
        alerts = ", ".join(r["alerts_fired"]) if r["alerts_fired"] else "None"
        verdict = "**PASS**" if r["pass"] else "**FAIL**"
        print(f"| `{sid}` | {name} | {verdict} | {r['total_events']} | {r['malicious_events_count']} | {obs} | `{alerts}` |")

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
