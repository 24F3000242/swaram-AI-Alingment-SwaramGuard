#!/usr/bin/env python3
"""Run a User-Directed Autonomous Multi-Agent Simulation with Gemini Reasoning.

Allows a user to specify any custom task via CLI argument or interactive prompt.
Five AI agents (Planner, Researcher, Analyst, Coder, Reviewer) collaborate to complete it
using the shared filesystem, shared database, message broker, and policy gateway.
"""
from __future__ import annotations

import argparse
import os
import sys
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
import time
from pathlib import Path

# Add backend directory to path
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

from dotenv import load_dotenv

# Load local environment variables from .env
env_file = backend_dir.parent / ".env"
if env_file.exists():
    load_dotenv(env_file)
else:
    load_dotenv()

from app.adapters import get_adapter
from app.adapters.gemini_adapter import GeminiAdapter, get_quota_tracker, mask_secret
from app.modules.simulator.engine import export_events_jsonl, run_simulation
from app.schemas import GatewayMode, ScenarioConfig


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run an autonomous multi-agent simulation on a user-directed task."
    )
    parser.add_argument(
        "--task",
        "-t",
        type=str,
        default=None,
        help="Task description for the multi-agent swarm to complete.",
    )
    parser.add_argument(
        "--backend",
        "-b",
        choices=["gemini", "deterministic"],
        default="gemini",
        help="Backend to power agent reasoning (default: gemini).",
    )
    parser.add_argument(
        "--gateway-mode",
        "-g",
        choices=["enforce", "monitor", "off"],
        default="enforce",
        help="Policy gateway enforcement mode (default: enforce).",
    )
    parser.add_argument(
        "--max-calls",
        type=int,
        default=8,
        help="Maximum Gemini API calls permitted for this run (default: 8, max 10).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Gemini request timeout in seconds (default: 45.0s, or GEMINI_TIMEOUT env var).",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=None,
        help="Maximum retries for transient 504/503 errors (default: 3).",
    )
    parser.add_argument(
        "--workspace",
        "-w",
        type=str,
        default=None,
        help="Optional custom directory for persistent disk workspace.",
    )
    parser.add_argument(
        "--export",
        "-e",
        type=str,
        default=None,
        help="Optional custom export path for canonical JSONL events.",
    )
    return parser.parse_args()


def print_banner(task: str, backend: str, model: str, gateway_mode: str) -> None:
    print("=" * 78)
    print("           SWARMGUARD -- USER-DIRECTED AUTONOMOUS MULTI-AGENT SWARM")
    print("=" * 78)
    print(f"Task:         {task}")
    print(f"Backend:      {backend.upper()} (Model: {model})")
    print(f"Gateway Mode: {gateway_mode.upper()} (Zero-trust policy enforcement)")
    print(f"Agents:       Planner, Researcher, Analyst, Coder, Reviewer")
    print("=" * 78)
    print()


def main() -> int:
    args = parse_args()

    # 1. Obtain user task
    user_task = args.task
    if not user_task:
        print("=" * 78)
        print("Enter the task you want the 5-agent team to collaborate on.")
        print("Example: 'Create a rate-limiting middleware with sliding window algorithms and unit tests'")
        print("=" * 78)
        try:
            user_task = input("\nEnter your task: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            return 1

    if not user_task:
        print("[!] No task provided. Exiting.")
        return 1

    backend = args.backend
    configured_model = os.getenv("GEMINI_MODEL", "gemini-3.5-flash")
    api_key = os.getenv("GEMINI_API_KEY")

    if backend == "gemini":
        if not api_key:
            print("[ERROR] GEMINI_API_KEY is not set in .env!")
            print("Configure GEMINI_API_KEY in your local .env or specify --backend deterministic.")
            return 1
        print(f"[*] Initializing Gemini adapter with model '{configured_model}' (API Key: {mask_secret(api_key)})")

    print_banner(user_task, backend, configured_model if backend == "gemini" else "N/A", args.gateway_mode)

    # 2. Configure adapter
    max_calls = min(max(1, args.max_calls), 10)
    adapter = None
    if backend == "gemini":
        try:
            timeout = args.timeout if args.timeout is not None else float(os.getenv("GEMINI_TIMEOUT", "45.0"))
            max_retries = args.max_retries if args.max_retries is not None else int(os.getenv("GEMINI_MAX_RETRIES", "3"))
            adapter = GeminiAdapter(
                api_key=api_key,
                model=configured_model,
                max_calls=max_calls,
                timeout=timeout,
                max_retries=max_retries,
            )
            # Minimal Gemini connection test
            print(f"[*] Probing Gemini connection (Model: {configured_model}, Timeout: {timeout}s, Retries: {max_retries})...")
            conn = adapter.verify_connection()
            if not conn.get("ok") and not conn.get("connected"):
                print(f"[ERROR] Gemini connection probe failed: {conn.get('error')}")
                print(f"    Status: {conn.get('status')} | Attempts: {conn.get('attempts', 1)}")
                return 1
            print(f"[OK] Gemini connection verified: {configured_model} (Latency: {conn.get('latency_ms', 'N/A')}ms, Response: '{conn.get('response', '')}')")
        except Exception as exc:
            print(f"[ERROR] Failed to initialize Gemini adapter: {exc}")
            return 1
    else:
        adapter = get_adapter("deterministic")

    # 3. Configure run and scenario
    config = ScenarioConfig(
        scenario_id="user_directed",
        agent_count=5,
        gateway_mode=args.gateway_mode,
        agent_backend=backend,
        user_task=user_task,
        workspace_dir=args.workspace,
    )

    print(f"\n[*] Starting collaborative execution...")
    start_time = time.time()

    try:
        sim_result = run_simulation(config, adapter=adapter)
    except Exception as exc:
        print(f"\n[ERROR] Simulation run failed: {exc}")
        import traceback
        traceback.print_exc()
        return 1

    elapsed = time.time() - start_time
    run_id = sim_result.run.run_id
    workspace_path = Path(args.workspace) if args.workspace else Path("runs") / run_id / "workspace"

    print("\n" + "=" * 78)
    print("                   CHRONOLOGICAL EXECUTION AUDIT LOG")
    print("=" * 78)

    # Display chronological agent actions
    for event in sim_result.events:
        agent_id = event.agent_id
        action = event.action
        event_type = event.event_type
        status = event.status
        resource = event.resource or event.target or ""
        gw = f" [GW: {event.gateway_decision}]" if event.gateway_decision and event.gateway_decision != "not_checked" else ""
        
        detail = ""
        if event_type == "message":
            intent = event.payload.get("intent", "")
            target = event.target or ""
            content_preview = str(event.payload.get("content", ""))[:65].replace("\n", " ")
            detail = f"-> {target} ({intent}): \"{content_preview}...\""
        elif event_type == "resource_access":
            detail = f"{action.upper()} {resource}"
        elif event_type == "task":
            phase = event.payload.get("phase") or event.payload.get("stage") or ""
            detail = f"TASK {action.upper()} ({phase})"
        elif event_type == "tool_call":
            detail = f"EXEC {resource}"
        else:
            detail = f"{event_type}:{action} {resource}"

        status_tag = f"[{status.upper()}]"
        print(f" {event.timestamp[11:19]} | {agent_id:<14} | {status_tag:<9} | {detail}{gw}")

    # Display shared database state
    print("\n" + "=" * 78)
    print("                   SHARED VIRTUAL DATABASE RECORDS")
    print("=" * 78)
    from app.modules.simulator.environment import ENVIRONMENT_REGISTRY
    env = ENVIRONMENT_REGISTRY.get(run_id)
    if env and env.db:
        for tbl_name, rows in env.db._tables.items():
            if rows:
                print(f"\nTable: {tbl_name} ({len(rows)} records)")
                for r_id, row in rows.items():
                    filtered_row = {k: v for k, v in row.items() if not k.startswith("_")}
                    print(f"  - [{r_id}]: {filtered_row}")

    # Display persistent workspace deliverables
    print("\n" + "=" * 78)
    print("                 SHARED PERSISTENT WORKSPACE DELIVERABLES")
    print("=" * 78)
    print(f"Workspace Directory: {workspace_path.resolve()}\n")

    deliverable_paths = [
        "docs/wiki/plan.md",
        "docs/wiki/research_notes.md",
        "data/public/analysis_report.json",
        "repo/src/solution.py",
        "repo/src/test_solution.py",
        "docs/wiki/review_report.md",
        "docs/wiki/final_summary.md",
    ]

    for rel_path in deliverable_paths:
        disk_file = workspace_path / rel_path
        if disk_file.is_file():
            size = disk_file.stat().st_size
            print(f"[FILE SAVED] {rel_path} ({size} bytes)")
            # Print preview
            try:
                content = disk_file.read_text(encoding="utf-8")
                lines = content.strip().splitlines()
                preview = "\n".join("    | " + line for line in lines[:8])
                print(preview)
                if len(lines) > 8:
                    print(f"    | ... ({len(lines) - 8} more lines)")
            except Exception as e:
                print(f"    [Error reading: {e}]")
            print()
        else:
            print(f"[MISSING] {rel_path}")

    # Export canonical JSONL events
    export_path = Path(args.export) if args.export else Path("runs") / run_id / "canonical_events.jsonl"
    export_path.parent.mkdir(parents=True, exist_ok=True)
    export_events_jsonl(sim_result, export_path)

    # Print summary statistics
    quota = get_quota_tracker().status() if backend == "gemini" else {}
    print("=" * 78)
    print("                              RUN SUMMARY")
    print("=" * 78)
    print(f"Run ID:                {run_id}")
    print(f"Execution Time:        {elapsed:.2f}s")
    print(f"Canonical Events:      {len(sim_result.events)} exported to {export_path}")
    print(f"Policy Gateway Checks: {sum(1 for e in sim_result.events if e.gateway_decision is not None)}")
    if backend == "gemini":
        calls_used = max_calls - (adapter.calls_left if adapter else 0)
        print(f"Gemini API Calls Used: {calls_used}/{max_calls}")
        print(f"Daily Quota Remaining: {quota.get('daily_calls_remaining', 'N/A')}/{quota.get('daily_budget', 'N/A')}")
    final_event = next((e for e in reversed(sim_result.events) if "deliverables" in e.payload), None)
    final_status = final_event.payload.get("status", "unknown").upper() if final_event else "UNKNOWN"
    final_verdict = final_event.payload.get("verdict", "") if final_event else ""
    verdict_suffix = f" (Verdict: {final_verdict})" if final_verdict else ""
    print(f"Task Final Status:     {final_status}{verdict_suffix}")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    sys.exit(main())
