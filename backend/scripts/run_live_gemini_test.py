"""First Live Gemini Integration Test Runner for SwarmGuard Member 1.

Runs 5 agents on the 'normal_collaboration' scenario with the real Gemini backend.
Enforces a hard limit of at most 5 Gemini API requests.
Tracks genuine LLM responses vs fallbacks, tool selections, and gateway decisions.
Exports canonical 12-field JSONL events.
"""
from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.adapters.gemini_adapter import GeminiAdapter, get_quota_tracker, mask_secret
from app.config import get_settings
from app.modules.simulator.engine import ScenarioConfig, export_events_jsonl, run_simulation
from app.schemas import RawEvent

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("live_gemini_test")


class TrackingGeminiAdapter(GeminiAdapter):
    """Subclass to instrument and record exact call details for auditing."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.call_records: list[dict] = []

    def compose_message(self, sender_role: str, recipient_role: str, intent: str, topic: str) -> str:
        calls_before = self.calls_left
        quota_before = self.quota_tracker.daily_calls_used
        result = super().compose_message(sender_role, recipient_role, intent, topic)
        quota_after = self.quota_tracker.daily_calls_used

        is_genuine = (quota_after > quota_before)
        record = {
            "type": "compose_message",
            "sender_role": sender_role,
            "recipient_role": recipient_role,
            "intent": intent,
            "topic": topic,
            "content": result,
            "genuine_gemini": is_genuine,
            "calls_left": self.calls_left,
        }
        self.call_records.append(record)
        return result


def main() -> int:
    print("=" * 70)
    print("  SWARMGUARD - First Live Gemini Multi-Agent Integration Test")
    print("=" * 70)

    # 1. Verify Configuration & Environment
    settings = get_settings()
    api_key = os.getenv("GEMINI_API_KEY")
    model = os.getenv("GEMINI_MODEL") or settings.gemini_model

    print(f"Target Model:          {model}")
    print(f"GEMINI_API_KEY Found:  {'YES' if api_key else 'NO'}")
    print(f"Masked Key:            {mask_secret(api_key)}")
    print(f"Max Allowed Calls:     5 (strictly enforced)")
    print("-" * 70)

    if not api_key:
        print("[!] ERROR: GEMINI_API_KEY is not configured. Aborting.")
        return 1

    # 2. Instantiate Instrumented Adapter with max_calls=5
    adapter = TrackingGeminiAdapter(
        api_key=api_key,
        model=model,
        max_calls=5,
        timeout=20.0,
    )

    quota = get_quota_tracker()
    quota_start = quota.daily_calls_used
    print(f"Starting Quota:        {quota_start} / {quota.daily_budget} daily calls used")

    # 3. Configure Scenario: 5 agents, normal_collaboration
    config = ScenarioConfig(
        scenario_id="normal_collaboration",
        agent_count=5,
        seed=42,
        gateway_mode="enforce",
        drop_rate=0.0,
        agent_backend="gemini",
    )

    print(f"Running simulation: scenario={config.scenario_id}, agents={config.agent_count}, seed={config.seed}...")
    sim_result = run_simulation(config, adapter=adapter)

    quota_end = quota.daily_calls_used
    actual_api_calls = quota_end - quota_start

    print("-" * 70)
    print("  SIMULATION COMPLETED SUCCESSFULLY")
    print("-" * 70)
    print(f"Run ID:                {sim_result.run.run_id}")
    print(f"Total Agents:          {len(sim_result.agents)}")
    print(f"Total Raw Events:      {len(sim_result.events)}")
    print(f"Actual Gemini Calls:   {actual_api_calls} (limit was 5)")
    print(f"Fallback Calls:        {len(adapter.call_records) - actual_api_calls}")
    print(f"Total Message Actions: {len(adapter.call_records)}")
    print("-" * 70)

    # 4. Detail each call
    print("Detailed Message Breakdown:")
    genuine_count = 0
    fallback_count = 0
    for idx, rec in enumerate(adapter.call_records, start=1):
        status_tag = "[GENUINE GEMINI]" if rec["genuine_gemini"] else "[DETERMINISTIC FALLBACK]"
        if rec["genuine_gemini"]:
            genuine_count += 1
        else:
            fallback_count += 1
        print(f"  {idx}. {status_tag} {rec['sender_role']} -> {rec['recipient_role']}")
        print(f"     Intent:  {rec['intent']}, Topic: {rec['topic']}")
        print(f"     Content: \"{rec['content']}\"")

    print("-" * 70)
    print("Agent Activities & Policy Gateway Check:")
    tool_events = [e for e in sim_result.events if e.event_type == "tool_call"]
    access_events = [e for e in sim_result.events if e.event_type == "file_access"]
    msg_send_events = [e for e in sim_result.events if e.event_type == "message" and e.action == "send"]
    msg_recv_events = [e for e in sim_result.events if e.event_type == "message" and e.action == "receive"]
    gateway_events = [e for e in sim_result.events if e.gateway_decision is not None]

    print(f"  - Message Sends:     {len(msg_send_events)}")
    print(f"  - Message Receives:  {len(msg_recv_events)}")
    print(f"  - Tool Calls:        {len(tool_events)}")
    print(f"  - Resource Accesses: {len(access_events)}")
    print(f"  - Gateway Checks:    {len(gateway_events)}")

    # 5. Export canonical 12-field JSONL
    out_dir = backend_dir.parent / "fixtures"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "live_gemini_events.jsonl"
    jsonl_output = export_events_jsonl(sim_result, destination=out_path)

    print(f"\nCanonical JSONL Exported: {out_path}")
    print(f"Lines exported: {len(jsonl_output.strip().splitlines())}")

    # Validate first line schema
    first_line = json.loads(jsonl_output.strip().splitlines()[0])
    print(f"First event fields: {list(first_line.keys())}")
    print("=" * 70)

    # Verification Assertions
    assert actual_api_calls <= 5, f"Exceeded maximum 5 Gemini API calls: {actual_api_calls}"
    assert genuine_count > 0, "No genuine Gemini responses received!"
    assert len(msg_recv_events) == len(msg_send_events), "Mismatch between send and receive events"
    print("[+] All verification assertions passed successfully!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
