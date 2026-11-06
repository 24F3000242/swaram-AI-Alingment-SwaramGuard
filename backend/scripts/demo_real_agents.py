"""Real-agent demo: model-driven agents on an outside platform, SwarmGuard enforcing at the network.

Offline, everything in one process (stand-in model that falls for the attack):

    python scripts/demo_real_agents.py --local
    python scripts/demo_real_agents.py --local --attack internal_goal

Against a running server, with real Gemini agents, shown live in the UI. Start the server with the proxy on:

    SWARMGUARD_EGRESS_PROXY_PORT=8899 SWARMGUARD_EGRESS_ALLOW=approved-partner-api \\
    SWARMGUARD_EGRESS_RESOLVE=*=127.0.0.1:9900 uvicorn app.main:app --port 8000

then (the script starts the "outside world" on port 9900):

    python scripts/demo_real_agents.py --backend gemini --attack poisoned_ticket

Attacks: poisoned_ticket, dsar (injections), internal_goal (no attacker). --use-gate makes the platform ask the gate
too; by default it doesn't, so only the network stops anything. With SWARMGUARD_API_KEYS on, pass an agent key with
--agent-key. About 6 model calls per run.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services.agent_demo import ATTACKS, OutsideWorld, Platform, ScriptedModel, run_local  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--attack", choices=sorted(ATTACKS), default="poisoned_ticket")
    ap.add_argument("--backend", default="scripted", help="scripted, gemini, openai or ollama")
    ap.add_argument("--local", action="store_true", help="run API, proxy and outside world in this process")
    ap.add_argument("--server", default="http://127.0.0.1:8000")
    ap.add_argument("--proxy", default="http://127.0.0.1:8899")
    ap.add_argument("--world-port", type=int, default=9900, help="where the outside world listens (server mode)")
    ap.add_argument("--agent-key", default=None)
    ap.add_argument("--use-gate", action="store_true")
    ap.add_argument("--rounds", type=int, default=2)
    args = ap.parse_args()

    if args.backend == "scripted":
        adapter = ScriptedModel()
    else:
        from app.adapters import get_adapter
        from app.config import get_settings

        get_settings()
        adapter = get_adapter(args.backend)
    if args.local:
        res, _ = run_local(adapter, args.attack, args.rounds)
    else:
        import httpx

        world = OutsideWorld(args.world_port)
        try:
            with httpx.Client(base_url=args.server, timeout=120) as api:
                res = Platform(api, args.proxy, adapter, args.agent_key, args.use_gate).run(args.attack, args.rounds)
        finally:
            world.close()
        res.received, res.leaked = list(world.received), world.leaked()
    print("\n" + res.summary())


if __name__ == "__main__":
    main()
