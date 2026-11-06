"""Agent simulator module for SwarmGuard."""
from app.modules.simulator.agent import SimulatedAgent
from app.modules.simulator.broker import (
    AgentInbox,
    DeliveryResult,
    Message,
    MessageBroker,
    get_broker,
    reset_brokers,
)
from app.modules.simulator.engine import AgentRunner, export_events_jsonl, run_simulation
from app.modules.simulator.environment import (
    ENVIRONMENT_REGISTRY,
    SharedEnvironment,
    VirtualDatabase,
    VirtualFile,
    VirtualFilesystem,
    get_environment,
    reset_environments,
)
from app.modules.simulator.export import (
    CANONICAL_FIELDS,
    CANONICAL_SCHEMA_VERSION,
    determine_source,
    export_canonical_jsonl,
    from_canonical_event,
    parse_canonical_jsonl,
    to_canonical_event,
    to_canonical_events,
)
from app.modules.simulator.gateway import GatewayResult, PolicyGateway
from app.modules.simulator.scenarios import (
    SCENARIO_ATTACKS,
    SCENARIOS,
    SCENARIOS_BY_ID,
)
from app.modules.simulator.tools import ToolRegistry, ToolResult

__all__ = [
    "AgentInbox",
    "AgentRunner",
    "CANONICAL_FIELDS",
    "CANONICAL_SCHEMA_VERSION",
    "DeliveryResult",
    "ENVIRONMENT_REGISTRY",
    "GatewayResult",
    "Message",
    "MessageBroker",
    "PolicyGateway",
    "SCENARIOS",
    "SCENARIOS_BY_ID",
    "SCENARIO_ATTACKS",
    "SharedEnvironment",
    "SimulatedAgent",
    "ToolRegistry",
    "ToolResult",
    "VirtualDatabase",
    "VirtualFile",
    "VirtualFilesystem",
    "determine_source",
    "export_canonical_jsonl",
    "export_events_jsonl",
    "from_canonical_event",
    "get_broker",
    "get_environment",
    "parse_canonical_jsonl",
    "reset_brokers",
    "reset_environments",
    "run_simulation",
    "to_canonical_event",
    "to_canonical_events",
]
