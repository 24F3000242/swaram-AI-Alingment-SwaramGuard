"""Shared data contracts for every SwarmGuard module.

These Pydantic models are the single source of truth. The TypeScript interfaces
in `frontend/src/types.ts` mirror them field-for-field; keep both in sync.
"""
from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------
EventType = Literal["message", "tool_call", "resource_access", "data_transfer", "task"]
EventStatus = Literal["success", "denied", "failed", "pending"]
# Decision recorded by the policy gateway that runs *before* a protected tool executes.
GatewayDecision = Literal["not_checked", "allow", "would_block", "blocked"]
GatewayMode = Literal["off", "monitor", "enforce"]
Severity = Literal["low", "medium", "high", "critical"]
ResponseDecision = Literal["allow", "alert", "block", "pause"]
ResponsePolicyMode = Literal["simulate", "enforce"]
# `blocked` is only ever recorded when the controlled gateway actually denied a request.
# contained = the live guard paused / held the agent mid-run (no later action needed denying); blocked = an action was
# actually denied before it executed.
ResponseOutcome = Literal["allowed", "alerted", "would_block", "would_pause", "blocked", "contained"]
AlertStatus = Literal["open", "responded", "contained"]

AGENT_COUNTS = (3, 5, 10, 20)


# ---------------------------------------------------------------------------
# Section 1: Agent Simulator
# ---------------------------------------------------------------------------
class Scenario(BaseModel):
    scenario_id: str
    name: str
    description: str
    malicious_roles: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    min_rounds: int = 2  # e.g. a sleeper injection needs a round to plant and a later one to trigger


class ScenarioConfig(BaseModel):
    """Input of the Agent Simulator."""

    scenario_id: str = "coordinated_leakage"
    agent_count: Literal[3, 5, 10, 20] = 5
    seed: int = 7
    gateway_mode: GatewayMode = "monitor"
    drop_rate: float = Field(0.0, ge=0.0, le=0.9, description="Fraction of events to drop (missing-data tests)")
    sensors: bool = Field(False, description="Also emit independent resource-side records (egress proxy, broker log, "
                          "resource/tool audit) for each executed action; dropped independently of the agent log")
    agent_backend: str = Field("deterministic", description="Adapter that writes message text")
    rounds: int = Field(2, ge=2, le=8, description="Work rounds; the attack or injection lands after round 1")
    agent_mode: Literal["scripted", "autonomous"] = Field(
        "scripted", description="scripted: fixed normal work; autonomous: each worker's model decides its actions")
    auto_pipeline: bool = Field(False, description="Run collect -> detect -> respond automatically")
    live_guard: Literal["off", "detect", "contain"] = Field(
        "off", description="Stream every event to Threat Detection as it happens; 'contain' also pauses risky agents")
    pause_at: float = Field(0.6, ge=0.2, le=0.99, description="Risk at which live containment pauses an agent")
    persist: bool = True
    user_task: Optional[str] = Field(None, description="User-provided task description for autonomous collaboration")
    workspace_dir: Optional[str] = Field(None, description="Path to persistent workspace directory on disk")


class Agent(BaseModel):
    agent_id: str
    run_id: str
    name: str
    role: str
    permissions: list[str]
    # Ground-truth label used only by the evaluation module, never by detection.
    is_malicious: bool = False


class RawEvent(BaseModel):
    run_id: str
    event_id: str
    agent_id: str
    timestamp: str | int | float
    event_type: str
    action: str
    status: str
    target: Optional[str] = None  # receiving agent or external destination
    resource: Optional[str] = None  # resource / tool touched by the action
    sequence: int = 0
    gateway_decision: Optional[str] = None
    payload: dict[str, Any] = Field(default_factory=dict)


class RunLabels(BaseModel):
    malicious_agent_ids: list[str] = Field(default_factory=list)
    malicious_event_ids: list[str] = Field(default_factory=list)


class Run(BaseModel):
    run_id: str
    scenario_id: str
    agent_count: int
    seed: int
    gateway_mode: GatewayMode
    drop_rate: float
    agent_backend: str
    agent_mode: str = "scripted"
    created_at: str
    base_time: str
    stages: dict[str, str] = Field(default_factory=dict)  # stage -> completed_at
    counts: dict[str, int] = Field(default_factory=dict)
    labels: RunLabels = Field(default_factory=RunLabels)
    dropped_event_ids: list[str] = Field(default_factory=list)
    log_anchor: Optional[str] = None  # hash-chain anchor of the collected log (collector/integrity.py)


class SimulationResult(BaseModel):
    run: Run
    agents: list[Agent]
    events: list[RawEvent]
    live_report: Optional["LiveReport"] = None


# ---------------------------------------------------------------------------
# Section 2: Event Collector
# ---------------------------------------------------------------------------
class NormalizedEvent(BaseModel):
    run_id: str
    event_id: str
    agent_id: str
    agent_role: Optional[str] = None
    timestamp: str  # ISO-8601 UTC, millisecond precision, `Z` suffix
    event_type: str
    action: str
    status: EventStatus
    target: Optional[str] = None
    resource: Optional[str] = None
    sequence: int = 0
    gateway_decision: GatewayDecision = "not_checked"
    payload: dict[str, Any] = Field(default_factory=dict)
    summary: str
    issues: list[str] = Field(default_factory=list)
    raw_hash: str  # hash of the event exactly as received (before redaction)
    raw: dict[str, Any]  # the event as received, with personal data redacted (see collector/privacy.py)
    normalized_at: str
    chain_hash: Optional[str] = None  # tamper-evident log: sha256(previous chain_hash + this event's content)


class CollectorIssue(BaseModel):
    index: int
    event_id: Optional[str] = None
    code: str
    message: str


class CollectionReport(BaseModel):
    run_id: Optional[str]
    total_input: int
    valid: int
    invalid: int
    duplicates: int
    warnings: list[CollectorIssue] = Field(default_factory=list)
    errors: list[CollectorIssue] = Field(default_factory=list)
    redactions: int = 0  # personal-data values replaced by pseudonyms
    ai: dict[str, int] = Field(default_factory=dict)  # events driven by an AI model: decisions, fallbacks, refusals, exposed
    log_anchor: Optional[str] = None  # last chain_hash: record it elsewhere to prove the log wasn't altered


class CollectRequest(BaseModel):
    run_id: Optional[str] = None
    events: Optional[list[Any]] = Field(None, description="Inline raw events; when omitted the stored raw events of run_id are used")
    persist: bool = True


class CollectionResult(BaseModel):
    report: CollectionReport
    events: list[NormalizedEvent]


# ---------------------------------------------------------------------------
# Section 3: Threat Detection
# ---------------------------------------------------------------------------
class DetectionRule(BaseModel):
    rule_id: str
    name: str
    description: str
    severity: Severity
    recommended_action: ResponseDecision
    enabled: bool = True
    params: dict[str, Any] = Field(default_factory=dict)


class EvidenceRef(BaseModel):
    event_id: str
    timestamp: str
    summary: str


class Alert(BaseModel):
    alert_id: str
    run_id: str
    rule_id: str
    rule_name: str
    severity: Severity
    agent_ids: list[str]
    event_ids: list[str]
    resource: Optional[str] = None
    reason: str
    recommended_action: ResponseDecision
    status: AlertStatus = "open"
    evidence: list[EvidenceRef] = Field(default_factory=list)
    created_at: str


class GraphNode(BaseModel):
    id: str
    kind: Literal["agent", "external"]
    role: Optional[str] = None
    flagged: bool = False
    event_count: int = 0
    degree_centrality: float = 0.0
    betweenness: float = 0.0


class GraphEdge(BaseModel):
    source: str
    target: str
    kind: Literal["message", "data_transfer", "indirect"]  # indirect = hidden hand-off via shared storage (SG-005)
    count: int
    event_ids: list[str]


class AgentGraph(BaseModel):
    run_id: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class RareBehavior(BaseModel):
    behavior: str
    p: float  # estimated P(an agent of this role shows the behavior)
    bits: float  # surprise, -log2(p)
    event_ids: list[str]


class Hypothesis(BaseModel):
    hypothesis: str
    label: str
    score: float  # normalized plausibility across the candidate explanations
    supporting: list[str]


class AgentAssessment(BaseModel):
    """Per-agent verdict combining System-1 anomaly and System-2 rule evidence."""

    run_id: str
    agent_id: str
    role: Optional[str] = None
    prior: float
    risk: float  # Bayesian posterior P(agent is acting maliciously | evidence)
    level: Literal["low", "watch", "high", "critical"]
    anomaly_bits: float
    rare_behaviors: list[RareBehavior] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)  # factors that moved the risk, with likelihood ratios
    alert_ids: list[str] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    best_explanation: Optional[str] = None


class AuditItem(BaseModel):
    """One action picked for human / trusted-model review (AI-control style audit budget). Not an alert."""

    event_id: str
    agent_id: str
    role: Optional[str] = None
    timestamp: str
    summary: str
    priority: float  # 0..1, higher = review first
    reasons: list[str]


class DetectRequest(BaseModel):
    run_id: str
    persist: bool = True


class DetectionResult(BaseModel):
    run_id: str
    alerts: list[Alert]
    graph: AgentGraph
    assessments: list[AgentAssessment] = Field(default_factory=list)


class LiveDetection(BaseModel):
    """First moment a finding appeared while the run was still going."""

    sequence: int
    timestamp: str
    event_id: str  # the event whose arrival produced the finding
    rule_id: str
    rule_name: str
    severity: Severity
    agent_ids: list[str]
    reason: str


class Containment(BaseModel):
    agent_id: str
    role: Optional[str] = None
    scope: Literal["agent", "egress"] = "agent"  # agent = all actions paused; egress = only outbound transfers held
    paused_at_sequence: int
    paused_at: str
    risk: float
    explanation: Optional[str] = None
    blocked_actions: int = 0
    trigger: Optional[str] = None  # risk | hijack_tripwire | need_to_know | policy | operator
    rule_id: Optional[str] = None  # the alert's rule, when the response policy triggered it


class LiveReport(BaseModel):
    run_id: str
    mode: Literal["detect", "contain"]
    pause_at: float
    events_processed: int
    detections: list[LiveDetection]
    containment: list[Containment]
    metrics: dict[str, Any]
    created_at: str


class ReplayRequest(BaseModel):
    """Plant one labeled attack (or benign look-alike) from the benchmark into a realistic run, live."""

    case: str
    agent_count: Literal[5, 10, 20] = 5
    seed: int = 7
    live_guard: Literal["off", "detect", "contain"] = "contain"
    pause_at: float = Field(0.6, ge=0.2, le=0.99)


class BaselineTrainRequest(BaseModel):
    source: Literal["synthetic", "run", "ai"] = "synthetic"
    runs: int = Field(3, ge=1, le=10, description="With source=ai: clean AI-mode runs to generate and learn")
    agent_backend: str = Field("gemini", description="With source=ai: the model that drives the agents")
    run_id: Optional[str] = Field(None, description="With source=run: a run confirmed clean to fold into the baseline")
    confirm_clean: bool = Field(False, description="With source=run: a reviewer confirms this run's alerts were false "
                                "positives, so it may be learned anyway (e.g. the first runs of a new kind of agent)")


# ---------------------------------------------------------------------------
# Section 4: Security Response
# ---------------------------------------------------------------------------
class ResponsePolicy(BaseModel):
    policy_id: str = "default"
    name: str = "Default severity policy"
    mode: ResponsePolicyMode = "simulate"
    severity_actions: dict[Severity, ResponseDecision] = Field(
        default_factory=lambda: {"low": "alert", "medium": "alert", "high": "block", "critical": "pause"}
    )
    # Newer rules: a hijacked agent is paused; spoofed authority and worm relays are blocked.
    rule_overrides: dict[str, ResponseDecision] = Field(
        default_factory=lambda: {"SG-012": "pause", "SG-026": "block", "SG-027": "block"})


class ResponseAction(BaseModel):
    response_id: str
    run_id: str
    alert_id: str
    policy_id: str
    decision: ResponseDecision
    outcome: ResponseOutcome
    mode: Literal["simulated", "enforced"]
    enforced: bool
    agent_ids: list[str]
    event_ids: list[str]
    gateway_event_ids: list[str] = Field(default_factory=list)
    note: str
    created_at: str


class RespondRequest(BaseModel):
    run_id: str
    policy: Optional[ResponsePolicy] = None
    persist: bool = True


class ResponseResult(BaseModel):
    run_id: str
    policy: ResponsePolicy
    actions: list[ResponseAction]


# ---------------------------------------------------------------------------
# Section 5: Dashboard & Evaluation
# ---------------------------------------------------------------------------
class EvaluationResult(BaseModel):
    evaluation_id: str
    run_id: str
    scenario_id: str
    agent_count: int
    drop_rate: float
    tp: int
    fp: int
    fn: int
    tn: int
    precision: Optional[float]
    recall: Optional[float]
    false_positive_rate: Optional[float]
    f1: Optional[float]
    evidence_coverage: Optional[float] = Field(None, description="Share of labeled malicious events cited by alerts")
    detection_latency_s: Optional[float] = Field(None, description="Mean seconds from first malicious event to the event that completed the alert evidence")
    containment_rate: Optional[float] = Field(None, description="Share of malicious agents that received a block/pause decision")
    enforced_containment_rate: Optional[float] = Field(None, description="Share of gateway-checked malicious events actually denied")
    alert_count: int
    created_at: str


class EvaluateRequest(BaseModel):
    run_id: str
    persist: bool = True


class SuiteRequest(BaseModel):
    scenario_ids: list[str] = Field(default_factory=lambda: ["normal_collaboration", "unauthorized_access", "coordinated_leakage"])
    agent_count: Literal[3, 5, 10, 20] = 5
    drop_rates: list[float] = Field(default_factory=lambda: [0.0, 0.1, 0.3, 0.5])
    seeds: list[int] = Field(default_factory=lambda: [1, 2, 3], max_length=5)
    gateway_mode: GatewayMode = "monitor"
    persist: bool = True


class SuiteRow(BaseModel):
    drop_rate: float
    runs: int
    tp: int
    fp: int
    fn: int
    tn: int
    precision: Optional[float]
    recall: Optional[float]
    false_positive_rate: Optional[float]
    mean_latency_s: Optional[float]
    containment_rate: Optional[float]


class SuiteResult(BaseModel):
    evaluation_id: str
    created_at: str
    config: SuiteRequest
    rows: list[SuiteRow]
    results: list[EvaluationResult]


class Dashboard(BaseModel):
    run: Run
    totals: dict[str, int]
    response_outcomes: dict[str, int]
    severity_counts: dict[str, int]
    graph: AgentGraph
    timeline: list[dict[str, Any]]
    flagged_agents: list[dict[str, Any]]
    evaluation: Optional[EvaluationResult] = None


SimulationResult.model_rebuild()  # resolves the forward reference to LiveReport
