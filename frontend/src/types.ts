// Mirrors backend/app/schemas.py. Keep both in sync.

export type EventType = "message" | "tool_call" | "resource_access" | "data_transfer" | "task";
export type EventStatus = "success" | "denied" | "failed" | "pending";
export type GatewayDecision = "not_checked" | "allow" | "would_block" | "blocked";
export type GatewayMode = "off" | "monitor" | "enforce";
export type Severity = "low" | "medium" | "high" | "critical";
export type ResponseDecision = "allow" | "alert" | "block" | "pause";
export type ResponsePolicyMode = "simulate" | "enforce";
export type ResponseOutcome = "allowed" | "alerted" | "would_block" | "would_pause" | "blocked" | "contained";
export type AlertStatus = "open" | "responded" | "contained";
export type AgentCount = 3 | 5 | 10 | 20;

export interface Scenario {
  scenario_id: string;
  name: string;
  description: string;
  malicious_roles: string[];
  tags: string[];
}

export interface ScenarioConfig {
  scenario_id: string;
  agent_count: AgentCount;
  seed: number;
  gateway_mode: GatewayMode;
  drop_rate: number;
  sensors?: boolean;
  agent_backend: string;
  agent_mode?: "scripted" | "autonomous";
  rounds?: number;
  auto_pipeline: boolean;
  live_guard?: "off" | "detect" | "contain";
  pause_at?: number;
  persist: boolean;
}

export interface Agent {
  agent_id: string;
  run_id: string;
  name: string;
  role: string;
  permissions: string[];
  is_malicious: boolean;
}

export interface RawEvent {
  run_id: string;
  event_id: string;
  agent_id: string;
  timestamp: string | number;
  event_type: string;
  action: string;
  status: string;
  target?: string | null;
  resource?: string | null;
  sequence: number;
  gateway_decision?: string | null;
  payload: Record<string, unknown>;
}

export interface RunLabels {
  malicious_agent_ids: string[];
  malicious_event_ids: string[];
}

export interface Run {
  run_id: string;
  scenario_id: string;
  agent_count: number;
  seed: number;
  gateway_mode: GatewayMode;
  drop_rate: number;
  agent_backend: string;
  agent_mode?: string;
  created_at: string;
  base_time: string;
  stages: Record<string, string>;
  counts: Record<string, number>;
  labels: RunLabels;
  dropped_event_ids: string[];
}

export interface SimulationResult {
  run: Run;
  agents: Agent[];
  events: RawEvent[];
  live_report?: LiveReport | null;
}

export interface NormalizedEvent {
  run_id: string;
  event_id: string;
  agent_id: string;
  agent_role?: string | null;
  timestamp: string;
  event_type: string;
  action: string;
  status: EventStatus;
  target?: string | null;
  resource?: string | null;
  sequence: number;
  gateway_decision: GatewayDecision;
  payload: Record<string, unknown>;
  summary: string;
  issues: string[];
  raw_hash: string;
  raw: Record<string, unknown>;
  normalized_at: string;
}

export interface CollectorIssue {
  index: number;
  event_id?: string | null;
  code: string;
  message: string;
}

export interface CollectionReport {
  run_id: string | null;
  total_input: number;
  valid: number;
  invalid: number;
  duplicates: number;
  warnings: CollectorIssue[];
  errors: CollectorIssue[];
}

export interface CollectionResult {
  report: CollectionReport;
  events: NormalizedEvent[];
}

export interface DetectionRule {
  rule_id: string;
  name: string;
  description: string;
  severity: Severity;
  recommended_action: ResponseDecision;
  enabled: boolean;
  params: Record<string, unknown>;
}

export interface EvidenceRef {
  event_id: string;
  timestamp: string;
  summary: string;
}

export interface Alert {
  alert_id: string;
  run_id: string;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  agent_ids: string[];
  event_ids: string[];
  resource?: string | null;
  reason: string;
  recommended_action: ResponseDecision;
  status: AlertStatus;
  evidence: EvidenceRef[];
  created_at: string;
}

export interface GraphNode {
  id: string;
  kind: "agent" | "external";
  role?: string | null;
  flagged: boolean;
  event_count: number;
  degree_centrality: number;
  betweenness: number;
}

export interface GraphEdge {
  source: string;
  target: string;
  kind: "message" | "data_transfer" | "indirect";
  count: number;
  event_ids: string[];
}

export interface AgentGraph {
  run_id: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface RareBehavior {
  behavior: string;
  p: number;
  bits: number;
  event_ids: string[];
}

export interface Hypothesis {
  hypothesis: string;
  label: string;
  score: number;
  supporting: string[];
}

export type RiskLevel = "low" | "watch" | "high" | "critical";

export interface AgentAssessment {
  run_id: string;
  agent_id: string;
  role?: string | null;
  prior: number;
  risk: number;
  level: RiskLevel;
  anomaly_bits: number;
  rare_behaviors: RareBehavior[];
  evidence: string[];
  alert_ids: string[];
  hypotheses: Hypothesis[];
  best_explanation?: string | null;
}

export interface AuditItem {
  event_id: string;
  agent_id: string;
  role?: string | null;
  timestamp: string;
  summary: string;
  priority: number;
  reasons: string[];
}

export interface LiveDetection {
  sequence: number;
  timestamp: string;
  event_id: string;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  agent_ids: string[];
  reason: string;
}

export interface Containment {
  agent_id: string;
  role?: string | null;
  scope?: "agent" | "egress";
  paused_at_sequence: number;
  paused_at: string;
  risk: number;
  explanation?: string | null;
  blocked_actions: number;
  trigger?: string;
  rule_id?: string;
}

export interface OwaspRuleRef {
  rule_id: string;
  name: string;
}

export interface OwaspRisk {
  id: string;
  name: string;
  coverage: "strong" | "partial" | "none";
  rules: OwaspRuleRef[];
  controls: string[];
  gaps: string;
}

export interface OwaspCoverageResult {
  framework: string;
  summary: {
    strong: number;
    partial: number;
    none: number;
  };
  risks: OwaspRisk[];
  rules_not_mapped: string[];
}

export interface LiveReport {
  run_id: string;
  mode: "detect" | "contain";
  pause_at: number;
  events_processed: number;
  detections: LiveDetection[];
  containment: Containment[];
  metrics: Record<string, number | boolean | null>;
  created_at: string;
}

export interface ReplayCase {
  name: string;
  threat: string;
  benign: boolean;
  expect_rules: string[];
  roles: Record<string, string>;
  culprits: string[];
}

export interface BenchmarkRow {
  drop_rate: number;
  trials: number;
  precision: number | null;
  recall: number | null;
  false_positive_rate: number | null;
  threat_detection_rate: number | null;
  right_rule_rate: number | null;
  evidence_survived: number | null;
  detection_given_evidence: number | null;
  benign_alarm_rate: number | null;
}

export interface BenchmarkResult {
  rows: BenchmarkRow[];
  cases: Record<string, Record<string, number | null>>;
  cases_info: Record<string, { threat: string; benign: boolean }>;
}

export interface ReviewItem {
  review_id: string;
  run_id: string;
  kind: "paused_agent" | "held_egress" | "quarantined_input";
  agent_id: string;
  role: string | null;
  trigger: string | null;
  explanation: string | null;
  resource: string | null;
  claimed_sender: string | null;
  risk: number | null;
  status: "pending" | "released" | "confirmed";
  created_at: string;
  decided_at: string | null;
  note: string | null;
  effect: string | null;
  decided_by?: string | null;
  escalated_at?: string | null;
}

export interface GeminiQuotaStatus {
  configured: boolean;
  model: string;
  calls_today: number;
  daily_limit: number;
  remaining_today: number;
  rpm_limit: number;
  calls_last_minute: number;
  resets_at: string;
  resets_in_s: number;
  exhausted: boolean;
  blocked_reason: string | null;
  calls_per_run: Record<string, { scripted: number; autonomous: number }>;
}

export interface BaselineSummary {
  trained: boolean;
  runs_learned: number;
  learned_run_ids: string[];
  agents_learned: number;
  identities_learned?: number;
  roles: Record<string, { agents: number; behaviors: number }>;
  taught?: { run_id: string; learned: boolean; skipped_because: string | null; ai_decisions: number }[];
}

export interface DetectionResult {
  run_id: string;
  alerts: Alert[];
  graph: AgentGraph;
  assessments: AgentAssessment[];
}

export interface ResponsePolicy {
  policy_id: string;
  name: string;
  mode: ResponsePolicyMode;
  severity_actions: Record<Severity, ResponseDecision>;
  rule_overrides: Record<string, ResponseDecision>;
}

export interface ResponseAction {
  response_id: string;
  run_id: string;
  alert_id: string;
  policy_id: string;
  decision: ResponseDecision;
  outcome: ResponseOutcome;
  mode: "simulated" | "enforced";
  enforced: boolean;
  agent_ids: string[];
  event_ids: string[];
  gateway_event_ids: string[];
  note: string;
  created_at: string;
}

export interface ResponseResult {
  run_id: string;
  policy: ResponsePolicy;
  actions: ResponseAction[];
}

export interface EvaluationResult {
  evaluation_id: string;
  run_id: string;
  scenario_id: string;
  agent_count: number;
  drop_rate: number;
  tp: number;
  fp: number;
  fn: number;
  tn: number;
  precision: number | null;
  recall: number | null;
  false_positive_rate: number | null;
  f1: number | null;
  evidence_coverage: number | null;
  detection_latency_s: number | null;
  containment_rate: number | null;
  enforced_containment_rate: number | null;
  alert_count: number;
  created_at: string;
}

export interface SuiteRequest {
  scenario_ids: string[];
  agent_count: AgentCount;
  drop_rates: number[];
  seeds: number[];
  gateway_mode: GatewayMode;
  persist: boolean;
}

export interface SuiteRow {
  drop_rate: number;
  runs: number;
  tp: number;
  fp: number;
  fn: number;
  tn: number;
  precision: number | null;
  recall: number | null;
  false_positive_rate: number | null;
  mean_latency_s: number | null;
  containment_rate: number | null;
}

export interface SuiteResult {
  evaluation_id: string;
  created_at: string;
  config: SuiteRequest;
  rows: SuiteRow[];
  results: EvaluationResult[];
}

export interface TimelineItem {
  event_id: string;
  agent_id: string;
  timestamp: string;
  event_type: string;
  status: string;
  summary: string;
  flagged: boolean;
}

export interface FlaggedAgent {
  agent_id: string;
  role?: string | null;
  rule_ids: string[];
  event_ids: string[];
}

export interface Dashboard {
  run: Run;
  totals: Record<string, number>;
  response_outcomes: Record<string, number>;
  severity_counts: Record<string, number>;
  graph: AgentGraph;
  timeline: TimelineItem[];
  flagged_agents: FlaggedAgent[];
  evaluation: EvaluationResult | null;
}

export interface Meta {
  scenarios: Scenario[];
  agent_counts: AgentCount[];
  agent_backends: { id: string; label: string; available: boolean }[];
}

export interface ModuleInfoPart {
  model: string;
  schema: unknown;
  fixture: string | null;
  sample: unknown;
}

export interface ModuleInfo {
  module: string;
  input?: ModuleInfoPart;
  output?: ModuleInfoPart;
  extra?: ModuleInfoPart;
}
