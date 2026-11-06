import { AUTH_REQUIRED, authHeaders } from "./lib/apiKey";
import type {
  Agent, AgentAssessment, Alert, AuditItem, BaselineSummary, GeminiQuotaStatus, ReviewItem, BenchmarkResult, LiveReport, ReplayCase, CollectionResult, Dashboard, DetectionResult, DetectionRule, EvaluationResult, Meta, ModuleInfo,
  NormalizedEvent, RawEvent, ResponseAction, ResponsePolicy, ResponseResult, Run, ScenarioConfig, SimulationResult,
  SuiteRequest, SuiteResult, AgentGraph,
} from "./types";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`/api${path}`, {
      ...init,
      headers: { "Content-Type": "application/json", ...authHeaders(), ...(init?.headers ?? {}) },
    });
  } catch {
    throw new ApiError(0, "Cannot reach the SwaramGuard API. Is the backend running on port 8000?");
  }
  const text = await res.text();
  const body = text ? JSON.parse(text) : null;
  if (!res.ok) {
    const detail = body?.detail;
    const msg = typeof detail === "string" ? detail
      : Array.isArray(detail) ? detail.map((d: { loc?: unknown[]; msg: string }) => `${(d.loc ?? []).join(".")}: ${d.msg}`).join("; ")
      : res.statusText;
    if (res.status === 401 || res.status === 403) window.dispatchEvent(new CustomEvent(AUTH_REQUIRED, { detail: msg }));
    throw new ApiError(res.status, msg);
  }
  return body as T;
}

const post = <T>(path: string, body: unknown) => request<T>(path, { method: "POST", body: JSON.stringify(body) });
const put = <T>(path: string, body: unknown) => request<T>(path, { method: "PUT", body: JSON.stringify(body) });

export const api = {
  health: () => request<{ ok: boolean; storage: string; workspace: string; auth?: "on" | "off" }>("/health"),
  meta: () => request<Meta>("/meta"),
  moduleInfo: (name: string) => request<ModuleInfo>(`/modules/${name}`),

  runs: () => request<Run[]>("/runs"),
  run: (id: string) => request<Run>(`/runs/${id}`),
  agents: (id: string) => request<Agent[]>(`/runs/${id}/agents`),
  rawEvents: (id: string) => request<RawEvent[]>(`/runs/${id}/raw-events`),
  normalizedEvents: (id: string) => request<NormalizedEvent[]>(`/runs/${id}/normalized-events`),
  alerts: (id: string) => request<Alert[]>(`/runs/${id}/alerts`),
  graph: (id: string) => request<AgentGraph>(`/runs/${id}/graph`),
  responses: (id: string) => request<ResponseAction[]>(`/runs/${id}/responses`),
  dashboard: (id: string) => request<Dashboard>(`/runs/${id}/dashboard`),
  runPipeline: (id: string) => post<Run>(`/runs/${id}/pipeline`, {}),

  simulate: (cfg: ScenarioConfig) => post<SimulationResult>("/simulate", cfg),
  collect: (body: { run_id?: string | null; events?: unknown[]; persist: boolean }) => post<CollectionResult>("/collect", body),
  detect: (run_id: string, persist: boolean) => post<DetectionResult>("/detect", { run_id, persist }),
  assessments: (id: string) => request<AgentAssessment[]>(`/runs/${id}/assessments`),
  auditQueue: (id: string) => request<AuditItem[]>(`/runs/${id}/audit-queue`),
  liveReport: (id: string) => request<LiveReport | null>(`/runs/${id}/live-report`),
  replayCases: () => request<ReplayCase[]>("/detection/replay-cases"),
  replay: (body: { case: string; agent_count: number; seed: number; live_guard: "off" | "detect" | "contain" }) =>
    post<SimulationResult>("/detection/replay", body),
  baseline: () => request<BaselineSummary>("/detection/baseline"),
  geminiQuota: () => request<GeminiQuotaStatus>("/gemini/quota"),
  reviews: (status?: string) => request<ReviewItem[]>(`/reviews${status ? `?status=${status}` : ""}`),
  decideReview: (id: string, decision: "release" | "confirm", note?: string, by?: string) =>
    request<ReviewItem>(`/reviews/${id}`, { method: "POST", body: JSON.stringify({ decision, note, by }) }),
  operateAgent: (runId: string, agentId: string, action: "pause" | "hold_egress", note?: string) =>
    request<{ result: string }>(`/live/${runId}/agents/${agentId}`, { method: "POST", body: JSON.stringify({ action, note }) }),
  stopRun: (runId: string, note?: string) =>
    request<{ paused: Record<string, string> }>(`/live/${runId}/stop`, { method: "POST", body: JSON.stringify({ note }) }),
  startRun: (cfg: ScenarioConfig) => request<{ run_id: string; stream: string }>("/runs/start", { method: "POST", body: JSON.stringify(cfg) }),
  benchmark: (full = false) => post<BenchmarkResult>(`/detection/benchmark?full=${full}`, {}),
  trainBaseline: (body: { source: "synthetic" | "run" | "ai"; run_id?: string; confirm_clean?: boolean; runs?: number }) => post<BaselineSummary>("/detection/baseline", body),
  rules: () => request<DetectionRule[]>("/detection-rules"),
  saveRule: (rule: DetectionRule) => put<DetectionRule>(`/detection-rules/${rule.rule_id}`, rule),
  respond: (run_id: string, policy: ResponsePolicy, persist: boolean) => post<ResponseResult>("/respond", { run_id, policy, persist }),
  policy: (id = "default") => request<ResponsePolicy>(`/response-policies/${id}`),
  savePolicy: (p: ResponsePolicy) => put<ResponsePolicy>(`/response-policies/${p.policy_id}`, p),
  evaluate: (run_id: string, persist: boolean) => post<EvaluationResult>("/evaluate", { run_id, persist }),
  suite: (req: SuiteRequest) => post<SuiteResult>("/evaluate/suite", req),
  evaluations: () => request<Array<Record<string, unknown>>>("/evaluations"),
};
