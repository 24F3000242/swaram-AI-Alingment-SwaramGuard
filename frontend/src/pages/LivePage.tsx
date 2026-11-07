import { SwarmPage } from "./SwarmPage";
import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { GeminiQuota } from "../components/GeminiQuota";
import { PageHeader } from "../components/PageHeader";
import { Badge, Button, Card, CustomSelect, Empty, Field, Segmented, StatusBanner, type Status } from "../components/ui";
import { shortId } from "../lib/format";
import { type LiveMessage, useLiveStream } from "../lib/live";
import { useAppState } from "../state";
import type { AgentCount } from "../types";
import { Zap, ShieldAlert, Lock, AlertTriangle, Play, Radio, RotateCcw } from "lucide-react";

type AnyData = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const TONE: Record<string, string> = {
  detection: "bg-[var(--med-bg)] text-[var(--med)]",
  containment: "bg-[var(--crit-bg)] text-[var(--crit)]",
  quarantine: "bg-[var(--high-bg)] text-[var(--high)]",
  run_started: "bg-[var(--accent)]/10 text-[var(--accent)]",
  run_finished: "bg-[var(--ok-bg)] text-[var(--ok)]",
  run_failed: "bg-[var(--crit-bg)] text-[var(--crit)]",
  response: "bg-[var(--accent)]/10 text-[var(--accent)]",
  operator: "bg-[var(--crit-bg)] text-[var(--crit)]",
  reset: "bg-[var(--ok-bg)] text-[var(--ok)]",
};

function describe(m: LiveMessage<AnyData>): { title: string; subtitle?: string; isPreBlock?: boolean; isCircuitBreaker?: boolean; isCovert?: boolean } {
  const d = m.data;
  switch (m.type) {
    case "event": {
      const isPreBlock = d.status === "denied" || (d.payload?.gateway_reason && String(d.payload.gateway_reason).includes("before execution"));
      const isCovertAction = d.event_type === "data_transfer" && (d.target || "").includes("paste-site");
      return {
        title: `${shortId(d.agent_id)} ${d.event_type}:${d.action} ${d.resource ?? d.target ?? ""}`,
        subtitle: isPreBlock ? (d.payload?.gateway_reason || "Refused by pre-execution policy check before tool execution") : undefined,
        isPreBlock,
        isCovert: isCovertAction,
      };
    }
    case "detection": {
      const isCovert = d.rule_id === "SG-029" || d.rule_id === "SG-003";
      return {
        title: `${d.rule_id} ${d.rule_name} · ${(d.agent_ids ?? []).map(shortId).join(", ") || "run-level"}`,
        subtitle: d.reason,
        isCovert,
      };
    }
    case "containment": {
      const isCircuitBreaker = d.trigger === "circuit_breaker" || (d.explanation && String(d.explanation).includes("circuit breaker"));
      return {
        title: `${d.scope === "egress" ? "Egress held" : "Agent paused"}: ${shortId(d.agent_id)} (${d.role})`,
        subtitle: d.explanation ?? "",
        isCircuitBreaker,
      };
    }
    case "quarantine":
      return {
        title: `Quarantined input for ${shortId(d.agent_id)}: ${d.resource}`,
        subtitle: d.reason === "classifier" ? `Prompt injection score: ${d.score} (SG-028)` : `Claims to be from ${d.claimed_sender} (SG-026)`,
      };
    case "run_started":
      return { title: `Run started: ${d.config?.scenario_id ?? ""}` };
    case "run_finished":
      return {
        title: `Run finished · Data left system: ${d.live_metrics?.data_left_the_system ? "YES (LEAK)" : "NO (CONTAINED)"}`,
        subtitle: d.live_metrics ? `Blocked: ${d.live_metrics.blocked_actions_total ?? 0} · Pre-execution checks: ${d.live_metrics.blocked_by_policy_check ?? 0}` : undefined,
      };
    case "run_failed":
      return { title: `Run failed: ${d.error}` };
    case "response":
      return {
        title: `Policy: ${d.rule_id} → ${d.decision} · ${(d.agent_ids ?? []).map(shortId).join(", ") || "run-level"}`,
        subtitle: (d.applied ?? []).join(", "),
      };
    case "operator":
      return { title: `Operator ${d.action} ${shortId(d.agent_id)}: ${d.result}` };
    case "review":
      return { title: `Review ${d.action}: ${shortId(d.item?.agent_id)} (${d.item?.kind})${d.item?.status !== "pending" ? ` → ${d.item?.status}` : ""}` };
    case "reset":
      return { title: "Live hub & containment reset by operator", subtitle: d.message };
    default:
      return { title: m.type };
  }
}

/** Live monitor: real-time streaming telemetry, pre-execution gates, and circuit breaker status */
export function LivePage({ initialView = "feed" }: { initialView?: "feed" | "topology" } = {}) {
  const [activeView, setActiveView] = useState<"feed" | "topology">(initialView);

  useEffect(() => {
    setActiveView(initialView);
  }, [initialView]);
  const { meta, selectRun, refreshRuns } = useAppState();
  const { messages, connected, totalReceived, clear, reset } = useLiveStream(undefined, 5000);
  const [startedRun, setStartedRun] = useState<string | null>(null);

  // Once the run started here finishes (and is saved), make it the app's selected run, so Dashboard, Incidents and
  // Pipeline show it instead of whatever run was selected before.
  useEffect(() => {
    if (!startedRun) return;
    const done = messages.some((m) => m.run_id === startedRun && (m.type === "run_finished" || m.type === "run_failed"));
    if (!done) return;
    setStartedRun(null);
    refreshRuns().then(() => selectRun(startedRun));
  }, [messages, startedRun, refreshRuns, selectRun]);
  const [scenario, setScenario] = useState("coordinated_leakage");
  const [count, setCount] = useState<AgentCount>(5);
  const [ai, setAi] = useState(false);
  const [busy, setBusy] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [status, setStatus] = useState<Status>(null);
  const [feedFilter, setFeedFilter] = useState<"all" | "security" | "blocks" | "containment">("all");

  // Derive live KPIs
  const { liveRun, running, agents, circuitBreakerTripped, preExecutionBlocks, covertAlerts, quarantinedCount } = useMemo(() => {
    let run: string | null = null;
    let open = false;
    let out = new Map<string, { role: string; state: string; trigger?: string }>();
    let cbTripped = false;
    let preBlocks = 0;
    let covertCount = 0;
    let qCount = 0;

    for (const m of messages as LiveMessage<AnyData>[]) {
      if (m.type === "run_agents") {
        run = m.run_id;
        open = true;
        out = new Map(m.data.agents.map((a: AnyData) => [a.agent_id, { role: a.role, state: "active" }]));
      } else if (m.run_id === run && (m.type === "run_finished" || m.type === "run_failed")) {
        open = false;
      } else if (m.run_id === run && m.type === "containment" && out.has(m.data.agent_id)) {
        const cur = out.get(m.data.agent_id)!;
        cur.state = m.data.scope === "egress" && cur.state !== "paused" ? "egress held" : "paused";
        cur.trigger = m.data.trigger;
        if (m.data.trigger === "circuit_breaker" || (m.data.explanation && String(m.data.explanation).includes("circuit breaker"))) {
          cbTripped = true;
        }
      } else if (m.run_id === run && m.type === "review" && m.data.item?.status === "released" && out.has(m.data.item.agent_id)) {
        out.get(m.data.item.agent_id)!.state = "active";
      } else if (m.type === "event" && (m.data.status === "denied" || (m.data.payload?.gateway_reason && String(m.data.payload.gateway_reason).includes("before execution")))) {
        preBlocks++;
      } else if (m.type === "detection" && (m.data.rule_id === "SG-029" || m.data.rule_id === "SG-003")) {
        covertCount++;
      } else if (m.type === "quarantine") {
        qCount++;
      }
    }
    return {
      liveRun: run,
      running: open,
      agents: [...out.entries()],
      circuitBreakerTripped: cbTripped,
      preExecutionBlocks: preBlocks,
      covertAlerts: covertCount,
      quarantinedCount: qCount,
    };
  }, [messages]);

  const [acting, setActing] = useState<string | null>(null);

  async function operate(agentId: string | null) {
    if (!liveRun) return;
    setActing(agentId ?? "stop");
    try {
      if (agentId) await api.operateAgent(liveRun, agentId, "pause");
      else await api.stopRun(liveRun);
    } catch (e) {
      setStatus({ kind: "error", message: (e as Error).message });
    } finally {
      setActing(null);
    }
  }

  async function handleResetAll() {
    setResetting(true);
    setStatus(null);
    try {
      const res = await api.resetLive();
      reset();
      setStatus({
        kind: "success",
        message: (
          <>
            All live telemetry, event queues, circuit breaker states, and {res.released_containments || "any"} contained agent states have been reset.
          </>
        ),
      });
    } catch (e) {
      reset();
      setStatus({
        kind: "info",
        message: "Local live stream, feed buffer, and counters reset.",
      });
    } finally {
      setResetting(false);
    }
  }

  // Filter feed items
  const feed = useMemo(() => {
    return (messages as LiveMessage<AnyData>[])
      .filter((m) => {
        if (feedFilter === "security") {
          return m.type === "detection" || m.type === "containment" || m.type === "quarantine" || (m.type === "event" && m.data.status === "denied");
        }
        if (feedFilter === "blocks") {
          return m.type === "event" && (m.data.status === "denied" || (m.data.payload?.gateway_reason && String(m.data.payload.gateway_reason).includes("before execution")));
        }
        if (feedFilter === "containment") {
          return m.type === "containment" || m.type === "operator" || m.type === "quarantine";
        }
        return true;
      })
      .slice(-1000)
      .reverse();
  }, [messages, feedFilter]);

  async function start(chosenScenario?: string) {
    setBusy(true);
    setStatus(null);
    try {
      const targetScenario = chosenScenario || scenario;
      const r = await api.startRun({
        scenario_id: targetScenario,
        agent_count: count,
        seed: Math.floor(Math.random() * 1000),
        gateway_mode: "monitor",
        drop_rate: 0,
        agent_backend: ai ? "gemini" : "deterministic",
        agent_mode: ai ? "autonomous" : "scripted",
        auto_pipeline: true,
        live_guard: "contain",
        persist: true,
      });
      setStartedRun(r.run_id);
      setStatus({
        kind: "success",
        message: <>Live streaming run <code className="font-mono">{r.run_id}</code> ({targetScenario}). Interception gates active.</>,
      });
    } catch (e) {
      setStatus({ kind: "error", message: (e as Error).message });
    } finally {
      setBusy(false);
    }
  }

  const displayCount = totalReceived || messages.length;

  return (
    <div className="min-w-0 space-y-6">
      <PageHeader
        title="Live Guard."
        subtitle="Real-time multi-agent telemetry stream, policy gating, covert transfer detection, and swarm communication topology."
        actions={
          <div className="flex flex-wrap items-center gap-3">
            <Segmented
              value={activeView}
              onChange={(v) => {
                setActiveView(v);
                if (v === "topology") window.location.hash = "#/swarm";
                else window.location.hash = "#/live";
              }}
              options={[
                { value: "feed", label: "Live Telemetry Feed" },
                { value: "topology", label: "Swarm Topology Graph" },
              ]}
            />
            {activeView === "feed" && (
              <Button
                variant="secondary"
                onClick={handleResetAll}
                busy={resetting}
                className="text-[13px] border-[var(--hairline)]"
              >
                <RotateCcw size={14} className="mr-1.5" />
                <span>Reset All</span>
              </Button>
            )}
          </div>
        }
      />

      <StatusBanner status={status} onClose={() => setStatus(null)} />

      {activeView === "topology" ? (
        <div className="transition-opacity">
          <SwarmPage hideHeader />
        </div>
      ) : (
        <>


      {/* Prominent Circuit Breaker Alert Banner */}
      {circuitBreakerTripped && (
        <div className="rounded-[var(--r-card)] border-2 border-[var(--crit)] bg-[var(--crit-bg)] p-5 shadow-lg">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-[var(--crit)] text-white">
                <ShieldAlert size={22} />
              </span>
              <div>
                <h3 className="text-[17px] font-bold text-[var(--crit)] uppercase tracking-wide">
                  Swarm Circuit Breaker Tripped (OWASP ASI08)
                </h3>
                <p className="mt-0.5 text-[14px] text-[var(--text)]">
                  Multiple agents compromised in coordinated activity. Swarm execution automatically paused to prevent cascading pipeline failure.
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={handleResetAll}
                disabled={resetting}
                className="inline-flex items-center gap-1.5 rounded-full bg-white border border-[var(--crit)]/30 px-3.5 py-2 text-[13px] font-semibold text-[var(--crit)] shadow-xs hover:bg-neutral-50 transition-all"
              >
                <RotateCcw size={13} className={resetting ? "animate-spin" : ""} />
                <span>Reset Circuit Breaker &amp; Resume</span>
              </button>
              <a
                href="#/responses"
                className="inline-flex items-center gap-1.5 rounded-full bg-[var(--crit)] px-4 py-2 text-[13px] font-semibold text-white shadow-xs hover:opacity-90"
              >
                <span>Inspect in Review Queue</span>
              </a>
            </div>
          </div>
        </div>
      )}

      {/* Real-Time Live HUD Stats Grid */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div className="rounded-[var(--r-card)] card p-4 border border-[var(--hairline-subtle)]">
          <div className="flex items-center justify-between text-[11px] font-medium uppercase tracking-wider text-[var(--text-3)]">
            <span>Live Stream</span>
            <span className={`h-2 w-2 rounded-full ${connected ? "bg-[var(--ok)] animate-pulse" : "bg-[var(--crit)]"}`} />
          </div>
          <div className="mt-2 text-[26px] font-bold tabular-nums text-[var(--text)]">
            {displayCount.toLocaleString()}
          </div>
          <span className="text-[12px] text-[var(--text-2)]">
            {totalReceived > messages.length ? `Showing latest ${messages.length.toLocaleString()} in feed` : "Events Received"}
          </span>
        </div>

        <div className="rounded-[var(--r-card)] card p-4 border border-[var(--hairline-subtle)]">
          <div className="flex items-center justify-between text-[11px] font-medium uppercase tracking-wider text-[var(--accent)]">
            <span>Pre-Execution Blocks</span>
            <Lock size={14} />
          </div>
          <div className="mt-2 text-[26px] font-bold tabular-nums text-[var(--accent)]">
            {preExecutionBlocks}
          </div>
          <span className="text-[12px] text-[var(--text-2)]">Harm Prevented Before Run</span>
        </div>

        <div className="rounded-[var(--r-card)] card p-4 border border-[var(--hairline-subtle)]">
          <div className="flex items-center justify-between text-[11px] font-medium uppercase tracking-wider text-[var(--crit)]">
            <span>Covert Transfers</span>
            <AlertTriangle size={14} />
          </div>
          <div className="mt-2 text-[26px] font-bold tabular-nums text-[var(--crit)]">
            {covertAlerts}
          </div>
          <span className="text-[12px] text-[var(--text-2)]">
            SG-029 Caught {quarantinedCount > 0 ? `· ${quarantinedCount} Quarantined` : ""}
          </span>
        </div>

        <div className="rounded-[var(--r-card)] card p-4 border border-[var(--hairline-subtle)]">
          <div className="flex items-center justify-between text-[11px] font-medium uppercase tracking-wider text-[var(--text-3)]">
            <span>Circuit Breaker</span>
            <Zap size={14} className={circuitBreakerTripped ? "text-[var(--crit)]" : "text-[var(--ok)]"} />
          </div>
          <div className="mt-2 text-[18px] font-bold tracking-tight">
            {circuitBreakerTripped ? (
              <span className="text-[var(--crit)]">TRIPPED</span>
            ) : (
              <span className="text-[var(--ok)]">ARMED (Max 3)</span>
            )}
          </div>
          <span className="text-[12px] text-[var(--text-2)]">{agents.filter(([, a]) => a.state === "paused").length} Paused Agents</span>
        </div>
      </div>

      {/* Control Console Card */}
      <Card
        title="Start Live Multi-Agent Run"
        actions={
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-1.5 text-[13px] text-[var(--text-2)]">
              <Radio size={14} className={connected ? "text-[var(--ok)]" : "text-[var(--crit)]"} />
              {connected ? "WebSocket Connected" : "Connecting…"}
            </span>
            <button
              onClick={handleResetAll}
              disabled={resetting}
              className="inline-flex items-center gap-1 rounded-full border border-[var(--hairline)] bg-[var(--card)] px-3 py-1 text-[12px] font-medium text-[var(--text-2)] hover:border-[var(--text-3)] hover:text-[var(--text)] transition-all"
            >
              <RotateCcw size={12} className={resetting ? "animate-spin" : ""} />
              <span>{resetting ? "Resetting…" : "Reset All"}</span>
            </button>
          </div>
        }
      >
        <div className="grid gap-4 sm:grid-cols-3 [&>*]:min-w-0">
          <Field label="Scenario" asDiv>
            <CustomSelect
              value={scenario}
              onChange={(val) => setScenario(val)}
              options={
                meta?.scenarios
                  .filter((s) => s.scenario_id !== "user_directed")
                  .map((s) => ({
                    value: s.scenario_id,
                    label: s.name,
                    description: s.description,
                  })) ?? []
              }
              ariaLabel="Select scenario for live run"
            />
          </Field>
          <Field label="Agents in Swarm" asDiv>
            <Segmented full value={count} onChange={setCount} options={[5, 10, 20].map((n) => ({ value: n as AgentCount, label: n }))} />
          </Field>
          <Field label="Driven by" asDiv>
            <Segmented full value={ai ? "ai" : "scripted"} onChange={(v) => setAi(v === "ai")}
              options={[{ value: "scripted", label: "Scripted" }, { value: "ai", label: "AI decides" }]} />
          </Field>
        </div>

        {ai && <div className="mt-4 max-w-md"><GeminiQuota agentCount={count} agentMode="autonomous" /></div>}

        {/* Quick Launch Buttons for Hackathon Demo */}
        <div className="mt-5 flex flex-wrap items-center justify-between gap-3 border-t border-[var(--hairline-subtle)] pt-4">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[13px] font-semibold text-[var(--text-2)]">Demo Attacks:</span>
            <button
              onClick={() => start("coordinated_leakage")}
              disabled={busy}
              className="rounded-full bg-[var(--card-alt)] border border-[var(--hairline-subtle)] px-3 py-1 text-[12px] font-medium text-[var(--text)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
            >
              SG-029 Covert Staged Transfer
            </button>
            <button
              onClick={() => start("unauthorized_access")}
              disabled={busy}
              className="rounded-full bg-[var(--card-alt)] border border-[var(--hairline-subtle)] px-3 py-1 text-[12px] font-medium text-[var(--text)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
            >
              Pre-Execution Policy Refusal
            </button>
          </div>

          <Button onClick={() => start()} busy={busy} variant="primary">
            <Play size={14} className="mr-1 fill-current" />
            <span>Start Live Run</span>
          </Button>
        </div>
      </Card>

      {/* Main Split: Agents Status + Live Telemetry Stream */}
      <div className="grid gap-6 lg:grid-cols-[300px_1fr] [&>*]:min-w-0">
        {/* Left Column: Live Agent Roster */}
        <Card title={running ? "Agents (live)" : "Swarm Agents"}>
          {agents.length ? (
            <>
              <ul className="space-y-2.5 text-[14px]">
                {agents.map(([id, a]) => (
                  <li key={id} className="flex items-center justify-between gap-2 rounded-xl bg-[var(--card-alt)] p-2.5 border border-[var(--hairline-subtle)]/40">
                    <div className="min-w-0">
                      <div className="font-mono text-[13px] font-semibold text-[var(--text)] truncate">{shortId(id)}</div>
                      <div className="text-[12px] text-[var(--text-2)] capitalize">{a.role}</div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge value={a.state === "active" ? "allowed" : a.state === "paused" ? "blocked" : "would_block"} />
                      {running && a.state !== "paused" && (
                        <button
                          className="rounded-md border border-[var(--crit)]/30 bg-[var(--crit-bg)] px-2 py-0.5 text-[11px] font-semibold text-[var(--crit)] hover:bg-[var(--crit)] hover:text-white transition-all disabled:opacity-40"
                          disabled={!!acting}
                          onClick={() => operate(id)}
                          aria-label={`Pause ${id}`}
                        >
                          {acting === id ? "…" : "Pause"}
                        </button>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
              {running && (
                <Button variant="secondary" className="mt-4 w-full" busy={acting === "stop"} onClick={() => operate(null)}>
                  Stop run (contain all)
                </Button>
              )}
              <div className="mt-3 flex items-center justify-between pt-2 border-t border-[var(--hairline-subtle)] text-[12px]">
                <span className="text-[var(--text-3)]">
                  {agents.filter(([, a]) => a.state === "paused").length} paused
                </span>
                <button
                  onClick={handleResetAll}
                  disabled={resetting}
                  className="font-medium text-[var(--link)] hover:underline"
                >
                  Reset &amp; resume all
                </button>
              </div>
            </>
          ) : (
            <Empty>Agents appear when a run starts.</Empty>
          )}
        </Card>

        {/* Right Column: Live Telemetry Stream */}
        <Card title={`Live Feed (${displayCount.toLocaleString()})`}>
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3 border-b border-[var(--hairline-subtle)] pb-3 text-[13px]">
            {/* Filter buttons */}
            <div className="inline-flex rounded-full bg-[var(--hairline-subtle)] p-0.5 text-[12px]">
              <button
                onClick={() => setFeedFilter("all")}
                className={`rounded-full px-3 py-1 font-medium transition-all ${
                  feedFilter === "all" ? "bg-[var(--card)] text-[var(--text)] shadow-xs" : "text-[var(--text-2)]"
                }`}
              >
                All
              </button>
              <button
                onClick={() => setFeedFilter("security")}
                className={`rounded-full px-3 py-1 font-medium transition-all ${
                  feedFilter === "security" ? "bg-[var(--card)] text-[var(--text)] shadow-xs" : "text-[var(--text-2)]"
                }`}
              >
                Detections &amp; Blocks
              </button>
              <button
                onClick={() => setFeedFilter("blocks")}
                className={`rounded-full px-3 py-1 font-medium transition-all ${
                  feedFilter === "blocks" ? "bg-[var(--card)] text-[var(--text)] shadow-xs" : "text-[var(--text-2)]"
                }`}
              >
                Pre-Execution Blocks
              </button>
              <button
                onClick={() => setFeedFilter("containment")}
                className={`rounded-full px-3 py-1 font-medium transition-all ${
                  feedFilter === "containment" ? "bg-[var(--card)] text-[var(--text)] shadow-xs" : "text-[var(--text-2)]"
                }`}
              >
                Containments
              </button>
            </div>

            <div className="flex items-center gap-3">
              <button className="text-[12px] text-[var(--text-3)] hover:text-[var(--text)] underline" onClick={clear}>
                Clear feed
              </button>
              <span className="text-[var(--hairline)]" aria-hidden>·</span>
              <button
                className="text-[12px] font-semibold text-[var(--crit)] hover:underline"
                onClick={handleResetAll}
                disabled={resetting}
              >
                {resetting ? "Resetting…" : "Reset All"}
              </button>
            </div>
          </div>

          {feed.length ? (
            <ol className="max-h-[580px] space-y-2 overflow-y-auto pr-1 text-[14px]" aria-label="Live feed">
              {feed.map((m) => {
                const desc = describe(m as LiveMessage<AnyData>);
                return (
                  <li
                    key={m.seq}
                    className={`rounded-xl p-3 border transition-all ${
                      desc.isCircuitBreaker
                        ? "border-[var(--crit)] bg-[var(--crit-bg)] font-semibold"
                        : desc.isPreBlock
                        ? "border-[var(--accent)]/40 bg-[var(--accent)]/5"
                        : desc.isCovert
                        ? "border-[var(--high)]/40 bg-[var(--high-bg)]"
                        : "border-[var(--hairline-subtle)] bg-[var(--card)]"
                    }`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[11px] text-[var(--text-3)]">#{m.seq}</span>
                        <span className={`rounded-full px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wider ${TONE[m.type] ?? "bg-[var(--low-bg)] text-[var(--text-2)]"}`}>
                          {m.type}
                        </span>

                        {desc.isPreBlock && (
                          <span className="rounded-full bg-[var(--accent)] text-white px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider">
                            Pre-Execution Blocked
                          </span>
                        )}

                        {desc.isCircuitBreaker && (
                          <span className="rounded-full bg-[var(--crit)] text-white px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider">
                            Circuit Breaker Tripped
                          </span>
                        )}

                        {desc.isCovert && (
                          <span className="rounded-full bg-[var(--crit-bg)] text-[var(--crit)] border border-[var(--crit)]/30 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider">
                            SG-029 Covert Transfer
                          </span>
                        )}
                      </div>

                      {m.ts && <span className="font-mono text-[11px] text-[var(--text-3)]">{new Date(m.ts).toLocaleTimeString()}</span>}
                    </div>

                    <div className="mt-1.5 font-medium text-[var(--text)] [overflow-wrap:anywhere]">
                      {desc.title}
                    </div>

                    {desc.subtitle && (
                      <div className="mt-1 text-[13px] text-[var(--text-2)] [overflow-wrap:anywhere]">
                        {desc.subtitle}
                      </div>
                    )}
                  </li>
                );
              })}
            </ol>
          ) : (
            <Empty>Waiting for live telemetry. Click a demo attack above or send events via ingest API.</Empty>
          )}
        </Card>
      </div>
        </>
      )}
    </div>
  );
}
