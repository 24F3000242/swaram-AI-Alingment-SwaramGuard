import { useMemo, useState } from "react";
import { api } from "../api";
import { GeminiQuota } from "../components/GeminiQuota";
import { PageHeader } from "../components/PageHeader";
import { Badge, Button, Card, Empty, Field, Segmented, StatusBanner, inputCls, type Status } from "../components/ui";
import { shortId } from "../lib/format";
import { type LiveMessage, useLiveStream } from "../lib/live";
import { useAppState } from "../state";
import type { AgentCount } from "../types";

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
};

function describe(m: LiveMessage<AnyData>): string {
  const d = m.data;
  switch (m.type) {
    case "event":
      return `${shortId(d.agent_id)} ${d.event_type}:${d.action} ${d.resource ?? d.target ?? ""}${d.status === "denied" ? " — BLOCKED" : ""}`;
    case "detection":
      return `${d.rule_id} ${d.rule_name} · ${(d.agent_ids ?? []).map(shortId).join(", ") || "run-level"} · ${d.reason}`;
    case "containment":
      return `${d.scope === "egress" ? "Egress held" : "Agent paused"}: ${shortId(d.agent_id)} (${d.role}) · ${d.explanation ?? ""}`;
    case "quarantine":
      return `Quarantined input for ${shortId(d.agent_id)}: ${d.resource} (claims to be from ${d.claimed_sender})`;
    case "run_started":
      return `Run started: ${d.config?.scenario_id ?? ""}`;
    case "run_finished":
      return `Run finished · ${d.live_metrics ? `data left the system: ${d.live_metrics.data_left_the_system ? "yes" : "no"}` : "no live guard"}`;
    case "run_failed":
      return `Run failed: ${d.error}`;
    case "response":
      return `Policy: ${d.rule_id} → ${d.decision} · ${(d.agent_ids ?? []).map(shortId).join(", ") || "run-level"} · ${(d.applied ?? []).join(", ")}`;
    case "operator":
      return `Operator ${d.action} ${shortId(d.agent_id)}: ${d.result}`;
    case "review":
      return `Review ${d.action}: ${shortId(d.item?.agent_id)} (${d.item?.kind})${d.item?.status !== "pending" ? ` → ${d.item?.status}` : ""}`;
    default:
      return m.type;
  }
}

/** Live monitor: everything that happens in any run, pushed as it happens (reference UI for the live stream). */
export function LivePage() {
  const { meta } = useAppState();
  const { messages, connected, clear } = useLiveStream();
  const [scenario, setScenario] = useState("sg003_leak_chain");
  const [count, setCount] = useState<AgentCount>(5);
  const [ai, setAi] = useState(false);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<Status>(null);
  const [showEvents, setShowEvents] = useState(true);

  // The most recent run: its agents, their live state, and whether it is still running (operator controls).
  const { liveRun, running, agents } = useMemo(() => {
    let run: string | null = null;
    let open = false;
    let out = new Map<string, { role: string; state: string }>();
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
      } else if (m.run_id === run && m.type === "review" && m.data.item?.status === "released" && out.has(m.data.item.agent_id)) {
        out.get(m.data.item.agent_id)!.state = "active";
      }
    }
    return { liveRun: run, running: open, agents: [...out.entries()] };
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
  const feed = (messages as LiveMessage<AnyData>[]).filter((m) => showEvents || m.type !== "event").slice(-200).reverse();

  async function start() {
    setBusy(true);
    setStatus(null);
    try {
      const r = await api.startRun({ scenario_id: scenario, agent_count: count, seed: Math.floor(Math.random() * 1000),
        gateway_mode: "monitor", drop_rate: 0, agent_backend: ai ? "gemini" : "deterministic",
        agent_mode: ai ? "autonomous" : "scripted", auto_pipeline: true, live_guard: "contain", persist: true });
      setStatus({ kind: "success", message: <>Started <code className="font-mono">{r.run_id}</code>; watch it below.</> });
    } catch (e) {
      setStatus({ kind: "error", message: (e as Error).message });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="min-w-0 space-y-5">
      <PageHeader title="Live."
        subtitle="Every action, detection, pause and quarantine as it happens, from simulated runs and from real agents reporting through the ingest API. Pause any agent, or stop the whole run." />
      <StatusBanner status={status} onClose={() => setStatus(null)} />
      <Card title="Start a run">
        <div className="grid gap-4 sm:grid-cols-3 [&>*]:min-w-0">
          <Field label="Scenario">
            <select className={inputCls} value={scenario} onChange={(e) => setScenario(e.target.value)}>
              {meta?.scenarios.filter((s) => s.scenario_id !== "user_directed").map((s) => <option key={s.scenario_id} value={s.scenario_id}>{s.name}</option>)}
            </select>
          </Field>
          <Field label="Agents" asDiv>
            <Segmented full value={count} onChange={setCount} options={[5, 10, 20].map((n) => ({ value: n as AgentCount, label: n }))} />
          </Field>
          <Field label="Driven by" asDiv>
            <Segmented full value={ai ? "ai" : "scripted"} onChange={(v) => setAi(v === "ai")}
              options={[{ value: "scripted", label: "Scripted" }, { value: "ai", label: "AI decides" }]} />
          </Field>
        </div>
        {ai && <div className="mt-4 max-w-md"><GeminiQuota agentCount={count} agentMode="autonomous" /></div>}
        <div className="mt-5 flex items-center justify-between gap-3">
          <span className="flex items-center gap-2 text-[13px] text-muted">
            <span className={`h-2.5 w-2.5 rounded-full ${connected ? "bg-[var(--ok)]" : "bg-[var(--crit)]"}`} />
            {connected ? "Live stream connected" : "Connecting…"}
          </span>
          <Button onClick={start} busy={busy}>Start live run</Button>
        </div>
      </Card>

      <div className="grid gap-5 lg:grid-cols-[260px_1fr] [&>*]:min-w-0">
        <Card title={running ? "Agents (live)" : "Agents"}>
          {agents.length ? (
            <>
              <ul className="space-y-2 text-[13px]">
                {agents.map(([id, a]) => (
                  <li key={id} className="flex items-center justify-between gap-2">
                    <span className="min-w-0"><span className="font-mono">{shortId(id)}</span> <span className="text-muted">{a.role}</span></span>
                    <span className="flex items-center gap-2">
                      <Badge value={a.state === "active" ? "allowed" : a.state === "paused" ? "blocked" : "would_block"} />
                      {running && a.state !== "paused" && (
                        <button className="text-[12px] font-medium text-[var(--crit)] hover:underline disabled:opacity-40"
                          disabled={!!acting} onClick={() => operate(id)} aria-label={`Pause ${id}`}>
                          {acting === id ? "…" : "Pause"}
                        </button>
                      )}
                    </span>
                  </li>
                ))}
              </ul>
              {running && (
                <Button variant="secondary" className="mt-4 w-full" busy={acting === "stop"} onClick={() => operate(null)}>
                  Stop run (pause every agent)
                </Button>
              )}
              {!running && <p className="mt-3 text-[12px] text-faint">The run has finished; decisions go to the review queue on Responses.</p>}
            </>
          ) : <Empty>Agents appear when a run starts.</Empty>}
        </Card>
        <Card title={`Live feed (${messages.length})`}>
          <div className="mb-3 flex items-center justify-between text-[12px] text-muted">
            <label className="flex items-center gap-2"><input type="checkbox" checked={showEvents} onChange={(e) => setShowEvents(e.target.checked)} /> Show every event</label>
            <button className="underline" onClick={clear}>Clear</button>
          </div>
          {feed.length ? (
            <ol className="max-h-[560px] space-y-1.5 overflow-y-auto text-[13px]" aria-label="Live feed">
              {feed.map((m) => (
                <li key={m.seq} className="flex items-start gap-2">
                  <span className="w-12 shrink-0 font-mono text-[11px] text-faint">#{m.seq}</span>
                  <span className={`shrink-0 rounded-full px-2 py-0.5 text-[11px] font-medium ${TONE[m.type] ?? "bg-[var(--low-bg)] text-muted"}`}>{m.type}</span>
                  <span className={`min-w-0 [overflow-wrap:anywhere] ${m.type === "event" && (m.data as AnyData).status === "denied" ? "text-[var(--crit)]" : "text-ink"}`}>{describe(m as LiveMessage<AnyData>)}</span>
                </li>
              ))}
            </ol>
          ) : <Empty>Waiting for activity. Start a run, or send events through the ingest API.</Empty>}
        </Card>
      </div>
    </div>
  );
}
