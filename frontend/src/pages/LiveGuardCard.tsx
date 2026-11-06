import { useState } from "react";
import { api } from "../api";
import { GeminiQuota } from "../components/GeminiQuota";
import { Badge, Button, Card, Empty, Field, Segmented, Stat, inputCls } from "../components/ui";
import { shortId } from "../lib/format";
import { useAppState, useRunData } from "../state";
import type { AgentCount, GatewayMode, LiveReport, ReplayCase } from "../types";

type Step = { seq: number; kind: "detect" | "contain"; title: string; detail: string; badge: string };

function timeline(r: LiveReport): Step[] {
  const steps: Step[] = [
    ...r.detections.map((d) => ({ seq: d.sequence, kind: "detect" as const, badge: d.severity,
      title: `${d.rule_id} ${d.rule_name} · ${d.agent_ids.map(shortId).join(", ") || "run"}`, detail: d.reason })),
    ...r.containment.map((c) => ({ seq: c.paused_at_sequence, kind: "contain" as const, badge: c.scope === "egress" ? "held" : "paused",
      title: c.scope === "egress" ? `Egress held: ${shortId(c.agent_id)} (${c.role})` : `Agent paused: ${shortId(c.agent_id)} (${c.role}) at risk ${Math.round(c.risk * 100)}%`,
      detail: `${c.explanation ?? ""} · ${c.blocked_actions} later action(s) denied before execution` })),
  ];
  return steps.sort((a, b) => a.seq - b.seq || (a.kind === "detect" ? -1 : 1));
}

/** Did the replay come out as the benchmark expects? */
function ReplayVerdict({ replayed, report }: { replayed: ReplayCase; report: LiveReport }) {
  const fired = new Set(report.detections.map((d) => d.rule_id));
  const flagged = report.detections.some((d) => d.agent_ids.length);
  const rows = replayed.benign
    ? [{ ok: !flagged, text: "Benign look-alike: no agent flagged" }]
    : [
        { ok: replayed.expect_rules.some((r) => fired.has(r)), text: `Expected rule ${replayed.expect_rules.join(" or ")} fired` },
        { ok: Number(report.metrics.detected_live) >= 1, text: `Culprit (${replayed.culprits.join(" + ")}) flagged live` },
      ];
  return (
    <div className="flex flex-wrap gap-2">
      <span className="rounded-full card-subtle px-3 py-1 text-[14px] text-[var(--text-2)]">{replayed.threat} · {replayed.name}</span>
      {rows.map((r) => (
        <span key={r.text} className={`rounded-full px-3 py-1 text-[14px] font-medium ${r.ok ? "bg-[var(--ok-bg)] text-[var(--ok)] border border-[var(--ok)]/30" : "bg-[var(--crit-bg)] text-[var(--crit)] border border-[var(--crit)]/30"}`}>
          <span className="font-semibold">{r.ok ? "[PASS]" : "[ALERT]"}</span> <span>{r.text}</span>
        </span>
      ))}
    </div>
  );
}

/** Run a scenario with detection streaming alongside it, and show what was caught and stopped in time. */
export function LiveGuardCard() {
  const { selectedRunId, selectRun, refreshRuns, runs, meta } = useAppState();
  // Every simulator scenario except the autonomous user-task mode (that one needs a task, not a live demo).
  const simScenarios = (meta?.scenarios ?? []).filter((s) => s.scenario_id !== "user_directed");
  const stored = useRunData(api.liveReport, selectedRunId);
  const catalog = useRunData(() => api.replayCases(), "replay-cases");
  const [scenario, setScenario] = useState("builtin:coordinated_leakage");
  const [count, setCount] = useState<AgentCount>(5);
  const [mode, setMode] = useState<"contain" | "detect">("contain");
  const [gateway, setGateway] = useState<GatewayMode>("monitor");
  const [ai, setAi] = useState(false);
  const [quotaOk, setQuotaOk] = useState(true);
  const [runsDone, setRunsDone] = useState(0);
  const gemini = meta?.agent_backends?.find((b) => b.id === "gemini");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const report = stored.data;
  const isReplay = scenario.startsWith("replay:");
  const cases = catalog.data ?? [];
  const runScenario = runs.find((r) => r.run_id === report?.run_id)?.scenario_id ?? "";
  const replayed = runScenario.startsWith("replay:") ? cases.find((c) => `replay:${c.name}` === runScenario) : undefined;

  async function run() {
    setBusy(true);
    setError(null);
    try {
      const seed = Math.floor(Math.random() * 1000);  // a different realistic run each time
      const res = isReplay
        ? await api.replay({ case: scenario.slice("replay:".length), agent_count: count, seed, live_guard: mode })
        : await api.simulate({ scenario_id: scenario.slice("builtin:".length), agent_count: count, seed: 7, gateway_mode: gateway,
            drop_rate: 0, agent_backend: ai ? "gemini" : "deterministic", agent_mode: ai ? "autonomous" : "scripted",
            auto_pipeline: true, live_guard: mode, persist: true });
      await refreshRuns();
      selectRun(res.run.run_id);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
      setRunsDone((n) => n + 1);
    }
  }

  const m = report?.metrics ?? {};
  return (
    <Card title="Live guard">
      <p className="mb-5 text-[14px] leading-relaxed text-[var(--text-2)]">
        Detection runs <strong>while the agents act</strong>. Every event is checked as it happens. In <em>contain</em> mode an
        agent reaching {Math.round((report?.pause_at ?? 0.6) * 100)}% risk is paused, and an agent handed restricted data it may not hold
        gets its outbound transfers held. Their next actions are denied <strong>before they execute</strong>.
      </p>
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
        <Field label="Scenario" hint={isReplay ? "Planted into a fresh realistic run at a random point." : undefined}>
          <select className={inputCls} value={scenario} onChange={(e) => setScenario(e.target.value)}>
            <optgroup label={`Simulator scenarios (${simScenarios.length})`}>
              {simScenarios.map((s) => <option key={s.scenario_id} value={`builtin:${s.scenario_id}`}>{s.name}</option>)}
            </optgroup>
            <optgroup label={`Attack replays (${cases.filter((c) => !c.benign).length})`}>
              {cases.filter((c) => !c.benign).map((c) => <option key={c.name} value={`replay:${c.name}`}>{c.threat} · {c.name}</option>)}
            </optgroup>
            <optgroup label={`Benign look-alikes (${cases.filter((c) => c.benign).length})`}>
              {cases.filter((c) => c.benign).map((c) => <option key={c.name} value={`replay:${c.name}`}>{c.name}</option>)}
            </optgroup>
          </select>
        </Field>
        <Field label="Agents" asDiv>
          <Segmented full value={count} onChange={setCount} options={[5, 10, 20].map((n) => ({ value: n as AgentCount, label: n }))} />
        </Field>
        <Field label="Driven by" asDiv hint={isReplay ? "Replays are scripted." : ai ? "Gemini decides each agent's actions (~1 min)." : undefined}>
          <Segmented full value={isReplay ? "scripted" : ai ? "ai" : "scripted"} onChange={(v) => setAi(v === "ai")}
            options={[{ value: "scripted", label: "Scripted" },
              { value: "ai", label: "AI decides", disabled: isReplay || !gemini?.available }]} />
        </Field>
        <Field label="Mode" asDiv>
          <Segmented full value={mode} onChange={setMode} options={[{ value: "contain", label: "Contain" }, { value: "detect", label: "Detect only" }]} />
        </Field>
        <Field label="Static gateway" hint={isReplay ? "Replays run with the gateway monitoring only." : "Monitor shows what the live guard adds on its own."}>
          <select className={inputCls} value={isReplay ? "monitor" : gateway} disabled={isReplay} onChange={(e) => setGateway(e.target.value as GatewayMode)}>
            <option value="monitor">monitor</option>
            <option value="enforce">enforce</option>
          </select>
        </Field>
      </div>
      {ai && !isReplay && (
        <div className="mt-4 max-w-md"><GeminiQuota agentCount={count} agentMode="autonomous" refreshKey={runsDone} onChange={setQuotaOk} /></div>
      )}
      <div className="mt-5 flex items-center justify-end gap-3">
        {error && <span className="text-[14px] text-[var(--crit)]">{error}</span>}
        <Button onClick={run} busy={busy} disabled={ai && !isReplay && !quotaOk}>Run live</Button>
      </div>

      <div className="mt-6 border-t border-[var(--hairline)]/40 pt-6">
        {!report && <Empty>{selectedRunId ? "This run wasn't simulated with the live guard. Click Run live." : "Click Run live to start."}</Empty>}
        {report && (
          <div className="space-y-6">
            <div className="text-[13px] text-[var(--text-3)]">Run <span className="font-mono text-[var(--text)]">{report.run_id}</span> · {report.events_processed} events checked live · mode {report.mode}</div>
            {replayed && <ReplayVerdict replayed={replayed} report={report} />}
            <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
              <Stat label="Data left the system" value={m.data_left_the_system ? "Yes" : "No"} tone={m.data_left_the_system ? "danger" : "ok"} />
              <Stat label="Attack actions stopped" value={`${m.attack_actions_blocked_by_pause ?? 0} / ${m.attack_actions ?? 0}`} />
              <Stat label="Agents contained" value={`${m.paused_malicious ?? 0} / ${m.malicious_agents ?? 0}`} tone={m.paused_innocent ? "danger" : undefined} />
              <Stat label="Detection latency" value={m.mean_latency_events == null ? "n/a" : `${m.mean_latency_events} ev · ${m.mean_latency_s}s`} />
            </div>
            {m.paused_innocent ? <p className="text-[14px] text-[var(--crit)]">{String(m.paused_innocent)} innocent agent(s) were paused.</p> : null}
            <ol className="relative space-y-4 border-l-2 border-[var(--hairline)]/50 pl-5">
              {timeline(report).map((s, i) => (
                <li key={i} className="relative">
                  <span className={`absolute -left-[27px] top-1 h-3 w-3 rounded-full border-2 border-[var(--card)] ${s.kind === "contain" ? "bg-[var(--crit)]" : "bg-[var(--accent)]"}`} />
                  <div className="flex flex-wrap items-center gap-2 text-[14px]">
                    <span className="font-mono text-[var(--text-3)]">#{s.seq}</span>
                    <Badge value={s.badge} />
                    <span className="font-medium text-[var(--text)]">{s.title}</span>
                  </div>
                  <p className="mt-0.5 text-[13px] leading-snug text-[var(--text-2)]">{s.detail}</p>
                </li>
              ))}
              {!report.detections.length && <li className="text-[14px] text-[var(--text-2)]">Nothing suspicious happened; no agent was paused.</li>}
            </ol>
          </div>
        )}
      </div>
    </Card>
  );
}
