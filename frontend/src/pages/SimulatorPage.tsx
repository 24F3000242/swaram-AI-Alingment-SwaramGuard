import { useState } from "react";
import { api } from "../api";
import { GeminiQuota } from "../components/GeminiQuota";
import { ResultViewer, type Column } from "../components/ResultViewer";
import { Badge, Button, CustomSelect, Drawer, Field, OutputSelect, PageHeader, Segmented, StatusBanner, inputCls, type Status } from "../components/ui";
import { ThreatMatrixView } from "../components/ThreatMatrixView";
import { shortId, time } from "../lib/format";
import { useAppState, useRunData } from "../state";
import type { AgentCount, GatewayMode, RawEvent, ScenarioConfig } from "../types";
import { Sliders, Copy, Check, Play } from "lucide-react";

// Max 5 columns for pristine table scan without horizontal overflow
const columns: Column<RawEvent>[] = [
  { key: "sequence", label: "#", className: "w-14 font-mono text-[14px]" },
  {
    key: "event_id",
    label: "Event ID",
    render: (e) => <span className="font-mono font-medium">{shortId(e.event_id)}</span>,
  },
  {
    key: "agent_id",
    label: "Agent",
    render: (e) => <span className="font-mono text-[var(--text-2)]">{shortId(e.agent_id)}</span>,
  },
  {
    key: "action",
    label: "Action",
    render: (e) => (
      <div className="flex items-center gap-1.5">
        <span className="font-medium text-[var(--text)]">{e.action}</span>
        <span className="rounded-md bg-[var(--card-alt)] px-1.5 py-0.5 text-[11px] text-[var(--text-3)]">
          {e.event_type}
        </span>
      </div>
    ),
  },
  {
    key: "gateway_decision",
    label: "Gateway",
    render: (e) =>
      e.gateway_decision && e.gateway_decision !== "not_checked" ? (
        <Badge
          value={
            e.gateway_decision === "blocked"
              ? "blocked"
              : e.gateway_decision === "would_block"
              ? "would_block"
              : "allowed"
          }
        />
      ) : (
        <span className="text-[12px] text-[var(--text-3)]">unchecked</span>
      ),
  },
];

const GATEWAY_HELP: Record<GatewayMode, string> = {
  off: "No pre-execution check.",
  monitor: "Gateway checks protected tools before they run, lets them through and records would_block.",
  enforce: "Gateway denies protected tool calls that violate policy before they run (status denied).",
};

export function SimulatorPage() {
  const { meta, selectedRunId, selectRun, refreshRuns } = useAppState();
  const [cfg, setCfg] = useState<ScenarioConfig>({
    scenario_id: "coordinated_leakage",
    agent_count: 5,
    seed: 7,
    gateway_mode: "monitor",
    drop_rate: 0,
    agent_backend: "deterministic",
    agent_mode: "scripted",
    auto_pipeline: false,
    persist: true,
  });

  const [settingsOpen, setSettingsOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [runs, setRuns] = useState(0);
  const [quotaOk, setQuotaOk] = useState(true);
  const [status, setStatus] = useState<Status>(null);
  const [preview, setPreview] = useState<RawEvent[] | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<RawEvent | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [showThreatContract, setShowThreatContract] = useState(false);

  const stored = useRunData(api.rawEvents, selectedRunId);
  const events = preview ?? stored.data;
  const scenario = meta?.scenarios.find((s) => s.scenario_id === cfg.scenario_id);
  const set = <K extends keyof ScenarioConfig>(k: K, v: ScenarioConfig[K]) =>
    setCfg((c) => ({ ...c, [k]: v }));

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  async function run() {
    setBusy(true);
    setStatus(null);
    try {
      const res = await api.simulate(cfg);
      if (cfg.persist) {
        setPreview(null);
        await refreshRuns();
        selectRun(res.run.run_id);
      } else {
        setPreview(res.events);
      }
      setSettingsOpen(false);
      const labels = res.run.labels.malicious_agent_ids.length;
      const c = res.run.counts;
      const ai =
        res.run.agent_mode === "autonomous"
          ? ` AI decisions: ${c.ai_decisions ?? 0}, fallbacks: ${c.ai_fallbacks ?? 0}, refusals: ${c.ai_refusals ?? 0}, violations: ${c.ai_policy_violations ?? 0}${
              c.injection_exposed ? `; injection followed ${c.injection_complied ?? 0}/${c.injection_exposed}` : ""
            }.`
          : "";

      setStatus({
        kind: "success",
        message: (
          <>
            Run <code className="font-mono">{res.run.run_id}</code> emitted {res.events.length} events from {res.agents.length} agents
            {res.run.dropped_event_ids.length ? ` (${res.run.dropped_event_ids.length} dropped)` : ""}; {labels} labeled malicious agent(s).{ai}
            {cfg.persist ? (cfg.auto_pipeline ? " Pipeline ran automatically." : " Saved to raw_events.") : " Preview only, not saved."}
          </>
        ),
      });
    } catch (e) {
      setStatus({ kind: "error", message: (e as Error).message });
    } finally {
      setBusy(false);
      setRuns((n) => n + 1);
    }
  }

  return (
    <div className="space-y-6">
      {/* Page Header without module numbers */}
      <PageHeader
        module="simulator"
        title="Agent simulator"
        description="Runs a multi-agent scenario (scripted, or with each agent's AI deciding) and emits structured JSON events. Protected tool calls pass through a policy gateway before they execute."
      >
        <div className="flex items-center gap-3">
          <button
            onClick={() => setSettingsOpen(true)}
            className="inline-flex h-9 items-center gap-1.5 rounded-full border border-[var(--hairline)]/80 bg-[var(--card)] px-4 text-[14px] font-medium text-[var(--text)] shadow-xs transition-colors hover:border-[var(--hairline)]"
          >
            <Sliders size={14} className="text-[var(--text-3)]" />
            <span>Run settings &rsaquo;</span>
          </button>
          <Button variant="primary" onClick={run} busy={busy}>
            <Play size={14} className="mr-1 fill-current" />
            <span>Run scenario</span>
          </Button>
        </div>
      </PageHeader>

      <StatusBanner status={status} onClose={() => setStatus(null)} />
      {stored.error && (
        <StatusBanner
          status={{ kind: "error", message: stored.error }}
          onClose={() => undefined}
        />
      )}

      {/* Results First: Events Table */}
      <ResultViewer
        title={preview ? "Raw events (preview)" : "Raw events"}
        rows={events}
        columns={columns}
        filename={`raw_events_${preview ? "preview" : selectedRunId}`}
        rowKey={(e) => e.event_id}
        onRowClick={(e) => setSelectedEvent(e)}
        selectedKey={selectedEvent?.event_id}
        empty="Run a simulation to generate raw events."
        extraActions={
          <button
            type="button"
            onClick={() => setShowThreatContract((s) => !s)}
            className="rounded-full border border-[var(--hairline)] bg-[var(--card-alt)] px-3 py-1 text-[12px] font-medium text-[var(--text-2)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
          >
            {showThreatContract ? "Hide telemetry rules" : "20-Rule telemetry contract"}
          </button>
        }
      />

      {showThreatContract && (
        <div className="mt-6">
          <ThreatMatrixView mode="simulator" />
        </div>
      )}

      {/* Run Settings Drawer */}
      <Drawer
        open={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        title="Simulation Settings"
        subtitle="Configure the multi-agent test scenario, swarm size, and gateway interception mode."
      >
        <div className="space-y-5">
          <Field label="Scenario" hint={scenario?.description} asDiv>
            <CustomSelect
              value={cfg.scenario_id}
              onChange={(val) => set("scenario_id", val)}
              options={
                meta?.scenarios.map((s) => ({
                  value: s.scenario_id,
                  label: s.name,
                  description: s.description,
                })) ?? []
              }
              ariaLabel="Select scenario"
            />
          </Field>

          <Field label="Agent count" asDiv>
            <Segmented
              full
              value={cfg.agent_count}
              onChange={(n) => set("agent_count", n)}
              options={(meta?.agent_counts ?? [3, 5, 10, 20]).map((n) => ({
                value: n as AgentCount,
                label: n,
              }))}
            />
          </Field>

          <Field label="Seed" hint="Same seed + scenario = identical event sequence.">
            <input
              type="number"
              className={inputCls}
              value={cfg.seed}
              onChange={(e) => set("seed", Number(e.target.value) || 0)}
            />
          </Field>

          <Field
            label="Agent mode"
            asDiv
            hint={
              cfg.agent_mode === "autonomous"
                ? "Each worker's AI decides its own actions; anything it does outside policy is labeled. Needs an AI backend."
                : "Workers follow fixed normal work; only the attack is scripted."
            }
          >
            <Segmented
              full
              value={cfg.agent_mode ?? "scripted"}
              onChange={(m) => set("agent_mode", m)}
              options={[
                { value: "scripted", label: "Scripted" },
                { value: "autonomous", label: "AI decides" },
              ]}
            />
          </Field>

          <Field label={`Rounds: ${cfg.rounds ?? 2}`}
            hint="Work rounds; the attack lands after round 1. More rounds let agents act on what they remembered (sleeper injections).">
            <input type="range" min={2} max={8} step={1} value={cfg.rounds ?? 2}
              onChange={(e) => set("rounds", Number(e.target.value))} className="w-full" aria-label="Rounds" />
          </Field>

          <Field label="Gateway mode" hint={GATEWAY_HELP[cfg.gateway_mode]} asDiv>
            <CustomSelect
              value={cfg.gateway_mode}
              onChange={(val) => set("gateway_mode", val as GatewayMode)}
              options={[
                { value: "monitor", label: "monitor (would_block)", description: "Log policy evaluation without blocking" },
                { value: "enforce", label: "enforce (deny before execution)", description: "Active interception: deny unauthorized actions" },
                { value: "off", label: "off", description: "Bypass gateway policy checks" },
              ]}
              ariaLabel="Select gateway mode"
            />
          </Field>
          <Field
            label={`Drop rate: ${Math.round(cfg.drop_rate * 100)}%`}
            hint="Randomly drop events to evaluate robustness against log tampering."
          >
            <input
              type="range"
              min={0}
              max={0.9}
              step={0.05}
              value={cfg.drop_rate}
              onChange={(e) => set("drop_rate", Number(e.target.value))}
              className="w-full"
            />
            <label className="mt-2 flex items-center gap-2 text-[14px] text-[var(--text)] cursor-pointer">
              <input
                type="checkbox"
                checked={!!cfg.sensors}
                onChange={(e) => set("sensors", e.target.checked)}
                className="accent-[var(--accent)]"
              />
              Independent sensors (egress proxy, broker log, resource audit), lost separately
            </label>
          </Field>

          <Field
            label="Agent backend"
            asDiv
            hint={
              cfg.agent_mode === "autonomous"
                ? "The model that makes each agent's decisions."
                : "Only formats messages; never used as detection evidence."
            }
          >
            <CustomSelect
              value={cfg.agent_backend}
              onChange={(val) => set("agent_backend", val)}
              options={
                (
                  meta?.agent_backends ?? [
                    { id: "deterministic", label: "Deterministic templates", available: true },
                  ]
                ).map((b) => ({
                  value: b.id,
                  label: b.available ? b.label : `${b.label} (no API key)`,
                  disabled: !b.available,
                }))
              }
              ariaLabel="Select agent backend"
            />
            {cfg.agent_backend === "gemini" && (
              <div className="mt-3"><GeminiQuota agentCount={cfg.agent_count} agentMode={cfg.agent_mode ?? "scripted"} rounds={cfg.rounds ?? 2} refreshKey={runs} onChange={setQuotaOk} /></div>
            )}
          </Field>

          <OutputSelect
            value={cfg.persist}
            onChange={(v) => set("persist", v)}
            collection="raw_events"
          />

          <label className="flex items-center gap-2.5 pt-2 text-[14px] text-[var(--text)]">
            <input
              type="checkbox"
              checked={cfg.auto_pipeline}
              disabled={!cfg.persist}
              onChange={(e) => set("auto_pipeline", e.target.checked)}
            />
            Auto-run collect &rarr; detect &rarr; respond &rarr; evaluate
          </label>
          <div className="pt-4">
            <Button
              variant="primary"
              onClick={run}
              busy={busy}
              disabled={cfg.agent_backend === "gemini" && !quotaOk}
              title={cfg.agent_backend === "gemini" && !quotaOk ? "Not enough Gemini quota for this run" : undefined}
              className="w-full justify-center"
            >
              Run simulation
            </Button>
          </div>
        </div>
      </Drawer>

      {/* Row Click Drawer: Full Event Inspector */}
      <Drawer
        open={Boolean(selectedEvent)}
        onClose={() => setSelectedEvent(null)}
        title={
          <div className="flex items-center gap-2">
            <span className="font-mono text-[16px]">{selectedEvent?.event_id}</span>
            <button
              onClick={() =>
                copyToClipboard(selectedEvent?.event_id || "", "event-id-drawer")
              }
              className="text-[var(--text-3)] hover:text-[var(--text)]"
              title="Copy event ID"
            >
              {copiedId === "event-id-drawer" ? (
                <Check size={14} className="text-[var(--ok)]" />
              ) : (
                <Copy size={14} />
              )}
            </button>
          </div>
        }
        subtitle={
          selectedEvent ? (
            <span className="font-mono text-[12px] text-[var(--text-2)]">
              Sequence #{selectedEvent.sequence} &bull; {time(String(selectedEvent.timestamp))}
            </span>
          ) : undefined
        }
      >
        {selectedEvent && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-2 text-[12px]">
              <div className="rounded-lg bg-[var(--card-alt)] p-2.5">
                <span className="text-[var(--text-3)]">Agent ID</span>
                <div className="font-mono font-medium text-[var(--text)]">
                  {selectedEvent.agent_id}
                </div>
              </div>
              <div className="rounded-lg bg-[var(--card-alt)] p-2.5">
                <span className="text-[var(--text-3)]">Event Type</span>
                <div className="font-mono font-medium text-[var(--text)] capitalize">
                  {selectedEvent.event_type}
                </div>
              </div>
              <div className="rounded-lg bg-[var(--card-alt)] p-2.5">
                <span className="text-[var(--text-3)]">Action</span>
                <div className="font-mono font-medium text-[var(--text)]">
                  {selectedEvent.action}
                </div>
              </div>
              <div className="rounded-lg bg-[var(--card-alt)] p-2.5">
                <span className="text-[var(--text-3)]">Gateway Decision</span>
                <div className="font-mono font-medium text-[var(--text)]">
                  {selectedEvent.gateway_decision ?? "none"}
                </div>
              </div>
            </div>

            {selectedEvent.resource && (
              <div className="rounded-lg bg-[var(--card-alt)] p-2.5 text-[12px]">
                <span className="text-[var(--text-3)]">Target Resource</span>
                <div className="mt-1 font-mono font-medium text-[var(--text)] break-all">
                  {selectedEvent.resource}
                </div>
              </div>
            )}

            <div>
              <div className="flex items-center justify-between pb-1.5">
                <span className="text-[12px] font-semibold text-[var(--text-2)]">
                  Raw Event JSON
                </span>
                <button
                  onClick={() =>
                    copyToClipboard(
                      JSON.stringify(selectedEvent, null, 2),
                      "payload-json-drawer"
                    )
                  }
                  className="inline-flex items-center gap-1 font-mono text-[11px] text-[var(--link)] hover:underline"
                >
                  {copiedId === "payload-json-drawer" ? (
                    <>
                      <Check size={12} /> Copied
                    </>
                  ) : (
                    <>
                      <Copy size={12} /> Copy JSON
                    </>
                  )}
                </button>
              </div>
              <pre className="max-h-[360px] overflow-auto rounded-xl border border-[var(--hairline)]/60 bg-[var(--card-alt)] p-4 font-mono text-[12px] leading-relaxed text-[var(--text)]">
                {JSON.stringify(selectedEvent, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </Drawer>
    </div>
  );
}
