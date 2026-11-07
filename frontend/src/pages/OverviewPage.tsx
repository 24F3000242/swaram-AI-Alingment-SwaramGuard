import { useState, useMemo } from "react";
import { useAppState, useRunData } from "../state";
import { api } from "../api";
import { PageHeader } from "../components/PageHeader";
import { Tile } from "../components/Tile";
import { Pill } from "../components/Pill";
import { Stepper } from "../components/Stepper";
import { Footnotes } from "../components/Footnotes";
import { Card, Empty } from "../components/ui";
import { Drawer } from "../components/Drawer";
import { GraphView } from "../components/GraphView";
import { download } from "../lib/export";
import { deriveIncidentTitle, getAgentRole } from "../lib/incidentHelper";
import { ArrowRight, Sparkles, ShieldCheck, ShieldAlert, Clock } from "lucide-react";

export function OverviewPage() {
  const { selectedRunId, runs } = useAppState();
  const dash = useRunData(api.dashboard, selectedRunId);
  const alertsData = useRunData(api.alerts, selectedRunId);
  const responsesData = useRunData(api.responses, selectedRunId);
  const agentsData = useRunData(api.agents, selectedRunId);

  const d = dash.data;
  const currentRun = runs.find((r) => r.run_id === selectedRunId);
  const alerts = alertsData.data ?? [];
  const responses = responsesData.data ?? [];
  const agents = agentsData.data ?? [];
  const [selectedAgentId, setSelectedAgentId] = useState<string | null>(null);
  const selectedAgent = agents.find((a) => a.agent_id === selectedAgentId);
  const selectedAgentAlerts = alerts.filter((alt) => alt.agent_ids.includes(selectedAgentId ?? ""));

  const alertEventIds = useMemo(() => {
    const set = new Set<string>();
    for (const a of alerts) {
      for (const eid of a.event_ids ?? []) set.add(eid);
    }
    return set;
  }, [alerts]);

  const topAlert = alerts[0];
  const totalThreats = d?.totals.threats ?? alerts.length;
  const totalFlagged = d?.totals.flagged_agents ?? currentRun?.labels.malicious_agent_ids.length ?? 0;

  // Severity breakdown
  const critCount = alerts.filter((a) => a.severity === "critical").length;
  const highCount = alerts.filter((a) => a.severity === "high").length;
  const medCount = alerts.filter((a) => a.severity === "medium").length;
  const lowCount = alerts.filter((a) => a.severity === "low").length;

  // Enforced vs simulated counts (enforced ONLY when mode === "enforced" and confirmed enforced)
  const enforcedCount = responses.filter((r) => r.mode === "enforced" && r.enforced).length;
  const simulatedCount = responses.length - enforcedCount;

  // Loading and selection states
  const isNoRun = !selectedRunId;
  const isLoading = !isNoRun && (dash.loading || alertsData.loading);
  const isCleanRun = !isNoRun && !isLoading && totalThreats === 0;
  const isThreatRun = !isNoRun && !isLoading && totalThreats > 0;

  // Pipeline stepper
  const pipelineSteps = [
    { id: "simulated", label: "Simulated", done: !!currentRun?.stages.simulated, time: currentRun?.stages.simulated },
    { id: "collected", label: "Collected", done: !!currentRun?.stages.collected, time: currentRun?.stages.collected },
    { id: "detected", label: "Detected", done: !!currentRun?.stages.detected, time: currentRun?.stages.detected },
    { id: "responded", label: "Responded", done: !!currentRun?.stages.responded, time: currentRun?.stages.responded },
    { id: "evaluated", label: "Evaluated", done: !!currentRun?.stages.evaluated, time: currentRun?.stages.evaluated },
  ];

  const handleExport = () => {
    if (d) {
      download(d, `swaramguard_${selectedRunId}_overview`, "json");
    }
  };

  return (
    <div className="space-y-12">
      {/* Page Header with Quick Links */}
      <PageHeader
        title="SwaramGuard."
        subtitle="Watching how your agents work together, and flagging when they shouldn't."
        quickLinks={[
          { label: "Latest incident", href: topAlert ? `#/incidents/${topAlert.alert_id}` : "#/incidents" },
          { label: "Run a scenario", href: "#/pipeline/simulator" },
          { label: "Export report", href: "#/", onClick: handleExport },
          { label: "See evaluation", href: "#/evaluation" },
        ]}
      />

      {/* Pipeline Stepper Banner */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-[var(--r-card)] card p-4 shadow-[var(--shadow-1)]">
        <div className="flex items-center gap-2 text-[14px] font-medium text-[var(--text-2)]">
          <Sparkles size={16} className="text-[var(--accent)]" />
          {isNoRun ? (
            <span>Pipeline status: <span className="font-medium text-[var(--text)]">No run selected</span>. Launch a scenario to inspect agent telemetry.</span>
          ) : isLoading ? (
            <span>Pipeline status: <span className="font-mono text-[var(--text)]">Loading telemetry for {selectedRunId}...</span></span>
          ) : (
            <span>Pipeline status for <code className="font-mono text-[var(--text)]">{selectedRunId}</code>:</span>
          )}
        </div>
        {!isNoRun && <Stepper steps={pipelineSteps} />}
      </div>

      {/* Hero Verdict Tile - Explicit 4 States */}
      <div className="rounded-[var(--r-tile)] card p-8 shadow-[var(--shadow-1)]">
        <div className="flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
          <div className="max-w-3xl">
            {isNoRun && (
              <>
                <div className="flex items-center gap-2 text-[12px] font-bold uppercase tracking-wider text-[var(--text-3)]">
                  <Clock size={14} />
                  <span>No Run Selected</span>
                </div>
                <h2 className="mt-2 text-[28px] sm:text-[34px] font-semibold leading-tight tracking-tight text-[var(--text)]">
                  No simulation run selected.
                </h2>
                <p className="mt-2 text-[16px] text-[var(--text-2)] leading-relaxed">
                  Select an existing scenario from the top bar or launch a new multi-agent simulation to evaluate communication security and threat containment.
                </p>
              </>
            )}

            {isLoading && (
              <>
                <div className="flex items-center gap-2 text-[12px] font-bold uppercase tracking-wider text-[var(--accent)]">
                  <Clock size={14} className="animate-spin" />
                  <span>Loading Run Telemetry</span>
                </div>
                <h2 className="mt-2 text-[28px] sm:text-[34px] font-semibold leading-tight tracking-tight text-[var(--text)]">
                  Analyzing {selectedRunId}...
                </h2>
                <p className="mt-2 text-[16px] text-[var(--text-2)] leading-relaxed">
                  Correlating agent topology, behavioral baselines, and security policies for this run.
                </p>
              </>
            )}

            {isCleanRun && (
              <>
                <div className="flex items-center gap-2 text-[12px] font-bold uppercase tracking-wider text-[var(--ok)]">
                  <ShieldCheck size={14} />
                  <span>Clean Run Verified</span>
                </div>
                <h2 className="mt-2 text-[28px] sm:text-[34px] font-semibold leading-tight tracking-tight text-[var(--text)]">
                  No suspicious behavior detected in {selectedRunId}.
                </h2>
                <p className="mt-2 text-[16px] text-[var(--text-2)] leading-relaxed">
                  All {currentRun?.agent_count ?? "participating"} agents operated strictly within learned behavioral baselines and established security policies.
                </p>
              </>
            )}

            {isThreatRun && (
              <>
                <div className="flex items-center gap-2 text-[12px] font-bold uppercase tracking-wider text-[var(--crit)]">
                  <ShieldAlert size={14} />
                  <span>Threats Detected</span>
                </div>
                <h2 className="mt-2 text-[28px] sm:text-[34px] font-semibold leading-tight tracking-tight text-[var(--text)]">
                  {totalThreats} incident{totalThreats === 1 ? "" : "s"} detected in {selectedRunId}. {totalFlagged} agent{totalFlagged === 1 ? "" : "s"} flagged.
                </h2>

                {/* Severity Breakdown Dots */}
                <div className="mt-4 flex flex-wrap items-center gap-4 text-[14px] text-[var(--text-2)]">
                  {critCount > 0 && (
                    <span className="flex items-center gap-1.5">
                      <span className="h-2.5 w-2.5 rounded-full bg-[var(--crit)]" />
                      <strong>{critCount}</strong> critical
                    </span>
                  )}
                  {highCount > 0 && (
                    <span className="flex items-center gap-1.5">
                      <span className="h-2.5 w-2.5 rounded-full bg-[var(--high)]" />
                      <strong>{highCount}</strong> high
                    </span>
                  )}
                  {medCount > 0 && (
                    <span className="flex items-center gap-1.5">
                      <span className="h-2.5 w-2.5 rounded-full bg-[var(--med)]" />
                      <strong>{medCount}</strong> medium
                    </span>
                  )}
                  {lowCount > 0 && (
                    <span className="flex items-center gap-1.5">
                      <span className="h-2.5 w-2.5 rounded-full bg-[var(--low)]" />
                      <strong>{lowCount}</strong> low
                    </span>
                  )}
                </div>
              </>
            )}
          </div>

          <div className="shrink-0">
            {topAlert ? (
              <a
                href={`#/incidents/${topAlert.alert_id}`}
                className="inline-flex h-12 items-center gap-2 rounded-full bg-[var(--accent)] px-7 text-[15px] font-medium text-white shadow-xs transition-colors hover:bg-[var(--accent-hover)]"
              >
                <span>Open incident</span>
                <ArrowRight size={16} />
              </a>
            ) : (
              <a
                href="#/pipeline/simulator"
                className="inline-flex h-12 items-center gap-2 rounded-full bg-[var(--accent)] px-7 text-[15px] font-medium text-white shadow-xs transition-colors hover:bg-[var(--accent-hover)]"
              >
                <span>Launch simulation</span>
                <ArrowRight size={16} />
              </a>
            )}
          </div>
        </div>
      </div>

      {/* 4 Stat Tiles */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Tile
          label="Agents active"
          value={isNoRun ? "—" : isLoading ? "..." : (d?.totals.agents ?? currentRun?.agent_count ?? "—")}
          subtext={isNoRun ? "No run loaded" : "Participating in scenario"}
        />
        <Tile
          label="Total events"
          value={isNoRun ? "—" : isLoading ? "..." : (d?.totals.events ?? currentRun?.counts.normalized_events ?? "—")}
          subtext={isNoRun ? "No run loaded" : "Normalized & verified"}
        />
        <Tile
          label="Incidents"
          value={isNoRun ? "—" : isLoading ? "..." : totalThreats}
          tone={isNoRun ? "normal" : isCleanRun ? "ok" : isThreatRun ? "crit" : "normal"}
          subtext={
            isNoRun
              ? "No run loaded"
              : isLoading
              ? "Evaluating..."
              : isCleanRun
              ? "Clean run (0 threats)"
              : `${totalFlagged} suspicious actor(s)`
          }
        />
        <Tile
          label="Responses recorded"
          value={isNoRun ? "—" : isLoading ? "..." : responses.length}
          subtext={
            isNoRun
              ? "No run loaded"
              : enforcedCount > 0
              ? `${enforcedCount} enforced at gateway`
              : "Simulated decisions‡"
          }
        />
      </div>

      {/* Swarm Communication Topology (Models Graph) */}
      <Card
        title="Swarm communication topology"
        actions={
          <a
            href="#/swarm"
            className="inline-flex items-center gap-1 text-[13px] font-medium text-[var(--link)] hover:underline"
          >
            <span>Explore full topology</span>
            <ArrowRight size={14} />
          </a>
        }
      >
        <div className="py-2">
          {isNoRun ? (
            <Empty>Select a simulation run from the top bar to inspect agent communication topology.</Empty>
          ) : isLoading ? (
            <Empty>Loading communication topology for {selectedRunId}...</Empty>
          ) : d?.graph ? (
            <GraphView
              graph={d.graph}
              height={400}
              alertEventIds={alertEventIds}
              selectedNodeId={selectedAgentId}
              onSelectNode={(nodeId) => {
                if (!nodeId.startsWith("external:")) {
                  setSelectedAgentId(nodeId);
                }
              }}
            />
          ) : (
            <Empty>No communication topology recorded for this run.</Empty>
          )}
        </div>
      </Card>

      {/* Two Columns: Latest Incidents & Operating Mode */}
      <div className="grid gap-6 lg:grid-cols-3">
        {/* Latest Incidents List */}
        <div className="lg:col-span-2 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-[21px] font-semibold text-[var(--text)]">Recent incidents</h3>
            {alerts.length > 3 && (
              <a href="#/incidents" className="text-[14px] font-medium text-[var(--link)] hover:underline">
                View all {alerts.length} &rsaquo;
              </a>
            )}
          </div>

          {isNoRun && (
            <Card>
              <Empty>No scenario run is selected. Choose a run from the top bar or simulate a new scenario to inspect incidents.</Empty>
            </Card>
          )}

          {isLoading && (
            <Card>
              <Empty>Loading incidents for {selectedRunId}...</Empty>
            </Card>
          )}

          {isCleanRun && (
            <Card>
              <Empty>No incidents detected in this run. All agents operated within established security baselines.</Empty>
            </Card>
          )}

          {isThreatRun && (
            <div className="space-y-3">
              {alerts.slice(0, 3).map((a) => (
                <a
                  key={a.alert_id}
                  href={`#/incidents/${a.alert_id}`}
                  className="block rounded-[var(--r-card)] card p-5 shadow-[var(--shadow-1)] transition-all hover:border-[var(--accent)] hover:shadow-md"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <Pill value={a.severity} />
                        <span className="font-mono text-[12px] text-[var(--text-3)]">{a.rule_id}</span>
                      </div>
                      <div className="mt-2 text-[16px] font-semibold text-[var(--text)]">
                        {deriveIncidentTitle(a, agents)}
                      </div>
                      <div className="mt-1 flex flex-wrap items-center gap-2 text-[14px] text-[var(--text-2)]">
                        <span>Roles: {a.agent_ids.map((id) => getAgentRole(id, agents)).join(", ")}</span>
                        <span>&middot;</span>
                        <span>Target: {a.resource}</span>
                      </div>
                    </div>
                    <span className="text-[14px] text-[var(--link)] font-medium">Inspect &rsaquo;</span>
                  </div>
                </a>
              ))}
            </div>
          )}
        </div>

        {/* Operating Mode Honesty Card */}
        <div className="space-y-4">
          <h3 className="text-[21px] font-semibold text-[var(--text)]">Enforcement mode</h3>
          <Card>
            <div className="space-y-4 text-[14px]">
              <div className="rounded-xl card p-4">
                <div className="text-[12px] font-bold uppercase tracking-wider text-[var(--text-3)]">
                  Gateway Mode: {isNoRun ? "None" : (currentRun?.gateway_mode ?? "monitor")}
                </div>
                <div className="mt-2 text-[15px] font-medium text-[var(--text)]">
                  {isNoRun ? (
                    <span className="text-[var(--text-2)]">No run loaded. Gateway is idle.</span>
                  ) : enforcedCount > 0 ? (
                    <span className="text-[var(--ok)]">
                      {enforcedCount} action(s) blocked at gateway.
                    </span>
                  ) : (
                    <span className="text-[var(--text-2)]">
                      All {responses.length} response decisions were simulated. No tool calls were terminated.‡
                    </span>
                  )}
                </div>
              </div>

              <div className="space-y-2 text-[14px] text-[var(--text-2)]">
                <div className="flex justify-between py-1 border-b border-[var(--hairline)]/30">
                  <span>Simulated decisions (replay)</span>
                  <strong className="font-mono text-[var(--text)]">{isNoRun ? "—" : simulatedCount}</strong>
                </div>
                <div className="flex justify-between py-1 border-b border-[var(--hairline)]/30">
                  <span>Enforced at gateway</span>
                  <strong className="font-mono text-[var(--ok)]">{isNoRun ? "—" : enforcedCount}</strong>
                </div>
                <div className="flex justify-between py-1">
                  <span>Pre-execution coverage</span>
                  <strong className="font-mono text-[var(--text)]">
                    {isNoRun
                      ? "—"
                      : d?.evaluation?.enforced_containment_rate != null
                      ? `${(d.evaluation.enforced_containment_rate * 100).toFixed(0)}%`
                      : "0%"}
                  </strong>
                </div>
              </div>
            </div>
          </Card>
        </div>
      </div>

      {/* Agent Dossier Slide-Over Drawer */}
      <Drawer
        open={!!selectedAgent}
        onClose={() => setSelectedAgentId(null)}
        title={selectedAgent ? `Agent ${selectedAgent.agent_id} Dossier` : "Agent Dossier"}
        subtitle={`Role: ${selectedAgent?.role ?? "Unknown"} · Baseline: ${selectedAgent?.is_malicious ? "Malicious" : "Normal"}`}
      >
        {selectedAgent && (
          <div className="space-y-6">
            <div className="flex items-center justify-between rounded-xl bg-[var(--card-alt)] p-4 border border-[var(--hairline)]/60">
              <div>
                <span className="text-[11px] font-bold uppercase tracking-wider text-[var(--text-3)]">
                  Swarm Identity
                </span>
                <div className="mt-0.5 font-mono text-[16px] font-semibold text-[var(--text)]">
                  {selectedAgent.agent_id}
                </div>
                <div className="text-[13px] text-[var(--text-2)] capitalize">
                  Role: {selectedAgent.role}
                </div>
              </div>
              <div className="text-right">
                <span className="text-[11px] font-bold uppercase tracking-wider text-[var(--text-3)]">
                  Status
                </span>
                <div className="mt-0.5">
                  {selectedAgentAlerts.length > 0 ? (
                    <span className="inline-flex items-center gap-1 rounded-full bg-[var(--crit-bg)] text-[var(--crit)] px-2.5 py-0.5 text-[11px] font-bold uppercase tracking-wider">
                      Flagged Threat ({selectedAgentAlerts.length})
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 rounded-full bg-[var(--ok-bg)] text-[var(--ok)] px-2.5 py-0.5 text-[11px] font-bold uppercase tracking-wider">
                      Baseline Normal
                    </span>
                  )}
                </div>
              </div>
            </div>

            {/* Assigned Role Permissions */}
            <div className="space-y-2">
              <h4 className="text-[14px] font-semibold text-[var(--text)]">Assigned Permissions</h4>
              <div className="flex flex-wrap gap-1.5">
                {selectedAgent.permissions && selectedAgent.permissions.length > 0 ? (
                  selectedAgent.permissions.map((perm) => (
                    <span key={perm} className="rounded-lg bg-[var(--card-alt)] border border-[var(--hairline)]/60 px-2.5 py-1 font-mono text-[12px] text-[var(--text-2)]">
                      {perm}
                    </span>
                  ))
                ) : (
                  <span className="text-[13px] text-[var(--text-3)]">Standard baseline role permissions</span>
                )}
              </div>
            </div>

            {/* Associated Incident Alerts */}
            {selectedAgentAlerts.length > 0 ? (
              <div className="space-y-3">
                <h4 className="text-[14px] font-semibold text-[var(--crit)]">Attributed Incidents ({selectedAgentAlerts.length})</h4>
                <div className="space-y-2">
                  {selectedAgentAlerts.map((alt) => (
                    <a
                      key={alt.alert_id}
                      href={`#/incidents/${alt.alert_id}`}
                      className="block rounded-xl border border-[var(--hairline)] bg-[var(--card)] p-3.5 transition-all hover:border-[var(--accent)] hover:shadow-xs"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Pill value={alt.severity} />
                          <span className="font-mono text-[12px] text-[var(--text-3)]">{alt.rule_id}</span>
                        </div>
                        <span className="text-[13px] font-medium text-[var(--link)]">Inspect &rsaquo;</span>
                      </div>
                      <div className="mt-2 text-[13px] font-medium text-[var(--text)]">{alt.reason}</div>
                    </a>
                  ))}
                </div>
              </div>
            ) : (
              <div className="rounded-xl border border-[var(--hairline)]/60 bg-[var(--card-alt)] p-4 text-[13px] text-[var(--text-2)]">
                No security alerts attributed to this agent. All recorded actions conformed to learned behavioral baselines.
              </div>
            )}
          </div>
        )}
      </Drawer>

      {/* Apple-style Footnotes block */}
      <Footnotes symbols={["†", "‡"]} />
    </div>
  );
}
