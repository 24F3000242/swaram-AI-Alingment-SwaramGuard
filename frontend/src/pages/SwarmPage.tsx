import { useState, useEffect } from "react";
import { useAppState, useRunData } from "../state";
import { api } from "../api";
import { PageHeader } from "../components/PageHeader";
import { GraphView } from "../components/GraphView";
import { Timeline } from "../components/Timeline";
import { Drawer } from "../components/Drawer";
import { Footnotes } from "../components/Footnotes";
import { Card, Empty } from "../components/ui";
import { shortId, time, pct } from "../lib/format";
import { Cpu, Copy, Check, ExternalLink } from "lucide-react";
import type { NormalizedEvent, Agent } from "../types";

export function SwarmPage({ hideHeader = false }: { hideHeader?: boolean } = {}) {
  const { selectedRunId } = useAppState();
  const dashData = useRunData(api.dashboard, selectedRunId);
  const assessmentsData = useRunData(api.assessments, selectedRunId);
  const alertsData = useRunData(api.alerts, selectedRunId);
  const eventsData = useRunData(api.normalizedEvents, selectedRunId);
  const agentsData = useRunData(api.agents, selectedRunId);

  const [selectedAgentId, setSelectedAgentId] = useState<string | null>(null);
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Reset selected agent and event drawer when run changes to prevent stale data
  useEffect(() => {
    setSelectedAgentId(null);
    setSelectedEventId(null);
  }, [selectedRunId]);

  const d = dashData.data;
  const assessments = assessmentsData.data ?? [];
  const alerts = alertsData.data ?? [];
  const events = eventsData.data ?? [];
  const agents: Agent[] = agentsData.data ?? [];
  const selectedAgent = agents.find((a: Agent) => a.agent_id === selectedAgentId);
  const selectedAssessment = assessments.find((ass) => ass.agent_id === selectedAgentId);
  const agentAlerts = alerts.filter((alt) => selectedAgentId && alt.agent_ids.includes(selectedAgentId));
  const agentEvents = events.filter((evt) => evt.agent_id === selectedAgentId);

  const selectedEvent: NormalizedEvent | undefined = events.find(
    (e) => e.event_id === selectedEventId
  );

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="space-y-12">
      {/* 56px Title / 21px Subtitle with quick link */}
      {!hideHeader && (
        <PageHeader
          title="Swarm."
          subtitle="Agent communication topology, event swimlane, and role-based anomaly profiles."
          actions={
            <a
              href="#/incidents"
              className="inline-flex h-9 items-center rounded-full card px-4 text-[14px] font-medium text-[var(--text)] shadow-xs transition-colors hover:border-[var(--text-3)]"
            >
              <span>View incidents &rsaquo;</span>
            </a>
          }
        />
      )}

      {!d && (
        <Card>
          <Empty>
            {selectedRunId
              ? `Loading swarm telemetry for ${selectedRunId}...`
              : "No scenario run is selected. Choose a run from the top bar to inspect swarm agents."}
          </Empty>
        </Card>
      )}

      {d && (
        <>
          {/* Section 1: Full-width Graph (min 520px tall) */}
          <section className="space-y-4">
            <div className="flex items-baseline justify-between">
              <div>
                <h2 className="text-[21px] font-semibold tracking-tight text-[var(--text)]">
                  Communication topology
                </h2>
                <p className="text-[14px] text-[var(--text-2)]">
                  Directed message graph and external sinks. Suspicious data transfers pulse in red.
                </p>
              </div>
              <span className="font-mono text-[13px] text-[var(--text-3)]">
                {d.graph.nodes.length} nodes &bull; {d.graph.edges.length} connections
              </span>
            </div>

            <div className="rounded-[var(--r-card)] card p-4 shadow-[var(--shadow-1)]">
              <GraphView
                graph={d.graph}
                height={520}
                alertEventIds={new Set(alerts.flatMap((a) => a.event_ids))}
                selectedNodeId={selectedAgentId}
                onSelectNode={(nodeId) => {
                  if (nodeId.startsWith("external:")) {
                    return;
                  }
                  setSelectedAgentId(nodeId);
                }}
              />
            </div>
          </section>

          {/* Section 2: Timeline Swimlane under graph */}
          <section className="space-y-4">
            <div className="flex items-baseline justify-between">
              <div>
                <h2 className="text-[21px] font-semibold tracking-tight text-[var(--text)]">
                  Execution swimlane
                </h2>
                <p className="text-[14px] text-[var(--text-2)]">
                  Chrono-ordered event distribution per agent. Flagged threat events carry a red halo.
                </p>
              </div>
              <span className="font-mono text-[13px] text-[var(--text-3)]">
                {d.timeline.length} normalized events
              </span>
            </div>

            <div className="rounded-[var(--r-card)] card p-4 shadow-[var(--shadow-1)]">
              <Timeline
                items={d.timeline}
                selectedEventId={selectedEventId}
                onSelect={(evtId) => setSelectedEventId(evtId)}
              />
            </div>
          </section>

          {/* Section 3: Agent Tiles (Grid, 3 across) */}
          <section className="space-y-4">
            <div>
              <h2 className="text-[21px] font-semibold tracking-tight text-[var(--text)]">
                Agent anomaly profiles
              </h2>
              <p className="text-[14px] text-[var(--text-2)]">
                Assessed Bayesian risk and behavioral deviations against learned role baselines.
              </p>
            </div>

            <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
              {agents.map((agent) => {
                const assessment = assessments.find((a) => a.agent_id === agent.agent_id);
                const isFlagged = d.flagged_agents.some((fa) => fa.agent_id === agent.agent_id);
                const matchedAlerts = alerts.filter((alt) => alt.agent_ids.includes(agent.agent_id));
                const totalAgentEvents = events.filter((e) => e.agent_id === agent.agent_id);
                const toolCalls = totalAgentEvents.filter((e) => e.event_type === "tool_call");

                const riskPercent = assessment?.risk != null ? Math.round(assessment.risk * 100) : 0;

                return (
                  <div
                    key={agent.agent_id}
                    onClick={() => setSelectedAgentId(agent.agent_id)}
                    className={`group cursor-pointer rounded-[var(--r-tile)] card p-6 transition-all hover:-translate-y-0.5 hover:shadow-[var(--shadow-2)] ${
                      isFlagged
                        ? "!border-[var(--crit)]/80 shadow-[0_2px_12px_rgba(215,0,21,0.08)]"
                        : "hover:border-[var(--text-3)]"
                    }`}
                  >
                    {/* Top Row: Name, Status Dot, Role */}
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="flex items-center gap-2">
                          <span
                            className={`h-2.5 w-2.5 rounded-full ${
                              isFlagged ? "bg-[var(--crit)] animate-pulse" : "bg-[var(--ok)]"
                            }`}
                          />
                          <h3 className="text-[18px] font-semibold tracking-tight text-[var(--text)]">
                            {agent.name}
                          </h3>
                        </div>
                        <div className="mt-1 font-mono text-[13px] text-[var(--text-3)]">
                          {shortId(agent.agent_id)}
                        </div>
                      </div>

                      {/* Status indicator badge */}
                      {isFlagged ? (
                        <span className="rounded-full border border-[var(--crit)]/40 bg-[var(--crit-bg)] px-2.5 py-0.5 text-[12px] font-semibold tracking-wide text-[var(--crit)]">
                          Flagged
                        </span>
                      ) : (
                        <span className="rounded-full border border-[var(--ok)]/40 bg-[var(--ok-bg)] px-2.5 py-0.5 text-[12px] font-semibold tracking-wide text-[var(--ok)]">
                          Normal
                        </span>
                      )}
                    </div>

                    {/* Role badge */}
                    <div className="mt-4 flex items-center justify-between border-t border-[var(--hairline)]/40 pt-3">
                      <span className="text-[14px] text-[var(--text-2)]">Assigned role</span>
                      <span className="rounded-md card-subtle px-2.5 py-1 text-[14px] font-semibold text-[var(--text)]">
                        {agent.role}
                      </span>
                    </div>

                    {/* Risk Score */}
                    <div className="mt-3 flex items-center justify-between">
                      <span className="text-[14px] text-[var(--text-2)]">Bayesian risk score†</span>
                      <span
                        className={`font-mono text-[18px] font-bold ${
                          riskPercent >= 70
                            ? "text-[var(--crit)]"
                            : riskPercent >= 40
                            ? "text-[var(--high)]"
                            : "text-[var(--text)]"
                        }`}
                      >
                        {riskPercent}%
                      </span>
                    </div>

                    {/* Mini Counts Grid */}
                    <div className="mt-4 grid grid-cols-3 gap-2 rounded-xl card-subtle p-3 text-center">
                      <div>
                        <div className="font-mono text-[16px] font-semibold text-[var(--text)]">
                          {totalAgentEvents.length}
                        </div>
                        <div className="text-[12px] text-[var(--text-3)]">Events</div>
                      </div>
                      <div>
                        <div className="font-mono text-[16px] font-semibold text-[var(--text)]">
                          {toolCalls.length}
                        </div>
                        <div className="text-[12px] text-[var(--text-3)]">Tools</div>
                      </div>
                      <div>
                        <div
                          className={`font-mono text-[16px] font-semibold ${
                            matchedAlerts.length > 0 ? "text-[var(--crit)]" : "text-[var(--text)]"
                          }`}
                        >
                          {matchedAlerts.length}
                        </div>
                        <div className="text-[12px] text-[var(--text-3)]">Threats</div>
                      </div>
                    </div>

                    <div className="mt-4 flex items-center justify-end text-[14px] font-medium text-[var(--link)] group-hover:underline">
                      Inspect telemetry &rsaquo;
                    </div>
                  </div>
                );
              })}
            </div>
          </section>

          {/* Footnotes */}
          <Footnotes symbols={["†", "‡"]} />
        </>
      )}

      {/* Drawer 1: Agent Telemetry & Anomaly Inspector */}
      <Drawer
        open={Boolean(selectedAgentId)}
        onClose={() => setSelectedAgentId(null)}
        title={
          <div className="flex items-center gap-2">
            <Cpu size={20} className="text-[var(--accent)]" />
            <span>{selectedAgent?.name || selectedAgentId}</span>
          </div>
        }
        subtitle={
          <div className="flex items-center gap-2">
            <span className="font-mono text-[13px] text-[var(--text-3)]">
              {selectedAgentId}
            </span>
            <button
              onClick={() => copyToClipboard(selectedAgentId || "", "agent-id")}
              className="inline-flex items-center text-[var(--text-3)] hover:text-[var(--text)]"
              title="Copy ID"
            >
              {copiedId === "agent-id" ? <Check size={14} className="text-[var(--ok)]" /> : <Copy size={14} />}
            </button>
          </div>
        }
      >
        <div className="space-y-6">
          {/* Agent Role & Permissions */}
          <div className="rounded-xl card-subtle p-4 space-y-3">
            <div className="flex items-center justify-between text-[14px]">
              <span className="text-[var(--text-2)]">Role archetype</span>
              <span className="font-semibold text-[var(--text)] capitalize">
                {selectedAgent?.role}
              </span>
            </div>
            <div className="border-t border-[var(--hairline)]/40 pt-2">
              <span className="text-[14px] text-[var(--text-3)]">Declared Permissions</span>
              <div className="mt-1.5 flex flex-wrap gap-1.5">
                {selectedAgent?.permissions?.map((p: string) => (
                  <span
                    key={p}
                    className="rounded-md card px-2 py-0.5 font-mono text-[12px] text-[var(--text-2)]"
                  >
                    {p}
                  </span>
                ))}
                {!selectedAgent?.permissions?.length && (
                  <span className="text-[14px] text-[var(--text-3)]">No special permissions</span>
                )}
              </div>
            </div>
          </div>

          {/* Risk & Bayesian Posterior */}
          {selectedAssessment && (
            <div className="rounded-xl card-subtle p-4 space-y-3">
              <h4 className="text-[14px] font-semibold tracking-wide text-[var(--text)] uppercase">
                Bayesian Risk Assessment
              </h4>
              <div className="grid grid-cols-2 gap-3 text-[14px]">
                <div className="rounded-lg card p-3">
                  <span className="text-[12px] text-[var(--text-3)]">Agent risk</span>
                  <div className="text-[20px] font-bold text-[var(--crit)]">
                    {pct(selectedAssessment.risk)}
                  </div>
                </div>
                <div className="rounded-lg card p-3">
                  <span className="text-[12px] text-[var(--text-3)]">Prior Probability</span>
                  <div className="text-[20px] font-bold text-[var(--text)]">
                    {pct(selectedAssessment.prior)}
                  </div>
                </div>
              </div>

              {selectedAssessment.best_explanation && (
                <div className="rounded-lg card p-3">
                  <span className="text-[12px] font-semibold text-[var(--text-3)]">
                    Best Explanation
                  </span>
                  <p className="mt-1 text-[14px] leading-relaxed text-[var(--text)]">
                    {selectedAssessment.best_explanation}
                  </p>
                </div>
              )}

              {/* Rare behaviors */}
              {selectedAssessment.rare_behaviors.length > 0 && (
                <div className="space-y-1.5">
                  <span className="text-[12px] font-semibold text-[var(--text-3)]">
                    Rare Behavioral Deviations
                  </span>
                  <div className="space-y-1.5">
                    {selectedAssessment.rare_behaviors.map((rb, idx) => (
                      <div
                        key={idx}
                        className="flex items-center justify-between rounded-lg card p-2.5 text-[14px]"
                      >
                        <span className="font-mono text-[var(--text)]">{rb.behavior}</span>
                        <span className="font-mono text-[12px] text-[var(--crit)]">
                          p={rb.p.toFixed(4)} ({rb.bits.toFixed(1)} bits)
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Related Threat Alerts */}
          <div className="space-y-3">
            <h4 className="text-[14px] font-semibold tracking-wide text-[var(--text)] uppercase">
              Threat Alerts Involving Agent ({agentAlerts.length})
            </h4>

            {agentAlerts.length === 0 && (
              <div className="rounded-xl card-subtle p-4 text-center text-[14px] text-[var(--text-3)]">
                No alerts cited this agent.
              </div>
            )}

            {agentAlerts.map((al) => (
              <div
                key={al.alert_id}
                className="rounded-xl card p-3.5 space-y-1.5"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[13px] font-semibold text-[var(--text)]">
                    {al.rule_id}
                  </span>
                  <span
                    className={`rounded-full px-2 py-0.5 text-[11px] font-bold uppercase ${
                      al.severity === "critical"
                        ? "bg-[var(--crit-bg)] text-[var(--crit)]"
                        : "bg-[var(--high-bg)] text-[var(--high)]"
                    }`}
                  >
                    {al.severity}
                  </span>
                </div>
                <p className="text-[14px] text-[var(--text-2)]">{al.reason}</p>
                <div className="flex items-center justify-between pt-1 text-[12px]">
                  <span className="font-mono text-[var(--text-3)]">
                    {al.event_ids.length} citing event(s)
                  </span>
                  <a
                    href={`#/incidents/${al.alert_id}`}
                    className="flex items-center gap-1 text-[var(--link)] hover:underline"
                  >
                    <span>View incident</span>
                    <ExternalLink size={12} />
                  </a>
                </div>
              </div>
            ))}
          </div>

          {/* Agent Events Sequence */}
          <div className="space-y-3">
            <h4 className="text-[14px] font-semibold tracking-wide text-[var(--text)] uppercase">
              Agent Normalized Event Stream ({agentEvents.length})
            </h4>

            <div className="space-y-2 max-h-[320px] overflow-y-auto pr-1">
              {agentEvents.map((evt) => (
                <div
                  key={evt.event_id}
                  onClick={() => setSelectedEventId(evt.event_id)}
                  className="cursor-pointer rounded-lg card-subtle p-2.5 transition-colors hover:border-[var(--accent)]"
                >
                  <div className="flex items-center justify-between text-[12px]">
                    <span className="font-mono font-medium text-[var(--text)]">{evt.event_id}</span>
                    <span className="text-[var(--text-3)]">{time(evt.timestamp)}</span>
                  </div>
                  <div className="mt-1 text-[14px] text-[var(--text-2)]">{evt.summary}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </Drawer>

      {/* Drawer 2: Event JSON Payload Viewer */}
      <Drawer
        open={Boolean(selectedEventId)}
        onClose={() => setSelectedEventId(null)}
        title={selectedEvent ? `Event ${selectedEvent.event_id}` : "Event"}
        subtitle={selectedEvent?.event_type}
      >
        {selectedEvent && (
          <div className="space-y-4">
            {/* Timestamp Reference Note (Item 4) */}
            <div className="rounded-lg card-subtle p-3.5 text-[14px] leading-relaxed text-[var(--text-2)] border border-[var(--hairline-subtle)]">
              <span className="font-semibold text-[var(--text)]">Timestamp reference:</span> Event <code className="font-mono text-[12px] text-[var(--accent)] font-semibold">timestamp</code> reflects simulator execution time; <code className="font-mono text-[12px] text-[var(--accent)] font-semibold">normalized_at</code> reflects collector ingestion wall-clock time. Raw telemetry data is unaltered.
            </div>

            <div className="flex items-center justify-between">
              <span className="text-[12px] font-semibold text-[var(--text-3)] uppercase tracking-wider">
                Raw Event Payload
              </span>
              <button
                onClick={() =>
                  copyToClipboard(JSON.stringify(selectedEvent, null, 2), "event-json")
                }
                type="button"
                className="inline-flex items-center gap-1.5 rounded-md card px-2.5 py-1 text-[14px] font-medium text-[var(--text-2)] hover:text-[var(--text)]"
              >
                {copiedId === "event-json" ? (
                  <Check size={13} className="text-[var(--ok)]" />
                ) : (
                  <Copy size={13} />
                )}
                <span>{copiedId === "event-json" ? "Copied" : "Copy JSON"}</span>
              </button>
            </div>

            <pre className="max-h-[500px] overflow-auto rounded-xl card-subtle p-4 font-mono text-[13px] leading-relaxed text-[var(--text)]">
              {JSON.stringify(selectedEvent, null, 2)}
            </pre>
          </div>
        )}
      </Drawer>
    </div>
  );
}
