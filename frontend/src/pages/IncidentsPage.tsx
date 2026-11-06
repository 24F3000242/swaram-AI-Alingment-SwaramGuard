import { useEffect, useState } from "react";
import { useAppState, useRunData } from "../state";
import { api } from "../api";
import { PageHeader } from "../components/PageHeader";
import { Pill } from "../components/Pill";
import { ModePill } from "../components/ModePill";
import { ScoreRing } from "../components/ScoreRing";
import { EvidenceChip } from "../components/EvidenceChip";
import { Drawer } from "../components/Drawer";
import { Footnotes } from "../components/Footnotes";
import { Card, Empty } from "../components/ui";
import { time } from "../lib/format";
import { deriveIncidentTitle, getAgentRole } from "../lib/incidentHelper";
import type { Alert, NormalizedEvent, ResponseAction } from "../types";
import { Check, Copy, ChevronDown, ChevronUp } from "lucide-react";

function AgentRoleBadge({
  agentId,
  role,
}: {
  agentId: string;
  role: string;
}) {
  const [copied, setCopied] = useState(false);
  return (
    <span
      className="group relative inline-flex items-center gap-1.5 rounded-md card px-2 py-0.5 text-[14px] font-medium text-[var(--text)] transition-colors hover:border-[var(--accent)]"
      title={`Click to copy full ID: ${agentId}`}
    >
      <span className="capitalize">{role}</span>
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          navigator.clipboard.writeText(agentId);
          setCopied(true);
          setTimeout(() => setCopied(false), 2000);
        }}
        className="text-[var(--text-3)] hover:text-[var(--accent)] transition-opacity"
        aria-label={`Copy full agent ID ${agentId}`}
      >
        {copied ? <Check size={12} className="text-[var(--ok)]" /> : <Copy size={12} />}
      </button>
    </span>
  );
}

export function IncidentsPage({ initialAlertId }: { initialAlertId?: string }) {
  const { selectedRunId } = useAppState();
  const alertsData = useRunData(api.alerts, selectedRunId);
  const normalizedData = useRunData(api.normalizedEvents, selectedRunId);
  const responsesData = useRunData(api.responses, selectedRunId);
  const assessmentsData = useRunData(api.assessments, selectedRunId);
  const agentsData = useRunData(api.agents, selectedRunId);

  const alerts = alertsData.data ?? [];
  const normalizedEvents = normalizedData.data ?? [];
  const responses = responsesData.data ?? [];
  const assessments = assessmentsData.data ?? [];
  const agents = agentsData.data ?? [];

  const [selectedId, setSelectedId] = useState<string | null>(initialAlertId ?? null);
  const [activeTab, setActiveTab] = useState<"summary" | "evidence" | "response">("summary");
  const [drawerEvent, setDrawerEvent] = useState<NormalizedEvent | null>(null);
  const [drawerMissingId, setDrawerMissingId] = useState<string | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const [copiedAgentId, setCopiedAgentId] = useState(false);
  const [scoringExpanded, setScoringExpanded] = useState(false);

  // Auto-select highest severity alert on load and reset when run changes
  useEffect(() => {
    if (alerts.length > 0) {
      if (initialAlertId && alerts.some((a) => a.alert_id === initialAlertId)) {
        setSelectedId(initialAlertId);
      } else if (!selectedId || !alerts.some((a) => a.alert_id === selectedId)) {
        const severityOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
        const sorted = [...alerts].sort((a, b) => (severityOrder[b.severity] ?? 0) - (severityOrder[a.severity] ?? 0));
        setSelectedId(sorted[0].alert_id);
      }
    } else {
      setSelectedId(null);
    }
  }, [alerts, initialAlertId, selectedRunId]);

  const currentAlert: Alert | null = alerts.find((a) => a.alert_id === selectedId) ?? alerts[0] ?? null;

  // Resolve matching response
  const currentResponse: ResponseAction | undefined = responses.find(
    (r) => r.alert_id === currentAlert?.alert_id
  );

  // Resolve involved agent assessments
  const primaryAgentId = currentAlert?.agent_ids[0];
  const currentAssessment = assessments.find((ass) => ass.agent_id === primaryAgentId);

  // Open drawer for an event chip
  const handleChipClick = (eventId: string) => {
    const found = normalizedEvents.find((e) => e.event_id === eventId);
    if (found) {
      setDrawerEvent(found);
      setDrawerMissingId(null);
    } else {
      setDrawerEvent(null);
      setDrawerMissingId(eventId);
    }
    setDrawerOpen(true);
  };

  const copyEventJson = () => {
    if (drawerEvent) {
      navigator.clipboard.writeText(JSON.stringify(drawerEvent, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const copyDrawerAgentId = (id: string) => {
    navigator.clipboard.writeText(id);
    setCopiedAgentId(true);
    setTimeout(() => setCopiedAgentId(false), 2000);
  };

  return (
    <div className="space-y-8">
      <PageHeader
        title="Incidents."
        subtitle="Cross-agent threat detections backed by verifiable event chains."
      />

      {!alerts.length && (
        <Card>
          <Empty>
            {selectedRunId
              ? `No incidents detected in run ${selectedRunId}. Swarm operated within normal parameters.`
              : "No scenario run is selected. Choose a run from the selector above or simulate a scenario."}
          </Empty>
        </Card>
      )}

      {alerts.length > 0 && currentAlert && (
        <div className="grid grid-cols-1 gap-8 lg:grid-cols-[380px_1fr]">
          {/* Left Column: 380px List */}
          <div className="space-y-3">
            <div className="text-[14px] font-semibold text-[var(--text-2)] uppercase tracking-wider px-1">
              {alerts.length} Incident{alerts.length === 1 ? "" : "s"} Detected
            </div>

            <div className="space-y-2 max-h-[calc(100vh-220px)] overflow-y-auto pr-1">
              {alerts.map((a) => {
                const isSelected = a.alert_id === currentAlert.alert_id;
                const shortTitle = deriveIncidentTitle(a, agents, normalizedEvents);
                return (
                  <button
                    key={a.alert_id}
                    onClick={() => {
                      setSelectedId(a.alert_id);
                      window.location.hash = `#/incidents/${a.alert_id}`;
                    }}
                    type="button"
                    className={`w-full rounded-[var(--r-card)] card p-4 text-left transition-all ${
                      isSelected
                        ? "!border-[var(--accent)] ring-1 ring-[var(--accent)] shadow-[var(--shadow-1)]"
                        : "hover:border-[var(--text-3)]"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <Pill value={a.severity} />
                        <span className="font-mono text-[12px] text-[var(--text-3)]">{a.rule_id}</span>
                      </div>
                      <span className="text-[12px] text-[var(--text-3)]">{time(a.created_at)}</span>
                    </div>

                    <div className="mt-2 text-[15px] font-semibold text-[var(--text)] line-clamp-2">
                      {shortTitle}
                    </div>

                    <div className="mt-2 flex flex-wrap items-center justify-between gap-2 text-[14px] text-[var(--text-2)]">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className="text-[12px] text-[var(--text-3)]">Roles:</span>
                        {a.agent_ids.map((id) => (
                          <AgentRoleBadge
                            key={id}
                            agentId={id}
                            role={getAgentRole(id, agents, normalizedEvents)}
                          />
                        ))}
                      </div>
                      <span className="font-mono text-[12px] text-[var(--accent)] font-medium shrink-0">
                        {a.event_ids.length} evts
                      </span>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Right Column: Incident Detail */}
          <div className="rounded-[var(--r-tile)] card p-8 shadow-[var(--shadow-1)]">
            {/* Header with Derived Title and Score Ring */}
            <div className="flex flex-wrap items-start justify-between gap-6 border-b border-[var(--hairline-subtle)] pb-6">
              <div className="min-w-0 max-w-xl">
                <div className="flex items-center gap-2.5">
                  <Pill value={currentAlert.severity} />
                  <span className="font-mono text-[14px] text-[var(--text-3)]">{currentAlert.rule_id}</span>
                  <span className="text-[14px] text-[var(--text-2)]">&middot; Detected {time(currentAlert.created_at)}</span>
                </div>
                <h2 className="mt-3 text-[26px] sm:text-[30px] font-semibold leading-tight tracking-tight text-[var(--text)]">
                  {deriveIncidentTitle(currentAlert, agents, normalizedEvents)}
                </h2>
                <div className="mt-3 text-[14px] text-[var(--text-2)] flex flex-wrap items-center gap-2">
                  <span>Rule: <strong className="text-[var(--text)]">{currentAlert.rule_name}</strong></span>
                  <span>&middot;</span>
                  <span>Target: <code className="font-mono text-[13px] text-[var(--text)]">{currentAlert.resource}</code></span>
                  <span>&middot;</span>
                  <span>Roles:</span>
                  {currentAlert.agent_ids.map((id) => (
                    <AgentRoleBadge
                      key={id}
                      agentId={id}
                      role={getAgentRole(id, agents, normalizedEvents)}
                    />
                  ))}
                </div>
              </div>

              {/* ScoreRing with explicit Alert confidence label */}
              <div className="flex flex-col items-center">
                <ScoreRing
                  score={currentAssessment?.risk ?? (currentAlert.severity === "critical" ? 0.95 : currentAlert.severity === "high" ? 0.82 : 0.6)}
                  severity={currentAlert.severity}
                  label="Alert confidence"
                />
                <span className="mt-2 text-[12px] font-medium text-[var(--text-3)] uppercase tracking-wider">
                  Alert confidence
                </span>
              </div>
            </div>

            {/* Sticky Sub-tabs: Summary · Evidence · Response */}
            <div className="mt-6 flex border-b border-[var(--hairline-subtle)]">
              <div className="flex gap-6">
                <button
                  type="button"
                  onClick={() => setActiveTab("summary")}
                  className={`pb-3 text-[14px] font-medium transition-colors relative ${
                    activeTab === "summary" ? "text-[var(--text)]" : "text-[var(--text-2)] hover:text-[var(--text)]"
                  }`}
                >
                  Summary
                  {activeTab === "summary" && (
                    <span className="absolute bottom-0 left-0 right-0 h-[2px] rounded-full bg-[var(--accent)]" />
                  )}
                </button>
                <button
                  type="button"
                  onClick={() => setActiveTab("evidence")}
                  className={`pb-3 text-[14px] font-medium transition-colors relative ${
                    activeTab === "evidence" ? "text-[var(--text)]" : "text-[var(--text-2)] hover:text-[var(--text)]"
                  }`}
                >
                  Evidence ({currentAlert.event_ids.length})
                  {activeTab === "evidence" && (
                    <span className="absolute bottom-0 left-0 right-0 h-[2px] rounded-full bg-[var(--accent)]" />
                  )}
                </button>
                <button
                  type="button"
                  onClick={() => setActiveTab("response")}
                  className={`pb-3 text-[14px] font-medium transition-colors relative ${
                    activeTab === "response" ? "text-[var(--text)]" : "text-[var(--text-2)] hover:text-[var(--text)]"
                  }`}
                >
                  Response & Mitigation
                  {activeTab === "response" && (
                    <span className="absolute bottom-0 left-0 right-0 h-[2px] rounded-full bg-[var(--accent)]" />
                  )}
                </button>
              </div>
            </div>

            {/* Tab 1: Summary */}
            {activeTab === "summary" && (
              <div className="mt-6 space-y-6">
                <div>
                  <h3 className="text-[16px] font-semibold text-[var(--text)]">What happened</h3>
                  <div className="mt-3 flex flex-wrap items-center gap-2">
                    {currentAlert.event_ids.map((id, idx) => {
                      const matched = normalizedEvents.find((e) => e.event_id === id);
                      return (
                        <div key={id} className="flex items-center gap-2">
                          <EvidenceChip
                            eventId={id}
                            action={matched?.action}
                            onClick={handleChipClick}
                            className="incident-evidence-chip"
                          />
                          {idx < currentAlert.event_ids.length - 1 && (
                            <span className="text-[var(--text-3)]" aria-hidden>&rarr;</span>
                          )}
                        </div>
                      );
                    })}
                  </div>
                  <div className="mt-2 text-[14px] text-[var(--text-3)]">
                    Click any event chip to inspect its raw JSON payload in the side drawer.
                  </div>
                </div>

                <div className="border-t border-[var(--hairline-subtle)] pt-4">
                  <h3 className="text-[16px] font-semibold text-[var(--text)]">Why we flagged it</h3>
                  <p className="mt-2 text-[14px] leading-relaxed text-[var(--text-2)]">
                    {currentAlert.reason}. This behavior violated declared role permissions and established normal communication baselines across the swarm.
                  </p>

                  {/* Collapsible Bayesian Explanation */}
                  {currentAssessment && (
                    <div className="mt-4 rounded-xl card-subtle p-4">
                      <button
                        onClick={() => setScoringExpanded((x) => !x)}
                        type="button"
                        className="flex w-full items-center justify-between text-[14px] font-medium text-[var(--text)]"
                      >
                        <span>How this was scored: Bayesian belief update & System-1 anomaly</span>
                        {scoringExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                      </button>

                      {scoringExpanded && (
                        <div className="mt-3 space-y-3 border-t border-[var(--hairline-subtle)] pt-3 text-[14px]">
                          <div>
                            <span className="text-[var(--text-3)]">Probability transition:</span>{" "}
                            <strong>{(currentAssessment.prior * 100).toFixed(0)}% prior</strong> &rarr;{" "}
                            <strong className="text-[var(--crit)]">{(currentAssessment.risk * 100).toFixed(0)}% posterior</strong> (<span className="font-semibold text-[var(--text)]">Agent risk</span>).
                          </div>

                          {currentAssessment.evidence.length > 0 && (
                            <div>
                              <div className="font-medium text-[var(--text)]">Contributing factors:</div>
                              <ul className="mt-1 list-disc pl-5 text-[var(--text-2)] space-y-0.5">
                                {currentAssessment.evidence.map((ev, i) => (
                                  <li key={i}>{ev}</li>
                                ))}
                              </ul>
                            </div>
                          )}

                          {currentAssessment.best_explanation && (
                            <div>
                              <div className="font-medium text-[var(--text)]">Abductive hypothesis:</div>
                              <div className="mt-1 rounded-md card p-3 text-[var(--text-2)] text-[14px] leading-relaxed">
                                {currentAssessment.best_explanation}
                              </div>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Tab 2: Evidence */}
            {activeTab === "evidence" && (
              <div className="mt-6 space-y-4">
                <div className="text-[14px] text-[var(--text-2)]">
                  The detector correlated the following ordered events as direct evidence for this incident:
                </div>

                <div className="divide-y divide-[var(--hairline-subtle)] rounded-xl card overflow-hidden">
                  {currentAlert.event_ids.map((id, idx) => {
                    const evt = normalizedEvents.find((e) => e.event_id === id);
                    const role = evt ? (evt.agent_role || getAgentRole(evt.agent_id, agents, normalizedEvents)) : "unknown";
                    return (
                      <div
                        key={id}
                        onClick={() => handleChipClick(id)}
                        className="flex cursor-pointer items-center justify-between p-4 transition-colors hover:bg-[var(--card-alt)] incident-evidence-row"
                      >
                        <div className="flex items-center gap-3">
                          <span className="flex h-6 w-6 items-center justify-center rounded-full bg-[var(--card-alt)] font-mono text-[12px] text-[var(--text-2)]">
                            {idx + 1}
                          </span>
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="font-mono text-[14px] font-semibold text-[var(--accent)]">
                                {id}
                              </span>
                              <span className="rounded-md card px-1.5 py-0.5 font-mono text-[11px] text-[var(--text-2)] capitalize">
                                {role}
                              </span>
                            </div>
                            <div className="text-[14px] text-[var(--text-2)]">
                              {evt ? `${evt.event_type} &middot; action: ${evt.action}` : "Raw telemetry event"}
                            </div>
                          </div>
                        </div>

                        <div className="text-right">
                          <div className="font-mono text-[12px] text-[var(--text-3)]">
                            {evt?.timestamp ? time(evt.timestamp) : "—"}
                          </div>
                          <span className="text-[12px] font-medium text-[var(--accent)]">
                            Inspect JSON &rarr;
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Tab 3: Response & Mitigation */}
            {activeTab === "response" && (
              <div className="mt-6 space-y-4">
                {currentResponse ? (
                  <div className="rounded-xl card p-6 space-y-4 border border-[var(--hairline-subtle)]">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="text-[14px] font-semibold text-[var(--text)]">Recommended Action:</span>
                        <ModePill mode={currentResponse.mode} decision={currentResponse.decision} outcome={currentResponse.outcome} />
                      </div>
                      <span className="text-[12px] text-[var(--text-3)]">
                        Policy ID: <code className="font-mono">{currentResponse.policy_id}</code>
                      </span>
                    </div>

                    <p className="text-[14px] leading-relaxed text-[var(--text-2)]">
                      {currentResponse.note || "Automated containment policy evaluated against gateway rules."}
                    </p>

                    <div className="border-t border-[var(--hairline-subtle)] pt-3 text-[14px] text-[var(--text-2)]">
                      <div>
                        <strong>Involved Agents:</strong>{" "}
                        <span className="font-mono">{currentResponse.agent_ids.join(", ")}</span>
                      </div>
                      <div className="mt-1">
                        <strong>Targeted Events:</strong>{" "}
                        <span className="font-mono">{currentResponse.event_ids.join(", ")}</span>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="rounded-xl card-subtle p-6 text-center text-[14px] text-[var(--text-2)]">
                    No automated response recorded for this incident yet.
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Slide-over Drawer for Raw Event JSON */}
      <Drawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        title={drawerEvent ? `Event ${drawerEvent.event_id}` : "Event Not Found"}
        subtitle={
          drawerEvent
            ? `${drawerEvent.event_type} by role "${drawerEvent.agent_role || getAgentRole(drawerEvent.agent_id, agents, normalizedEvents)}"`
            : drawerMissingId
        }
      >
        {drawerEvent ? (
          <div className="space-y-4">
            {/* Timestamp Reference Note (Item 4) */}
            <div className="rounded-lg card-subtle p-3.5 text-[14px] leading-relaxed text-[var(--text-2)] border border-[var(--hairline-subtle)]">
              <span className="font-semibold text-[var(--text)]">Timestamp reference:</span> Event <code className="font-mono text-[12px] text-[var(--accent)] font-semibold">timestamp</code> reflects simulator execution time; <code className="font-mono text-[12px] text-[var(--accent)] font-semibold">normalized_at</code> reflects collector ingestion wall-clock time. Raw telemetry data is unaltered.
            </div>

            {/* Agent Full ID Card with Copy button */}
            <div className="rounded-lg card p-3 flex items-center justify-between text-[14px]">
              <div>
                <span className="text-[var(--text-3)] block text-[11px] uppercase tracking-wider font-semibold">Full Agent ID</span>
                <span className="font-mono text-[13px] text-[var(--text)] select-all">{drawerEvent.agent_id}</span>
              </div>
              <button
                type="button"
                onClick={() => copyDrawerAgentId(drawerEvent.agent_id)}
                className="inline-flex items-center gap-1 rounded-md card-subtle px-2.5 py-1 text-[12px] font-medium text-[var(--text-2)] hover:text-[var(--text)]"
              >
                {copiedAgentId ? <Check size={12} className="text-[var(--ok)]" /> : <Copy size={12} />}
                <span>{copiedAgentId ? "Copied" : "Copy ID"}</span>
              </button>
            </div>

            <div className="flex items-center justify-between pt-1">
              <span className="text-[12px] font-semibold text-[var(--text-3)] uppercase tracking-wider">
                Raw Event Payload
              </span>
              <button
                onClick={copyEventJson}
                type="button"
                className="inline-flex items-center gap-1.5 rounded-md card px-2.5 py-1 text-[14px] font-medium text-[var(--text-2)] hover:text-[var(--text)]"
              >
                {copied ? <Check size={13} className="text-[var(--ok)]" /> : <Copy size={13} />}
                <span>{copied ? "Copied" : "Copy JSON"}</span>
              </button>
            </div>

            <pre className="overflow-auto rounded-xl card-subtle p-4 font-mono text-[13px] leading-relaxed text-[var(--text)] max-h-[calc(100vh-320px)]">
              {JSON.stringify(drawerEvent, null, 2)}
            </pre>
          </div>
        ) : (
          <div className="rounded-xl bg-[var(--high-bg)] p-4 text-[14px] text-[var(--high)]">
            Event ID <code className="font-mono">{drawerMissingId}</code> was not found in the normalized event repository.
          </div>
        )}
      </Drawer>

      <Footnotes symbols={["†", "‡"]} />
    </div>
  );
}
