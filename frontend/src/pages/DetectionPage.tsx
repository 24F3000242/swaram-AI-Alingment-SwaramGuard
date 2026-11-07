import { useState } from "react";
import { api } from "../api";
import { ResultViewer, type Column } from "../components/ResultViewer";
import { Badge, Button, Drawer, OutputSelect, PageHeader, RunSelect, StatusBanner, type Status } from "../components/ui";
import { shortId } from "../lib/format";
import { useAppState, useRunData } from "../state";
import type { AgentAssessment, Alert, AgentGraph, DetectionRule } from "../types";
import { AssessmentDetail, auditColumns, BaselineCard, BenchmarkCard, riskColumns } from "./DetectionInsights";
import { LiveGuardCard } from "./LiveGuardCard";
import { Sliders, Play, Copy, Check } from "lucide-react";
import { THREAT_CATEGORIES, THREAT_RULES } from "../lib/threatRules";
import { ThreatMatrixView } from "../components/ThreatMatrixView";

// 5-column maximum for clean, overflow-free alert listing
const columns: Column<Alert>[] = [
  {
    key: "severity",
    label: "Severity",
    className: "w-24",
    render: (a) => <Badge value={a.severity} />,
  },
  {
    key: "rule_id",
    label: "Rule",
    render: (a) => (
      <div>
        <span className="font-semibold text-[var(--text)]">{a.rule_name}</span>
        <span className="ml-2 font-mono text-[11px] text-[var(--text-3)]">{a.rule_id}</span>
      </div>
    ),
  },
  {
    key: "agent_ids",
    label: "Agents",
    render: (a) => (
      <span className="font-mono text-[var(--text)]">
        {a.agent_ids.map(shortId).join(", ")}
      </span>
    ),
  },
  {
    key: "event_ids",
    label: "Evidence",
    render: (a) => (
      <span className="font-mono text-[13px] text-[var(--accent)] font-medium">
        {a.event_ids.length} event(s)
      </span>
    ),
  },
  {
    key: "recommended_action",
    label: "Recommendation",
    render: (a) => (
      <span className="rounded-md bg-[var(--card-alt)] px-2 py-0.5 text-[12px] font-medium text-[var(--text)] capitalize">
        {a.recommended_action}
      </span>
    ),
  },
];

export function DetectionPage() {
  const { selectedRunId, refreshRuns } = useAppState();
  const [persist, setPersist] = useState(true);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<Status>(null);
  const [activeTab, setActiveTab] = useState<"findings" | "rules" | "observability" | "liveguard" | "baseline" | "audit">("findings");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [ruleSearch, setRuleSearch] = useState("");
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const [preview, setPreview] = useState<{
    alerts: Alert[];
    graph: AgentGraph;
    assessments: AgentAssessment[];
  } | null>(null);

  const alerts = useRunData(api.alerts, selectedRunId);
  const graph = useRunData(api.graph, selectedRunId);
  const assessments = useRunData(api.assessments, selectedRunId);
  const audit = useRunData(api.auditQueue, selectedRunId);
  const rules = useRunData(() => api.rules(), "rules");

  const shownAlerts = preview?.alerts ?? alerts.data;
  const shownRisk = preview?.assessments ?? assessments.data;
  const currentAgent = shownRisk?.find((a) => a.agent_id === selectedAgent) ?? shownRisk?.[0] ?? null;

  const copyToClipboard = (t: string, id: string) => {
    navigator.clipboard.writeText(t);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  async function run() {
    if (!selectedRunId) return setStatus({ kind: "error", message: "Select a run first." });
    setBusy(true);
    setStatus(null);
    try {
      const res = await api.detect(selectedRunId, persist);
      if (persist) {
        setPreview(null);
        await Promise.all([
          alerts.reload(),
          graph.reload(),
          assessments.reload(),
          audit.reload(),
          refreshRuns(),
        ]);
      } else {
        setPreview({ alerts: res.alerts, graph: res.graph, assessments: res.assessments });
      }
      setSelectedAlert(res.alerts[0] ?? null);
      setSelectedAgent(res.assessments[0]?.agent_id ?? null);
      setSettingsOpen(false);
      const risky = res.assessments.filter((a) => a.level === "high" || a.level === "critical").length;
      setStatus({
        kind: res.alerts.length ? "warning" : "success",
        message: `${res.alerts.length} alert(s) generated${persist ? " and saved" : " (preview)"} · ${risky} agent(s) at elevated risk.`,
      });
    } catch (e) {
      setStatus({ kind: "error", message: (e as Error).message });
    } finally {
      setBusy(false);
    }
  }

  async function toggleRule(rule: DetectionRule) {
    try {
      await api.saveRule({ ...rule, enabled: !rule.enabled });
      await rules.reload();
      setStatus({
        kind: "info",
        message: `${rule.rule_id} ${rule.enabled ? "disabled" : "enabled"}. Re-run detection to apply.`,
      });
    } catch (e) {
      setStatus({ kind: "error", message: (e as Error).message });
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        module="detection"
        title="Threat detection"
        description="Two layers of defense: fast behavioral screening against a learned baseline, and rule-based attack graph correlation across all threat vectors."
      >
        <div className="flex items-center gap-3">
          <button
            onClick={() => setSettingsOpen(true)}
            className="inline-flex h-9 items-center gap-1.5 rounded-full border border-[var(--hairline)]/80 bg-[var(--card)] px-4 text-[14px] font-medium text-[var(--text)] shadow-xs transition-colors hover:border-[var(--hairline)]"
          >
            <Sliders size={14} className="text-[var(--text-3)]" />
            <span>Detection settings &rsaquo;</span>
          </button>
          <Button variant="primary" onClick={run} busy={busy}>
            <Play size={14} className="mr-1 fill-current" />
            <span>Run detection</span>
          </Button>
        </div>
      </PageHeader>

      <StatusBanner status={status} onClose={() => setStatus(null)} />

      {/* Clean segmented tab switcher for secondary views so rules never push findings off screen */}
      <div className="flex border-b border-[var(--hairline)]/60 pb-3">
        <div className="inline-flex rounded-full bg-[var(--hairline-subtle)] p-1">
          <button
            onClick={() => setActiveTab("findings")}
            className={`rounded-full px-4 py-1.5 text-[14px] font-medium transition-all ${
              activeTab === "findings"
                ? "bg-[var(--card)] text-[var(--text)] shadow-xs"
                : "text-[var(--text-2)] hover:text-[var(--text)]"
            }`}
          >
            Findings &amp; Alerts ({shownAlerts?.length ?? 0})
          </button>
          <button
            onClick={() => setActiveTab("rules")}
            className={`rounded-full px-4 py-1.5 text-[14px] font-medium transition-all ${
              activeTab === "rules"
                ? "bg-[var(--card)] text-[var(--text)] shadow-xs"
                : "text-[var(--text-2)] hover:text-[var(--text)]"
            }`}
          >
            Rules (20)
          </button>
          <button
            onClick={() => setActiveTab("observability")}
            className={`rounded-full px-4 py-1.5 text-[14px] font-medium transition-all ${
              activeTab === "observability"
                ? "bg-[var(--card)] text-[var(--text)] shadow-xs"
                : "text-[var(--text-2)] hover:text-[var(--text)]"
            }`}
          >
            Observability (12)
          </button>
          <button
            onClick={() => setActiveTab("liveguard")}
            className={`rounded-full px-4 py-1.5 text-[14px] font-medium transition-all ${
              activeTab === "liveguard"
                ? "bg-[var(--card)] text-[var(--text)] shadow-xs"
                : "text-[var(--text-2)] hover:text-[var(--text)]"
            }`}
          >
            Live Guard
          </button>
          <button
            onClick={() => setActiveTab("baseline")}
            className={`rounded-full px-4 py-1.5 text-[14px] font-medium transition-all ${
              activeTab === "baseline"
                ? "bg-[var(--card)] text-[var(--text)] shadow-xs"
                : "text-[var(--text-2)] hover:text-[var(--text)]"
            }`}
          >
            Learned Baseline
          </button>
          <button
            onClick={() => setActiveTab("audit")}
            className={`rounded-full px-4 py-1.5 text-[14px] font-medium transition-all ${
              activeTab === "audit"
                ? "bg-[var(--card)] text-[var(--text)] shadow-xs"
                : "text-[var(--text-2)] hover:text-[var(--text)]"
            }`}
          >
            Audit Queue ({audit.data?.length ?? 0})
          </button>
        </div>
      </div>

      {/* Tab 1: Findings & Alerts (Results First) */}
      {activeTab === "findings" && (
        <div className="space-y-6">
          <ResultViewer
            title="Generated Threat Alerts"
            rows={shownAlerts}
            columns={columns}
            filename={`alerts_${selectedRunId}`}
            rowKey={(a) => a.alert_id}
            onRowClick={(a) => setSelectedAlert(a)}
            selectedKey={selectedAlert?.alert_id}
            empty="No threat alerts detected for this run."
          />

          {/* Risk ranking table */}
          {shownRisk && shownRisk.length > 0 && (
            <div className="grid gap-6 lg:grid-cols-3">
              <div className="lg:col-span-2">
                <ResultViewer
                  title="Bayesian Risk Ranking"
                  rows={shownRisk}
                  columns={riskColumns}
                  filename={`risk_${selectedRunId}`}
                  rowKey={(a) => a.agent_id}
                  onRowClick={(a) => setSelectedAgent(a.agent_id)}
                  selectedKey={currentAgent?.agent_id}
                />
              </div>
              <div className="lg:col-span-1">
                <AssessmentDetail a={currentAgent} />
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Rules (20) - Grouped by categories */}
      {activeTab === "rules" && (
        <div className="space-y-6">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <h3 className="text-[20px] font-semibold text-[var(--text)]">
                20-Rule Detection Matrix
              </h3>
              <p className="text-[14px] text-[var(--text-2)]">
                Toggle rules or view parameter bounds for behavioral baseline screening and explicit threat rules.
              </p>
            </div>
            <input
              placeholder="Search rules..."
              value={ruleSearch}
              onChange={(e) => setRuleSearch(e.target.value)}
              className="w-56 rounded-full border border-[var(--hairline-subtle)] bg-[var(--card)] px-4 py-2 text-[14px] text-[var(--text)] focus:border-[var(--accent)] focus:outline-none"
            />
          </div>

          <div className="space-y-6">
            {THREAT_CATEGORIES.map((cat) => {
              const catRules = (rules.data ?? []).filter((r) => {
                const def = THREAT_RULES.find((tr) => tr.id === r.rule_id);
                const matchesCat = def?.category === cat.key;
                const matchesQuery =
                  !ruleSearch ||
                  r.name.toLowerCase().includes(ruleSearch.toLowerCase()) ||
                  r.rule_id.toLowerCase().includes(ruleSearch.toLowerCase());
                return matchesCat && matchesQuery;
              });

              if (!catRules.length) return null;

              return (
                <div
                  key={cat.key}
                  className="rounded-[var(--r-card)] card p-6 shadow-[var(--shadow-1)] border border-[var(--hairline-subtle)]"
                >
                  <div className="mb-4 flex items-center justify-between border-b border-[var(--hairline-subtle)] pb-3">
                    <div className="flex items-center gap-2.5">
                      <span className="h-3 w-3 rounded-full" style={{ background: cat.color }} />
                      <h4 className="text-[17px] font-semibold text-[var(--text)]">{cat.label}</h4>
                      <span className="font-mono text-[12px] text-[var(--text-3)]">{cat.code}</span>
                    </div>
                    <span className="text-[14px] text-[var(--text-3)]">
                      {catRules.length} rule(s)
                    </span>
                  </div>

                  <div className="divide-y divide-[var(--hairline-subtle)]">
                    {catRules.map((r) => (
                      <div
                        key={r.rule_id}
                        className="flex items-center justify-between gap-4 py-3.5 first:pt-1 last:pb-1"
                      >
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-[13px] font-semibold text-[var(--text)]">
                              {r.rule_id}
                            </span>
                            <span className="text-[15px] font-medium text-[var(--text)]">
                              {r.name}
                            </span>
                            <Badge value={r.severity} />
                          </div>
                          <p className="mt-1.5 text-[14px] leading-relaxed text-[var(--text-2)]">{r.description}</p>
                        </div>

                        {/* iOS-style toggle */}
                        <button
                          type="button"
                          onClick={() => toggleRule(r)}
                          role="switch"
                          aria-checked={r.enabled}
                          className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                            r.enabled ? "bg-[var(--ok)]" : "bg-[var(--card-alt)] border border-[var(--hairline-subtle)]"
                          }`}
                        >
                          <span
                            className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow-md ring-0 transition duration-200 ease-in-out ${
                              r.enabled ? "translate-x-5" : "translate-x-0"
                            }`}
                          />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Tab 2b: Observability (12 Layers) */}
      {activeTab === "observability" && (
        <div className="space-y-6">
          <ThreatMatrixView mode="detection" />
        </div>
      )}

      {/* Tab 3: Live Guard */}
      {activeTab === "liveguard" && (
        <div className="space-y-6">
          <LiveGuardCard />
        </div>
      )}

      {/* Tab 4: Learned Baseline */}
      {activeTab === "baseline" && (
        <div className="space-y-6">
          <BaselineCard
            runId={selectedRunId}
            runHasAlerts={(shownAlerts?.length ?? 0) > 0}
            onStatus={setStatus}
            onChanged={() => alerts.reload()}
          />
          <BenchmarkCard />
        </div>
      )}

      {/* Tab 5: Audit Queue */}
      {activeTab === "audit" && (
        <ResultViewer
          title="Triage Audit Queue"
          rows={audit.data}
          columns={auditColumns}
          filename={`audit_${selectedRunId}`}
          rowKey={(i) => i.event_id}
          empty="Audit queue is clear."
        />
      )}

      {/* Detection Settings Drawer */}
      <Drawer
        open={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        title="Detection Execution Settings"
        subtitle="Select the analyzed run and output storage configuration."
      >
        <div className="space-y-5">
          <RunSelect requireStage="collected" />
          <OutputSelect value={persist} onChange={setPersist} collection="alerts" />

          <div className="pt-4">
            <Button variant="primary" onClick={run} busy={busy} className="w-full justify-center">
              Run threat detection
            </Button>
          </div>
        </div>
      </Drawer>

      {/* Row Click Drawer: Alert Evidence Inspector */}
      <Drawer
        open={Boolean(selectedAlert)}
        onClose={() => setSelectedAlert(null)}
        title={
          <div className="flex items-center gap-2">
            <Badge value={selectedAlert?.severity ?? "medium"} />
            <span className="text-[17px] font-semibold">{selectedAlert?.rule_name}</span>
          </div>
        }
        subtitle={
          selectedAlert ? (
            <span className="font-mono text-[12px] text-[var(--text-3)]">
              {selectedAlert.rule_id} &bull; {selectedAlert.alert_id}
            </span>
          ) : undefined
        }
      >
        {selectedAlert && (
          <div className="space-y-5">
            <div className="rounded-xl border border-[var(--hairline)]/60 bg-[var(--card-alt)] p-4 text-[14px] leading-relaxed text-[var(--text)]">
              {selectedAlert.reason}
            </div>

            <div className="grid grid-cols-2 gap-2 text-[12px]">
              <div className="rounded-lg bg-[var(--card-alt)] p-2.5">
                <span className="text-[var(--text-3)]">Target Resource</span>
                <div className="font-mono font-medium text-[var(--text)]">
                  {selectedAlert.resource || "none"}
                </div>
              </div>
              <div className="rounded-lg bg-[var(--card-alt)] p-2.5">
                <span className="text-[var(--text-3)]">Recommended Action</span>
                <div className="font-mono font-medium text-[var(--text)] capitalize">
                  {selectedAlert.recommended_action}
                </div>
              </div>
            </div>

            {/* Evidence items */}
            <div>
              <h4 className="text-[14px] font-semibold text-[var(--text)] mb-2">
                Citing Evidence ({selectedAlert.evidence?.length ?? selectedAlert.event_ids.length})
              </h4>
              <div className="space-y-2">
                {selectedAlert.evidence?.map((ev) => (
                  <div
                    key={ev.event_id}
                    className="rounded-lg border border-[var(--hairline)]/40 bg-[var(--card-alt)] p-3 text-[12px]"
                  >
                    <div className="flex items-center justify-between font-mono text-[11px] text-[var(--accent)]">
                      <span>{ev.event_id}</span>
                      <span className="text-[var(--text-3)]">{ev.timestamp}</span>
                    </div>
                    <div className="mt-1 text-[14px] text-[var(--text)]">{ev.summary}</div>
                  </div>
                ))}
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between pb-1.5">
                <span className="text-[12px] font-semibold text-[var(--text-2)]">Raw Alert JSON</span>
                <button
                  onClick={() =>
                    copyToClipboard(JSON.stringify(selectedAlert, null, 2), "alert-json-copy")
                  }
                  className="inline-flex items-center gap-1 font-mono text-[11px] text-[var(--link)] hover:underline"
                >
                  {copiedId === "alert-json-copy" ? (
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
              <pre className="max-h-[300px] overflow-auto rounded-xl border border-[var(--hairline)]/60 bg-[var(--card-alt)] p-4 font-mono text-[12px] leading-relaxed text-[var(--text)]">
                {JSON.stringify(selectedAlert, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </Drawer>
    </div>
  );
}
