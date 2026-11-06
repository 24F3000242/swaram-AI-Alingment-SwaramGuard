import { useEffect, useState } from "react";
import { api } from "../api";
import { ResultViewer, type Column } from "../components/ResultViewer";
import { Badge, Button, Drawer, Field, ModePill, OutputSelect, PageHeader, RunSelect, StatusBanner, inputCls, type Status } from "../components/ui";
import { shortId, time } from "../lib/format";
import { useAppState, useRunData } from "../state";
import type { ResponseAction, ResponseDecision, ResponsePolicy, Severity } from "../types";
import { Sliders, Play, Copy, Check } from "lucide-react";

const DECISIONS: ResponseDecision[] = ["allow", "alert", "block", "pause"];
const SEVERITIES: Severity[] = ["low", "medium", "high", "critical"];

// 5-column maximum
const columns: Column<ResponseAction>[] = [
  {
    key: "decision",
    label: "Decision",
    render: (a) => (
      <div className="flex items-center gap-2">
        <span className="font-semibold capitalize text-[var(--text)]">{a.decision}</span>
        <ModePill mode={a.mode} decision={a.decision} outcome={a.outcome} />
      </div>
    ),
  },
  {
    key: "outcome",
    label: "Outcome",
    render: (a) => (
      <span className="rounded-md bg-[var(--card-alt)] px-2 py-0.5 font-mono text-[11px] text-[var(--text-3)]">
        {a.outcome}
      </span>
    ),
  },
  {
    key: "alert_id",
    label: "Alert ID",
    render: (a) => (
      <a
        href={`#/incidents/${a.alert_id}`}
        className="font-mono text-[12px] font-medium text-[var(--link)] hover:underline"
      >
        {shortId(a.alert_id)}
      </a>
    ),
  },
  {
    key: "agent_ids",
    label: "Agents",
    render: (a) => (
      <span className="font-mono text-[var(--text)]">{a.agent_ids.map(shortId).join(", ")}</span>
    ),
  },
  {
    key: "note",
    label: "Policy Note",
    className: "max-w-xs truncate",
    render: (a) => <span className="text-[var(--text-2)]">{a.note}</span>,
  },
];

export function ResponsePage() {
  const { selectedRunId, runs, refreshRuns } = useAppState();
  const [policy, setPolicy] = useState<ResponsePolicy | null>(null);
  const [persist, setPersist] = useState(true);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<Status>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [selectedAction, setSelectedAction] = useState<ResponseAction | null>(null);
  const [preview, setPreview] = useState<ResponseAction[] | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const stored = useRunData(api.responses, selectedRunId);
  const run = runs.find((r) => r.run_id === selectedRunId);
  const actions = preview ?? stored.data;

  useEffect(() => {
    api
      .policy()
      .then(setPolicy)
      .catch((e) => setStatus({ kind: "error", message: e.message }));
  }, []);

  const update = (patch: Partial<ResponsePolicy>) =>
    setPolicy((p) => (p ? { ...p, ...patch } : p));

  const copyToClipboard = (t: string, id: string) => {
    navigator.clipboard.writeText(t);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  async function savePolicy() {
    if (!policy) return;
    try {
      await api.savePolicy(policy);
      setStatus({ kind: "success", message: "Policy saved to response_policies/default." });
    } catch (e) {
      setStatus({ kind: "error", message: (e as Error).message });
    }
  }

  async function run_() {
    if (!selectedRunId || !policy)
      return setStatus({ kind: "error", message: "Select a run first." });
    setBusy(true);
    setStatus(null);
    try {
      const res = await api.respond(selectedRunId, policy, persist);
      if (persist) {
        setPreview(null);
        await Promise.all([stored.reload(), refreshRuns()]);
      } else {
        setPreview(res.actions);
      }
      setSettingsOpen(false);
      const counts = res.actions.reduce<Record<string, number>>(
        (m, a) => ({ ...m, [a.outcome]: (m[a.outcome] ?? 0) + 1 }),
        {}
      );
      setStatus({
        kind: "success",
        message: `${res.actions.length} response record(s): ${
          Object.entries(counts)
            .map(([k, v]) => `${v} ${k}`)
            .join(", ") || "none"
        }.`,
      });
    } catch (e) {
      setStatus({ kind: "error", message: (e as Error).message });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        module="response"
        title="Security response"
        description="Maps each alert to allow / alert / block / pause using a configurable policy, and links every mitigation record to its alert ID."
      >
        <div className="flex items-center gap-3">
          <button
            onClick={() => setSettingsOpen(true)}
            className="inline-flex h-9 items-center gap-1.5 rounded-full card px-4 text-[14px] font-medium text-[var(--text)] shadow-xs transition-colors hover:border-[var(--hairline)]"
          >
            <Sliders size={14} className="text-[var(--text-3)]" />
            <span>Configure policy &rsaquo;</span>
          </button>
          <Button variant="primary" onClick={run_} busy={busy} disabled={!policy}>
            <Play size={14} className="mr-1 fill-current" />
            <span>Apply policy</span>
          </Button>
        </div>
      </PageHeader>

      <StatusBanner status={status} onClose={() => setStatus(null)} />

      {/* Honesty Callout Banner */}
      <div className="rounded-2xl card p-4 text-[14px] leading-relaxed text-[var(--text-2)] shadow-[var(--shadow-1)]">
        <strong className="text-[var(--text)]">Honesty guarantee: </strong>
        Decisions in simulation mode record <em>would_block</em> or <em>would_pause</em>. The word{" "}
        <strong className="text-[var(--ok)]">blocked</strong> is only recorded when the pre-execution gateway actively intercepted the tool before execution. Logging after the fact never stops an action that already executed.
      </div>

      {/* Results First: Mitigation Decisions Table */}
      <ResultViewer
        title="Mitigation Actions"
        rows={actions}
        columns={columns}
        filename={`response_actions_${selectedRunId}`}
        rowKey={(a) => a.response_id}
        onRowClick={(a) => setSelectedAction(a)}
        selectedKey={selectedAction?.response_id}
        empty="No response actions recorded. Apply a policy to generate mitigation actions."
      />

      {/* Policy Configuration Drawer */}
      <Drawer
        open={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        title="Policy & Execution Settings"
        subtitle="Configure severity mappings and gateway enforcement mode."
      >
        <div className="space-y-5">
          <RunSelect requireStage="detected" />
          {run && (
            <div className="rounded-lg bg-[var(--card-alt)] p-2.5 text-[12px] text-[var(--text-2)]">
              Simulation gateway mode:{" "}
              <strong className="text-[var(--text)]">{run.gateway_mode}</strong>
            </div>
          )}

          <OutputSelect
            value={persist}
            onChange={setPersist}
            collection="response_actions"
          />

          {policy && (
            <div className="space-y-4 border-t border-[var(--hairline)]/60 pt-4">
              <Field
                label="Enforcement mode"
                hint={
                  policy.mode === "enforce"
                    ? "Records blocked only where gateway denied request."
                    : "Decisions are simulated: would_block / would_pause."
                }
              >
                <select
                  className={inputCls}
                  value={policy.mode}
                  onChange={(e) =>
                    update({ mode: e.target.value as ResponsePolicy["mode"] })
                  }
                >
                  <option value="simulate">simulate (replay only)</option>
                  <option value="enforce">enforce (active gateway)</option>
                </select>
              </Field>

              <div className="space-y-2">
                <span className="text-[14px] font-medium text-[var(--text-2)]">
                  Severity &rarr; Decision mapping
                </span>
                <div className="grid grid-cols-2 gap-2">
                  {SEVERITIES.map((s) => (
                    <div key={s} className="rounded-lg bg-[var(--card-alt)] p-2">
                      <div className="flex items-center justify-between">
                        <Badge value={s} />
                        <select
                          className="rounded border border-[var(--hairline)] bg-[var(--card)] px-2 py-0.5 text-[12px] text-[var(--text)]"
                          value={policy.severity_actions[s]}
                          onChange={(e) =>
                            update({
                              severity_actions: {
                                ...policy.severity_actions,
                                [s]: e.target.value as ResponseDecision,
                              },
                            })
                          }
                        >
                          {DECISIONS.map((d) => (
                            <option key={d} value={d}>
                              {d}
                            </option>
                          ))}
                        </select>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="pt-2">
                <Button
                  variant="secondary"
                  onClick={savePolicy}
                  className="w-full justify-center"
                >
                  Save policy defaults
                </Button>
              </div>
            </div>
          )}

          <div className="pt-4 border-t border-[var(--hairline)]/60">
            <Button
              variant="primary"
              onClick={run_}
              busy={busy}
              disabled={!policy}
              className="w-full justify-center"
            >
              Apply policy
            </Button>
          </div>
        </div>
      </Drawer>

      {/* Row Click Drawer: Mitigation Action Inspector */}
      <Drawer
        open={Boolean(selectedAction)}
        onClose={() => setSelectedAction(null)}
        title={
          <div className="flex items-center gap-2">
            <span className="text-[18px] font-semibold uppercase">{selectedAction?.decision}</span>
            {selectedAction && (
              <ModePill mode={selectedAction.mode} decision={selectedAction.decision} outcome={selectedAction.outcome} />
            )}
          </div>
        }
        subtitle={
          selectedAction ? (
            <span className="font-mono text-[12px] text-[var(--text-3)]">
              {time(selectedAction.created_at)} &bull; {selectedAction.response_id}
            </span>
          ) : undefined
        }
      >
        {selectedAction && (
          <div className="space-y-5">
            <div className="rounded-xl border border-[var(--hairline)]/60 bg-[var(--card-alt)] p-4 text-[14px] leading-relaxed text-[var(--text)]">
              {selectedAction.note}
            </div>

            <div className="grid grid-cols-2 gap-2 text-[12px]">
              <div className="rounded-lg bg-[var(--card-alt)] p-2.5">
                <span className="text-[var(--text-3)]">Target Agents</span>
                <div className="font-mono font-medium text-[var(--text)]">
                  {selectedAction.agent_ids.map(shortId).join(", ")}
                </div>
              </div>
              <div className="rounded-lg bg-[var(--card-alt)] p-2.5">
                <span className="text-[var(--text-3)]">Policy ID</span>
                <div className="font-mono font-medium text-[var(--text)]">
                  {selectedAction.policy_id}
                </div>
              </div>
              <div className="rounded-lg bg-[var(--card-alt)] p-2.5">
                <span className="text-[var(--text-3)]">Recorded Outcome</span>
                <div className="font-mono font-medium text-[var(--text)]">
                  {selectedAction.outcome}
                </div>
              </div>
              <div className="rounded-lg bg-[var(--card-alt)] p-2.5">
                <span className="text-[var(--text-3)]">Enforced at Gateway</span>
                <div className="font-mono font-medium text-[var(--text)]">
                  {selectedAction.enforced ? "Yes" : "No (simulation)"}
                </div>
              </div>
            </div>

            {selectedAction.gateway_event_ids.length > 0 && (
              <div className="rounded-lg border border-[var(--ok)]/30 bg-[var(--ok-bg)] p-3 text-[12px]">
                <span className="font-semibold text-[var(--ok)]">Gateway Denials Intercepted:</span>
                <div className="mt-1 font-mono text-[11px] text-[var(--ok)]">
                  {selectedAction.gateway_event_ids.join(", ")}
                </div>
              </div>
            )}

            <div>
              <div className="flex items-center justify-between pb-1.5">
                <span className="text-[12px] font-semibold text-[var(--text-2)]">
                  Raw Response JSON
                </span>
                <button
                  onClick={() =>
                    copyToClipboard(
                      JSON.stringify(selectedAction, null, 2),
                      "response-json-drawer"
                    )
                  }
                  className="inline-flex items-center gap-1 font-mono text-[11px] text-[var(--link)] hover:underline"
                >
                  {copiedId === "response-json-drawer" ? (
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
                {JSON.stringify(selectedAction, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </Drawer>
    </div>
  );
}
