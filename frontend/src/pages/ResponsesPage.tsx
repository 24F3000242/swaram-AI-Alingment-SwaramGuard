import { useState } from "react";
import { useAppState, useRunData } from "../state";
import { api } from "../api";
import { PageHeader } from "../components/PageHeader";
import { ModePill } from "../components/ModePill";
import { Footnotes } from "../components/Footnotes";
import { Card, Empty } from "../components/ui";
import { shortId, time } from "../lib/format";
import { getAgentRole } from "../lib/incidentHelper";
import { ShieldCheck, ShieldAlert, Sliders } from "lucide-react";
import { ReviewQueueCard } from "./ReviewQueueCard";
import type { ResponseAction } from "../types";

export function ResponsesPage() {
  const { selectedRunId } = useAppState();
  const responsesData = useRunData(api.responses, selectedRunId);
  const alertsData = useRunData(api.alerts, selectedRunId);
  const agentsData = useRunData(api.agents, selectedRunId);

  const responses: ResponseAction[] = responsesData.data ?? [];
  const alerts = alertsData.data ?? [];
  const agents = agentsData.data ?? [];

  const [modeFilter, setModeFilter] = useState<"all" | "enforced" | "simulated">("all");

  const enforcedResponses = responses.filter((r) => r.mode === "enforced");
  const simulatedResponses = responses.filter((r) => r.mode !== "enforced");

  const allSimulated = responses.length > 0 && enforcedResponses.length === 0;

  const filteredResponses =
    modeFilter === "enforced"
      ? enforcedResponses
      : modeFilter === "simulated"
      ? simulatedResponses
      : responses;

  return (
    <div className="space-y-8">
      {/* 56px Title / 21px Subtitle with quick link */}
      <PageHeader
        title="Responses."
        subtitle="Auditable mitigation actions mapped from threat alerts to controllable gateway decisions."
        actions={
          <a
            href="#/pipeline/response"
            className="inline-flex h-9 items-center gap-1.5 rounded-full card px-4 text-[14px] font-medium text-[var(--text)] shadow-xs transition-colors hover:border-[var(--text-3)]"
          >
            <Sliders size={14} className="text-[var(--text-3)]" />
            <span>Configure policy &rsaquo;</span>
          </a>
        }
      />

      {/* Human review of live containment (paused agents, held egress, quarantined inputs) */}
      <ReviewQueueCard />

      {/* Top Banner: Data-dependent honesty */}
      {responses.length > 0 && (
        <div
          className={`flex items-start gap-3 rounded-2xl card p-5 text-[14px] leading-relaxed transition-colors ${
            allSimulated
              ? "text-[var(--text-2)] shadow-[var(--shadow-1)]"
              : "!border-[var(--ok)]/30 bg-[var(--ok-bg)] text-[var(--ok)] shadow-xs"
          }`}
        >
          {allSimulated ? (
            <ShieldAlert size={20} className="mt-0.5 shrink-0 text-[var(--text-3)]" />
          ) : (
            <ShieldCheck size={20} className="mt-0.5 shrink-0 text-[var(--ok)]" />
          )}
          <div>
            <div className="font-semibold text-[var(--text)]">
              {allSimulated
                ? "Simulation Replay Mode Active"
                : "Active Gateway Enforcement Active"}
            </div>
            <div className="mt-1">
              {allSimulated ? (
                <span>
                  All {responses.length} responses were recorded in simulation. No tool call was actually stopped at the gateway.‡
                </span>
              ) : (
                <span>
                  {enforcedResponses.length} of {responses.length} mitigation actions were verified and actively enforced at the gateway.
                </span>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Stats Summary Tiles */}
      {responses.length > 0 && (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <div className="rounded-[var(--r-card)] card p-5 shadow-[var(--shadow-1)]">
            <span className="text-[14px] font-medium text-[var(--text-2)]">Total Decisions</span>
            <div className="mt-2 text-[32px] font-light tracking-tight text-[var(--text)]">
              {responses.length}
            </div>
          </div>
          <div className="rounded-[var(--r-card)] card p-5 shadow-[var(--shadow-1)]">
            <span className="text-[14px] font-medium text-[var(--text-2)]">Simulated Replay‡</span>
            <div className="mt-2 text-[32px] font-light tracking-tight text-[var(--text-2)]">
              {simulatedResponses.length}
            </div>
          </div>
          <div className="rounded-[var(--r-card)] card p-5 shadow-[var(--shadow-1)]">
            <span className="text-[14px] font-medium text-[var(--text-2)]">Enforced Gateway</span>
            <div className="mt-2 text-[32px] font-light tracking-tight text-[var(--ok)]">
              {enforcedResponses.length}
            </div>
          </div>
          <div className="rounded-[var(--r-card)] card p-5 shadow-[var(--shadow-1)]">
            <span className="text-[14px] font-medium text-[var(--text-2)]">Containment Rate</span>
            <div className="mt-2 text-[32px] font-light tracking-tight text-[var(--accent)]">
              {responses.length > 0
                ? `${Math.round(
                    (responses.filter((r) => r.decision === "block" || r.decision === "pause")
                      .length /
                      responses.length) *
                      100
                  )}%`
                : "0%"}
            </div>
          </div>
        </div>
      )}

      {/* Mode Filters if mixed modes exist */}
      {enforcedResponses.length > 0 && simulatedResponses.length > 0 && (
        <div className="flex items-center gap-2">
          <button
            onClick={() => setModeFilter("all")}
            className={`rounded-full px-4 py-1.5 text-[14px] font-medium transition-colors ${
              modeFilter === "all"
                ? "bg-[var(--text)] text-[var(--bg)]"
                : "card text-[var(--text-2)] hover:border-[var(--text)]"
            }`}
          >
            All actions ({responses.length})
          </button>
          <button
            onClick={() => setModeFilter("enforced")}
            className={`rounded-full px-4 py-1.5 text-[14px] font-medium transition-colors ${
              modeFilter === "enforced"
                ? "bg-[var(--text)] text-[var(--bg)]"
                : "card text-[var(--text-2)] hover:border-[var(--text)]"
            }`}
          >
            Enforced only ({enforcedResponses.length})
          </button>
          <button
            onClick={() => setModeFilter("simulated")}
            className={`rounded-full px-4 py-1.5 text-[14px] font-medium transition-colors ${
              modeFilter === "simulated"
                ? "bg-[var(--text)] text-[var(--bg)]"
                : "card text-[var(--text-2)] hover:border-[var(--text)]"
            }`}
          >
            Simulated only ({simulatedResponses.length})
          </button>
        </div>
      )}

      {/* Empty State */}
      {!responses.length && (
        <Card>
          <Empty>
            {selectedRunId
              ? `No mitigation actions recorded for run ${selectedRunId}. Apply a policy in the Security response module to generate mitigation decisions.`
              : "No scenario run is selected. Choose a run from the selector above to inspect responses."}
          </Empty>
        </Card>
      )}

      {/* Responses List Cards */}
      <div className="space-y-4">
        {filteredResponses.map((r) => {
          const matchedAlert = alerts.find((a) => a.alert_id === r.alert_id);
          return (
            <div
              key={r.response_id}
              className="rounded-[var(--r-card)] card p-6 shadow-[var(--shadow-1)] transition-all"
            >
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--hairline)]/40 pb-4">
                <div className="flex flex-wrap items-center gap-3">
                  <span className="text-[22px] font-semibold tracking-tight text-[var(--text)] uppercase">
                    {r.decision}
                  </span>
                  <ModePill mode={r.mode} decision={r.decision} outcome={r.outcome} />
                  <span className="rounded-md card-subtle px-2 py-0.5 font-mono text-[12px] text-[var(--text-3)]">
                    outcome: {r.outcome}
                  </span>
                </div>

                <div className="flex items-center gap-3">
                  <a
                    href={`#/incidents/${r.alert_id}`}
                    className="inline-flex items-center gap-1 rounded-md card px-2.5 py-1 font-mono text-[13px] font-medium text-[var(--link)] hover:underline"
                  >
                    <span>Alert: {shortId(r.alert_id)}</span>
                    <span aria-hidden>&rsaquo;</span>
                  </a>
                  <span className="text-[14px] text-[var(--text-3)]" title={r.created_at}>
                    {time(r.created_at)}
                  </span>
                </div>
              </div>

              {/* Note / reason */}
              <div className="mt-4 text-[15px] leading-relaxed text-[var(--text)]">
                {r.note || matchedAlert?.reason || "Response policy mapped from alert severity."}
              </div>

              {/* Metadata row */}
              <div className="mt-4 flex flex-wrap items-center gap-x-6 gap-y-2 border-t border-[var(--hairline)]/40 pt-3 font-mono text-[14px] text-[var(--text-2)]">
                <div>
                  <span className="text-[var(--text-3)]">Target Agents: </span>
                  <span className="font-semibold text-[var(--text)]">
                    {r.agent_ids.map((id) => `${getAgentRole(id, agents)} (${shortId(id)})`).join(", ") || "None"}
                  </span>
                </div>
                <div>
                  <span className="text-[var(--text-3)]">Citing Events: </span>
                  <span className="font-semibold text-[var(--text)]">
                    {r.event_ids.map(shortId).join(", ") || "None"}
                  </span>
                </div>
                {r.gateway_event_ids.length > 0 && (
                  <div>
                    <span className="text-[var(--text-3)]">Gateway Dropped: </span>
                    <span className="font-semibold text-[var(--ok)]">
                      {r.gateway_event_ids.map(shortId).join(", ")}
                    </span>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      <Footnotes symbols={["†", "‡"]} />
    </div>
  );
}
