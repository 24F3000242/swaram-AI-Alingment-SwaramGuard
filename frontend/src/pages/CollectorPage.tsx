import { useState } from "react";
import { api } from "../api";
import { ResultViewer, type Column } from "../components/ResultViewer";
import { Badge, Button, Drawer, Field, OutputSelect, PageHeader, RunSelect, Segmented, StatusBanner, inputCls, type Status } from "../components/ui";
import { ThreatMatrixView } from "../components/ThreatMatrixView";
import { parseJsonOrJsonl } from "../lib/export";
import { shortId, time } from "../lib/format";
import { useAppState, useRunData } from "../state";
import type { CollectionReport, NormalizedEvent } from "../types";
import { Sliders, Play, Copy, Check } from "lucide-react";

// Max 5 columns for fast scanning without horizontal scrolling
const columns: Column<NormalizedEvent>[] = [
  {
    key: "timestamp",
    label: "Time (UTC)",
    className: "w-28 font-mono text-[14px]",
    render: (e) => <span>{e.timestamp.slice(11, 19)}</span>,
  },
  {
    key: "event_id",
    label: "Event ID",
    render: (e) => <span className="font-mono font-medium">{shortId(e.event_id)}</span>,
  },
  {
    key: "agent_id",
    label: "Agent & Role",
    render: (e) => (
      <div className="flex items-center gap-1.5">
        <span className="font-mono text-[var(--text)]">{shortId(e.agent_id)}</span>
        {e.agent_role && (
          <span className="rounded-md bg-[var(--card-alt)] px-1.5 py-0.5 text-[11px] text-[var(--text-3)]">
            {e.agent_role}
          </span>
        )}
      </div>
    ),
  },
  {
    key: "action",
    label: "Action",
    render: (e) => (
      <div className="max-w-[280px] truncate">
        <span className="font-medium text-[var(--text)]">{e.action}</span>
        {e.resource && (
          <span className="ml-1.5 font-mono text-[11px] text-[var(--text-3)]">
            &bull; {e.resource}
          </span>
        )}
      </div>
    ),
  },
  {
    key: "status",
    label: "Status / Issues",
    render: (e) => (
      <div className="flex items-center gap-2">
        <Badge value={e.status} />
        {e.issues.length > 0 && (
          <span className="rounded-md bg-[var(--high-bg)] px-1.5 py-0.5 font-mono text-[11px] text-[var(--high)]">
            {e.issues.length} issue(s)
          </span>
        )}
      </div>
    ),
  },
];

export function CollectorPage() {
  const { selectedRunId, refreshRuns } = useAppState();
  const [source, setSource] = useState<"run" | "upload">("run");
  const [text, setText] = useState("");
  const [persist, setPersist] = useState(true);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<Status>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [report, setReport] = useState<CollectionReport | null>(null);
  const [preview, setPreview] = useState<NormalizedEvent[] | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<NormalizedEvent | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [showOptimizationMatrix, setShowOptimizationMatrix] = useState(false);

  const stored = useRunData(api.normalizedEvents, selectedRunId);
  const events = preview ?? stored.data;

  const copyToClipboard = (t: string, id: string) => {
    navigator.clipboard.writeText(t);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  async function onFile(file: File | undefined) {
    if (file) setText(await file.text());
  }

  async function run() {
    setBusy(true);
    setStatus(null);
    try {
      let body: { run_id?: string | null; events?: unknown[]; persist: boolean };
      if (source === "upload") {
        const parsed = parseJsonOrJsonl(text);
        if (!parsed.length) throw new Error("Paste or upload JSON / JSONL events first.");
        body = { run_id: persist ? selectedRunId : null, events: parsed, persist };
      } else {
        if (!selectedRunId) throw new Error("Select a run first.");
        body = { run_id: selectedRunId, persist };
      }
      const res = await api.collect(body);
      setReport(res.report);
      const saved = body.persist && !!body.run_id;
      setPreview(saved ? null : res.events);
      if (saved) {
        await stored.reload();
        await refreshRuns();
      }
      setSettingsOpen(false);
      const kind = res.report.errors.length ? "warning" : "success";
      setStatus({
        kind,
        message: `Normalized ${res.report.valid} of ${res.report.total_input} events · ${res.report.duplicates} duplicate(s) · ${res.report.errors.length} error(s) · ${res.report.warnings.length} warning(s)${saved ? " · saved to normalized_events" : " · preview only"}.`,
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
        module="collector"
        title="Event collector"
        description="Validates raw events, deduplicates streams, normalizes timestamps, verifies agent identities, and computes evidence integrity hashes."
      >
        <div className="flex items-center gap-3">
          <button
            onClick={() => setSettingsOpen(true)}
            className="inline-flex h-9 items-center gap-1.5 rounded-full border border-[var(--hairline)]/80 bg-[var(--card)] px-4 text-[14px] font-medium text-[var(--text)] shadow-xs transition-colors hover:border-[var(--hairline)]"
          >
            <Sliders size={14} className="text-[var(--text-3)]" />
            <span>Collector settings &rsaquo;</span>
          </button>
          <Button variant="primary" onClick={run} busy={busy}>
            <Play size={14} className="mr-1 fill-current" />
            <span>Normalize events</span>
          </Button>
        </div>
      </PageHeader>

      <StatusBanner status={status} onClose={() => setStatus(null)} />

      {report && (
        <div className="flex flex-wrap items-center gap-4 rounded-xl border border-[var(--hairline)]/60 bg-[var(--card)] p-3 text-[14px] text-[var(--text-2)]">
          <span className="font-semibold text-[var(--text)]">Ingestion Report:</span>
          <span>Valid: <strong className="font-mono text-[var(--ok)]">{report.valid}</strong></span>
          <span>Total input: <strong className="font-mono text-[var(--text)]">{report.total_input}</strong></span>
          <span>Duplicates: <strong className="font-mono text-[var(--text)]">{report.duplicates}</strong></span>
          <span>Errors: <strong className="font-mono text-[var(--crit)]">{report.errors.length}</strong></span>
          <span>Warnings: <strong className="font-mono text-[var(--high)]">{report.warnings.length}</strong></span>
        </div>
      )}

      {/* Results First: Normalized Events Table */}
      <ResultViewer
        title={preview ? "Normalized events (preview)" : "Normalized events"}
        rows={events}
        columns={columns}
        filename={`normalized_events_${preview ? "preview" : selectedRunId}`}
        rowKey={(e) => e.event_id}
        onRowClick={(e) => setSelectedEvent(e)}
        selectedKey={selectedEvent?.event_id}
        empty="Select a run and run normalization to inspect normalized telemetry."
        extraActions={
          <button
            type="button"
            onClick={() => setShowOptimizationMatrix((s) => !s)}
            className="rounded-full border border-[var(--hairline)] bg-[var(--card-alt)] px-3 py-1 text-[12px] font-medium text-[var(--text-2)] hover:border-[var(--accent)] hover:text-[var(--accent)]"
          >
            {showOptimizationMatrix ? "Hide optimization rules" : "Collector validation matrix"}
          </button>
        }
      />

      {showOptimizationMatrix && (
        <div className="mt-6">
          <ThreatMatrixView mode="collector" />
        </div>
      )}

      {/* Collector Settings Drawer */}
      <Drawer
        open={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        title="Collector Ingestion Settings"
        subtitle="Configure event source, upload raw JSONL payloads, and set output destination."
      >
        <div className="space-y-5">
          <Field label="Input Source">
            <Segmented
              full
              value={source}
              onChange={setSource}
              options={[
                { value: "run", label: "Stored run events" },
                { value: "upload", label: "Upload / Paste JSON" },
              ]}
            />
          </Field>

          {source === "run" ? (
            <RunSelect requireStage="simulated" />
          ) : (
            <div className="space-y-3">
              <Field
                label="Raw JSON or JSONL Payload"
                hint="Paste newline-delimited event records or upload a .jsonl file."
              >
                <textarea
                  className={`${inputCls} h-36 font-mono text-[12px]`}
                  value={text}
                  onChange={(e) => setText(e.target.value)}
                  placeholder='{"event_id": "evt_...", "agent_id": "...", ...}'
                />
              </Field>
              <input
                type="file"
                accept=".json,.jsonl,application/json"
                onChange={(e) => onFile(e.target.files?.[0])}
                className="text-[14px] text-[var(--text-2)]"
              />
            </div>
          )}

          <OutputSelect
            value={persist}
            onChange={setPersist}
            collection="normalized_events"
          />

          <div className="pt-4">
            <Button variant="primary" onClick={run} busy={busy} className="w-full justify-center">
              Normalize events
            </Button>
          </div>
        </div>
      </Drawer>

      {/* Row Click Drawer: Normalized Event Details */}
      <Drawer
        open={Boolean(selectedEvent)}
        onClose={() => setSelectedEvent(null)}
        title={
          <div className="flex items-center gap-2">
            <span className="font-mono text-[16px]">{selectedEvent?.event_id}</span>
            <button
              onClick={() => copyToClipboard(selectedEvent?.event_id || "", "event-id-col")}
              className="text-[var(--text-3)] hover:text-[var(--text)]"
              title="Copy event ID"
            >
              {copiedId === "event-id-col" ? (
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
              {time(selectedEvent.timestamp)} &bull; {selectedEvent.event_type}
            </span>
          ) : undefined
        }
      >
        {selectedEvent && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-2 text-[12px]">
              <div className="rounded-lg bg-[var(--card-alt)] p-2.5">
                <span className="text-[var(--text-3)]">Agent</span>
                <div className="font-mono font-medium text-[var(--text)]">
                  {selectedEvent.agent_id}
                </div>
              </div>
              <div className="rounded-lg bg-[var(--card-alt)] p-2.5">
                <span className="text-[var(--text-3)]">Role</span>
                <div className="font-mono font-medium text-[var(--text)]">
                  {selectedEvent.agent_role || "none"}
                </div>
              </div>
              <div className="rounded-lg bg-[var(--card-alt)] p-2.5">
                <span className="text-[var(--text-3)]">Action</span>
                <div className="font-mono font-medium text-[var(--text)]">
                  {selectedEvent.action}
                </div>
              </div>
              <div className="rounded-lg bg-[var(--card-alt)] p-2.5">
                <span className="text-[var(--text-3)]">Status</span>
                <div className="font-mono font-medium text-[var(--text)]">
                  {selectedEvent.status}
                </div>
              </div>
            </div>

            {selectedEvent.summary && (
              <div className="rounded-lg bg-[var(--card-alt)] p-3 text-[13px]">
                <span className="text-[11px] font-semibold text-[var(--text-3)]">Summary</span>
                <p className="mt-1 leading-relaxed text-[var(--text)]">{selectedEvent.summary}</p>
              </div>
            )}

            <div className="rounded-lg bg-[var(--card-alt)] p-3 text-[12px]">
              <span className="text-[var(--text-3)]">Evidence Integrity Hash (SHA-256)</span>
              <div className="mt-1 font-mono text-[11px] text-[var(--text-2)] break-all">
                {selectedEvent.raw_hash}
              </div>
            </div>

            {selectedEvent.issues.length > 0 && (
              <div className="rounded-lg border border-[var(--high)]/30 bg-[var(--high-bg)] p-3 text-[12px]">
                <span className="font-semibold text-[var(--high)]">Normalization Issues:</span>
                <ul className="mt-1 list-disc pl-4 space-y-1 text-[var(--high)]">
                  {selectedEvent.issues.map((iss, i) => (
                    <li key={i}>{iss}</li>
                  ))}
                </ul>
              </div>
            )}

            <div>
              <div className="flex items-center justify-between pb-1.5">
                <span className="text-[12px] font-semibold text-[var(--text-2)]">
                  Normalized Event Payload
                </span>
                <button
                  onClick={() =>
                    copyToClipboard(
                      JSON.stringify(selectedEvent, null, 2),
                      "payload-json-col"
                    )
                  }
                  className="inline-flex items-center gap-1 font-mono text-[11px] text-[var(--link)] hover:underline"
                >
                  {copiedId === "payload-json-col" ? (
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
                {JSON.stringify(selectedEvent, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </Drawer>
    </div>
  );
}
