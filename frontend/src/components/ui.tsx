import { useEffect, useRef, useState, type ReactNode } from "react";
import { api } from "../api";
import { download, type ExportFormat } from "../lib/export";
import { dateTime } from "../lib/format";
import { useAppState } from "../state";
import type { ModuleInfo, ModuleInfoPart, Run } from "../types";

export const STAGES = ["simulated", "collected", "detected", "responded", "evaluated"] as const;

export function Button({ children, variant = "primary", busy, ...props }:
  React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "ghost"; busy?: boolean }) {
  const styles = {
    primary: "bg-[var(--accent)] text-white hover:bg-[var(--accent-hover)] shadow-xs",
    secondary: "bg-[var(--card-alt)] text-[var(--text)] border border-[var(--hairline)]/50 hover:bg-[var(--card)] hover:border-[var(--text-3)]",
    ghost: "text-[var(--accent)] hover:bg-[var(--accent)]/10",
  }[variant];
  return (
    <button {...props} disabled={props.disabled || busy}
      className={`inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-full px-[18px] py-2 text-[14px] font-medium transition-colors duration-150 focus-visible:outline-none focus-visible:ring-4 focus-visible:ring-[var(--accent)]/25 disabled:cursor-not-allowed disabled:opacity-40 ${styles} ${props.className ?? ""}`}>
      {busy && <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent" />}
      {children}
    </button>
  );
}

export function Card({ title, actions, children, className = "", flush = false }:
  { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; flush?: boolean }) {
  return (
    <section className={`rounded-[var(--r-card)] card shadow-[var(--shadow-1)] transition-all ${className}`}>
      {(title || actions) && (
        <header className="flex flex-wrap items-center justify-between gap-3 px-6 pt-5">
          <h2 className="text-[21px] font-semibold tracking-tight text-[var(--text)]">{title}</h2>
          <div className="flex flex-wrap items-center gap-2">{actions}</div>
        </header>
      )}
      <div className={flush ? "pt-4" : "p-6"}>{children}</div>
    </section>
  );
}

export function Field({ label, hint, children, asDiv = false }: { label: string; hint?: ReactNode; children: ReactNode; asDiv?: boolean }) {
  const Tag = asDiv ? "div" : "label";
  return (
    <Tag className="block">
      <span className="mb-1.5 block text-[14px] font-medium text-[var(--text-2)]">{label}</span>
      {children}
      {hint && <span className="mt-1.5 block text-[12px] leading-snug text-[var(--text-3)]">{hint}</span>}
    </Tag>
  );
}

export const inputCls =
  "w-full rounded-xl border border-[var(--hairline)] bg-[var(--card)] px-3.5 py-2 text-[14px] text-[var(--text)] transition placeholder:text-[var(--text-3)] focus:border-[var(--accent)] focus:outline-none focus:ring-4 focus:ring-[var(--accent)]/15";

/** iOS/macOS-style segmented control using design tokens. */
export function Segmented<T extends string | number>({ options, value, onChange, full = false, size = "md" }: {
  options: { value: T; label: ReactNode; disabled?: boolean }[]; value: T; onChange: (v: T) => void; full?: boolean; size?: "sm" | "md";
}) {
  return (
    <div role="radiogroup" className={`${full ? "flex w-full" : "inline-flex"} rounded-[10px] bg-[var(--bg-alt)] border border-[var(--hairline)]/50 p-[3px]`}>
      {options.map((o) => {
        const on = o.value === value;
        return (
          <button key={String(o.value)} type="button" role="radio" aria-checked={on} disabled={o.disabled} onClick={() => onChange(o.value)}
            className={`${full ? "flex-1" : ""} disabled:cursor-not-allowed disabled:opacity-40 rounded-[8px] font-medium transition-all duration-150 ${size === "sm" ? "px-3 py-1 text-[13px]" : "px-3.5 py-1.5 text-[14px]"} ${on ? "bg-[var(--card)] text-[var(--text)] shadow-[var(--shadow-1)] border border-[var(--hairline)]/40" : "text-[var(--text-2)] hover:text-[var(--text)]"}`}>
            {o.label}
          </button>
        );
      })}
    </div>
  );
}

export function Banner({ kind, children, onClose }: { kind: "error" | "success" | "info" | "warning"; children: ReactNode; onClose?: () => void }) {
  const styles = {
    error: "bg-[var(--crit-bg)] text-[var(--crit)] border border-[var(--crit)]/20",
    success: "bg-[var(--ok-bg)] text-[var(--ok)] border border-[var(--ok)]/20",
    info: "bg-[var(--accent)]/10 text-[var(--accent)] border border-[var(--accent)]/20",
    warning: "bg-[var(--med-bg)] text-[var(--med)] border border-[var(--med)]/20",
  }[kind];
  return (
    <div role={kind === "error" ? "alert" : "status"} className={`flex items-start justify-between gap-3 rounded-2xl px-4 py-3 text-[14px] leading-relaxed ${styles}`}>
      <div className="min-w-0 break-words">{children}</div>
      {onClose && (
        <button onClick={onClose} className="-mr-1 shrink-0 rounded-full p-1 opacity-50 transition hover:bg-black/5 hover:opacity-100" aria-label="Dismiss">
          <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden><path d="M2 2l8 8M10 2l-8 8" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" /></svg>
        </button>
      )}
    </div>
  );
}

export type Status = { kind: "error" | "success" | "info" | "warning"; message: ReactNode } | null;

export function StatusBanner({ status, onClose }: { status: Status; onClose: () => void }) {
  return status ? <Banner kind={status.kind} onClose={onClose}>{status.message}</Banner> : null;
}

const RED = "bg-[var(--crit-bg)] text-[var(--crit)] border border-[var(--crit)]/20";
const ORANGE = "bg-[var(--high-bg)] text-[var(--high)] border border-[var(--high)]/20";
const AMBER = "bg-[var(--med-bg)] text-[var(--med)] border border-[var(--med)]/20";
const GREEN = "bg-[var(--ok-bg)] text-[var(--ok)] border border-[var(--ok)]/20";
const BLUE = "bg-[var(--accent)]/10 text-[var(--accent)] border border-[var(--accent)]/20";
const GRAY = "bg-[var(--card-alt)] text-[var(--text-2)] border border-[var(--hairline)]/40";

// Zero purple - colors strictly map to severity and mode tokens
const BADGE: Record<string, string> = {
  critical: "bg-[var(--crit)] text-white",
  high: RED,
  medium: ORANGE,
  low: GRAY,
  watch: AMBER,
  blocked: "bg-[var(--crit)] text-white",
  would_block: ORANGE,
  would_pause: AMBER,
  alerted: ORANGE,
  allowed: GRAY,
  denied: RED,
  success: GREEN,
  failed: GRAY,
  pending: GRAY,
  open: ORANGE,
  responded: BLUE,
  contained: GREEN,
  simulated: BLUE,
  enforced: RED,
  error: RED,
  warning: ORANGE,
  paused: "bg-[var(--crit)] text-white",
  held: ORANGE,
};

export function Badge({ value }: { value: string | null | undefined }) {
  if (!value) return null;
  return (
    <span className={`inline-block whitespace-nowrap rounded-full px-2.5 py-[3px] text-[14px] font-medium leading-none ${BADGE[value] ?? GRAY}`}>
      {value.replace(/_/g, " ")}
    </span>
  );
}

export function Stat({ label, value, tone }: { label: string; value: ReactNode; tone?: "danger" | "ok" }) {
  const color = tone === "danger" ? "text-[var(--crit)]" : tone === "ok" ? "text-[var(--ok)]" : "text-[var(--text)]";
  return (
    <div className="rounded-[18px] card px-5 py-4 shadow-[var(--shadow-1)]">
      <div className="text-[14px] text-[var(--text-2)]">{label}</div>
      <div className={`mt-1 text-[28px] font-semibold leading-tight tracking-[-0.02em] tabular-nums ${color}`}>{value}</div>
    </div>
  );
}

/** Pipeline progress as a compact stepper. */
export function StageBadges({ run }: { run: Run }) {
  return (
    <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
      {STAGES.map((s) => {
        const done = !!run.stages[s];
        return (
          <span key={s} className={`rounded-full px-2.5 py-0.5 text-[12px] font-medium ${done ? "bg-[var(--ok-bg)] text-[var(--ok)] border border-[var(--ok)]/20" : "bg-[var(--card-alt)] text-[var(--text-3)]"}`}>
            {s}
          </span>
        );
      })}
    </div>
  );
}

/** Run picker using theme input style. */
export function RunSelect({ label = "Select run", requireStage }: { label?: string; requireStage?: typeof STAGES[number] }) {
  const { runs, selectedRunId, selectRun } = useAppState();
  const run = runs.find((r) => r.run_id === selectedRunId);
  return (
    <Field label={label}>
      <select className={inputCls} value={selectedRunId ?? ""} onChange={(e) => selectRun(e.target.value || null)}>
        {!runs.length && <option value="">No runs yet. Create one in Agent Simulator.</option>}
        {runs.map((r) => (
          <option key={r.run_id} value={r.run_id}>
            {r.run_id} · {r.scenario_id} · {r.agent_count} agents · {dateTime(r.created_at)}
          </option>
        ))}
      </select>
      {run && (
        <div className="mt-2 space-y-1">
          <StageBadges run={run} />
          {requireStage && !run.stages[requireStage] && (
            <p className="text-[13px] text-[var(--med)]">This run hasn't completed the “{requireStage}” stage yet.</p>
          )}
        </div>
      )}
    </Field>
  );
}

/** Output dataset selector: persist to the shared workspace or preview only. */
export function OutputSelect({ value, onChange, collection }: { value: boolean; onChange: (v: boolean) => void; collection: string }) {
  const { health } = useAppState();
  return (
    <Field label="Output dataset">
      <select className={inputCls} value={value ? "store" : "preview"} onChange={(e) => onChange(e.target.value === "store")}>
        <option value="store">Save to {health?.workspace ?? "default"}/{collection} ({health?.storage ?? "store"})</option>
        <option value="preview">Preview only (don't save)</option>
      </select>
    </Field>
  );
}

export function ExportMenu({ data, filename }: { data: unknown; filename: string }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const empty = data === null || data === undefined || (Array.isArray(data) && data.length === 0);
  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => !ref.current?.contains(e.target as Node) && setOpen(false);
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, [open]);
  return (
    <div className="relative" ref={ref}>
      <Button variant="secondary" disabled={empty} onClick={() => setOpen((o) => !o)} aria-haspopup="menu" className="!px-4 !py-1.5 !text-[14px]">
        Export
        <svg width="10" height="6" viewBox="0 0 12 8" aria-hidden><path d="M1 1.5l5 5 5-5" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" /></svg>
      </Button>
      {open && (
        <div role="menu" className="absolute right-0 z-20 mt-2 w-44 overflow-hidden rounded-xl card p-1 shadow-[var(--shadow-2)] backdrop-blur-xl">
          {(["json", "jsonl", "csv"] as ExportFormat[]).map((f) => (
            <button key={f} role="menuitem" className="block w-full rounded-lg px-3 py-2 text-left text-[14px] text-[var(--text)] hover:bg-[var(--accent)] hover:text-white transition-colors"
              onClick={() => { download(data, filename, f); setOpen(false); }}>
              Download .{f}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export function JsonBlock({ value, maxHeight = "24rem" }: { value: unknown; maxHeight?: string }) {
  return (
    <pre className="overflow-auto rounded-2xl bg-[var(--card-alt)] border border-[var(--hairline)]/60 p-4 font-mono text-[13px] leading-relaxed text-[var(--text)]" style={{ maxHeight }}>
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

function InfoPart({ title, part }: { title: string; part?: ModuleInfoPart }) {
  const [view, setView] = useState<"sample" | "schema">("sample");
  if (!part) return null;
  return (
    <div className="space-y-2.5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h3 className="text-[15px] font-semibold text-[var(--text)]">{title} <code className="ml-1 font-mono text-[14px] font-normal text-[var(--text-2)]">{part.model}</code></h3>
          {part.fixture && <div className="text-[12px] text-[var(--text-3)]">fixtures/{part.fixture}</div>}
        </div>
        <Segmented size="sm" value={view} onChange={setView} options={[{ value: "sample", label: "Sample" }, { value: "schema", label: "Schema" }]} />
      </div>
      <JsonBlock value={view === "sample" ? part.sample ?? "(no sample fixture)" : part.schema} maxHeight="16rem" />
    </div>
  );
}

export function InfoButton({ module }: { module: string }) {
  const [open, setOpen] = useState(false);
  const [info, setInfo] = useState<ModuleInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (open && !info) api.moduleInfo(module).then(setInfo).catch((e) => setError(e.message));
  }, [open, info, module]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  return (
    <>
      <button onClick={() => setOpen(true)} title="Data contract: input/output schema and sample JSON" aria-label="Show data contract"
        className="flex h-7 w-7 items-center justify-center rounded-full text-[var(--text-3)] transition hover:bg-[var(--card-alt)] hover:text-[var(--accent)]">
        <svg width="18" height="18" viewBox="0 0 20 20" aria-hidden>
          <circle cx="10" cy="10" r="8.25" fill="none" stroke="currentColor" strokeWidth="1.5" />
          <path d="M10 9v5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
          <circle cx="10" cy="6.2" r="1" fill="currentColor" />
        </svg>
      </button>
      {open && (
        <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/40 p-4 backdrop-blur-sm sm:p-12" onClick={() => setOpen(false)}>
          <div role="dialog" aria-modal="true" className="w-full max-w-3xl space-y-6 rounded-[24px] card p-6 shadow-[var(--shadow-2)] sm:p-8" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-start justify-between gap-4">
              <div>
                <h2 className="text-[24px] font-semibold tracking-[-0.02em] text-[var(--text)]">Data contract</h2>
                <p className="text-[14px] text-[var(--text-2)]">What this module reads and writes.</p>
              </div>
              <button onClick={() => setOpen(false)} aria-label="Close"
                className="flex h-8 w-8 items-center justify-center rounded-full bg-[var(--card-alt)] text-[var(--text-2)] hover:bg-[var(--card)] hover:text-[var(--text)]">
                <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden><path d="M2 2l8 8M10 2l-8 8" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" /></svg>
              </button>
            </div>
            {error && <Banner kind="error">{error}</Banner>}
            {!info && !error && <p className="text-[14px] text-[var(--text-2)]">Loading…</p>}
            {info && (
              <>
                <InfoPart title="Input" part={info.input} />
                <InfoPart title="Output" part={info.output} />
                <InfoPart title="Also returns" part={info.extra} />
              </>
            )}
          </div>
        </div>
      )}
    </>
  );
}

export function PageHeader({ title, description, module, children }: { step?: number; title: string; description: string; module?: string; children?: ReactNode }) {
  return (
    <header className="mb-8 pt-2">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <h1 className="text-[36px] sm:text-[48px] font-semibold leading-[1.08] tracking-[-0.015em] text-[var(--text)]">{title}</h1>
            {module && <InfoButton module={module} />}
          </div>
          <p className="mt-3 max-w-2xl text-[19px] sm:text-[21px] font-normal leading-relaxed text-[var(--text-2)]">{description}</p>
        </div>
        {children}
      </div>
    </header>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="py-10 text-center text-[14px] text-[var(--text-3)]">{children}</p>;
}

export { ModePill } from "./ModePill";
export { Pill } from "./Pill";
export { Tile } from "./Tile";
export { Footnotes } from "./Footnotes";
export { ThemeToggle } from "./ThemeToggle";
export { GlobalNav } from "./GlobalNav";
export { Drawer } from "./Drawer";
