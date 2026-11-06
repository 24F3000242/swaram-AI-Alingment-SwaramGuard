import { useEffect } from "react";
import { api } from "../api";
import { useRunData } from "../state";

function inHours(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return h ? `${h}h ${m}m` : `${m}m`;
}

/** Today's Gemini usage and whether the next run fits. Shown wherever a Gemini-backed run can be started. */
export function GeminiQuota({ agentCount, agentMode = "scripted", rounds = 2, refreshKey = 0, onChange }: {
  agentCount: number; agentMode?: "scripted" | "autonomous"; rounds?: number; refreshKey?: number; onChange?: (enough: boolean) => void;
}) {
  const q = useRunData(() => api.geminiQuota(), "gemini-quota", [refreshKey]);
  const d = q.data;
  // calls_per_run is for the default 2 rounds; calls grow linearly with rounds.
  const need = Math.ceil(((d?.calls_per_run[String(agentCount)]?.[agentMode] ?? 0) * rounds) / 2);
  const enough = !!d && d.configured && need <= d.remaining_today;
  useEffect(() => { if (d) onChange?.(enough); }, [d, enough, onChange]);

  if (q.error) return <p className="text-[13px] text-[var(--crit)]">Gemini quota unavailable: {q.error}</p>;
  if (!d) return <p className="text-[13px] text-[var(--text-3)]">Checking Gemini quota…</p>;
  if (!d.configured) return <p className="text-[13px] text-[var(--text-3)]">Gemini isn't configured (no API key).</p>;
  // Google can cut us off before our own count reaches the limit (usage from elsewhere): show that as a full bar.
  const used = d.exhausted ? 1 : Math.min(1, d.calls_today / Math.max(1, d.daily_limit));
  return (
    <div className="space-y-1.5" aria-label="Gemini quota">
      <div className="flex items-baseline justify-between gap-3 text-[13px]">
        <span className="text-[var(--text)]"><span className="font-semibold tabular-nums">{d.remaining_today}</span> of {d.daily_limit} Gemini calls left today</span>
        <span className="text-[var(--text-3)]">resets in {inHours(d.resets_in_s)}</span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-[var(--hairline-subtle)]">
        <div className={`h-full rounded-full ${enough ? "bg-[var(--accent)]" : "bg-[var(--crit)]"}`} style={{ width: `${used * 100}%` }} />
      </div>
      <p className={`text-[13px] ${enough ? "text-[var(--text-3)]" : "text-[var(--crit)]"}`}>
        {enough
          ? `This run needs about ${need} calls · ${d.rpm_limit}/min pace (~${Math.ceil(need / d.rpm_limit)} min)`
          : d.blocked_reason ?? `This run needs about ${need} calls; only ${d.remaining_today} left. Use fewer agents or the deterministic backend.`}
      </p>
    </div>
  );
}
