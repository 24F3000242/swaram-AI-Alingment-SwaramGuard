import { useState } from "react";
import { api } from "../api";
import { type Column } from "../components/ResultViewer";
import { Badge, Button, Card, Empty, type Status } from "../components/ui";
import { pct, shortId } from "../lib/format";
import { useAppState, useRunData } from "../state";
import type { AgentAssessment, AuditItem, BenchmarkResult } from "../types";

function RiskBar({ value }: { value: number }) {
  const color = value >= 0.9 ? "var(--crit)" : value >= 0.6 ? "var(--high)" : value >= 0.2 ? "var(--med)" : "var(--ok)";
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-20 overflow-hidden rounded-full bg-[var(--hairline-subtle)]">
        <div className="h-full rounded-full" style={{ width: `${Math.max(2, value * 100)}%`, background: color }} />
      </div>
      <span className="tabular-nums">{pct(value)}</span>
    </div>
  );
}

export const riskColumns: Column<AgentAssessment>[] = [
  { key: "agent_id", label: "agent", render: (a) => <span className="font-mono" title={a.agent_id}>{shortId(a.agent_id)}</span> },
  { key: "role", label: "role" },
  { key: "risk", label: "risk (posterior)", render: (a) => <RiskBar value={a.risk} /> },
  { key: "level", label: "level", render: (a) => <Badge value={a.level} /> },
  { key: "anomaly_bits", label: "anomaly", render: (a) => (a.anomaly_bits ? `${a.anomaly_bits} bits` : "") },
  { key: "best_explanation", label: "best explanation", className: "max-w-xs whitespace-normal", render: (a) => a.best_explanation ?? "" },
];

export const auditColumns: Column<AuditItem>[] = [
  { key: "priority", label: "priority", render: (i) => <RiskBar value={i.priority} /> },
  { key: "timestamp", label: "time (UTC)", render: (i) => <span className="font-mono">{i.timestamp.slice(11, 19)}</span> },
  { key: "agent_id", label: "agent", render: (i) => <span className="font-mono" title={i.agent_id}>{shortId(i.agent_id)}</span> },
  { key: "summary", label: "action", className: "max-w-sm whitespace-normal" },
  { key: "reasons", label: "why review", className: "max-w-xs whitespace-normal", render: (i) => i.reasons.join(" · ") },
];

/** Why an agent got its risk: Bayesian factors, System-1 behaviors and ranked hypotheses. */
export function AssessmentDetail({ a }: { a: AgentAssessment | null }) {
  if (!a) return <Card title="Why this agent"><Empty>Select an agent in the risk ranking.</Empty></Card>;
  return (
    <Card title="Why this agent" actions={<Badge value={a.level} />}>
      <div className="space-y-5 text-[14px]">
        <div>
          <div className="font-mono text-[13px] text-[var(--text-3)]">{a.agent_id} · {a.role}</div>
          <div className="mt-1 text-[22px] font-semibold tracking-[-0.02em]">{pct(a.prior)} → {pct(a.risk)}</div>
          <div className="text-[12px] text-[var(--text-3)]">prior → posterior probability of malicious behavior</div>
        </div>

        <section>
          <h3 className="mb-1.5 text-[13px] font-semibold">Evidence (Bayesian update)</h3>
          {a.evidence.length ? (
            <ul className="space-y-1 text-[14px] text-[var(--text)]">
              {a.evidence.map((e) => <li key={e} className="font-mono">{e}</li>)}
            </ul>
          ) : <p className="text-[13px] text-[var(--text-3)]">No evidence moved this agent's risk.</p>}
        </section>

        {a.rare_behaviors.length > 0 && (
          <section>
            <h3 className="mb-1.5 text-[13px] font-semibold">Rare for its role (System 1)</h3>
            <ul className="space-y-1.5">
              {a.rare_behaviors.map((r) => (
                <li key={r.behavior} className="rounded-xl bg-[var(--card-alt)] px-3 py-2">
                  <div className="break-all font-mono text-[12px] text-[var(--text)]">{r.behavior}</div>
                  <div className="mt-0.5 text-[12px] tabular-nums text-[var(--text-3)]">seen in {pct(r.p)} of same-role agents · {r.bits} bits</div>
                </li>
              ))}
            </ul>
          </section>
        )}

        {a.hypotheses.length > 0 && (
          <section>
            <h3 className="mb-2 text-[13px] font-semibold">Possible explanations (abductive)</h3>
            <ul className="space-y-2.5">
              {a.hypotheses.map((h, i) => (
                <li key={h.hypothesis}>
                  <div className="flex items-baseline justify-between gap-3 text-[13px]">
                    <span className={i === 0 ? "font-semibold text-[var(--text)]" : "text-[var(--text-2)]"}>{h.label}</span>
                    <span className="tabular-nums text-[var(--text-3)]">{pct(h.score)}</span>
                  </div>
                  <div className="mt-1 h-1 overflow-hidden rounded-full bg-[var(--hairline-subtle)]">
                    <div className="h-full rounded-full" style={{ width: `${h.score * 100}%`, background: i === 0 ? "var(--accent)" : "var(--hairline-subtle)" }} />
                  </div>
                  {h.supporting.length > 0 && <div className="mt-1 text-[12px] text-[var(--text-3)]">{h.supporting.join(" · ")}</div>}
                </li>
              ))}
            </ul>
          </section>
        )}
      </div>
    </Card>
  );
}

/** Accuracy on planted attacks and benign look-alikes, across missing-event rates. */
export function BenchmarkCard() {
  const [res, setRes] = useState<BenchmarkResult | null>(null);
  const [busy, setBusy] = useState<"quick" | "full" | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function run(full: boolean) {
    setBusy(full ? "full" : "quick");
    setError(null);
    try {
      setRes(await api.benchmark(full));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  }

  const drops = res?.rows.map((r) => String(r.drop_rate)) ?? [];
  const weakest = res
    ? Object.entries(res.cases)
        .filter(([name]) => !res.cases_info[name]?.benign)
        .map(([name, by]) => ({ name, threat: res.cases_info[name]?.threat, rate: by[drops[drops.length - 1]] ?? 0 }))
        .sort((a, b) => (a.rate ?? 0) - (b.rate ?? 0))
        .slice(0, 5)
    : [];

  return (
    <Card title="Accuracy benchmark" actions={
      <>
        <Button variant="secondary" busy={busy === "quick"} disabled={!!busy} onClick={() => run(false)} className="!px-4 !py-1.5 !text-[13px]">Quick run</Button>
        <Button variant="ghost" busy={busy === "full"} disabled={!!busy} onClick={() => run(true)} className="!px-4 !py-1.5 !text-[13px]">Full run</Button>
      </>
    }>
      <p className="mb-4 text-[14px] leading-relaxed text-[var(--text-2)]">
        Plants 26 labeled attacks (one per threat) and 12 benign look-alikes at random points in realistic runs, then
        drops events to simulate incomplete logs. <strong>Caught</strong> = an attacker was flagged.
        <strong> Caught | evidence</strong> = among trials where some attack evidence survived the drop.
      </p>
      {error && <p className="text-[13px] text-[var(--crit)]">{error}</p>}
      {!res && !error && <Empty>Run the benchmark to measure detection accuracy.</Empty>}
      {res && (
        <div className="space-y-5">
          <div className="-mx-6 overflow-x-auto">
            <table className="w-full min-w-max text-left text-[14px]">
              <thead>
                <tr className="text-[12px] text-[var(--text-3)]">
                  {["missing events", "trials", "precision", "false-positive rate", "caught", "caught | evidence", "benign alarms"].map((h, i) => (
                    <th key={h} className={`border-b border-[var(--hairline)] py-2 pr-4 font-medium ${i === 0 ? "pl-6" : ""}`}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {res.rows.map((r) => (
                  <tr key={r.drop_rate} className="border-b border-[var(--hairline-subtle)] last:border-0">
                    <td className="py-2 pl-6 pr-4">{pct(r.drop_rate)}</td>
                    <td className="py-2 pr-4 tabular-nums">{r.trials}</td>
                    <td className="py-2 pr-4 font-medium tabular-nums">{pct(r.precision)}</td>
                    <td className="py-2 pr-4 tabular-nums">{pct(r.false_positive_rate)}</td>
                    <td className="py-2 pr-4 tabular-nums">{pct(r.threat_detection_rate)}</td>
                    <td className="py-2 pr-4 font-medium tabular-nums">{pct(r.detection_given_evidence)}</td>
                    <td className="py-2 pr-4 tabular-nums">{pct(r.benign_alarm_rate)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div>
            <h3 className="mb-2 text-[13px] font-semibold">Hardest threats at {pct(Number(drops[drops.length - 1]))} missing</h3>
            <ul className="space-y-1.5">
              {weakest.map((w) => (
                <li key={w.name} className="flex items-center justify-between gap-3 text-[13px]">
                  <span><span className="font-mono text-[12px] text-[var(--text-3)]">{w.threat}</span> {w.name}</span>
                  <RiskBar value={w.rate ?? 0} />
                </li>
              ))}
            </ul>
            <p className="mt-2 text-[12px] text-[var(--text-3)]">
              Misses here are mostly runs where the incriminating step itself was never logged.
              {res.rows[0]?.trials < 200 && " Quick run uses only 2 trials per threat, so per-threat rates are noisy; use Full run for stable numbers."}
            </p>
          </div>
        </div>
      )}
    </Card>
  );
}

/** System-1 baseline status and continual learning controls. */
export function BaselineCard({ runId, runHasAlerts, onStatus, onChanged }: {
  runId: string | null; runHasAlerts: boolean; onStatus: (s: Status) => void; onChanged: () => void;
}) {
  const summary = useRunData(() => api.baseline(), "baseline");
  const { meta } = useAppState();
  const gemini = meta?.agent_backends?.find((b) => b.id === "gemini");
  const [busy, setBusy] = useState<string | null>(null);
  const s = summary.data;
  const learned = !!(runId && s?.learned_run_ids.includes(runId));

  async function teachAI() {
    setBusy("ai");
    try {
      const res = await api.trainBaseline({ source: "ai", runs: 3 });
      summary.setData(res);
      onChanged();
      const learned = res.taught?.filter((t) => t.learned).length ?? 0;
      const skipped = res.taught?.find((t) => !t.learned)?.skipped_because;
      onStatus({ kind: learned ? "success" : "error", message: learned
        ? `Learned ${learned} clean AI-mode run(s); AI agents' normal behaviour is now part of the baseline. Re-run detection to use it.${skipped ? ` Skipped: ${skipped}.` : ""}`
        : `No AI run could be learned${skipped ? `: ${skipped}` : ""}.` });
    } catch (e) {
      onStatus({ kind: "error", message: (e as Error).message });
    } finally {
      setBusy(null);
    }
  }

  async function train(source: "synthetic" | "run", confirmClean = false) {
    if (confirmClean && !window.confirm("Learn this run as normal even though it has alerts? Only do this if you reviewed the alerts and they are false positives (for example the first runs of AI-mode agents).")) return;
    setBusy(source);
    try {
      const res = await api.trainBaseline(source === "run" ? { source, run_id: runId ?? undefined, confirm_clean: confirmClean } : { source });
      summary.setData(res);
      onChanged();
      onStatus({ kind: "success", message: source === "run"
        ? `Folded ${runId} into the baseline (${res.agents_learned} agents learned). Re-run detection to use it.`
        : `Baseline retrained from synthetic normal runs (${res.agents_learned} agents). Re-run detection to use it.` });
    } catch (e) {
      onStatus({ kind: "error", message: (e as Error).message });
    } finally {
      setBusy(null);
    }
  }

  return (
    <Card title="Behavioral baseline">
      <div className="space-y-4 text-[14px]">
        <p className="text-[14px] leading-relaxed text-[var(--text-2)]">
          What each role normally does, learned from benign runs. SG-004 scores how surprising an agent's behavior is
          for its role. Free-text messages are never used.
        </p>
        {s ? (
          <dl className="grid grid-cols-2 gap-3">
            <div><dt className="text-[12px] text-[var(--text-3)]">Agents learned</dt><dd className="text-[22px] font-semibold tabular-nums">{s.agents_learned}</dd></div>
            <div><dt className="text-[12px] text-[var(--text-3)]">Runs learned</dt><dd className="text-[22px] font-semibold tabular-nums">{s.runs_learned}</dd></div>
            <div className="col-span-2 text-[12px] text-[var(--text-3)]">
              Per-agent histories: <span className="font-medium text-[var(--text)]">{s.identities_learned ?? 0}</span> agent identities
              (SG-025 compares each agent with its own past, not just its role)
            </div>
            <div className="col-span-2 flex flex-wrap gap-1.5">
              {Object.entries(s.roles).map(([role, r]) => (
                <span key={role} className="rounded-full bg-[var(--hairline-subtle)] px-2.5 py-1 text-[12px] text-[var(--text-2)]">{role}: {r.agents} agents · {r.behaviors} behaviors</span>
              ))}
            </div>
          </dl>
        ) : <p className="text-[13px] text-[var(--text-3)]">{summary.error ?? "Loading…"}</p>}
        <div className="flex flex-wrap gap-2">
          <Button variant="secondary" busy={busy === "run"} disabled={!runId || runHasAlerts || learned} onClick={() => train("run")}
            title={runHasAlerts ? "Only runs with no alerts can be learned" : learned ? "Already learned" : "Add this run to the baseline"}>
            Learn from this run
          </Button>
          {runHasAlerts && !learned && (
            <Button variant="ghost" busy={busy === "run"} disabled={!runId} onClick={() => train("run", true)}
              title="Reviewed: the alerts on this run are false positives">
              Alerts were false positives: learn anyway
            </Button>
          )}
          <Button variant="secondary" busy={busy === "ai"} disabled={!gemini?.available || !!busy} onClick={teachAI}
            title={gemini?.available ? "Runs 3 clean AI-mode runs with Gemini (~3 min, ~50 model calls) and learns them" : "Needs a Gemini API key"}>
            Teach AI behaviour
          </Button>
          <Button variant="ghost" busy={busy === "synthetic"} onClick={() => train("synthetic")}>Retrain from scratch</Button>
        </div>
        <p className="text-[12px] text-[var(--text-3)]">
          {learned ? "This run is already part of the baseline." : runHasAlerts ? "This run has alerts, so it can't be learned as normal." : "Continual learning: confirm a run is clean, then add it."}
        </p>
      </div>
    </Card>
  );
}
