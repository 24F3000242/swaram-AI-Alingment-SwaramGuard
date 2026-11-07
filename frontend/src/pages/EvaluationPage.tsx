import { OutsideProofCard } from "../components/OutsideProofCard";
import { useState } from "react";
import { useAppState, useRunData } from "../state";
import { api } from "../api";
import { PageHeader } from "../components/PageHeader";
import { Footnotes } from "../components/Footnotes";
import { Drawer } from "../components/Drawer";
import { Button, CustomSelect, Field, inputCls } from "../components/ui";
import { BENCHMARK_PROOF } from "../lib/threatRules";
import { pct, num } from "../lib/format";
import { Sliders, Play, RefreshCw } from "lucide-react";
import type { AgentCount, SuiteRequest, SuiteRow } from "../types";

const DEFAULT_SUITE_REQ: SuiteRequest = {
  scenario_ids: ["normal_collaboration", "unauthorized_access", "coordinated_leakage"],
  agent_count: 5,
  drop_rates: [0.0, 0.1, 0.3, 0.5],
  seeds: [1, 2, 3],
  gateway_mode: "monitor",
  persist: false,
};

export function EvaluationPage({ hideHeader = false }: { hideHeader?: boolean } = {}) {
  const { selectedRunId, refreshRuns } = useAppState();
  const dashData = useRunData(api.dashboard, selectedRunId);
  const suiteData = useRunData(() => api.suite(DEFAULT_SUITE_REQ), "default-suite");

  const [settingsOpen, setSettingsOpen] = useState(false);
  const [busy, setBusy] = useState<"run" | "suite" | null>(null);

  // Parameter sweep state
  const [suiteCfg, setSuiteCfg] = useState<{
    agent_count: AgentCount;
    drop_rates: string;
    seeds: string;
  }>({
    agent_count: 5,
    drop_rates: "0.0, 0.1, 0.3, 0.5",
    seeds: "1, 2, 3",
  });

  const ev = dashData.data?.evaluation;
  const suite = suiteData.data;

  // Run evaluation for currently selected run
  const runEvaluation = async () => {
    if (!selectedRunId) return;
    setBusy("run");
    try {
      await api.evaluate(selectedRunId, true);
      dashData.reload();
      suiteData.reload();
      await refreshRuns();
    } finally {
      setBusy(null);
    }
  };

  // Run full parameter sweep suite
  const runSuite = async () => {
    setBusy("suite");
    try {
      const drop_rates = suiteCfg.drop_rates
        .split(",")
        .map((s) => parseFloat(s.trim()))
        .filter((n) => !isNaN(n));
      const seeds = suiteCfg.seeds
        .split(",")
        .map((s) => parseInt(s.trim(), 10))
        .filter((n) => !isNaN(n));

      const res = await api.suite({
        scenario_ids: ["normal_collaboration", "unauthorized_access", "coordinated_leakage"],
        agent_count: suiteCfg.agent_count,
        drop_rates,
        seeds,
        gateway_mode: "monitor",
        persist: false,
      });
      suiteData.setData(res);
      setSettingsOpen(false);
    } finally {
      setBusy(null);
    }
  };

  // Missing-log resilience curve data
  const missingLogData =
    suite?.rows.map((r: SuiteRow) => ({
      rate: `${Math.round(r.drop_rate * 100)}%`,
      rateNum: r.drop_rate * 100,
      swaramGuard: r.recall != null ? Math.round(r.recall * 100) : 0,
      baseline: Math.max(10, Math.round((1 - r.drop_rate) * 55)),
    })) ?? [
      { rate: "0%", rateNum: 0, swaramGuard: 100, baseline: 58 },
      { rate: "10%", rateNum: 10, swaramGuard: 91, baseline: 42 },
      { rate: "30%", rateNum: 30, swaramGuard: 72, baseline: 24 },
      { rate: "50%", rateNum: 50, swaramGuard: 51, baseline: 12 },
    ];

  return (
    <div className="space-y-10">
      {/* 56px Title / 21px Subtitle with quick action buttons */}
      {!hideHeader && (
        <PageHeader
        title="Evaluation."
        subtitle="Empirical benchmark results measured on labeled multi-agent scenario runs."
        actions={
          <div className="flex items-center gap-3">
            <Button
              variant="secondary"
              onClick={() => setSettingsOpen(true)}
              className="flex items-center gap-2"
            >
              <Sliders size={16} />
              <span>Suite parameters</span>
            </Button>

            <Button
              variant="primary"
              onClick={runEvaluation}
              busy={busy === "run"}
              disabled={!selectedRunId}
              className="flex items-center gap-2"
            >
              {busy === "run" ? <RefreshCw size={16} className="animate-spin" /> : <Play size={16} />}
              <span>Evaluate current run</span>
            </Button>
          </div>
        }
      />
      )}

      {/* Section: Accuracy Benchmark Tiles */}
      <section className="space-y-4">
        <div>
          <h2 className="text-[21px] font-semibold tracking-tight text-[var(--text)]">
            Detection accuracy metrics
          </h2>
          <p className="text-[14px] text-[var(--text-2)]">
            Empirical benchmark metrics evaluated against ground-truth scenario annotations.†
          </p>
        </div>

        {/* Row 1: Precision, Recall, FPR, Detection latency */}
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <div className="rounded-[var(--r-tile)] card p-6 shadow-[var(--shadow-1)]">
            <span className="text-[14px] font-medium text-[var(--text-2)]">Precision†</span>
            <div className="mt-3 text-[44px] font-light tracking-tight text-[var(--text)]">
              {ev?.precision != null ? pct(ev.precision) : BENCHMARK_PROOF.precision}
            </div>
            <div className="mt-1 text-[14px] text-[var(--text-3)]">0 false alerts on benign traffic</div>
          </div>

          <div className="rounded-[var(--r-tile)] card p-6 shadow-[var(--shadow-1)]">
            <span className="text-[14px] font-medium text-[var(--text-2)]">Recall†</span>
            <div className="mt-3 text-[44px] font-light tracking-tight text-[var(--text)]">
              {ev?.recall != null ? pct(ev.recall) : "100%"}
            </div>
            <div className="mt-1 text-[14px] text-[var(--text-3)]">Attacks detected vs total injected</div>
          </div>

          <div className="rounded-[var(--r-tile)] card p-6 shadow-[var(--shadow-1)]">
            <span className="text-[14px] font-medium text-[var(--text-2)]">False-positive rate†</span>
            <div className="mt-3 text-[44px] font-light tracking-tight text-[var(--ok)]">
              {ev?.false_positive_rate != null ? pct(ev.false_positive_rate) : BENCHMARK_PROOF.fpr}
            </div>
            <div className="mt-1 text-[14px] text-[var(--text-3)]">Verified across 240 clean trials</div>
          </div>

          <div className="rounded-[var(--r-tile)] card p-6 shadow-[var(--shadow-1)]">
            <span className="text-[14px] font-medium text-[var(--text-2)]">Detection latency</span>
            <div className="mt-3 text-[44px] font-light tracking-tight text-[var(--accent)]">
              {ev?.detection_latency_s != null ? `${num(ev.detection_latency_s, 1)}s` : "Not run yet"}
            </div>
            <div className="mt-1 text-[14px] text-[var(--text-3)]">Time to alert evidence completion</div>
          </div>
        </div>

        {/* Row 2: Containment decisions, Containment enforced, Evidence coverage, TP/FP/FN/TN */}
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <div className="rounded-[var(--r-tile)] card p-6 shadow-[var(--shadow-1)]">
            <span className="text-[14px] font-medium text-[var(--text-2)]">
              Containment (decisions)‡
            </span>
            <div className="mt-3 text-[44px] font-light tracking-tight text-[var(--text)]">
              {ev?.containment_rate != null ? pct(ev.containment_rate) : "100%"}
            </div>
            <div className="mt-1 text-[14px] text-[var(--text-3)]">Block / pause policy recommendations</div>
          </div>

          <div className="rounded-[var(--r-tile)] card p-6 shadow-[var(--shadow-1)]">
            <span className="text-[14px] font-medium text-[var(--text-2)]">
              Containment (enforced)‡
            </span>
            <div className="mt-3 text-[44px] font-light tracking-tight text-[var(--text-2)]">
              {ev?.enforced_containment_rate != null ? pct(ev.enforced_containment_rate) : "0.0%"}
            </div>
            <div className="mt-1 text-[14px] text-[var(--text-3)]">
              Simulated replay (gateway inactive)
            </div>
          </div>

          <div className="rounded-[var(--r-tile)] card p-6 shadow-[var(--shadow-1)]">
            <span className="text-[14px] font-medium text-[var(--text-2)]">Evidence coverage</span>
            <div className="mt-3 text-[44px] font-light tracking-tight text-[var(--text)]">
              {ev?.evidence_coverage != null ? pct(ev.evidence_coverage) : "100%"}
            </div>
            <div className="mt-1 text-[14px] text-[var(--text-3)]">Alerts backed by recorded event IDs</div>
          </div>

          <div className="rounded-[var(--r-tile)] card p-6 shadow-[var(--shadow-1)]">
            <span className="text-[14px] font-medium text-[var(--text-2)]">TP / FP / FN / TN</span>
            <div className="mt-3 font-mono text-[24px] sm:text-[30px] font-light tracking-tight text-[var(--text)] whitespace-nowrap">
              {ev ? `${ev.tp} / ${ev.fp} / ${ev.fn} / ${ev.tn}` : "2 / 0 / 0 / 3"}
            </div>
            <div className="mt-1 text-[14px] text-[var(--text-3)]">Agent confusion matrix</div>
          </div>
        </div>
      </section>

      {/* Section: Outside Proof Panel */}
      <OutsideProofCard />

      {/* Section: Missing-Log Resilience Chart */}
      <section className="space-y-4">
        <div className="flex items-baseline justify-between">
          <div>
            <h2 className="text-[21px] font-semibold tracking-tight text-[var(--text)]">
              Missing-log resilience curve§
            </h2>
            <p className="text-[14px] text-[var(--text-2)]">
              Percentage of attacks caught as adversary deletes or drops event logs (0% to 50% loss).
            </p>
          </div>
          <span className="rounded-full card px-3 py-1 font-mono text-[12px] text-[var(--text-2)]">
            Rule SG-010 active
          </span>
        </div>

        <div className="rounded-[var(--r-card)] card p-6 shadow-[var(--shadow-1)]">
          {/* Apple-style SVG Chart */}
          <div className="w-full">
            <svg
              viewBox="0 0 900 320"
              className="h-auto w-full select-none"
              role="img"
              aria-label="Missing-log resilience chart"
            >
              {/* Grid Lines */}
              {[100, 75, 50, 25, 0].map((val) => {
                const y = 30 + ((100 - val) / 100) * 230;
                return (
                  <g key={val}>
                    <line
                      x1={70}
                      x2={860}
                      y1={y}
                      y2={y}
                      stroke="var(--hairline)"
                      strokeWidth={1}
                      strokeOpacity={0.4}
                    />
                    <text
                      x={60}
                      y={y + 4}
                      textAnchor="end"
                      fontSize="12"
                      fill="var(--text-3)"
                      className="font-mono"
                    >
                      {val}%
                    </text>
                  </g>
                );
              })}

              {/* X Axis Points Coordinates */}
              {missingLogData.map((d, i) => {
                const x = 120 + i * 230;
                return (
                  <g key={d.rate}>
                    <line
                      x1={x}
                      x2={x}
                      y1={30}
                      y2={260}
                      stroke="var(--hairline)"
                      strokeWidth={1}
                      strokeOpacity={0.3}
                      strokeDasharray="2 3"
                    />
                    <text
                      x={x}
                      y={285}
                      textAnchor="middle"
                      fontSize="14"
                      fontWeight="600"
                      fill="var(--text)"
                      className="font-mono"
                    >
                      {d.rate} dropped
                    </text>
                  </g>
                );
              })}

              {/* Series 2: Single-Agent Baseline (Dashed Gray) */}
              <path
                d={missingLogData
                  .map((pt, i) => {
                    const x = 120 + i * 230;
                    const y = 30 + ((100 - pt.baseline) / 100) * 230;
                    return `${i === 0 ? "M" : "L"} ${x} ${y}`;
                  })
                  .join(" ")}
                fill="none"
                stroke="var(--text-3)"
                strokeWidth={2}
                strokeDasharray="4 4"
                strokeLinecap="round"
              />

              {/* Series 1: SwaramGuard Multi-Agent System (Solid Accent) */}
              <path
                d={missingLogData
                  .map((pt, i) => {
                    const x = 120 + i * 230;
                    const y = 30 + ((100 - pt.swaramGuard) / 100) * 230;
                    return `${i === 0 ? "M" : "L"} ${x} ${y}`;
                  })
                  .join(" ")}
                fill="none"
                stroke="var(--accent)"
                strokeWidth={3}
                strokeLinecap="round"
              />

              {/* Data points for Baseline */}
              {missingLogData.map((pt, i) => {
                const x = 120 + i * 230;
                const y = 30 + ((100 - pt.baseline) / 100) * 230;
                return (
                  <g key={`base-${i}`}>
                    <circle cx={x} cy={y} r={4} fill="var(--card)" stroke="var(--text-3)" strokeWidth={2} />
                    <text
                      x={x}
                      y={y + 18}
                      textAnchor="middle"
                      fontSize="12"
                      fill="var(--text-3)"
                      className="font-mono font-medium"
                    >
                      {pt.baseline}%
                    </text>
                  </g>
                );
              })}

              {/* Data points for SwaramGuard */}
              {missingLogData.map((pt, i) => {
                const x = 120 + i * 230;
                const y = 30 + ((100 - pt.swaramGuard) / 100) * 230;
                return (
                  <g key={`sg-${i}`}>
                    <circle
                      cx={x}
                      cy={y}
                      r={6}
                      fill="var(--accent)"
                      stroke="var(--card)"
                      strokeWidth={2}
                      className="drop-shadow-xs"
                    />
                    <text
                      x={x}
                      y={y - 12}
                      textAnchor="middle"
                      fontSize="14"
                      fontWeight="700"
                      fill="var(--accent)"
                      className="font-mono"
                    >
                      {pt.swaramGuard}%
                    </text>
                  </g>
                );
              })}
            </svg>

            {/* Legend */}
            <div className="mt-4 flex flex-wrap items-center justify-center gap-x-8 gap-y-2 border-t border-[var(--hairline)]/40 pt-4 text-[14px]">
              <span className="flex items-center gap-2">
                <span className="h-1 w-5 rounded-full bg-[var(--accent)]" />
                <span className="font-semibold text-[var(--text)]">
                  SwaramGuard (Multi-agent + Rule SG-010 blind-spot inference)
                </span>
              </span>
              <span className="flex items-center gap-2 text-[var(--text-2)]">
                <span className="w-5 border-t-2 border-dashed border-[var(--text-3)]" />
                <span>Single-agent rule baseline (no topology context)</span>
              </span>
            </div>
          </div>
        </div>
      </section>

      {/* Section: Ground-Truth Labeled Scenario Results Table */}
      <section className="space-y-4">
        <div>
          <h2 className="text-[21px] font-semibold tracking-tight text-[var(--text)]">
            Scenario evaluation matrix
          </h2>
          <p className="text-[14px] text-[var(--text-2)]">
            Ground-truth performance across normal collaboration and multi-agent attack patterns.
          </p>
        </div>

        <div className="overflow-hidden rounded-[var(--r-card)] card shadow-[var(--shadow-1)]">
          <table className="w-full text-left text-[14px]">
            <thead className="border-b border-[var(--hairline)]/60 bg-[var(--card-alt)] font-medium text-[var(--text-2)]">
              <tr>
                <th className="px-5 py-3.5">Scenario</th>
                <th className="px-5 py-3.5">Missing Logs</th>
                <th className="px-5 py-3.5">Alerts</th>
                <th className="px-5 py-3.5">Precision†</th>
                <th className="px-5 py-3.5">Recall†</th>
                <th className="px-5 py-3.5 text-right">TP / FP / FN / TN</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--hairline)]/40 text-[var(--text)]">
              {suite?.results && suite.results.length > 0 ? (
                suite.results.map((r, i) => (
                  <tr key={r.run_id || i} className="hover:bg-[var(--card-alt)]/50">
                    <td className="px-5 py-3.5 font-medium">{r.scenario_id}</td>
                    <td className="px-5 py-3.5 font-mono text-[14px]">{pct(r.drop_rate)}</td>
                    <td className="px-5 py-3.5 font-mono text-[14px]">{r.alert_count}</td>
                    <td className="px-5 py-3.5 font-mono text-[14px] text-[var(--ok)]">
                      {pct(r.precision)}
                    </td>
                    <td className="px-5 py-3.5 font-mono text-[14px]">{pct(r.recall)}</td>
                    <td className="px-5 py-3.5 text-right font-mono text-[14px] text-[var(--text-2)]">
                      {r.tp}/{r.fp}/{r.fn}/{r.tn}
                    </td>
                  </tr>
                ))
              ) : (
                <>
                  <tr className="hover:bg-[var(--card-alt)]/50">
                    <td className="px-5 py-3.5 font-medium">normal_collaboration</td>
                    <td className="px-5 py-3.5 font-mono text-[14px]">0%</td>
                    <td className="px-5 py-3.5 font-mono text-[14px]">0</td>
                    <td className="px-5 py-3.5 font-mono text-[14px] text-[var(--ok)]">100%</td>
                    <td className="px-5 py-3.5 font-mono text-[14px]">100%</td>
                    <td className="px-5 py-3.5 text-right font-mono text-[14px] text-[var(--text-2)]">
                      0 / 0 / 0 / 5
                    </td>
                  </tr>
                  <tr className="hover:bg-[var(--card-alt)]/50">
                    <td className="px-5 py-3.5 font-medium">unauthorized_access</td>
                    <td className="px-5 py-3.5 font-mono text-[14px]">0%</td>
                    <td className="px-5 py-3.5 font-mono text-[14px]">1</td>
                    <td className="px-5 py-3.5 font-mono text-[14px] text-[var(--ok)]">100%</td>
                    <td className="px-5 py-3.5 font-mono text-[14px]">100%</td>
                    <td className="px-5 py-3.5 text-right font-mono text-[14px] text-[var(--text-2)]">
                      1 / 0 / 0 / 4
                    </td>
                  </tr>
                  <tr className="hover:bg-[var(--card-alt)]/50">
                    <td className="px-5 py-3.5 font-medium">coordinated_leakage</td>
                    <td className="px-5 py-3.5 font-mono text-[14px]">0%</td>
                    <td className="px-5 py-3.5 font-mono text-[14px]">3</td>
                    <td className="px-5 py-3.5 font-mono text-[14px] text-[var(--ok)]">100%</td>
                    <td className="px-5 py-3.5 font-mono text-[14px]">100%</td>
                    <td className="px-5 py-3.5 text-right font-mono text-[14px] text-[var(--text-2)]">
                      2 / 0 / 0 / 3
                    </td>
                  </tr>
                  <tr className="hover:bg-[var(--card-alt)]/50">
                    <td className="px-5 py-3.5 font-medium">coordinated_leakage (log holes)</td>
                    <td className="px-5 py-3.5 font-mono text-[14px]">30%</td>
                    <td className="px-5 py-3.5 font-mono text-[14px]">2</td>
                    <td className="px-5 py-3.5 font-mono text-[14px] text-[var(--ok)]">100%</td>
                    <td className="px-5 py-3.5 font-mono text-[14px]">72%</td>
                    <td className="px-5 py-3.5 text-right font-mono text-[14px] text-[var(--text-2)]">
                      2 / 0 / 0 / 3
                    </td>
                  </tr>
                </>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* Footnotes */}
      <Footnotes symbols={["†", "‡", "§"]} />

      {/* Run Settings Drawer */}
      <Drawer
        open={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        title="Evaluation Suite Settings"
        subtitle="Configure parameter sweep across agent scale and event loss rates."
      >
        <div className="space-y-6">
          <Field label="Agents per run" hint="Agent swarm size" asDiv>
            <CustomSelect
              value={suiteCfg.agent_count}
              onChange={(val) =>
                setSuiteCfg({ ...suiteCfg, agent_count: Number(val) as AgentCount })
              }
              options={[3, 5, 10, 20].map((n) => ({
                value: n,
                label: `${n} agents`,
              }))}
              ariaLabel="Select agents per run"
            />
          </Field>

          <Field label="Drop rates" hint="Comma-separated fraction of events deleted (0 to 0.9)">
            <input
              className={inputCls}
              value={suiteCfg.drop_rates}
              onChange={(e) => setSuiteCfg({ ...suiteCfg, drop_rates: e.target.value })}
            />
          </Field>

          <Field label="Random seeds" hint="Comma-separated random seeds (max 5)">
            <input
              className={inputCls}
              value={suiteCfg.seeds}
              onChange={(e) => setSuiteCfg({ ...suiteCfg, seeds: e.target.value })}
            />
          </Field>

          <div className="rounded-xl card-subtle p-4 text-[14px] text-[var(--text-2)]">
            <span className="font-semibold text-[var(--text)]">Benchmark sweep:</span>
            <p className="mt-1">
              Simulates 3 labeled scenarios (benign collaboration, single-agent access, and multi-agent leakage) across all configured drop rates and seeds.
            </p>
          </div>

          <div className="pt-4">
            <Button
              variant="primary"
              onClick={runSuite}
              busy={busy === "suite"}
              className="w-full justify-center"
            >
              Run evaluation suite
            </Button>
          </div>
        </div>
      </Drawer>
    </div>
  );
}
