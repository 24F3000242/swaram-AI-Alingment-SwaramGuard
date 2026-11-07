import { OUTSIDE_PROOF } from "../lib/threatRules";
import { ShieldAlert, Globe, Cpu, ArrowUpRight } from "lucide-react";

export function OutsideProofCard() {
  const { swarmTraces, agentDojo } = OUTSIDE_PROOF;

  return (
    <section className="space-y-6">
      <div>
        <div className="flex items-center gap-2">
          <span className="rounded-md bg-[var(--accent)]/10 px-2 py-0.5 font-mono text-[11px] font-bold uppercase tracking-wider text-[var(--accent)]">
            Held-Out Verification
          </span>
          <span className="text-[12px] text-[var(--text-3)]">
            External Datasets · Zero Training Leakage
          </span>
        </div>
        <h2 className="mt-1 text-[24px] font-semibold tracking-tight text-[var(--text)]">
          Outside proof: Real intrusion &amp; frontier model benchmarks
        </h2>
        <p className="mt-1 text-[14px] text-[var(--text-2)] leading-relaxed max-w-4xl">
          Multi-agent security cannot rely solely on internal synthetic test suites. These results are measured on real-world intrusion telemetry from a wild swarm attack (Swarm Traces) and prompt injection benchmark traces across 5 leading commercial frontier models (AgentDojo).
        </p>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Card 1: Swarm Traces Intrusion */}
        <div className="rounded-[var(--r-card)] card p-6 shadow-[var(--shadow-1)] border border-[var(--hairline-subtle)] flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-[var(--hairline-subtle)] pb-4">
              <div className="flex items-center gap-2.5">
                <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-[var(--crit-bg)] text-[var(--crit)]">
                  <ShieldAlert size={18} />
                </span>
                <div>
                  <h3 className="text-[17px] font-semibold text-[var(--text)]">
                    {swarmTraces.title}
                  </h3>
                  <span className="font-mono text-[12px] text-[var(--text-3)]">
                    Rule SG-029 Covert Staged Transfer
                  </span>
                </div>
              </div>
              <a
                href="https://swarmtraces.org/"
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 text-[13px] font-medium text-[var(--link)] hover:underline"
              >
                swarmtraces.org <ArrowUpRight size={13} />
              </a>
            </div>

            <p className="mt-4 text-[13px] text-[var(--text-2)] leading-relaxed">
              {swarmTraces.subtitle}
            </p>

            {/* Headline Stats Row */}
            <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-3">
              <div className="rounded-xl bg-[var(--card-alt)] p-3 border border-[var(--hairline-subtle)]/40">
                <span className="text-[11px] font-medium uppercase tracking-wider text-[var(--text-3)]">
                  Rows Scored
                </span>
                <div className="mt-1 text-[22px] font-bold tabular-nums text-[var(--text)]">
                  {swarmTraces.totalRowsScored.toLocaleString()}
                </div>
              </div>

              <div className="rounded-xl bg-[var(--crit-bg)] p-3 border border-[var(--crit)]/20">
                <span className="text-[11px] font-medium uppercase tracking-wider text-[var(--crit)]">
                  Covert Caught
                </span>
                <div className="mt-1 text-[22px] font-bold tabular-nums text-[var(--crit)]">
                  {swarmTraces.flaggedCovert.toLocaleString()}
                </div>
              </div>

              <div className="rounded-xl bg-[var(--ok-bg)] p-3 border border-[var(--ok)]/20 col-span-2 sm:col-span-1">
                <span className="text-[11px] font-medium uppercase tracking-wider text-[var(--ok)]">
                  Benign False Positives
                </span>
                <div className="mt-1 text-[22px] font-bold tabular-nums text-[var(--ok)]">
                  {swarmTraces.benignFlagged} / {swarmTraces.benignBaseline} (0%)
                </div>
              </div>
            </div>

            {/* Signal Breakdown */}
            <div className="mt-5 space-y-2">
              <span className="text-[12px] font-semibold uppercase tracking-wider text-[var(--text-3)]">
                Fired Staging &amp; Exfiltration Signals
              </span>
              <div className="grid grid-cols-2 gap-2 text-[13px]">
                {swarmTraces.signals.map((sig) => (
                  <div
                    key={sig.name}
                    className="flex items-center justify-between rounded-lg bg-[var(--card-alt)] px-3 py-2 border border-[var(--hairline-subtle)]/30"
                  >
                    <span className="text-[var(--text-2)]">{sig.name}</span>
                    <span className="font-mono font-semibold text-[var(--text)]">
                      {sig.count.toLocaleString()}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Coordination Callout */}
          <div className="mt-6 rounded-xl border border-[var(--accent)]/20 bg-[var(--accent)]/5 p-3.5 text-[13px] text-[var(--text)]">
            <div className="flex items-center gap-2 font-semibold text-[var(--accent)]">
              <Globe size={15} />
              <span>Multi-Agent Swarm Funnelling</span>
            </div>
            <p className="mt-1 text-[12px] text-[var(--text-2)] leading-relaxed">
              Analyzed {swarmTraces.coordination.distinctDestinations.toLocaleString()} destinations: <strong>{swarmTraces.coordination.sharedDropPoints.toLocaleString()}</strong> drop points were targeted by multiple distinct agents, with a single drop point receiving coordinates from up to <strong>{swarmTraces.coordination.maxAgentsToOneDropPoint.toLocaleString()}</strong> agent identities.
            </p>
          </div>
        </div>

        {/* Card 2: AgentDojo Benchmark */}
        <div className="rounded-[var(--r-card)] card p-6 shadow-[var(--shadow-1)] border border-[var(--hairline-subtle)] flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-[var(--hairline-subtle)] pb-4">
              <div className="flex items-center gap-2.5">
                <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-[var(--accent)]/10 text-[var(--accent)]">
                  <Cpu size={18} />
                </span>
                <div>
                  <h3 className="text-[17px] font-semibold text-[var(--text)]">
                    {agentDojo.title}
                  </h3>
                  <span className="font-mono text-[12px] text-[var(--text-3)]">
                    Rule SG-028 Injection Classifier Replay
                  </span>
                </div>
              </div>
              <span className="rounded-full bg-[var(--ok-bg)] px-2.5 py-0.5 text-[12px] font-semibold text-[var(--ok)]">
                5 Frontier Models
              </span>
            </div>

            <p className="mt-4 text-[13px] text-[var(--text-2)] leading-relaxed">
              {agentDojo.subtitle}
            </p>

            {/* Headline Stats Row */}
            <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-3">
              <div className="rounded-xl bg-[var(--card-alt)] p-3 border border-[var(--hairline-subtle)]/40">
                <span className="text-[11px] font-medium uppercase tracking-wider text-[var(--text-3)]">
                  Attacked Results
                </span>
                <div className="mt-1 text-[22px] font-bold tabular-nums text-[var(--text)]">
                  {agentDojo.attackedToolResults.toLocaleString()}
                </div>
              </div>

              <div className="rounded-xl bg-[var(--accent)]/10 p-3 border border-[var(--accent)]/20">
                <span className="text-[11px] font-medium uppercase tracking-wider text-[var(--accent)]">
                  Benchmark Recall
                </span>
                <div className="mt-1 text-[22px] font-bold tabular-nums text-[var(--accent)]">
                  {agentDojo.overallRecall}
                </div>
              </div>

              <div className="rounded-xl bg-[var(--ok-bg)] p-3 border border-[var(--ok)]/20 col-span-2 sm:col-span-1">
                <span className="text-[11px] font-medium uppercase tracking-wider text-[var(--ok)]">
                  Internal Fuzzer Recall
                </span>
                <div className="mt-1 text-[22px] font-bold tabular-nums text-[var(--ok)]">
                  {agentDojo.internalFuzzerRecall}
                </div>
              </div>
            </div>

            {/* Per-Model Progress Bars */}
            <div className="mt-5 space-y-2.5">
              <div className="flex items-center justify-between text-[12px] font-semibold uppercase tracking-wider text-[var(--text-3)]">
                <span>Model In-The-Wild Recall</span>
                <span>Caught %</span>
              </div>
              <div className="space-y-2">
                {agentDojo.models.map((m) => {
                  const numVal = parseInt(m.recall, 10);
                  return (
                    <div key={m.model} className="space-y-1">
                      <div className="flex justify-between text-[13px] font-medium">
                        <span className="text-[var(--text)]">{m.model}</span>
                        <span className="font-mono text-[var(--accent)]">{m.recall}</span>
                      </div>
                      <div className="h-2 w-full overflow-hidden rounded-full bg-[var(--hairline-subtle)]">
                        <div
                          className="h-full rounded-full bg-[var(--accent)] transition-all duration-500"
                          style={{ width: `${numVal}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Honest Ceiling Callout */}
          <div className="mt-6 rounded-xl border border-[var(--hairline-subtle)] bg-[var(--bg-alt)] p-3.5 text-[12px] text-[var(--text-2)] leading-relaxed">
            <span className="font-semibold text-[var(--text)]">Honest Ceiling Disclosure:</span> External clean documents (long emails, calendars, invoices) have a {Math.round(parseFloat(agentDojo.falsePositiveRate) * 100)}% false alarm rate on raw content. Defense-in-depth relies on pre-execution behavioral tripwires (SG-012) and egress proxy containment rather than linear classification alone.
          </div>
        </div>
      </div>
    </section>
  );
}
