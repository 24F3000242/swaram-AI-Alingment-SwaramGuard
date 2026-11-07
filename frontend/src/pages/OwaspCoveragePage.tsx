import { useEffect, useState } from "react";
import { api } from "../api";
import { PageHeader } from "../components/PageHeader";
import { Badge, Card, Empty } from "../components/ui";
import type { OwaspCoverageResult } from "../types";
import { THREAT_RULES } from "../lib/threatRules";
import { ShieldCheck, AlertCircle, ArrowUpRight, CheckCircle2, Lock, ExternalLink } from "lucide-react";

export function OwaspCoveragePage({ hideHeader = false }: { hideHeader?: boolean } = {}) {
  const [data, setData] = useState<OwaspCoverageResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<"all" | "strong" | "partial">("all");

  useEffect(() => {
    let active = true;
    setLoading(true);
    api
      .owaspCoverage()
      .then((res) => {
        if (active) {
          setData(res);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (active) {
          setError(err.message);
          setLoading(false);
        }
      });
    return () => {
      active = false;
    };
  }, []);

  const risks = (data?.risks ?? []).filter((r) => {
    if (filter === "strong") return r.coverage === "strong";
    if (filter === "partial") return r.coverage === "partial";
    return true;
  });

  return (
    <div className="space-y-8">
      {!hideHeader && (
        <PageHeader
          title="OWASP Agentic."
          subtitle="Mapping SwarmGuard's 30 detection rules and pre-execution enforcement controls to the OWASP Top 10 for Agentic Applications (2026)."
        />
      )}

      {/* Top 3 Scorecard Tiles */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <div className="rounded-[var(--r-tile)] card p-6 shadow-[var(--shadow-1)] border border-[var(--hairline-subtle)]">
          <div className="flex items-center justify-between text-[13px] font-medium text-[var(--text-2)] uppercase tracking-wider">
            <span>Strong Coverage</span>
            <span className="flex h-6 w-6 items-center justify-center rounded-full bg-[var(--ok-bg)] text-[var(--ok)]">
              <CheckCircle2 size={14} />
            </span>
          </div>
          <div className="mt-3 text-[42px] font-semibold tabular-nums tracking-tight text-[var(--ok)]">
            {data?.summary.strong ?? 7}
          </div>
          <p className="mt-1 text-[13px] text-[var(--text-2)] leading-relaxed">
            Detected and pre-execution enforced with verified automated tests.
          </p>
        </div>

        <div className="rounded-[var(--r-tile)] card p-6 shadow-[var(--shadow-1)] border border-[var(--hairline-subtle)]">
          <div className="flex items-center justify-between text-[13px] font-medium text-[var(--text-2)] uppercase tracking-wider">
            <span>Partial Coverage</span>
            <span className="flex h-6 w-6 items-center justify-center rounded-full bg-[var(--med-bg)] text-[var(--med)]">
              <AlertCircle size={14} />
            </span>
          </div>
          <div className="mt-3 text-[42px] font-semibold tabular-nums tracking-tight text-[var(--med)]">
            {data?.summary.partial ?? 3}
          </div>
          <p className="mt-1 text-[13px] text-[var(--text-2)] leading-relaxed">
            Detected or contained in part; transparent gap boundaries disclosed.
          </p>
        </div>

        <div className="rounded-[var(--r-tile)] card p-6 shadow-[var(--shadow-1)] border border-[var(--hairline-subtle)]">
          <div className="flex items-center justify-between text-[13px] font-medium text-[var(--text-2)] uppercase tracking-wider">
            <span>Uncovered Risks</span>
            <span className="flex h-6 w-6 items-center justify-center rounded-full bg-[var(--ok-bg)] text-[var(--ok)]">
              <ShieldCheck size={14} />
            </span>
          </div>
          <div className="mt-3 text-[42px] font-semibold tabular-nums tracking-tight text-[var(--text)]">
            {data?.summary.none ?? 0}
          </div>
          <p className="mt-1 text-[13px] text-[var(--text-2)] leading-relaxed">
            All 10 agentic risks addressed across 29 active threat rules.
          </p>
        </div>
      </div>

      {/* Filter Segmented Control */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[var(--hairline-subtle)] pb-3">
        <div className="inline-flex rounded-full bg-[var(--hairline-subtle)] p-1">
          <button
            onClick={() => setFilter("all")}
            className={`rounded-full px-4 py-1.5 text-[14px] font-medium transition-all ${
              filter === "all"
                ? "bg-[var(--card)] text-[var(--text)] shadow-xs"
                : "text-[var(--text-2)] hover:text-[var(--text)]"
            }`}
          >
            All Risks (10)
          </button>
          <button
            onClick={() => setFilter("strong")}
            className={`rounded-full px-4 py-1.5 text-[14px] font-medium transition-all ${
              filter === "strong"
                ? "bg-[var(--card)] text-[var(--text)] shadow-xs"
                : "text-[var(--text-2)] hover:text-[var(--text)]"
            }`}
          >
            Strong (7)
          </button>
          <button
            onClick={() => setFilter("partial")}
            className={`rounded-full px-4 py-1.5 text-[14px] font-medium transition-all ${
              filter === "partial"
                ? "bg-[var(--card)] text-[var(--text)] shadow-xs"
                : "text-[var(--text-2)] hover:text-[var(--text)]"
            }`}
          >
            Partial (3)
          </button>
        </div>

        <div className="flex items-center gap-3 text-[13px] text-[var(--text-3)]">
          <span>Standards Baseline: OWASP GenAI Security Project (Dec 2025)</span>
          <a
            href="https://genai.owasp.org/"
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1 text-[var(--link)] hover:underline"
          >
            OWASP GenAI <ExternalLink size={12} />
          </a>
        </div>
      </div>

      {/* Loading & Error State */}
      {loading && (
        <Card>
          <Empty>Loading OWASP coverage telemetry...</Empty>
        </Card>
      )}

      {error && (
        <Card>
          <Empty>Failed to load OWASP coverage: {error}</Empty>
        </Card>
      )}

      {/* Risks Grid */}
      {!loading && !error && (
        <div className="space-y-6">
          {risks.map((risk) => {
            return (
              <div
                key={risk.id}
                className="rounded-[var(--r-card)] card p-6 shadow-[var(--shadow-1)] border border-[var(--hairline-subtle)] transition-all hover:border-[var(--accent)]/40"
              >
                {/* Header row */}
                <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--hairline-subtle)] pb-4">
                  <div className="flex items-center gap-3">
                    <span className="font-mono text-[14px] font-bold text-[var(--accent)] bg-[var(--accent)]/10 px-2.5 py-1 rounded-md">
                      {risk.id}
                    </span>
                    <h3 className="text-[20px] font-semibold text-[var(--text)]">
                      {risk.name}
                    </h3>
                  </div>

                  <span
                    className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-[12px] font-semibold uppercase tracking-wider ${
                      risk.coverage === "strong"
                        ? "bg-[var(--ok-bg)] text-[var(--ok)] border border-[var(--ok)]/20"
                        : "bg-[var(--med-bg)] text-[var(--med)] border border-[var(--med)]/20"
                    }`}
                  >
                    {risk.coverage === "strong" ? (
                      <CheckCircle2 size={13} />
                    ) : (
                      <AlertCircle size={13} />
                    )}
                    <span>{risk.coverage} coverage</span>
                  </span>
                </div>

                {/* Content columns */}
                <div className="mt-5 grid grid-cols-1 gap-6 lg:grid-cols-3">
                  {/* Column 1: Rules Mapped */}
                  <div className="space-y-2">
                    <span className="text-[12px] font-semibold uppercase tracking-wider text-[var(--text-3)]">
                      Detection Rules ({risk.rules.length})
                    </span>
                    <div className="space-y-2">
                      {risk.rules.map((r) => {
                        const ruleDef = THREAT_RULES.find((tr) => tr.id === r.rule_id);
                        return (
                          <div
                            key={r.rule_id}
                            className="flex items-center justify-between rounded-lg bg-[var(--card-alt)] px-3 py-2 text-[14px] border border-[var(--hairline-subtle)]/40"
                          >
                            <div className="flex items-center gap-2 min-w-0">
                              <span className="font-mono text-[12px] font-bold text-[var(--text)]">
                                {r.rule_id}
                              </span>
                              <span className="text-[13px] text-[var(--text-2)] truncate">
                                {r.name}
                              </span>
                            </div>
                            {ruleDef && <Badge value={ruleDef.severity} />}
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  {/* Column 2: Enforcement Controls */}
                  <div className="space-y-2">
                    <span className="text-[12px] font-semibold uppercase tracking-wider text-[var(--text-3)]">
                      Pre-Execution &amp; Runtime Controls
                    </span>
                    <ul className="space-y-2 text-[14px] text-[var(--text)]">
                      {risk.controls.map((ctrl, i) => (
                        <li key={i} className="flex items-start gap-2 rounded-lg bg-[var(--card-alt)] p-2.5 border border-[var(--hairline-subtle)]/40">
                          <Lock size={14} className="mt-0.5 text-[var(--accent)] shrink-0" />
                          <span className="text-[13px] leading-snug">{ctrl}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* Column 3: Gap Analysis */}
                  <div className="space-y-2">
                    <span className="text-[12px] font-semibold uppercase tracking-wider text-[var(--text-3)]">
                      Transparent Gap Disclosure
                    </span>
                    <div className="rounded-xl border border-[var(--hairline-subtle)] bg-[var(--bg-alt)] p-4 text-[13px] leading-relaxed text-[var(--text-2)]">
                      <p>{risk.gaps}</p>
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* SIEM & OCSF Export Footer Banner */}
      <Card
        title="Enterprise SIEM & OCSF Alignment"
        actions={
          <a
            href="/api/coverage/owasp"
            target="_blank"
            className="inline-flex items-center gap-1.5 rounded-full border border-[var(--hairline)]/80 bg-[var(--card)] px-4 py-1.5 text-[13px] font-medium text-[var(--text)] hover:border-[var(--hairline)]"
          >
            <span>Raw JSON API</span>
            <ArrowUpRight size={14} />
          </a>
        }
      >
        <p className="text-[14px] leading-relaxed text-[var(--text-2)]">
          Every alert generated by SwarmGuard embeds its corresponding OWASP risk identifiers (e.g. <code>ASI01</code>, <code>ASI07</code>, <code>ASI08</code>).
          When exporting to enterprise SIEM platforms (Splunk, Elastic, Sentinel) via OCSF Detection Finding format (<code>/api/runs/&#123;id&#125;/alerts?format=ocsf</code>), all security findings are automatically tagged with standardized OWASP risk taxons for unified compliance auditing.
        </p>
      </Card>
    </div>
  );
}
