import { useState } from "react";
import { Badge, Card } from "./ui";
import {
  THREAT_CATEGORIES,
  THREAT_RULES,
  BENCHMARK_PROOF,
  MONITORING_COMPONENTS,
  type ThreatCategory,
  type MonitoringComponentDef,
} from "../lib/threatRules";
import { Layers, ShieldCheck } from "lucide-react";

interface ThreatMatrixViewProps {
  mode?: "all" | "simulator" | "collector" | "detection";
  defaultCategory?: ThreatCategory["key"];
}

export function ThreatMatrixView({
  mode = "all",
  defaultCategory = "data_access",
}: ThreatMatrixViewProps) {
  const [mainView, setMainView] = useState<"threats" | "observability">("threats");
  const [selectedCat, setSelectedCat] = useState<ThreatCategory["key"]>(defaultCategory);
  const [selectedRuleId, setSelectedRuleId] = useState<string>("SG-001");
  const [selectedCompId, setSelectedCompId] = useState<number>(1);
  const [activeTab, setActiveTab] = useState<"simulator" | "collector" | "detection">(
    mode === "all" ? "simulator" : mode
  );

  const currentCategory = THREAT_CATEGORIES.find((c) => c.key === selectedCat)!;
  const filteredRules = THREAT_RULES.filter((r) => r.category === selectedCat);
  const activeRule = THREAT_RULES.find((r) => r.id === selectedRuleId) ?? filteredRules[0];
  const activeComponent: MonitoringComponentDef =
    MONITORING_COMPONENTS.find((c) => c.id === selectedCompId) ?? MONITORING_COMPONENTS[0];

  const handleSelectRuleFromComponent = (ruleId: string) => {
    const targetRule = THREAT_RULES.find((r) => r.id === ruleId);
    if (targetRule) {
      setSelectedCat(targetRule.category);
      setSelectedRuleId(targetRule.id);
      setMainView("threats");
    }
  };

  return (
    <Card
      title={
        <div className="flex flex-wrap items-center gap-3">
          <span className="font-semibold text-[var(--text)]">
            {mainView === "threats" ? "20-Rule Threat & Telemetry Matrix" : "12-Component Observability Architecture"}
          </span>
          <div className="inline-flex rounded-full bg-[var(--hairline-subtle)] p-0.5 text-[13px]">
            <button
              onClick={() => setMainView("threats")}
              className={`flex items-center gap-1.5 rounded-full px-3 py-1 font-medium transition-all ${
                mainView === "threats"
                  ? "bg-[var(--card)] text-[var(--text)] shadow-xs"
                  : "text-[var(--text-2)] hover:text-[var(--text)]"
              }`}
            >
              <ShieldCheck size={14} />
              <span>20 Threat Rules</span>
            </button>
            <button
              onClick={() => setMainView("observability")}
              className={`flex items-center gap-1.5 rounded-full px-3 py-1 font-medium transition-all ${
                mainView === "observability"
                  ? "bg-[var(--card)] text-[var(--text)] shadow-xs"
                  : "text-[var(--text-2)] hover:text-[var(--text)]"
              }`}
            >
              <Layers size={14} />
              <span>12 Observability Layers</span>
            </button>
          </div>
        </div>
      }
      actions={
        <div className="flex items-center gap-2">
          <span className="rounded-full bg-[var(--ok-bg)] border border-[var(--ok)]/20 px-2.5 py-0.5 text-[12px] font-semibold text-[var(--ok)]">
            PASSED: {BENCHMARK_PROOF.testsPassing} Tests
          </span>
          <span className="rounded-full bg-[var(--accent)]/10 border border-[var(--accent)]/20 px-2.5 py-0.5 text-[12px] font-semibold text-[var(--accent)]">
            100% Precision
          </span>
        </div>
      }
    >
      {mainView === "observability" ? (
        /* 12-Component Observability Architecture View */
        <div className="space-y-6">
          <div className="flex items-center justify-between rounded-lg bg-[var(--card-alt)] px-4 py-3 text-[14px] text-[var(--text-2)] border border-[var(--hairline-subtle)]">
            <span>
              <strong className="text-[var(--text)]">12-Component Telemetry Mesh:</strong> Comprehensive observability covering agent execution, tools, network, storage, activity logging, and Bayesian graph coordination.
            </span>
            <span className="shrink-0 text-[13px] text-[var(--text-3)] font-mono">12 Active Sensors</span>
          </div>

          {/* 12 Component Cards Grid */}
          <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-4">
            {MONITORING_COMPONENTS.map((comp) => {
              const isSelected = comp.id === selectedCompId;
              return (
                <button
                  key={comp.id}
                  onClick={() => setSelectedCompId(comp.id)}
                  className={`flex flex-col items-start rounded-xl p-3 text-left transition-all border ${
                    isSelected
                      ? "bg-[var(--card)] ring-2 ring-[var(--accent)] shadow-xs border-[var(--accent)]"
                      : "bg-[var(--card-alt)] hover:bg-[var(--card)] border-[var(--hairline-subtle)]"
                  }`}
                >
                  <div className="flex w-full items-center justify-between">
                    <span className="font-mono text-[12px] font-bold text-[var(--accent)]">
                      #{comp.id.toString().padStart(2, "0")}
                    </span>
                    <span
                      className={`rounded-full px-2 py-0.5 text-[11px] font-semibold uppercase ${
                        comp.priority === "Critical"
                          ? "bg-[var(--crit-bg)] text-[var(--crit)] border border-[var(--crit)]/30"
                          : comp.priority === "High"
                          ? "bg-[var(--med-bg)] text-[var(--med)] border border-[var(--med)]/30"
                          : "bg-[var(--card)] text-[var(--text-3)] border border-[var(--hairline-subtle)]"
                      }`}
                    >
                      {comp.priority}
                    </span>
                  </div>
                  <div className="mt-2 text-[14px] font-semibold text-[var(--text)] leading-tight">{comp.component}</div>
                  <div className="mt-1 line-clamp-1 text-[12px] text-[var(--text-3)]">{comp.collectionMethod}</div>
                </button>
              );
            })}
          </div>

          {/* Active Component Deep-Dive */}
          {activeComponent && (
            <div className="rounded-xl border border-[var(--hairline-subtle)] bg-[var(--card-alt)] p-5 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--hairline-subtle)] pb-3">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[14px] font-bold text-[var(--accent)]">
                    Sensor #{activeComponent.id.toString().padStart(2, "0")}:
                  </span>
                  <span className="text-[16px] font-semibold text-[var(--text)]">{activeComponent.component}</span>
                </div>
                <div className="flex items-center gap-2 text-[13px]">
                  <span className="text-[var(--text-3)]">Collection Method:</span>
                  <code className="rounded bg-[var(--card)] px-2 py-0.5 font-mono font-medium text-[var(--text)] border border-[var(--hairline-subtle)]">
                    {activeComponent.collectionMethod}
                  </code>
                </div>
              </div>

              <div className="text-[14px] text-[var(--text-2)] leading-relaxed">
                <strong>Monitored Scope:</strong> {activeComponent.scope}. {activeComponent.description}
              </div>

              {/* Two Perspective Cards: Simulator Emits vs Collector Ingests */}
              <div className="grid gap-4 md:grid-cols-2">
                {/* Simulator Emits */}
                <div className="rounded-xl bg-[var(--card)] p-4 border border-[var(--hairline-subtle)] space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[12px] font-bold uppercase tracking-wider text-[var(--accent)]">
                      1. What AI Agent Simulator Emits
                    </span>
                    <span className="font-mono text-[12px] text-[var(--text-2)]">
                      sample: <strong className="text-[var(--text)]">{activeComponent.simulatorTelemetry.sampleAction}</strong>
                    </span>
                  </div>

                  <div>
                    <div className="text-[12px] font-semibold text-[var(--text-3)]">Supported Event Types:</div>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {activeComponent.simulatorTelemetry.eventTypes.map((t) => (
                        <span key={t} className="rounded bg-[var(--card-alt)] px-2 py-0.5 font-mono text-[12px] text-[var(--accent)] border border-[var(--hairline-subtle)]">
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div>
                    <div className="text-[12px] font-semibold text-[var(--text-3)]">Required Telemetry Fields:</div>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {activeComponent.simulatorTelemetry.requiredFields.map((f) => (
                        <span key={f} className="rounded bg-[var(--card-alt)] px-2 py-0.5 font-mono text-[12px] text-[var(--text)] border border-[var(--hairline-subtle)]">
                          {f}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Collector Optimizes */}
                <div className="rounded-xl bg-[var(--card)] p-4 border border-[var(--hairline-subtle)] space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[12px] font-bold uppercase tracking-wider text-[var(--ok)]">
                      2. How Data Collector Optimizes It
                    </span>
                    <span className="font-mono text-[12px] text-[var(--text-2)]">
                      priority: <strong className="text-[var(--text)]">{activeComponent.priority}</strong>
                    </span>
                  </div>

                  <div>
                    <div className="text-[12px] font-semibold text-[var(--text-3)]">Intake Validation Check:</div>
                    <div className="mt-1 text-[13px] text-[var(--text-2)]">{activeComponent.collectorPipeline.intakeValidation}</div>
                  </div>

                  <div>
                    <div className="text-[12px] font-semibold text-[var(--text-3)]">Normalization & Normalizing Step:</div>
                    <div className="mt-1 text-[13px] text-[var(--text-2)]">{activeComponent.collectorPipeline.normalizationStep}</div>
                  </div>

                  <div>
                    <div className="text-[12px] font-semibold text-[var(--text-3)]">Deduplication Strategy:</div>
                    <div className="mt-1 font-mono text-[12px] text-[var(--text)]">{activeComponent.collectorPipeline.dedupStrategy}</div>
                  </div>
                </div>
              </div>

              {/* Mapped Threat Rules */}
              <div className="pt-2 flex flex-wrap items-center gap-2">
                <span className="text-[13px] font-medium text-[var(--text-3)]">Listening Threat Rules:</span>
                {activeComponent.mappedRules.map((rId) => (
                  <button
                    key={rId}
                    onClick={() => handleSelectRuleFromComponent(rId)}
                    className="inline-flex items-center gap-1.5 rounded-full card px-3 py-1 text-[12px] font-mono text-[var(--accent)] hover:border-[var(--accent)] transition-all"
                  >
                    <span>{rId}</span>
                    <span className="text-[var(--text-3)]">&rsaquo;</span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      ) : (
        /* 20-Rule Threat & Telemetry Matrix View */
        <div className="space-y-4">
          {/* Category Selector Tabs */}
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            {THREAT_CATEGORIES.map((cat) => {
              const isSelected = cat.key === selectedCat;
              const count = THREAT_RULES.filter((r) => r.category === cat.key).length;
              return (
                <button
                  key={cat.key}
                  onClick={() => {
                    setSelectedCat(cat.key);
                    const firstInCat = THREAT_RULES.find((r) => r.category === cat.key);
                    if (firstInCat) setSelectedRuleId(firstInCat.id);
                  }}
                  className={`flex flex-col items-start rounded-xl p-3.5 text-left transition-all ${
                    isSelected
                      ? "bg-[var(--card)] ring-2 ring-[var(--accent)] shadow-sm border border-[var(--hairline-subtle)]"
                      : "bg-[var(--card-alt)] hover:bg-[var(--card)] border border-transparent"
                  }`}
                >
                  <div className="flex w-full items-center justify-between">
                    <span className="font-mono text-[11px] font-bold text-[var(--accent)]">{cat.code}</span>
                    <span className="rounded-full bg-[var(--card)] px-2 py-0.5 text-[11px] font-medium text-[var(--text-2)] border border-[var(--hairline-subtle)]">
                      {count} rules
                    </span>
                  </div>
                  <div className="mt-2 text-[14px] font-semibold text-[var(--text)]">{cat.label}</div>
                  <div className="mt-0.5 line-clamp-1 text-[14px] text-[var(--text-3)]">{cat.description}</div>
                </button>
              );
            })}
          </div>

          {/* Category Description Banner */}
          <div className="flex items-center justify-between rounded-lg bg-[var(--card-alt)] px-3.5 py-2.5 text-[13px] text-[var(--text-2)] border border-[var(--hairline-subtle)]">
            <span>
              <strong className="text-[var(--text)]">{currentCategory.label}</strong> ({currentCategory.code}): {currentCategory.description}
            </span>
            <span className="shrink-0 text-[var(--text-3)]">Showing {filteredRules.length} rules</span>
          </div>

          {/* Perspective Switcher */}
          {mode === "all" && (
            <div className="flex items-center justify-between border-y border-[var(--hairline-subtle)] py-2">
              <span className="text-[14px] font-medium text-[var(--text-3)]">Operational Perspective:</span>
              <div className="inline-flex rounded-lg bg-[var(--card-alt)] p-0.5 text-[14px] border border-[var(--hairline-subtle)]">
                <button
                  onClick={() => setActiveTab("simulator")}
                  className={`rounded-md px-3 py-1.5 font-medium transition-all ${
                    activeTab === "simulator"
                      ? "bg-[var(--card)] text-[var(--text)] shadow-xs"
                      : "text-[var(--text-2)] hover:text-[var(--text)]"
                  }`}
                >
                  1. Simulator Telemetry Contract
                </button>
                <button
                  onClick={() => setActiveTab("collector")}
                  className={`rounded-md px-3 py-1.5 font-medium transition-all ${
                    activeTab === "collector"
                      ? "bg-[var(--card)] text-[var(--text)] shadow-xs"
                      : "text-[var(--text-2)] hover:text-[var(--text)]"
                  }`}
                >
                  2. Collector Ingestion Contract
                </button>
                <button
                  onClick={() => setActiveTab("detection")}
                  className={`rounded-md px-3 py-1.5 font-medium transition-all ${
                    activeTab === "detection"
                      ? "bg-[var(--card)] text-[var(--text)] shadow-xs"
                      : "text-[var(--text-2)] hover:text-[var(--text)]"
                  }`}
                >
                  3. Detection Logic & Scoring
                </button>
              </div>
            </div>
          )}

          {/* Rule Pills in Selected Category */}
          <div className="flex flex-wrap gap-1.5">
            {filteredRules.map((r) => {
              const isSelected = r.id === activeRule?.id;
              return (
                <button
                  key={r.id}
                  onClick={() => setSelectedRuleId(r.id)}
                  className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-left text-[14px] transition-all border ${
                    isSelected
                      ? "bg-[var(--accent)] font-semibold text-white shadow-xs border-[var(--accent)]"
                      : "bg-[var(--card-alt)] text-[var(--text)] hover:bg-[var(--card)] border-[var(--hairline-subtle)]"
                  }`}
                >
                  <span className="font-mono text-[12px]">{r.id}</span>
                  <span className="truncate max-w-[150px]">{r.name}</span>
                  <span
                    className={`h-2 w-2 rounded-full ${
                      r.severity === "critical"
                        ? "bg-[var(--crit)]"
                        : r.severity === "high"
                        ? "bg-[var(--med)]"
                        : "bg-[var(--accent)]"
                    }`}
                  />
                </button>
              );
            })}
          </div>

          {/* Active Rule Deep-Dive Pane */}
          {activeRule && (
            <div className="rounded-xl border border-[var(--hairline-subtle)] bg-[var(--card-alt)] p-5">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--hairline-subtle)] pb-3">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[13px] font-bold text-[var(--accent)]">{activeRule.id}</span>
                  <span className="text-[15px] font-semibold text-[var(--text)]">{activeRule.name}</span>
                </div>
                <div className="flex items-center gap-2">
                  <Badge value={activeRule.severity} />
                  <span className="rounded-full bg-[var(--card)] px-2.5 py-0.5 text-[12px] font-medium text-[var(--text-2)] border border-[var(--hairline-subtle)]">
                    {activeRule.detectionLayer}
                  </span>
                </div>
              </div>

              <p className="mt-3 text-[14px] leading-relaxed text-[var(--text-2)]">
                {activeRule.description}
              </p>

              {/* Perspective View Content */}
              {activeTab === "simulator" && (
                <div className="mt-4 space-y-3 rounded-lg bg-[var(--card)] p-4 shadow-xs border border-[var(--hairline-subtle)]">
                  <div className="flex items-center justify-between">
                    <span className="text-[12px] font-bold uppercase tracking-wider text-[var(--text-3)]">
                      Agent simulator telemetry contract
                    </span>
                    <span className="font-mono text-[12px] text-[var(--text-2)]">
                      event_type: <strong className="text-[var(--text)]">{activeRule.simulatorTelemetry.event_type}</strong> | action: <strong className="text-[var(--text)]">{activeRule.simulatorTelemetry.action}</strong>
                    </span>
                  </div>

                  <div>
                    <div className="text-[14px] font-semibold text-[var(--text-2)]">Attack Behavior Pattern:</div>
                    <div className="mt-1 rounded-md bg-[var(--med-bg)] border border-[var(--med)]/20 px-3 py-2 text-[14px] font-medium text-[var(--med)]">
                      {activeRule.simulatorTelemetry.attackPattern}
                    </div>
                  </div>

                  <div className="grid gap-3 sm:grid-cols-2">
                    <div>
                      <div className="text-[14px] font-semibold text-[var(--text-2)]">Required Event Fields:</div>
                      <div className="mt-1 flex flex-wrap gap-1">
                        {activeRule.simulatorTelemetry.requiredFields.map((f) => (
                          <span key={f} className="rounded bg-[var(--card-alt)] px-2 py-0.5 font-mono text-[12px] text-[var(--text)] border border-[var(--hairline-subtle)]">
                            {f}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div>
                      <div className="text-[14px] font-semibold text-[var(--text-2)]">Sample Agent Payload:</div>
                      <pre className="mt-1 overflow-x-auto rounded bg-[var(--card-alt)] p-2 font-mono text-[12px] text-[var(--text)] border border-[var(--hairline-subtle)]">
                        {JSON.stringify(activeRule.simulatorTelemetry.samplePayload ?? {}, null, 2)}
                      </pre>
                    </div>
                  </div>
                </div>
              )}

              {activeTab === "collector" && (
                <div className="mt-4 space-y-3 rounded-lg bg-[var(--card)] p-4 shadow-xs border border-[var(--hairline-subtle)]">
                  <div className="flex items-center justify-between">
                    <span className="text-[12px] font-bold uppercase tracking-wider text-[var(--text-3)]">
                      Event collector validation contract
                    </span>
                    <span className="font-mono text-[12px] text-[var(--text-2)]">
                      Index Key: <strong className="text-[var(--text)]">{activeRule.collectorOptimization.targetIndex}</strong>
                    </span>
                  </div>

                  <div className="grid gap-3 sm:grid-cols-2">
                    <div className="rounded-md bg-[var(--accent)]/5 p-3 border border-[var(--accent)]/15">
                      <div className="text-[14px] font-bold text-[var(--accent)]">1. Intake Validation Check</div>
                      <div className="mt-1 text-[14px] text-[var(--text-2)]">
                        {activeRule.collectorOptimization.validationCheck}
                      </div>
                    </div>

                    <div className="rounded-md bg-[var(--ok-bg)] p-3 border border-[var(--ok)]/20">
                      <div className="text-[14px] font-bold text-[var(--ok)]">2. Normalization & Storage Optimization</div>
                      <div className="mt-1 text-[14px] text-[var(--text-2)]">
                        {activeRule.collectorOptimization.normalizationStep}
                      </div>
                    </div>
                  </div>

                  <div className="text-[12px] text-[var(--text-3)]">
                    <em>Note: The Collector enforces strict UTC ISO timestamps, deduplicates by (run_id, event_id), and generates sha256 evidence hashes.</em>
                  </div>
                </div>
              )}

              {activeTab === "detection" && (
                <div className="mt-4 space-y-3 rounded-lg bg-[var(--card)] p-4 shadow-xs border border-[var(--hairline-subtle)]">
                  <div className="flex items-center justify-between">
                    <span className="text-[12px] font-bold uppercase tracking-wider text-[var(--text-3)]">
                      Threat detection contract
                    </span>
                    <span className="rounded-full bg-[var(--card-alt)] px-2.5 py-0.5 text-[12px] font-semibold text-[var(--text-2)] border border-[var(--hairline-subtle)]">
                      {activeRule.detectionLayer}
                    </span>
                  </div>

                  <div className="grid gap-3 sm:grid-cols-3">
                    <div className="rounded-md bg-[var(--card-alt)] p-3 border border-[var(--hairline-subtle)]">
                      <div className="text-[14px] font-semibold text-[var(--text-2)]">Detection Method</div>
                      <div className="mt-1 text-[14px] font-medium text-[var(--text)]">{activeRule.detectionLayer}</div>
                    </div>
                    <div className="rounded-md bg-[var(--card-alt)] p-3 border border-[var(--hairline-subtle)]">
                      <div className="text-[14px] font-semibold text-[var(--text-2)]">Evidence Requirement</div>
                      <div className="mt-1 text-[14px] font-medium text-[var(--text)]">Strict event_id correlation</div>
                    </div>
                    <div className="rounded-md bg-[var(--card-alt)] p-3 border border-[var(--hairline-subtle)]">
                      <div className="text-[14px] font-semibold text-[var(--text-2)]">False Alarm Target</div>
                      <div className="mt-1 text-[14px] font-bold text-[var(--ok)]">0% on benign baseline</div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </Card>
  );
}
