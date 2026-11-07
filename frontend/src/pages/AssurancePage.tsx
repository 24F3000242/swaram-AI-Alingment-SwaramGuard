import { useState, useEffect } from "react";
import { PageHeader } from "../components/PageHeader";
import { Segmented } from "../components/ui";
import { OwaspCoveragePage } from "./OwaspCoveragePage";
import { EvaluationPage } from "./EvaluationPage";
import { OutsideProofCard } from "../components/OutsideProofCard";
import { ShieldCheck, BarChart3, Database } from "lucide-react";

export type AssuranceTab = "owasp" | "benchmarks" | "outside_proof";

export function AssurancePage({ initialTab = "owasp" }: { initialTab?: AssuranceTab }) {
  const [activeTab, setActiveTab] = useState<AssuranceTab>(initialTab);

  useEffect(() => {
    setActiveTab(initialTab);
  }, [initialTab]);

  return (
    <div className="space-y-8">
      <PageHeader
        title="Assurance."
        subtitle="Security standards alignment, empirical benchmark accuracy, and external real-world intrusion verification."
        actions={
          <div className="flex items-center">
            <Segmented
              value={activeTab}
              onChange={(tab) => {
                setActiveTab(tab);
                if (tab === "owasp") window.location.hash = "#/owasp";
                else if (tab === "benchmarks") window.location.hash = "#/evaluation";
                else if (tab === "outside_proof") window.location.hash = "#/assurance/proof";
              }}
              options={[
                {
                  value: "owasp",
                  label: (
                    <span className="inline-flex items-center gap-1.5">
                      <ShieldCheck size={14} />
                      <span>OWASP Top 10</span>
                    </span>
                  ),
                },
                {
                  value: "benchmarks",
                  label: (
                    <span className="inline-flex items-center gap-1.5">
                      <BarChart3 size={14} />
                      <span>Benchmark Accuracy</span>
                    </span>
                  ),
                },
                {
                  value: "outside_proof",
                  label: (
                    <span className="inline-flex items-center gap-1.5">
                      <Database size={14} />
                      <span>Outside Proof</span>
                    </span>
                  ),
                },
              ]}
            />
          </div>
        }
      />

      {/* Render selected view */}
      {activeTab === "owasp" && (
        <div className="transition-opacity">
          <OwaspCoveragePage hideHeader />
        </div>
      )}

      {activeTab === "benchmarks" && (
        <div className="transition-opacity">
          <EvaluationPage hideHeader />
        </div>
      )}

      {activeTab === "outside_proof" && (
        <div className="space-y-6 transition-opacity">
          <OutsideProofCard />
        </div>
      )}
    </div>
  );
}
