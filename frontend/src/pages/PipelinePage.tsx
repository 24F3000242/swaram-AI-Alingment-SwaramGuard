import { useState, useEffect } from "react";
import { SimulatorPage } from "./SimulatorPage";
import { CollectorPage } from "./CollectorPage";
import { DetectionPage } from "./DetectionPage";
import { ResponsePage } from "./ResponsePage";

interface PipelinePageProps {
  subpage?: string;
}

const TABS = [
  { id: "simulator", label: "Agent simulator", Component: SimulatorPage },
  { id: "collector", label: "Event collector", Component: CollectorPage },
  { id: "detection", label: "Threat detection", Component: DetectionPage },
  { id: "response", label: "Security response", Component: ResponsePage },
] as const;

export function PipelinePage({ subpage = "simulator" }: PipelinePageProps) {
  const [activeTab, setActiveTab] = useState<string>(subpage);

  useEffect(() => {
    if (subpage && subpage !== activeTab) {
      setActiveTab(subpage);
    }
  }, [subpage]);

  const onTabChange = (tabId: string) => {
    setActiveTab(tabId);
    window.location.hash = `#/pipeline/${tabId}`;
  };

  const current = TABS.find((t) => t.id === activeTab) ?? TABS[0];
  const PageComponent = current.Component;

  return (
    <div className="space-y-6">
      {/* Sub-tab switcher */}
      <div className="flex border-b border-[var(--hairline)]/60 pb-3">
        <div className="inline-flex rounded-full bg-[var(--hairline-subtle)] p-1">
          {TABS.map((tab) => {
            const on = tab.id === activeTab;
            return (
              <button
                key={tab.id}
                onClick={() => onTabChange(tab.id)}
                className={`rounded-full px-4 py-1.5 text-[14px] font-medium transition-all ${
                  on
                    ? "bg-[var(--card)] text-[var(--text)] shadow-xs"
                    : "text-[var(--text-2)] hover:text-[var(--text)]"
                }`}
              >
                {tab.label}
              </button>
            );
          })}
        </div>
      </div>

      <PageComponent />
    </div>
  );
}
