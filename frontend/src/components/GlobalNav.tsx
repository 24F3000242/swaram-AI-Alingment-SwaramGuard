import { useAppState } from "../state";
import { ThemeToggle } from "./ThemeToggle";
import { ChevronDown } from "lucide-react";

export interface NavItem {
  id: string;
  path: string;
  label: string;
}

export const NAV_ITEMS: NavItem[] = [
  { id: "overview", path: "#/", label: "Overview" },
  { id: "live", path: "#/live", label: "Live" },
  { id: "incidents", path: "#/incidents", label: "Incidents" },
  { id: "swarm", path: "#/swarm", label: "Swarm" },
  { id: "responses", path: "#/responses", label: "Responses" },
  { id: "evaluation", path: "#/evaluation", label: "Evaluation" },
  { id: "pipeline", path: "#/pipeline/simulator", label: "Pipeline" },
];

export function GlobalNav({ currentRoute }: { currentRoute: string }) {
  const { runs, selectedRunId, selectRun, health } = useAppState();

  const isCurrent = (id: string) => {
    if (id === "overview") return currentRoute === "" || currentRoute === "overview" || currentRoute === "/";
    if (id === "pipeline") return currentRoute.startsWith("pipeline");
    return currentRoute.startsWith(id);
  };

  return (
    <header className="sticky top-0 z-40 h-12 w-full border-b border-[var(--hairline)]/60 bg-[var(--glass)] backdrop-blur-xl">
      <div className="mx-auto flex h-full max-w-[1280px] items-center justify-between px-4 sm:px-6">
        {/* Left Wordmark */}
        <a href="#/" className="shrink-0 flex items-center gap-2 text-[15px] font-semibold tracking-tight text-[var(--text)]">
          <span className="flex h-6 w-6 items-center justify-center rounded-md bg-[var(--text)] text-[var(--bg)]">
            <svg width="13" height="15" viewBox="0 0 16 18" fill="none" aria-hidden>
              <path d="M8 1.2l6 2.3v4.8c0 4-2.6 7.2-6 8.5-3.4-1.3-6-4.5-6-8.5V3.5l6-2.3z" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" />
              <path d="M5.3 9l1.9 1.9 3.6-3.8" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </span>
          <span>SwaramGuard</span>
        </a>

        {/* Center Nav Links */}
        <nav className="flex items-center gap-3 sm:gap-6 overflow-x-auto no-scrollbar" aria-label="Main Navigation">
          {NAV_ITEMS.map((item) => {
            const active = isCurrent(item.id);
            return (
              <a
                key={item.id}
                href={item.path}
                aria-current={active ? "page" : undefined}
                className={`relative py-3 text-[14px] transition-colors ${
                  active
                    ? "font-medium text-[var(--text)]"
                    : "text-[var(--text-2)] hover:text-[var(--text)]"
                }`}
              >
                {item.label}
                {active && (
                  <span className="absolute bottom-0 left-0 right-0 h-[2px] rounded-full bg-[var(--accent)]" />
                )}
              </a>
            );
          })}
        </nav>

        {/* Right Controls: Run Selector & Theme Toggle */}
        <div className="flex min-w-0 shrink items-center gap-2 sm:gap-3">
          {runs.length > 0 && (
            <div className="relative min-w-0">
              <select
                value={selectedRunId ?? ""}
                onChange={(e) => selectRun(e.target.value)}
                className="h-7 w-full min-w-[88px] max-w-[140px] sm:max-w-[320px] truncate cursor-pointer appearance-none rounded-full border border-[var(--hairline)]/60 bg-[var(--card)] pl-3 pr-7 text-[12px] font-medium text-[var(--text)] shadow-xs transition-colors hover:border-[var(--hairline)] focus:outline-none focus:ring-1 focus:ring-[var(--accent)]"
                aria-label="Select Run"
              >
                {runs.map((r) => (
                  <option key={r.run_id} value={r.run_id}>
                    {r.run_id} ({r.scenario_id.replace(/_/g, " ")})
                  </option>
                ))}
              </select>
              <ChevronDown
                size={12}
                className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 text-[var(--text-3)]"
              />
            </div>
          )}

          {health && (
            <span
              className="h-2 w-2 rounded-full bg-[var(--ok)]"
              title={`Connected (${health.storage})`}
              aria-label="Database connected"
            />
          )}

          <ThemeToggle />
        </div>
      </div>
    </header>
  );
}
