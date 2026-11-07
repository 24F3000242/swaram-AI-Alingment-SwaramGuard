import { useEffect, useState } from "react";
import { Banner, GlobalNav } from "./components/ui";
import { OverviewPage } from "./pages/OverviewPage";
import { IncidentsPage } from "./pages/IncidentsPage";
import { LivePage } from "./pages/LivePage";
import { AssurancePage } from "./pages/AssurancePage";
import { PipelinePage } from "./pages/PipelinePage";
import { ApiKeyPrompt } from "./components/ApiKeyPrompt";
import { useAppState } from "./state";

export function useHashRoute(): string {
  const read = () => {
    const raw = window.location.hash.replace(/^#\/?/, "");
    // Route redirect handler
    if (raw === "dashboard") {
      window.location.hash = "#/";
      return "";
    }
    if (raw === "detection") {
      window.location.hash = "#/pipeline/detection";
      return "pipeline/detection";
    }
    if (raw === "simulator") {
      window.location.hash = "#/pipeline/simulator";
      return "pipeline/simulator";
    }
    if (raw === "collector") {
      window.location.hash = "#/pipeline/collector";
      return "pipeline/collector";
    }
    if (raw === "response") {
      window.location.hash = "#/pipeline/response";
      return "pipeline/response";
    }
    return raw;
  };

  const [route, setRoute] = useState(read);

  useEffect(() => {
    const onChange = () => setRoute(read());
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);

  return route;
}

export default function App() {
  const route = useHashRoute();
  const { apiError } = useAppState();

  useEffect(() => {
    try {
      localStorage.setItem("sg_theme", "light");
      document.documentElement.setAttribute("data-theme", "light");
    } catch {}
  }, []);

  // Route routing resolution across the 5 core hubs
  let content = <OverviewPage />;
  const cleanRoute = route.split("/")[0] || "dashboard";

  if (route === "" || route === "/" || cleanRoute === "dashboard" || cleanRoute === "overview") {
    content = <OverviewPage />;
  } else if (cleanRoute === "incidents") {
    const alertId = route.split("/")[1];
    content = <IncidentsPage initialAlertId={alertId} initialView="alerts" />;
  } else if (cleanRoute === "responses") {
    content = <IncidentsPage initialView="reviews" />;
  } else if (cleanRoute === "swarm") {
    content = <LivePage initialView="topology" />;
  } else if (cleanRoute === "live") {
    const isTopology = route.includes("swarm") || route.includes("topology");
    content = <LivePage initialView={isTopology ? "topology" : "feed"} />;
  } else if (cleanRoute === "owasp" || cleanRoute === "coverage") {
    content = <AssurancePage initialTab="owasp" />;
  } else if (cleanRoute === "evaluation") {
    content = <AssurancePage initialTab="benchmarks" />;
  } else if (cleanRoute === "assurance" || cleanRoute === "standards") {
    const tab = route.includes("proof") ? "outside_proof" : route.includes("benchmark") || route.includes("eval") ? "benchmarks" : "owasp";
    content = <AssurancePage initialTab={tab} />;
  } else if (cleanRoute === "pipeline") {
    const subpage = route.split("/")[1] || "simulator";
    content = <PipelinePage subpage={subpage} />;
  }

  const isWide = cleanRoute === "swarm" || route.includes("swarm") || route.includes("topology");

  return (
    <div className="min-h-screen bg-[var(--bg-alt)] text-[var(--text)] selection:bg-[var(--accent)]/20">
      {/* 48px Apple-style Global Nav */}
      <GlobalNav currentRoute={route} />

      <main className={`mx-auto ${isWide ? "max-w-[1280px]" : "max-w-[1120px]"} px-6 py-10 transition-all`}>
        <ApiKeyPrompt />
        {apiError && (
          <div className="mb-6">
            <Banner kind="error">
              {apiError} Start the backend with <code className="font-mono">uvicorn app.main:app --reload</code> in <code className="font-mono">backend/</code>.
            </Banner>
          </div>
        )}
        {content}
      </main>
    </div>
  );
}
