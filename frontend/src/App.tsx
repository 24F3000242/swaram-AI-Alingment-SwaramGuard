import { useEffect, useState } from "react";
import { Banner, GlobalNav } from "./components/ui";
import { OverviewPage } from "./pages/OverviewPage";
import { IncidentsPage } from "./pages/IncidentsPage";
import { SwarmPage } from "./pages/SwarmPage";
import { ResponsesPage } from "./pages/ResponsesPage";
import { EvaluationPage } from "./pages/EvaluationPage";
import { CollectorPage } from "./pages/CollectorPage";
import { DetectionPage } from "./pages/DetectionPage";
import { SimulatorPage } from "./pages/SimulatorPage";
import { PipelinePage } from "./pages/PipelinePage";
import { LivePage } from "./pages/LivePage";
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
      window.location.hash = "#/incidents";
      return "incidents";
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
      window.location.hash = "#/responses";
      return "responses";
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

  // Route routing resolution
  let content = <OverviewPage />;
  const cleanRoute = route.split("/")[0] || "overview";

  if (route === "" || route === "/" || cleanRoute === "overview") {
    content = <OverviewPage />;
  } else if (cleanRoute === "incidents") {
    const alertId = route.split("/")[1];
    content = <IncidentsPage initialAlertId={alertId} />;
  } else if (cleanRoute === "swarm") {
    content = <SwarmPage />;
  } else if (cleanRoute === "responses") {
    content = <ResponsesPage />;
  } else if (cleanRoute === "live") {
    content = <LivePage />;
  } else if (cleanRoute === "evaluation") {
    content = <EvaluationPage />;
  } else if (cleanRoute === "pipeline") {
    const subpage = route.split("/")[1] || "simulator";
    content = <PipelinePage subpage={subpage} />;
  } else if (cleanRoute === "detection") {
    content = <DetectionPage />;
  } else if (cleanRoute === "simulator") {
    content = <SimulatorPage />;
  } else if (cleanRoute === "collector") {
    content = <CollectorPage />;
  }

  return (
    <div className="min-h-screen bg-[var(--bg-alt)] text-[var(--text)] selection:bg-[var(--accent)]/20">
      {/* 48px Apple-style Global Nav */}
      <GlobalNav currentRoute={route} />

      <main className={`mx-auto ${cleanRoute === "swarm" ? "max-w-[1280px]" : "max-w-[1120px]"} px-6 py-10 transition-all`}>
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
