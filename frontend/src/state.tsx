import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { api } from "./api";
import type { Meta, Run } from "./types";

const RUN_KEY = "swaramguard.selectedRun";

interface AppState {
  runs: Run[];
  meta: Meta | null;
  health: { storage: string; workspace: string } | null;
  apiError: string | null;
  selectedRunId: string | null;
  selectRun: (id: string | null) => void;
  refreshRuns: () => Promise<void>;
}

const Ctx = createContext<AppState | null>(null);

function readStoredRun(): string | null {
  try {
    return localStorage.getItem(RUN_KEY);
  } catch {
    return null;
  }
}

export function AppStateProvider({ children }: { children: ReactNode }) {
  const [runs, setRuns] = useState<Run[]>([]);
  const [meta, setMeta] = useState<Meta | null>(null);
  const [health, setHealth] = useState<AppState["health"]>(null);
  const [apiError, setApiError] = useState<string | null>(null);
  const [selectedRunId, setSelected] = useState<string | null>(readStoredRun);

  const selectRun = useCallback((id: string | null) => {
    setSelected(id);
    try {
      if (id) localStorage.setItem(RUN_KEY, id);
      else localStorage.removeItem(RUN_KEY);
    } catch {
      /* storage unavailable: selection just won't survive reload */
    }
  }, []);

  const refreshRuns = useCallback(async () => {
    try {
      const list = await api.runs();
      setRuns(list);
      setApiError(null);
      setSelected((cur) => (cur && list.some((r) => r.run_id === cur) ? cur : list[0]?.run_id ?? null));
    } catch (e) {
      setApiError((e as Error).message);
    }
  }, []);

  useEffect(() => {
    refreshRuns();
    api.meta().then(setMeta).catch((e) => setApiError(e.message));
    api.health().then(setHealth).catch(() => undefined);
  }, [refreshRuns]);

  return (
    <Ctx.Provider value={{ runs, meta, health, apiError, selectedRunId, selectRun, refreshRuns }}>{children}</Ctx.Provider>
  );
}

export function useAppState(): AppState {
  const v = useContext(Ctx);
  if (!v) throw new Error("useAppState outside provider");
  return v;
}

/** Load something for the selected run; re-runs when the run (or deps) change. */
export function useRunData<T>(loader: (runId: string) => Promise<T>, runId: string | null, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const reload = useCallback(async () => {
    if (!runId) {
      setData(null);
      return;
    }
    setLoading(true);
    try {
      setData(await loader(runId));
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [runId, ...deps]);
  useEffect(() => {
    setData(null); // Clear stale data immediately upon runId change to prevent stale display
    reload();
  }, [reload]);
  return { data, setData, error, loading, reload };
}
