import { useEffect, useState } from "react";
import { AUTH_REQUIRED, getApiKey, setApiKey } from "../lib/apiKey";

/** Shown when the API answers 401/403: enter (or change) the key this browser sends. */
export function ApiKeyPrompt() {
  const [reason, setReason] = useState<string | null>(null);
  const [value, setValue] = useState("");

  useEffect(() => {
    const onAuth = (e: Event) => setReason((e as CustomEvent<string>).detail || "This server needs an API key.");
    window.addEventListener(AUTH_REQUIRED, onAuth);
    return () => window.removeEventListener(AUTH_REQUIRED, onAuth);
  }, []);

  if (!reason) return null;
  const save = () => {
    setApiKey(value.trim());
    window.location.reload();
  };
  return (
    <div role="dialog" aria-label="API key" className="mb-6 rounded-2xl border border-[var(--hairline)] bg-[var(--card)] p-5 shadow-[var(--shadow-1)]">
      <p className="text-[15px] font-medium text-[var(--text)]">Sign in with your API key</p>
      <p className="mt-1 text-[13px] text-[var(--text-2)]">
        {reason} {getApiKey() ? "The key saved in this browser was not accepted." : "Ask your SwarmGuard admin for a key."}
      </p>
      <div className="mt-3 flex flex-wrap gap-2">
        <input type="password" autoComplete="off" aria-label="API key" placeholder="Paste your key" value={value}
          onChange={(e) => setValue(e.target.value)} onKeyDown={(e) => e.key === "Enter" && save()}
          className="h-9 min-w-0 flex-1 rounded-full border border-[var(--hairline)] bg-[var(--bg)] px-4 text-[14px] text-[var(--text)]" />
        <button onClick={save} className="h-9 rounded-full bg-[var(--accent)] px-5 text-[14px] font-medium text-white">Save key</button>
        {getApiKey() && (
          <button onClick={() => { setApiKey(""); window.location.reload(); }}
            className="h-9 rounded-full px-4 text-[14px] text-[var(--text-2)] hover:text-[var(--text)]">Forget saved key</button>
        )}
      </div>
    </div>
  );
}
