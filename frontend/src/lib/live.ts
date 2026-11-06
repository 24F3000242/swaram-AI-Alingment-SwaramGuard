/** Client for the live stream (WebSocket /api/live). See docs/live-stream.md for every message type. */
import { useEffect, useRef, useState } from "react";
import { getApiKey } from "./apiKey";

export type LiveType = "hello" | "run_started" | "run_agents" | "event" | "detection" | "containment" | "quarantine" | "response" | "operator"
  | "run_finished" | "run_failed" | "quota" | "review";

export interface LiveMessage<T = Record<string, unknown>> {
  type: LiveType;
  seq: number;
  ts?: string;
  run_id: string | null;
  data: T;
}

export function liveUrl(runId?: string | null, since = 0): string {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const q = new URLSearchParams();
  if (runId) q.set("run_id", runId);
  if (since) q.set("since", String(since));
  const key = getApiKey();
  if (key) q.set("key", key); // browsers can't send headers on a WebSocket
  return `${proto}://${location.host}/api/live${q.toString() ? `?${q}` : ""}`;
}

/** Subscribe to the live stream; reconnects automatically and resumes from the last message seen. */
export function useLiveStream(runId?: string | null, max = 500) {
  const [messages, setMessages] = useState<LiveMessage[]>([]);
  const [connected, setConnected] = useState(false);
  const last = useRef(0);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let stop = false;
    let retry: ReturnType<typeof setTimeout> | undefined;
    const open = () => {
      ws = new WebSocket(liveUrl(runId, last.current));
      ws.onopen = () => setConnected(true);
      ws.onmessage = (ev) => {
        const m = JSON.parse(ev.data) as LiveMessage;
        if (m.type === "hello" || m.seq <= last.current) return;
        last.current = m.seq;
        setMessages((prev) => [...prev, m].slice(-max));
      };
      ws.onclose = () => {
        setConnected(false);
        if (!stop) retry = setTimeout(open, 1500);
      };
    };
    open();
    return () => {
      stop = true;
      clearTimeout(retry);
      ws?.close();
    };
  }, [runId, max]);

  return { messages, connected, clear: () => setMessages([]) };
}
