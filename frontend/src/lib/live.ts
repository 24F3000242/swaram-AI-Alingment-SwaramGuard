/** Client for the live stream (WebSocket /api/live). See docs/live-stream.md for every message type. */
import { useEffect, useRef, useState } from "react";
import { getApiKey } from "./apiKey";

export type LiveType =
  | "hello"
  | "run_started"
  | "run_agents"
  | "event"
  | "detection"
  | "containment"
  | "quarantine"
  | "response"
  | "operator"
  | "run_finished"
  | "run_failed"
  | "quota"
  | "review"
  | "reset";

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
export function useLiveStream(runId?: string | null, max = 5000) {
  const [messages, setMessages] = useState<LiveMessage[]>([]);
  const [totalReceived, setTotalReceived] = useState(0);
  const [connected, setConnected] = useState(false);
  const last = useRef(0);
  const wsRef = useRef<WebSocket | null>(null);

  const reset = () => {
    last.current = 0;
    setTotalReceived(0);
    setMessages([]);
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.close(); // Triggers clean reconnect with since=0
    }
  };

  const clear = () => {
    setMessages([]);
  };

  useEffect(() => {
    let ws: WebSocket | null = null;
    let stop = false;
    let retry: ReturnType<typeof setTimeout> | undefined;
    const open = () => {
      ws = new WebSocket(liveUrl(runId, last.current));
      wsRef.current = ws;
      ws.onopen = () => setConnected(true);
      ws.onmessage = (ev) => {
        const m = JSON.parse(ev.data) as LiveMessage;
        if (m.type === "hello") return;
        if (m.type === "reset") {
          last.current = 0;
          setTotalReceived(0);
          setMessages([]);
          return;
        }
        // If server sequence reset back to 1 (e.g. after an operator reset), accept the new stream
        if (last.current > 50 && m.seq === 1) {
          last.current = 0;
          setTotalReceived(0);
          setMessages([]);
        }
        if (m.seq <= last.current) return;
        last.current = m.seq;
        setTotalReceived((n) => n + 1);
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

  return { messages, connected, totalReceived, clear, reset };
}
