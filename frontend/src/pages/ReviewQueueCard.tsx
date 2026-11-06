import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Button, Card, Empty, Segmented } from "../components/ui";
import { shortId } from "../lib/format";
import { useLiveStream } from "../lib/live";
import { useRunData } from "../state";
import type { ReviewItem } from "../types";

const KIND_LABEL: Record<ReviewItem["kind"], string> = {
  paused_agent: "Agent paused",
  held_egress: "Outbound transfers held",
  quarantined_input: "Input quarantined",
};

/** Human review of live containment: release or confirm each paused agent, egress hold and quarantined input. */
export function ReviewQueueCard() {
  const [filter, setFilter] = useState<"pending" | "all">("pending");
  const [tick, setTick] = useState(0);
  const items = useRunData(() => api.reviews(filter === "pending" ? "pending" : undefined), "reviews", [filter, tick]);
  const live = useLiveStream(undefined, 50);
  const [busy, setBusy] = useState<string | null>(null);
  const [reviewer, setReviewer] = useState(() => {
    try { return localStorage.getItem("swarmguard.reviewer") ?? ""; } catch { return ""; }
  });
  const saveReviewer = (v: string) => {
    setReviewer(v);
    try { localStorage.setItem("swarmguard.reviewer", v); } catch { /* private mode: keep it in memory */ }
  };
  const [error, setError] = useState<string | null>(null);

  // New containment anywhere: refresh the queue without a page reload.
  const reviewMsgs = live.messages.filter((m) => m.type === "review");
  const lastReview = reviewMsgs[reviewMsgs.length - 1]?.seq;
  useEffect(() => { if (lastReview) setTick((t) => t + 1); }, [lastReview]);

  async function decide(item: ReviewItem, decision: "release" | "confirm") {
    setBusy(item.review_id + decision);
    setError(null);
    try {
      await api.decideReview(item.review_id, decision, undefined, reviewer || undefined);
      setTick((t) => t + 1);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  }

  const list = items.data ?? [];
  return (
    <Card title={`Review queue${filter === "pending" ? ` (${list.length} pending)` : ""}`}>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <p className="max-w-2xl text-[13px] leading-relaxed text-muted">
          Every agent the live guard pauses, every outbound hold and every quarantined input waits here for a person.
          <strong> Release</strong> lets a still-running agent continue at once; <strong>Confirm</strong> keeps it contained.
        </p>
        <div className="flex items-center gap-2">
          <input aria-label="Your name" placeholder="Your name" value={reviewer} onChange={(e) => saveReviewer(e.target.value)}
            className="h-8 w-32 rounded-full border border-[var(--hairline)] bg-[var(--card)] px-3 text-[13px] text-[var(--text)]" />
          <Segmented size="sm" value={filter} onChange={setFilter} options={[{ value: "pending", label: "Pending" }, { value: "all", label: "All" }]} />
        </div>
      </div>
      {error && <p className="mb-3 text-[13px] text-[var(--crit)]">{error}</p>}
      {list.length ? (
        <ul className="divide-y divide-[var(--hairline-subtle)]">
          {list.map((i) => (
            <li key={i.review_id} className="flex flex-wrap items-start justify-between gap-3 py-3">
              <div className="min-w-0 flex-1 text-[13px]">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium text-ink">{KIND_LABEL[i.kind]}</span>
                  <span className="font-mono text-faint">{shortId(i.agent_id)}</span>
                  {i.role && <span className="text-muted">{i.role}</span>}
                  {i.trigger && <span className="rounded-full bg-[var(--low-bg)] px-2 py-0.5 text-[11px] text-muted">{i.trigger}</span>}
                  {i.status !== "pending" && <Badge value={i.status === "released" ? "allowed" : "blocked"} />}
                  {i.status === "pending" && i.escalated_at && (
                    <span className="rounded-full bg-[var(--crit-bg)] px-2 py-0.5 text-[11px] font-medium text-[var(--crit)]">overdue</span>
                  )}
                </div>
                <p className="mt-1 [overflow-wrap:anywhere] text-muted">
                  {i.explanation ?? (i.kind === "quarantined_input" ? `${i.resource} claims to be from ${i.claimed_sender}` : "")}
                </p>
                <p className="mt-0.5 text-[11px] text-faint">run <span className="font-mono">{i.run_id}</span>{i.effect ? ` · ${i.effect}` : ""}{i.decided_by ? ` · by ${i.decided_by}` : ""}</p>
              </div>
              {i.status === "pending" && (
                <div className="flex gap-2">
                  <Button variant="secondary" busy={busy === i.review_id + "release"} onClick={() => decide(i, "release")}>Release</Button>
                  <Button variant="ghost" busy={busy === i.review_id + "confirm"} onClick={() => decide(i, "confirm")}>Confirm</Button>
                </div>
              )}
            </li>
          ))}
        </ul>
      ) : <Empty>{items.error ?? (filter === "pending" ? "Nothing waiting. Contained agents appear here the moment the live guard acts." : "No reviews yet.")}</Empty>}
    </Card>
  );
}
