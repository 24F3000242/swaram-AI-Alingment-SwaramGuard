import { useState } from "react";
import type { TimelineItem } from "../types";
import { Empty } from "./ui";
import { shortId, time } from "../lib/format";

const TYPE_COLOR: Record<string, string> = {
  message: "var(--hairline)",
  task: "var(--text-3)",
  tool_call: "var(--accent)",
  resource_access: "var(--accent)",
  data_transfer: "var(--crit)",
};

export interface TimelineProps {
  items: TimelineItem[];
  onSelect?: (eventId: string) => void;
  selectedEventId?: string | null;
}

/**
 * Apple-style multi-agent swimlane timeline.
 * 1 lane per agent, 10px dots with flagged halos, labeled time axis,
 * and hover tooltip showing event details.
 */
export function Timeline({ items, onSelect, selectedEventId }: TimelineProps) {
  const [hoveredEvent, setHoveredEvent] = useState<TimelineItem | null>(null);
  const [mousePos, setMousePos] = useState<{ x: number; y: number }>({ x: 0, y: 0 });

  if (!items.length) {
    return <Empty>No normalized events available for this run.</Empty>;
  }

  const agents = Array.from(new Set(items.map((i) => i.agent_id))).sort();
  const times = items.map((i) => new Date(i.timestamp).getTime());
  const t0 = Math.min(...times);
  const t1 = Math.max(...times);
  const span = Math.max(1, t1 - t0);

  const laneHeight = 44;
  const leftMargin = 140;
  const rightMargin = 30;
  const W = 1000;
  const H = agents.length * laneHeight + 50;

  const getX = (t: number) => leftMargin + ((W - leftMargin - rightMargin) * (t - t0)) / span;

  return (
    <div className="relative w-full select-none">
      <div className="overflow-x-auto rounded-[var(--r-card)] bg-[var(--card)] p-4">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          className="h-auto w-full"
          role="img"
          aria-label="Multi-agent event swimlane timeline"
          onMouseMove={(e) => {
            const rect = e.currentTarget.getBoundingClientRect();
            setMousePos({ x: e.clientX - rect.left, y: e.clientY - rect.top });
          }}
        >
          {/* Swimlane background alternating strips & divider lines */}
          {agents.map((a, i) => {
            const y = i * laneHeight + 20;
            const shortName = a.split("-").pop() || a;
            return (
              <g key={a}>
                {/* Lane background */}
                <rect
                  x={leftMargin - 10}
                  y={y - 14}
                  width={W - leftMargin + 10}
                  height={laneHeight}
                  fill={i % 2 === 0 ? "transparent" : "var(--card-alt)"}
                  rx={8}
                  opacity={0.6}
                />

                {/* Guideline */}
                <line
                  x1={leftMargin}
                  x2={W - rightMargin}
                  y1={y + 8}
                  y2={y + 8}
                  stroke="var(--hairline)"
                  strokeWidth={1}
                  strokeOpacity={0.6}
                  strokeDasharray="2 4"
                />

                {/* Agent Label on Left */}
                <text
                  x={leftMargin - 16}
                  y={y + 12}
                  textAnchor="end"
                  fontSize="13"
                  fontWeight="600"
                  fill="var(--text)"
                  className="font-mono tracking-tight"
                >
                  agent-{shortName}
                </text>
              </g>
            );
          })}

          {/* Event Dots */}
          {items.map((it) => {
            const yi = agents.indexOf(it.agent_id);
            if (yi === -1) return null;
            const cy = yi * laneHeight + 28;
            const cx = getX(new Date(it.timestamp).getTime());
            const isSelected = selectedEventId === it.event_id;
            const isHovered = hoveredEvent?.event_id === it.event_id;

            return (
              <g
                key={it.event_id}
                className="cursor-pointer transition-transform"
                onMouseEnter={() => setHoveredEvent(it)}
                onMouseLeave={() => setHoveredEvent(null)}
                onClick={() => onSelect?.(it.event_id)}
              >
                {/* Red halo for flagged alerts */}
                {it.flagged && (
                  <circle
                    cx={cx}
                    cy={cy}
                    r={isHovered || isSelected ? 13 : 10}
                    fill="var(--crit)"
                    fillOpacity={0.2}
                    className="animate-pulse"
                  />
                )}

                {/* Outer focus ring if selected */}
                {isSelected && (
                  <circle
                    cx={cx}
                    cy={cy}
                    r={8}
                    fill="none"
                    stroke="var(--accent)"
                    strokeWidth={2}
                  />
                )}

                {/* 10px diameter dot (r=5) */}
                <circle
                  cx={cx}
                  cy={cy}
                  r={it.flagged ? 5.5 : 4.5}
                  fill={it.flagged ? "var(--crit)" : TYPE_COLOR[it.event_type] ?? "var(--text-3)"}
                  stroke={it.status === "denied" ? "var(--text)" : "var(--bg)"}
                  strokeWidth={1.5}
                  className="drop-shadow-xs"
                />
              </g>
            );
          })}

          {/* Time Axis at bottom */}
          <g transform={`translate(0, ${H - 14})`}>
            <line
              x1={leftMargin}
              x2={W - rightMargin}
              y1={0}
              y2={0}
              stroke="var(--hairline)"
              strokeWidth={1}
            />
            <text x={leftMargin} y={12} fontSize="11" fill="var(--text-3)" className="font-mono">
              {new Date(t0).toLocaleTimeString()}
            </text>
            <text
              x={(leftMargin + W - rightMargin) / 2}
              y={12}
              textAnchor="middle"
              fontSize="11"
              fill="var(--text-3)"
              className="font-mono"
            >
              Timeline Span: {Math.round(span / 1000)}s
            </text>
            <text
              x={W - rightMargin}
              y={12}
              fontSize="11"
              fill="var(--text-3)"
              textAnchor="end"
              className="font-mono"
            >
              {new Date(t1).toLocaleTimeString()}
            </text>
          </g>
        </svg>

        {/* Hover Tooltip Overlay */}
        {hoveredEvent && (
          <div
            className="pointer-events-none absolute z-20 max-w-[320px] -translate-x-1/2 -translate-y-full rounded-xl border border-[var(--hairline)]/80 bg-[var(--card)] p-3 text-left shadow-lg backdrop-blur-md"
            style={{
              left: `${Math.min(Math.max(mousePos.x, 150), 850)}px`,
              top: `${Math.max(mousePos.y - 12, 10)}px`,
            }}
          >
            <div className="flex items-center justify-between gap-3 border-b border-[var(--hairline)]/50 pb-1.5 text-[11px]">
              <span className="font-mono font-semibold text-[var(--accent)]">
                {shortId(hoveredEvent.event_id)}
              </span>
              <span className="text-[var(--text-3)]">{time(hoveredEvent.timestamp)}</span>
            </div>
            <div className="mt-1.5 text-[13px] font-medium leading-snug text-[var(--text)]">
              {hoveredEvent.summary}
            </div>
            <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px] text-[var(--text-2)]">
              <span className="capitalize">{hoveredEvent.event_type.replace("_", " ")}</span>
              <span>&bull;</span>
              <span className="font-mono">{hoveredEvent.status}</span>
              {hoveredEvent.flagged && (
                <span className="rounded-md bg-[var(--crit-bg)] px-1.5 py-0.5 font-semibold text-[var(--crit)]">
                  Alert Flag
                </span>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Single-line legend */}
      <div className="mt-3 flex flex-wrap items-center justify-center gap-x-6 gap-y-2 border-t border-[var(--hairline)]/40 pt-3 text-[13px] text-[var(--text-2)]">
        {Object.entries(TYPE_COLOR).map(([k, c]) => (
          <span key={k} className="inline-flex items-center gap-1.5 capitalize">
            <span className="h-2.5 w-2.5 rounded-full" style={{ background: c }} />
            {k.replace("_", " ")}
          </span>
        ))}
        <span className="inline-flex items-center gap-1.5">
          <span className="relative flex h-3 w-3 items-center justify-center">
            <span className="absolute h-3 w-3 rounded-full bg-[var(--crit)] opacity-30" />
            <span className="h-2 w-2 rounded-full bg-[var(--crit)]" />
          </span>
          Flagged event
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full border-2 border-[var(--text)] bg-[var(--card)]" />
          Gateway denied
        </span>
      </div>
    </div>
  );
}
