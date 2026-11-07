import { useState } from "react";
import type { AgentGraph } from "../types";
import { Empty } from "./ui";

const ROLE_COLOR: Record<string, string> = {
  planner: "var(--accent)",
  analyst: "var(--ok)",
  coder: "var(--med)",
  researcher: "var(--high)",
  reviewer: "var(--text-2)",
};

export interface GraphViewProps {
  graph: AgentGraph | null | undefined;
  height?: number;
  onSelectNode?: (nodeId: string) => void;
  selectedNodeId?: string | null;
  alertEventIds?: Set<string> | string[];
}

/**
 * 1280px wide Apple-style circular agent graph.
 * 56px node circles, role initials, hairline edges,
 * animated red dashes ONLY for alert evidence paths,
 * approved destinations get neutral edge and neutral node outline.
 */
export function GraphView({
  graph,
  height = 520,
  onSelectNode,
  selectedNodeId,
  alertEventIds,
}: GraphViewProps) {
  const [hover, setHover] = useState<string | null>(null);

  if (!graph || graph.nodes.length === 0) {
    return <Empty>No agent graph available. Run detection on this run to construct the communication topology.</Empty>;
  }

  const alertEventSet = new Set(
    alertEventIds instanceof Set
      ? alertEventIds
      : alertEventIds ?? []
  );

  const W = 1000;
  const H = height;
  const agents = graph.nodes.filter((n) => n.kind === "agent");
  const externals = graph.nodes.filter((n) => n.kind === "external");

  const nodeCount = agents.length;
  const isDense = nodeCount > 8;
  const isVeryDense = nodeCount > 14;
  const nodeRadius = isVeryDense ? 18 : isDense ? 22 : 28;

  const cx = externals.length ? W * 0.42 : W / 2;
  const cy = H / 2;
  const R = Math.min(cx, cy) - (isVeryDense ? 48 : 68);

  const pos: Record<string, { x: number; y: number }> = {};
  agents.forEach((n, i) => {
    const a = (2 * Math.PI * i) / (agents.length || 1) - Math.PI / 2;
    pos[n.id] = { x: cx + R * Math.cos(a), y: cy + R * Math.sin(a) };
  });

  externals.forEach((n, i) => {
    pos[n.id] = {
      x: W - 120,
      y: ((i + 1) * H) / (externals.length + 1),
    };
  });

  const maxCount = Math.max(1, ...graph.edges.map((e) => e.count));
  const active = (id: string) =>
    !hover ||
    hover === id ||
    graph.edges.some(
      (e) => (e.source === hover && e.target === id) || (e.target === hover && e.source === id)
    );

  const getRoleInitial = (role?: string | null, id?: string) => {
    if (!role && !id) return "A";
    const r = (role || "").toLowerCase();
    if (r.startsWith("plan")) return "P";
    if (r.startsWith("code")) return "C";
    if (r.startsWith("anal")) return "A";
    if (r.startsWith("rese")) return "R";
    if (r.startsWith("revi")) return "V";
    return (role || id || "A").slice(0, 1).toUpperCase();
  };

  return (
    <div className="w-full select-none">
      <style>{`
        @keyframes flowDash {
          to {
            stroke-dashoffset: -20;
          }
        }
        .suspicious-dash {
          stroke-dasharray: 6 4;
          animation: flowDash 1.2s linear infinite;
        }
        @media (prefers-reduced-motion: reduce) {
          .suspicious-dash {
            animation: none;
          }
        }
      `}</style>

      <div className="overflow-hidden rounded-[var(--r-card)] bg-[var(--card)] p-4">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          className="h-auto w-full transition-all"
          role="img"
          aria-label="Agent communication topology graph"
        >
          <defs>
            <marker
              id="arrow-message"
              viewBox="0 0 10 10"
              refX="8"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M0,1 L8,5 L0,9 z" fill="var(--hairline)" />
            </marker>
            <marker
              id="arrow-suspicious"
              viewBox="0 0 10 10"
              refX="8"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M0,1 L8,5 L0,9 z" fill="var(--crit)" />
            </marker>
            <marker
              id="arrow-hidden"
              viewBox="0 0 10 10"
              refX="8"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M0,1 L8,5 L0,9 z" fill="var(--accent)" />
            </marker>
          </defs>

          {/* Edges */}
          {graph.edges.map((e) => {
            const s = pos[e.source];
            const t = pos[e.target];
            if (!s || !t) return null;

            const dx = t.x - s.x;
            const dy = t.y - s.y;
            const len = Math.hypot(dx, dy) || 1;
            const off = nodeRadius + 4;
            const x1 = s.x + (dx / len) * off;
            const y1 = s.y + (dy / len) * off;
            const x2 = t.x - (dx / len) * (off + 4);
            const y2 = t.y - (dy / len) * (off + 4);

            const mx = (x1 + x2) / 2 - (dy / len) * 16;
            const my = (y1 + y2) / 2 + (dx / len) * 16;

            // Only color edge red if its event_ids appear in alert evidence
            const isSuspicious = e.event_ids && e.event_ids.some((id) => alertEventSet.has(id));
            const isHidden = e.kind === "indirect";
            const dim = hover && e.source !== hover && e.target !== hover;

            let strokeColor = "var(--hairline)";
            let marker = "url(#arrow-message)";
            let strokeWidth = 1.5;
            let className = "";

            if (isSuspicious) {
              strokeColor = "var(--crit)";
              marker = "url(#arrow-suspicious)";
              strokeWidth = 3;
              className = "suspicious-dash";
            } else if (isHidden) {
              strokeColor = "var(--accent)";
              marker = "url(#arrow-hidden)";
              strokeWidth = 2;
            } else {
              strokeWidth = 1.5 + (2.5 * e.count) / maxCount;
            }

            return (
              <path
                key={`${e.source}-${e.target}-${e.kind}`}
                d={`M${x1},${y1} Q${mx},${my} ${x2},${y2}`}
                fill="none"
                stroke={strokeColor}
                strokeWidth={strokeWidth}
                strokeOpacity={dim ? 0.15 : isSuspicious ? 1 : 0.7}
                strokeLinecap="round"
                strokeDasharray={isHidden ? "5 4" : undefined}
                className={className}
                markerEnd={marker}
              >
                <title>{`${e.source} → ${e.target}: ${e.count} ${e.kind}(s)${isSuspicious ? " [ALERT EVIDENCE]" : ""}`}</title>
              </path>
            );
          })}

          {/* Nodes */}
          {graph.nodes.map((n) => {
            const p = pos[n.id];
            if (!p) return null;
            const ext = n.kind === "external";
            const isSelected = selectedNodeId === n.id;
            const label = ext ? n.id.replace(/^external:/, "") : n.id.split("-").pop() || n.id;
            const roleInitial = ext ? "EXT" : getRoleInitial(n.role, n.id);
            const roleColor = ROLE_COLOR[n.role ?? ""] ?? "var(--text-3)";

            // Approved destinations get a neutral outline; only suspicious external sinks get red
            const isSuspiciousExternal =
              ext &&
              graph.edges.some(
                (e) => e.target === n.id && e.event_ids.some((id) => alertEventSet.has(id))
              );

            return (
              <g
                key={n.id}
                transform={`translate(${p.x},${p.y})`}
                opacity={active(n.id) ? 1 : 0.25}
                onMouseEnter={() => setHover(n.id)}
                onMouseLeave={() => setHover(null)}
                onClick={() => onSelectNode?.(n.id)}
                className="cursor-pointer transition-opacity"
              >
                {/* Flagged halo */}
                {n.flagged && !ext && (
                  <circle
                    r={nodeRadius + 8}
                    fill="var(--crit)"
                    fillOpacity={0.14}
                    className="animate-pulse"
                  />
                )}

                {/* Selected Ring */}
                {isSelected && (
                  <circle
                    r={nodeRadius + 6}
                    fill="none"
                    stroke="var(--accent)"
                    strokeWidth={2.5}
                    strokeDasharray="4 3"
                  />
                )}

                {ext ? (
                  <rect
                    x={-24}
                    y={-24}
                    width={48}
                    height={48}
                    rx={12}
                    fill="var(--card)"
                    stroke={isSuspiciousExternal ? "var(--crit)" : "var(--hairline-subtle)"}
                    strokeWidth={isSuspiciousExternal ? 2.5 : 1.5}
                    className="drop-shadow-xs"
                  />
                ) : (
                  <circle
                    r={nodeRadius}
                    fill={roleColor}
                    stroke={n.flagged ? "var(--crit)" : isSelected ? "var(--accent)" : "var(--bg)"}
                    strokeWidth={n.flagged || isSelected ? 3 : 2}
                    className="drop-shadow-sm"
                  />
                )}

                {/* Role Initial in Center */}
                <text
                  y={ext ? 4 : isVeryDense ? 4 : 5}
                  textAnchor="middle"
                  fontSize={ext ? "11" : isVeryDense ? "12" : "15"}
                  fontWeight="600"
                  fill={ext ? (isSuspiciousExternal ? "var(--crit)" : "var(--text-2)") : "var(--bg)"}
                  className="pointer-events-none select-none tracking-tight"
                >
                  {roleInitial}
                </text>

                {/* Name & Role Labels - collision-free adaptive positioning */}
                {!isVeryDense ? (
                  <>
                    <text
                      y={nodeRadius + 16}
                      textAnchor="middle"
                      fontSize={isDense ? "11" : "13"}
                      fontWeight="600"
                      fill={ext && !isSuspiciousExternal ? "var(--text-2)" : "var(--text)"}
                      className="pointer-events-none select-none"
                    >
                      {ext ? label : `agent ${label}`}
                    </text>

                    {!ext && n.role && (
                      <text
                        y={nodeRadius + 29}
                        textAnchor="middle"
                        fontSize="10"
                        fill="var(--text-2)"
                        className="pointer-events-none select-none capitalize"
                      >
                        {n.role}
                      </text>
                    )}
                  </>
                ) : (
                  <text
                    y={nodeRadius + 13}
                    textAnchor="middle"
                    fontSize="11"
                    fontWeight="600"
                    fill={ext && !isSuspiciousExternal ? "var(--text-2)" : "var(--text)"}
                    className="pointer-events-none select-none"
                  >
                    {label}
                  </text>
                )}

                <title>
                  {`${n.id}${n.role ? ` (${n.role})` : ""}\nEvents: ${n.event_count}\nDegree: ${n.degree_centrality}\nBetweenness: ${n.betweenness}${n.flagged ? "\nSTATUS: FLAGGED" : ""}${isSuspiciousExternal ? "\nSTATUS: SUSPICIOUS SINK" : ext ? "\nSTATUS: APPROVED DESTINATION" : ""}`}
                </title>
              </g>
            );
          })}
        </svg>

        {/* Live Hover HUD */}
        {hover && (
          <div className="mt-2 flex items-center justify-between rounded-xl bg-[var(--card-alt)] border border-[var(--hairline)]/60 px-3.5 py-2 text-[12px] shadow-xs">
            {(() => {
              const hNode = graph.nodes.find((n) => n.id === hover);
              if (!hNode) return null;
              const isExt = hNode.kind === "external";
              return (
                <>
                  <div className="flex items-center gap-2">
                    <span
                      className="h-2.5 w-2.5 rounded-full"
                      style={{ background: ROLE_COLOR[hNode.role ?? ""] ?? "var(--text-3)" }}
                    />
                    <strong className="text-[var(--text)] font-semibold">
                      {isExt ? hNode.id : `Agent ${hNode.id}`}
                    </strong>
                    {hNode.role && (
                      <span className="text-[var(--text-2)] capitalize font-medium">({hNode.role})</span>
                    )}
                    {hNode.flagged && (
                      <span className="rounded-full bg-[var(--crit-bg)] text-[var(--crit)] px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider">
                        Flagged Threat
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-4 text-[var(--text-3)] font-mono text-[11px]">
                    <span>{hNode.event_count} events</span>
                    <span>degree: {hNode.degree_centrality.toFixed(2)}</span>
                    <span className="text-[var(--accent)] font-sans font-medium cursor-pointer">Click node to inspect dossier &rsaquo;</span>
                  </div>
                </>
              );
            })()}
          </div>
        )}
      </div>

      {/* Legend below graph */}
      <div className="mt-3 flex flex-wrap items-center justify-center gap-x-6 gap-y-2 text-[12px] text-[var(--text-2)]">
        {Object.entries(ROLE_COLOR).map(([r, c]) => (
          <span key={r} className="inline-flex items-center gap-1.5 capitalize">
            <span className="h-2.5 w-2.5 rounded-full" style={{ background: c }} />
            {r}
          </span>
        ))}
        <span className="inline-flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full ring-2 ring-[var(--crit)] ring-offset-1" />
          Flagged agent
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="h-0.5 w-4 rounded-full bg-[var(--crit)]" />
          Suspicious data transfer (alert evidence)
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="h-0.5 w-4 rounded-full bg-[var(--hairline)]" />
          Approved / normal connection
        </span>
      </div>
    </div>
  );
}
