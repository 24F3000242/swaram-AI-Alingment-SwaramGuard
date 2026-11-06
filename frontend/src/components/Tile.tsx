import type { ReactNode } from "react";

export interface TileProps {
  label: ReactNode;
  value: ReactNode;
  subtext?: ReactNode;
  footnote?: string;
  tone?: "normal" | "crit" | "high" | "ok";
  className?: string;
}

export function Tile({
  label,
  value,
  subtext,
  footnote,
  tone = "normal",
  className = "",
}: TileProps) {
  const valueColor =
    tone === "crit"
      ? "text-[var(--crit)]"
      : tone === "high"
      ? "text-[var(--high)]"
      : tone === "ok"
      ? "text-[var(--ok)]"
      : "text-[var(--text)]";

  return (
    <div
      className={`rounded-[var(--r-tile)] card p-8 shadow-[var(--shadow-1)] transition-all ${className}`}
    >
      <div className="flex items-center justify-between">
        <div className="text-[14px] font-medium text-[var(--text-2)]">
          {label}
          {footnote && <sup className="ml-0.5 text-[11px] text-[var(--text-3)]">{footnote}</sup>}
        </div>
      </div>
      <div className={`mt-3 text-[48px] font-semibold leading-none tracking-tight tabular-nums ${valueColor}`}>
        {value}
      </div>
      {subtext && <div className="mt-2 text-[14px] text-[var(--text-3)]">{subtext}</div>}
    </div>
  );
}
