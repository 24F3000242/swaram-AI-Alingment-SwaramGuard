import type { ReactNode } from "react";
import type { Severity } from "../types";

export interface PillProps {
  value: Severity | "ok" | "simulated" | "enforced" | string;
  children?: ReactNode;
  className?: string;
}

const STYLES: Record<string, { bg: string; text: string; dot: string }> = {
  critical: { bg: "bg-[var(--crit-bg)]", text: "text-[var(--crit)]", dot: "bg-[var(--crit)]" },
  crit: { bg: "bg-[var(--crit-bg)]", text: "text-[var(--crit)]", dot: "bg-[var(--crit)]" },
  high: { bg: "bg-[var(--high-bg)]", text: "text-[var(--high)]", dot: "bg-[var(--high)]" },
  medium: { bg: "bg-[var(--med-bg)]", text: "text-[var(--med)]", dot: "bg-[var(--med)]" },
  med: { bg: "bg-[var(--med-bg)]", text: "text-[var(--med)]", dot: "bg-[var(--med)]" },
  low: { bg: "bg-[var(--low-bg)]", text: "text-[var(--low)]", dot: "bg-[var(--low)]" },
  ok: { bg: "bg-[var(--ok-bg)]", text: "text-[var(--ok)]", dot: "bg-[var(--ok)]" },
  success: { bg: "bg-[var(--ok-bg)]", text: "text-[var(--ok)]", dot: "bg-[var(--ok)]" },
  enforced: { bg: "bg-[var(--ok-bg)]", text: "text-[var(--ok)]", dot: "bg-[var(--ok)]" },
  open: { bg: "bg-[var(--crit-bg)]", text: "text-[var(--crit)]", dot: "bg-[var(--crit)]" },
  responded: { bg: "bg-[var(--high-bg)]", text: "text-[var(--high)]", dot: "bg-[var(--high)]" },
  contained: { bg: "bg-[var(--ok-bg)]", text: "text-[var(--ok)]", dot: "bg-[var(--ok)]" },
};

export function Pill({ value, children, className = "" }: PillProps) {
  const key = String(value).toLowerCase();
  const style = STYLES[key] ?? {
    bg: "bg-black/[0.05] dark:bg-white/[0.08]",
    text: "text-[var(--text-2)]",
    dot: "bg-[var(--text-3)]",
  };

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-[12px] font-medium leading-none ${style.bg} ${style.text} ${className}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${style.dot}`} />
      <span>{children ?? value}</span>
    </span>
  );
}
