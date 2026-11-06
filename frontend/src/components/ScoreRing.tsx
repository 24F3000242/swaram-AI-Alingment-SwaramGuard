import { useEffect, useState } from "react";
import type { Severity } from "../types";

export interface ScoreRingProps {
  score: number; // 0 to 1
  severity?: Severity | string;
  size?: number;
  label?: string;
  className?: string;
}

export function ScoreRing({
  score,
  severity = "medium",
  size = 110,
  label = "Alert confidence",
  className = "",
}: ScoreRingProps) {
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    const timer = setTimeout(() => {
      setAnimatedScore(Math.max(0, Math.min(1, score)));
    }, 50);
    return () => clearTimeout(timer);
  }, [score]);

  const strokeWidth = 8;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - animatedScore * circumference;

  const color =
    severity === "critical"
      ? "var(--crit)"
      : severity === "high"
      ? "var(--high)"
      : severity === "medium" || severity === "med"
      ? "var(--med)"
      : "var(--ok)";

  return (
    <div
      className={`relative inline-flex items-center justify-center ${className}`}
      style={{ width: size, height: size }}
    >
      <svg width={size} height={size} className="-rotate-90">
        {/* Track */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="var(--hairline)"
          strokeOpacity={0.3}
          strokeWidth={strokeWidth}
        />
        {/* Fill Ring */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          style={{ transition: "stroke-dashoffset 600ms cubic-bezier(.28, .11, .32, 1)" }}
        />
      </svg>
      {/* Centered Score */}
      <div className="absolute inset-0 flex flex-col items-center justify-center text-center px-1">
        <span className="text-[22px] font-bold tracking-tight tabular-nums" style={{ color }}>
          {Math.round(score * 100)}%
        </span>
        <span className="text-[9px] font-semibold text-[var(--text-3)] uppercase tracking-wider leading-tight max-w-[70px]">
          {label}
        </span>
      </div>
    </div>
  );
}
