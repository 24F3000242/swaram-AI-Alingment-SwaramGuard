export interface FootnotesProps {
  symbols?: Array<"†" | "‡" | "§">;
  className?: string;
}

const DEFINITIONS: Record<string, string> = {
  "†": "Measured on labeled synthetic scenarios, not real traffic.",
  "‡": "Simulation mode: decisions are recorded, no tool call was actually stopped.",
  "§": "Missing-log runs drop events at random with fixed seeds.",
};

export function Footnotes({ symbols = ["†", "‡"], className = "" }: FootnotesProps) {
  return (
    <footer className={`mt-20 border-t border-[var(--hairline)]/60 pt-6 text-[12px] text-[var(--text-3)] leading-relaxed space-y-1.5 ${className}`}>
      {symbols.map((sym) => {
        const text = DEFINITIONS[sym];
        if (!text) return null;
        return (
          <div key={sym} className="flex items-start gap-1.5">
            <span className="font-medium text-[var(--text-2)]">{sym}</span>
            <span>{text}</span>
          </div>
        );
      })}
      <div className="pt-2 text-[11px] text-[var(--text-3)]/80">
        A detection is not proof of compromise.
      </div>
    </footer>
  );
}
