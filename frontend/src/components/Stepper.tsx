import { Check } from "lucide-react";

export interface StepItem {
  id: string;
  label: string;
  done: boolean;
  active?: boolean;
  time?: string | null;
}

export interface StepperProps {
  steps: StepItem[];
  className?: string;
}

export function Stepper({ steps, className = "" }: StepperProps) {
  return (
    <div className={`flex flex-wrap items-center gap-2 sm:gap-3 ${className}`}>
      {steps.map((step, idx) => {
        return (
          <div key={step.id} className="flex items-center gap-2 sm:gap-3">
            <div
              className={`flex items-center gap-1.5 rounded-full px-3 py-1 text-[12px] font-medium transition-colors ${
                step.done
                  ? "bg-[var(--ok-bg)] text-[var(--ok)]"
                  : step.active
                  ? "bg-[var(--accent)]/10 text-[var(--accent)] ring-1 ring-[var(--accent)]"
                  : "bg-black/[0.04] text-[var(--text-3)] dark:bg-white/[0.06]"
              }`}
            >
              <span className="flex h-4 w-4 items-center justify-center rounded-full text-[10px]">
                {step.done ? <Check size={11} strokeWidth={2.5} /> : idx + 1}
              </span>
              <span>{step.label}</span>
            </div>

            {idx < steps.length - 1 && (
              <span className="text-[var(--hairline)]" aria-hidden>
                &rarr;
              </span>
            )}
          </div>
        );
      })}
    </div>
  );
}
