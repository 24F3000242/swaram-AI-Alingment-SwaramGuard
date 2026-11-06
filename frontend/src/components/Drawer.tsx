import { useEffect, useRef, type ReactNode } from "react";
import { X } from "lucide-react";

export interface DrawerProps {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  subtitle?: ReactNode;
  children: ReactNode;
  width?: string;
}

export function Drawer({
  open,
  onClose,
  title,
  subtitle,
  children,
  width = "max-w-[480px]",
}: DrawerProps) {
  const drawerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-hidden" role="dialog" aria-modal="true">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/40 backdrop-blur-xs transition-opacity duration-200"
        onClick={onClose}
        aria-hidden
      />

      {/* Slide-over panel */}
      <div className="fixed inset-y-0 right-0 flex pl-10">
        <div
          ref={drawerRef}
          className={`w-screen ${width} transform border-l border-[var(--hairline-subtle)] bg-[var(--card)] p-6 shadow-2xl transition-transform duration-300 ease-out`}
        >
          {/* Header */}
          <div className="flex items-start justify-between gap-4 border-b border-[var(--hairline-subtle)] pb-4">
            <div>
              <h2 className="text-[20px] font-semibold tracking-tight text-[var(--text)]">{title}</h2>
              {subtitle && <div className="mt-1 text-[14px] text-[var(--text-2)]">{subtitle}</div>}
            </div>
            <button
              onClick={onClose}
              type="button"
              className="inline-flex h-8 w-8 items-center justify-center rounded-full text-[var(--text-3)] hover:bg-[var(--card-alt)] hover:text-[var(--text)]"
              aria-label="Close drawer"
            >
              <X size={18} strokeWidth={1.5} />
            </button>
          </div>

          {/* Body */}
          <div className="mt-5 h-[calc(100vh-140px)] overflow-y-auto pr-1 text-[14px]">
            {children}
          </div>
        </div>
      </div>
    </div>
  );
}
