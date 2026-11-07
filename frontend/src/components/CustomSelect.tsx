import { useEffect, useRef, useState, useId, type ReactNode } from "react";
import { ChevronDown, Check } from "lucide-react";

export interface SelectOption<T = string | number> {
  value: T;
  label: string;
  description?: string;
  disabled?: boolean;
  group?: string;
}

export type RawOption<T = string | number> = SelectOption<T> | T;

export interface CustomSelectProps<T extends string | number = string> {
  value: T | null | undefined;
  onChange: (value: T) => void;
  options: RawOption<T>[];
  placeholder?: string;
  disabled?: boolean;
  size?: "sm" | "md" | "lg";
  variant?: "default" | "pill" | "subtle";
  align?: "left" | "right";
  className?: string;
  menuClassName?: string;
  ariaLabel?: string;
  prefix?: ReactNode;
}

/**
 * Pure Apple Light Mode Custom Select Dropdown
 * Replaces native HTML selects with a polished, accessible, theme-consistent dropdown.
 */
export function CustomSelect<T extends string | number = string>({
  value,
  onChange,
  options,
  placeholder = "Select an option…",
  disabled = false,
  size = "md",
  variant = "default",
  align = "left",
  className = "",
  menuClassName = "",
  ariaLabel,
  prefix,
}: CustomSelectProps<T>) {
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);
  const listboxRef = useRef<HTMLDivElement>(null);
  const id = useId();

  // Normalize options to SelectOption[]
  const normalizedOptions: SelectOption<T>[] = options.map((opt) => {
    if (typeof opt === "object" && opt !== null && "value" in opt) {
      return opt as SelectOption<T>;
    }
    return {
      value: opt as T,
      label: String(opt),
    };
  });

  // Selected item
  const selectedOption = normalizedOptions.find((opt) => opt.value === value);

  // Close on outside click or blur
  useEffect(() => {
    if (!open) return;
    const handleOutsideClick = (e: MouseEvent | TouchEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setOpen(false);
      }
    };

    document.addEventListener("mousedown", handleOutsideClick);
    document.addEventListener("touchstart", handleOutsideClick);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("mousedown", handleOutsideClick);
      document.removeEventListener("touchstart", handleOutsideClick);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [open]);

  // Size styling
  const sizeClasses = {
    sm: "h-7.5 px-3 py-1 text-[12px]",
    md: "h-10 px-3.5 py-2 text-[14px]",
    lg: "h-11 px-4 py-2.5 text-[15px]",
  }[size];

  // Variant styling
  const variantClasses = {
    default: "rounded-xl border border-[var(--hairline)] bg-[var(--card)] hover:border-[var(--text-3)]",
    pill: "rounded-full border border-[var(--hairline)]/80 bg-[var(--card)] hover:border-[var(--text-3)] shadow-xs",
    subtle: "rounded-lg border border-[var(--hairline)]/60 bg-[var(--card-alt)] hover:bg-[var(--card)] hover:border-[var(--hairline)]",
  }[variant];

  // Group options if applicable
  const hasGroups = normalizedOptions.some((opt) => opt.group);
  const groupedOptions: { groupName: string | null; items: SelectOption<T>[] }[] = [];

  if (hasGroups) {
    const map = new Map<string | null, SelectOption<T>[]>();
    for (const opt of normalizedOptions) {
      const g = opt.group ?? null;
      if (!map.has(g)) map.set(g, []);
      map.get(g)!.push(opt);
    }
    for (const [groupName, items] of map.entries()) {
      groupedOptions.push({ groupName, items });
    }
  }

  return (
    <div
      ref={containerRef}
      className={`relative inline-block w-full text-left font-[var(--font)] ${className}`}
    >
      {/* Anchor Trigger Button */}
      <button
        type="button"
        id={id}
        disabled={disabled}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={ariaLabel || selectedOption?.label || placeholder}
        onClick={() => !disabled && setOpen((prev) => !prev)}
        className={`group flex w-full items-center justify-between gap-2.5 text-[var(--text)] transition-all duration-150 focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]/30 focus-visible:border-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-50 ${sizeClasses} ${variantClasses} ${
          open ? "border-[var(--accent)] ring-2 ring-[var(--accent)]/20 shadow-sm" : ""
        }`}
      >
        <div className="flex min-w-0 items-center gap-2 truncate">
          {prefix && <span className="shrink-0 text-[var(--text-3)]">{prefix}</span>}
          <span
            className={`truncate font-medium leading-none ${
              selectedOption ? "text-[var(--text)]" : "text-[var(--text-3)]"
            }`}
          >
            {selectedOption ? selectedOption.label : placeholder}
          </span>
        </div>

        <ChevronDown
          size={size === "sm" ? 12 : 14}
          className={`shrink-0 text-[var(--text-3)] transition-transform duration-200 group-hover:text-[var(--text)] ${
            open ? "rotate-180 text-[var(--accent)]" : ""
          }`}
          aria-hidden
        />
      </button>

      {/* Popover Dropdown Menu */}
      {open && (
        <div
          ref={listboxRef}
          role="listbox"
          tabIndex={-1}
          aria-labelledby={id}
          className={`absolute z-50 mt-1.5 min-w-full rounded-xl border border-[var(--hairline)] bg-[var(--card)] p-1.5 shadow-[var(--shadow-2)] backdrop-blur-md transition-all duration-150 ${
            align === "right"
              ? "right-0 left-auto w-max max-w-[min(100vw-32px,360px)]"
              : "left-0 right-auto w-full sm:w-[380px] max-w-[min(100vw-32px,440px)]"
          } ${menuClassName}`}
        >
          <div className="max-h-60 overflow-y-auto overscroll-contain space-y-0.5 no-scrollbar">
            {normalizedOptions.length === 0 ? (
              <div className="px-3 py-2 text-[13px] text-[var(--text-3)]">
                No options available
              </div>
            ) : hasGroups ? (
              groupedOptions.map((group, gIdx) => (
                <div key={group.groupName || gIdx} className="space-y-0.5">
                  {group.groupName && (
                    <div className="px-2.5 pt-2 pb-1 text-[11px] font-semibold uppercase tracking-wider text-[var(--text-3)]">
                      {group.groupName}
                    </div>
                  )}
                  {group.items.map((opt) => renderOptionItem(opt))}
                </div>
              ))
            ) : (
              normalizedOptions.map((opt) => renderOptionItem(opt))
            )}
          </div>
        </div>
      )}
    </div>
  );

  function renderOptionItem(opt: SelectOption<T>) {
    const isSelected = opt.value === value;
    return (
      <button
        key={String(opt.value)}
        type="button"
        role="option"
        aria-selected={isSelected}
        disabled={opt.disabled}
        onClick={() => {
          if (!opt.disabled) {
            onChange(opt.value);
            setOpen(false);
          }
        }}
        className={`flex w-full items-center justify-between gap-3 rounded-lg px-3 py-2 text-left transition-colors duration-100 ${
          opt.disabled
            ? "cursor-not-allowed opacity-40"
            : isSelected
            ? "bg-[var(--accent)]/10 text-[var(--accent)] font-semibold"
            : "text-[var(--text)] hover:bg-[var(--bg-alt)] hover:text-[var(--text)]"
        }`}
      >
        <div className="min-w-0 flex-1">
          <div className="text-[13px] font-medium leading-snug">{opt.label}</div>
          {opt.description && (
            <div className="mt-0.5 text-[11px] font-normal leading-normal text-[var(--text-3)] line-clamp-2">
              {opt.description}
            </div>
          )}
        </div>
        {isSelected && (
          <Check size={14} className="shrink-0 text-[var(--accent)]" aria-hidden />
        )}
      </button>
    );
  }
}
