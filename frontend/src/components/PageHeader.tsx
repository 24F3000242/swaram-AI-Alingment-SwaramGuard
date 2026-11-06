import type { ReactNode } from "react";

export interface QuickLink {
  label: string;
  href: string;
  onClick?: () => void;
}

export interface PageHeaderProps {
  title: string;
  subtitle?: ReactNode;
  quickLinks?: QuickLink[];
  actions?: ReactNode;
  className?: string;
}

export function PageHeader({
  title,
  subtitle,
  quickLinks,
  actions,
  className = "",
}: PageHeaderProps) {
  return (
    <div className={`mb-12 pt-6 ${className}`}>
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-[40px] font-semibold leading-[1.07] tracking-[-0.015em] text-[var(--text)] sm:text-[56px]">
            {title}
          </h1>
          {subtitle && (
            <div className="mt-3 max-w-[640px] text-[19px] sm:text-[21px] font-normal leading-relaxed text-[var(--text-2)]">
              {subtitle}
            </div>
          )}
        </div>
        {actions && <div className="flex items-center gap-3 pb-1">{actions}</div>}
      </div>

      {quickLinks && quickLinks.length > 0 && (
        <div className="mt-5 flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-[var(--hairline)]/60 pt-4 text-[14px]">
          {quickLinks.map((link) => (
            <a
              key={link.label}
              href={link.href}
              onClick={link.onClick}
              className="inline-flex items-center gap-1 font-medium text-[var(--link)] hover:underline"
            >
              <span>{link.label}</span>
              <span aria-hidden>&rsaquo;</span>
            </a>
          ))}
        </div>
      )}
    </div>
  );
}
