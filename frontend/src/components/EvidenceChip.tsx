export interface EvidenceChipProps {
  eventId: string;
  onClick: (eventId: string) => void;
  action?: string;
  className?: string;
}

export function EvidenceChip({
  eventId,
  onClick,
  action,
  className = "",
}: EvidenceChipProps) {
  return (
    <button
      onClick={() => onClick(eventId)}
      type="button"
      className={`inline-flex items-center gap-1.5 rounded-md border border-[var(--hairline)] bg-[var(--card-alt)] px-2.5 py-1 font-mono text-[13px] text-[var(--text)] transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)] ${className}`}
      title={`Click to inspect raw event ${eventId}`}
    >
      <span className="font-semibold">{eventId}</span>
      {action && <span className="text-[11px] font-sans text-[var(--text-3)]">({action})</span>}
    </button>
  );
}
