import { useMemo, useState, type ReactNode } from "react";
import { Card, Empty, ExportMenu, JsonBlock, Segmented } from "./ui";

export interface Column<T> {
  key: string;
  label: string;
  render?: (row: T) => ReactNode;
  className?: string;
}

const PAGE = 100;

/**
 * Apple-style Table + JSON viewer with sticky header, 14px typography,
 * search filtering, drawer trigger on row click, and export.
 */
export function ResultViewer<T extends object>({
  title,
  rows,
  columns,
  filename,
  onRowClick,
  selectedKey,
  rowKey,
  empty,
  extraActions,
}: {
  title: ReactNode;
  rows: T[] | null;
  columns: Column<T>[];
  filename: string;
  onRowClick?: (row: T) => void;
  selectedKey?: string | null;
  rowKey?: (row: T) => string;
  empty?: ReactNode;
  extraActions?: ReactNode;
}) {
  const [view, setView] = useState<"table" | "json">("table");
  const [query, setQuery] = useState("");
  const [limit, setLimit] = useState(PAGE);

  const filtered = useMemo(() => {
    if (!rows) return [];
    const q = query.trim().toLowerCase();
    return q ? rows.filter((r) => JSON.stringify(r).toLowerCase().includes(q)) : rows;
  }, [rows, query]);

  return (
    <Card
      flush
      title={
        <div className="flex items-center gap-2">
          <span>{title}</span>
          {rows && (
            <span className="rounded-full bg-[var(--card-alt)] px-2.5 py-0.5 font-mono text-[12px] font-normal text-[var(--text-3)]">
              {query ? `${filtered.length} of ${rows.length}` : rows.length}
            </span>
          )}
        </div>
      }
      actions={
        <div className="flex flex-wrap items-center gap-2">
          {extraActions}
          <div className="relative">
            <svg
              className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-3)]"
              width="13"
              height="13"
              viewBox="0 0 16 16"
              aria-hidden
            >
              <circle cx="7" cy="7" r="5.25" fill="none" stroke="currentColor" strokeWidth="1.6" />
              <path d="M11 11l3.5 3.5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
            </svg>
            <input
              aria-label="Filter records"
              placeholder="Filter..."
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                setLimit(PAGE);
              }}
              className="w-36 rounded-full card-subtle py-1.5 pl-8 pr-3 text-[14px] text-[var(--text)] placeholder:text-[var(--text-3)] focus:border-[var(--accent)] focus:bg-[var(--card)] focus:outline-none focus:ring-2 focus:ring-[var(--accent)]/20"
            />
          </div>
          <Segmented
            size="sm"
            value={view}
            onChange={setView}
            options={[
              { value: "table", label: "Table" },
              { value: "json", label: "JSON" },
            ]}
          />
          <ExportMenu data={filtered} filename={filename} />
        </div>
      }
    >
      {!rows || rows.length === 0 ? (
        <div className="px-6 pb-6 pt-2">
          <Empty>{empty ?? "No telemetry records yet."}</Empty>
        </div>
      ) : view === "json" ? (
        <div className="px-6 pb-6 pt-2">
          <JsonBlock value={filtered.slice(0, limit)} maxHeight="32rem" />
        </div>
      ) : (
        <div className="max-h-[32rem] overflow-auto">
          <table className="w-full text-left text-[14px]">
            <thead className="sticky top-0 z-10 border-b border-[var(--hairline)]/60 bg-[var(--card)]/95 backdrop-blur-md">
              <tr>
                {columns.map((c, i) => (
                  <th
                    key={c.key}
                    className={`py-3 pr-4 text-[12px] font-semibold uppercase tracking-wider text-[var(--text-3)] ${
                      i === 0 ? "pl-6" : ""
                    }`}
                  >
                    {c.label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--hairline)]/30 text-[var(--text)]">
              {filtered.slice(0, limit).map((row, i) => {
                const key = rowKey ? rowKey(row) : String(i);
                const isSelected = selectedKey === key;
                return (
                  <tr
                    key={key}
                    onClick={onRowClick ? () => onRowClick(row) : undefined}
                    className={`transition-colors ${
                      onRowClick ? "cursor-pointer" : ""
                    } ${
                      isSelected
                        ? "bg-[var(--accent)]/10 text-[var(--accent)] font-medium"
                        : "hover:bg-[var(--card-alt)]"
                    }`}
                  >
                    {columns.map((c, ci) => (
                      <td
                        key={c.key}
                        className={`py-3 pr-4 align-middle ${ci === 0 ? "pl-6" : ""} ${
                          c.className ?? ""
                        }`}
                      >
                        {c.render ? c.render(row) : String((row as Record<string, unknown>)[c.key] ?? "")}
                      </td>
                    ))}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {filtered.length > limit && (
        <div className="border-t border-[var(--hairline)]/40 py-3 text-center">
          <button
            className="text-[13px] font-medium text-[var(--link)] hover:underline"
            onClick={() => setLimit((l) => l + PAGE)}
          >
            Show more ({filtered.length - limit} remaining)
          </button>
        </div>
      )}
    </Card>
  );
}
