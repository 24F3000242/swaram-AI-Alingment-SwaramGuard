export type ExportFormat = "json" | "jsonl" | "csv";

function cell(value: unknown): string {
  if (value === null || value === undefined) return "";
  const s = typeof value === "object" ? JSON.stringify(value) : String(value);
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function toCsv(rows: Record<string, unknown>[]): string {
  if (!rows.length) return "";
  const cols = Array.from(rows.reduce((set, r) => { Object.keys(r).forEach((k) => set.add(k)); return set; }, new Set<string>()));
  return [cols.join(","), ...rows.map((r) => cols.map((c) => cell(r[c])).join(","))].join("\n") + "\n";
}

export function toJsonl(rows: unknown[]): string {
  return rows.map((r) => JSON.stringify(r)).join("\n") + (rows.length ? "\n" : "");
}

export function serialize(data: unknown, format: ExportFormat): string {
  const rows = Array.isArray(data) ? data : [data];
  if (format === "jsonl") return toJsonl(rows);
  if (format === "csv") return toCsv(rows as Record<string, unknown>[]);
  return JSON.stringify(data, null, 2) + "\n";
}

export function parseJsonOrJsonl(text: string): unknown[] {
  const trimmed = text.trim();
  if (!trimmed) return [];
  if (trimmed.startsWith("[")) return JSON.parse(trimmed);
  if (trimmed.startsWith("{") && !trimmed.includes("\n")) return [JSON.parse(trimmed)];
  return trimmed.split(/\r?\n/).filter((l) => l.trim()).map((line, i) => {
    try {
      return JSON.parse(line);
    } catch {
      throw new Error(`Line ${i + 1} is not valid JSON`);
    }
  });
}

export function download(data: unknown, filename: string, format: ExportFormat): void {
  const mime = format === "csv" ? "text/csv" : format === "jsonl" ? "application/x-ndjson" : "application/json";
  const blob = new Blob([serialize(data, format)], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${filename}.${format}`;
  a.click();
  URL.revokeObjectURL(url);
}
