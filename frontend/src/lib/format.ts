export const pct = (v: number | null | undefined) => (v === null || v === undefined ? "n/a" : `${(v * 100).toFixed(1)}%`);

export const num = (v: number | null | undefined, digits = 2) => (v === null || v === undefined ? "n/a" : v.toFixed(digits));

/** `evt-abcdef12-0001` -> `evt-…-0001` for compact tables. */
export const shortId = (id: string) => id.replace(/^([a-z]+)-[0-9a-z]{6,}-(\d+)$/, "$1-…-$2");

export const time = (iso: string) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
};

export const dateTime = (iso: string) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
};
