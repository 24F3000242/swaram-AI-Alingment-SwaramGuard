import { describe, expect, it } from "vitest";
import { parseJsonOrJsonl, serialize, toCsv } from "./export";
import { pct, shortId } from "./format";

describe("export", () => {
  it("writes CSV with escaping and nested objects", () => {
    const csv = toCsv([{ a: 1, b: "x,y" }, { a: 2, c: { k: 1 } }]);
    expect(csv).toBe('a,b,c\n1,"x,y",\n2,,"{""k"":1}"\n');
  });

  it("round-trips JSONL", () => {
    const rows = [{ id: 1 }, { id: 2 }];
    expect(parseJsonOrJsonl(serialize(rows, "jsonl"))).toEqual(rows);
    expect(parseJsonOrJsonl(serialize(rows, "json"))).toEqual(rows);
  });

  it("reports the bad JSONL line", () => {
    expect(() => parseJsonOrJsonl('{"a":1}\nnope')).toThrow("Line 2");
  });
});

describe("format", () => {
  it("formats metrics", () => {
    expect(pct(0.5)).toBe("50.0%");
    expect(pct(null)).toBe("n/a");
    expect(shortId("evt-abcdef12-0001")).toBe("evt-…-0001");
  });
});
