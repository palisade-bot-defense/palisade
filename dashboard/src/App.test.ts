import { describe, expect, it } from "vitest";

import { countComparableCanaries, formatInterval } from "./App";

describe("aggregate endpoint evidence", () => {
  it("does not invent an interval for an absent sample", () => {
    expect(formatInterval({ count: 0, total: 0, rate: 0, lower_95: 0, upper_95: 0 })).toBe("no sample");
  });

  it("labels a populated interval and counts only comparable canaries", () => {
    expect(formatInterval({ count: 10, total: 100, rate: 0.1, lower_95: 0.055, upper_95: 0.174 })).toContain("95%");
    expect(countComparableCanaries([{ comparable: true }, { comparable: false }, { comparable: true }])).toBe(2);
  });
});
