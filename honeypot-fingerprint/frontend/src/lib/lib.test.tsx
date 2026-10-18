import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { FAMILIES, categoryColor, familyOf } from "./colors";
import { fmtNum, fmtPct, fmtRel } from "./format";
import { qs } from "./api";
import { CategoryChip, SeverityBadge } from "../components/ui";

describe("colour mapping", () => {
  it("assigns every known category to a fixed family", () => {
    expect(familyOf("syn_flood")).toBe("flood");
    expect(familyOf("ssh_bruteforce")).toBe("bruteforce");
    expect(familyOf("benign")).toBe("benign");
    expect(familyOf("unmatched")).toBe("unclassified");
    expect(familyOf("something_new")).toBe("unknown");
    expect(categoryColor("udp_flood")).toBe(categoryColor("http_flood"));
  });
  it("uses at most 7 categorical slots plus two neutrals", () => {
    const slots = FAMILIES.filter((f) => f.color.startsWith("var(--s"));
    expect(slots).toHaveLength(7);
    expect(new Set(slots.map((s) => s.color)).size).toBe(7);
  });
});

describe("formatting", () => {
  it("formats numbers, percentages and replay-relative time", () => {
    expect(fmtNum(12345)).toBe("12.3k");
    expect(fmtNum(null)).toBe("–");
    expect(fmtPct(0.875)).toBe("87.5%");
    expect(fmtRel(1065, 1000)).toBe("T+1:05");
    expect(qs({ a: 1, b: "", c: undefined, d: "x y" })).toBe("?a=1&d=x+y");
  });
});

describe("components", () => {
  it("renders severity with an icon and label, not colour alone", () => {
    render(<SeverityBadge severity="critical" />);
    expect(screen.getByText("critical")).toBeTruthy();
  });
  it("renders a category chip with its name", () => {
    render(<CategoryChip category="port_scan_fast" name="Port scan (fast)" />);
    expect(screen.getByText("Port scan (fast)")).toBeTruthy();
  });
});
