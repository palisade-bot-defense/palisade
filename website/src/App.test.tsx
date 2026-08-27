import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { App } from "./App";

describe("business website", () => {
  it("states the complete business offer and honest availability boundary", () => {
    const html = renderToStaticMarkup(<App />);

    expect(html).toContain("Palisade Core");
    expect(html).toContain("Palisade Pilot");
    expect(html).toContain("Palisade Managed");
    expect(html).toContain("Available now");
    expect(html).toContain("Design partner");
    expect(html).toContain("Early access");
    expect(html).toContain("production SLAs");
  });

  it("makes the security and licensing boundaries visible", () => {
    const html = renderToStaticMarkup(<App />);

    expect(html).toContain("No cross-site identity graph");
    expect(html).toContain("No tracking on this site");
    expect(html).toContain("Core AGPL-3.0-only");
    expect(html).toContain("Sensor Apache-2.0");
    expect(html).not.toContain("guaranteed bot detection");
  });

  it("keeps the demo explicitly illustrative", () => {
    const html = renderToStaticMarkup(<App />);

    expect(html).toContain("Illustrative, not customer data");
    expect(html).toContain("Shadow-first");
    expect(html).toContain("computed CHALLENGE");
  });
});
