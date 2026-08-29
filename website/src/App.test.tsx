import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { App } from "./App";

describe("open-source project website", () => {
  it("states the repository scope and honest maturity boundary", () => {
    const html = renderToStaticMarkup(<App />);

    expect(html).toContain("THE COMPLETE OPEN CONTROL LOOP");
    expect(html).toContain("Decision service");
    expect(html).toContain("Origin integration");
    expect(html).toContain("Local evaluation");
    expect(html).toContain("not a production-supported release");
    expect(html).not.toContain('href="#contact"');
  });

  it("makes the security and licensing boundaries visible", () => {
    const html = renderToStaticMarkup(<App />);

    expect(html).toContain("No required telemetry");
    expect(html).toContain("No required vendor egress");
    expect(html).toContain("Machine-readable posture");
    expect(html).toContain("No tracking on this site");
    expect(html).toContain("Core AGPL-3.0-only");
    expect(html).toContain("Sensor Apache-2.0");
    expect(html).not.toContain("guaranteed bot detection");
  });

  it("keeps the demo explicitly illustrative", () => {
    const html = renderToStaticMarkup(<App />);

    expect(html).toContain("Illustrative, not customer data or measured efficacy");
    expect(html).toContain("signed, reversible rollout");
    expect(html).toContain("computed CHALLENGE");
  });

  it("leads with the three verifiable product contracts", () => {
    const html = renderToStaticMarkup(<App />);
    expect(html).toContain("THREE VERIFIABLE CONTRACTS");
    expect(html).toContain("Sovereignty");
    expect(html).toContain("Evidence");
    expect(html).toContain("Rollout");
    expect(html).toContain("Does self-hosting make a deployment GDPR compliant?");
  });

  it("does not expose a sales or contact funnel", () => {
    const html = renderToStaticMarkup(<App />);
    expect(html).toContain("No analytics, form submissions or private contact funnel");
    expect(html).not.toContain("mailto:");
    expect(html).not.toContain("VITE_CONTACT_URL");
  });
});
