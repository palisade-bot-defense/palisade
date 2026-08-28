import { describe, expect, it } from "vitest";
import { createSeoArtifacts, normalizePublicSiteUrl } from "./seo";

describe("public SEO and GEO artifacts", () => {
  it("fails closed when no reviewed canonical origin is configured", () => {
    const artifacts = createSeoArtifacts(undefined);
    expect(artifacts.head).toContain("noindex, nofollow");
    expect(artifacts.robots).toContain("Disallow: /");
    expect(artifacts.sitemap).toBeNull();
    expect(artifacts.llms).toContain("no production-supported or managed-service release");
  });

  it("emits consistent canonical, structured, sitemap and machine-readable facts", () => {
    const artifacts = createSeoArtifacts("https://palisade.example/");
    expect(artifacts.head).toContain('<link rel="canonical" href="https://palisade.example/"');
    expect(artifacts.head).toContain('"@type":"SoftwareSourceCode"');
    expect(artifacts.head).toContain("https://palisade.example/palisade-social-card.png");
    expect(artifacts.robots).toContain("Sitemap: https://palisade.example/sitemap.xml");
    expect(artifacts.sitemap).toContain("<loc>https://palisade.example/</loc>");
    expect(artifacts.llms).toContain("no cross-site identity graph");
    expect(artifacts.llms).not.toContain("guaranteed");
  });

  it("rejects ambiguous or insecure canonical configuration", () => {
    for (const value of [
      "http://palisade.example/",
      "https://user:secret@palisade.example/",
      "https://palisade.example/path",
      "https://palisade.example/?campaign=tracking",
      "https://palisade.example/#fragment",
    ]) {
      expect(() => normalizePublicSiteUrl(value)).toThrow();
    }
  });
});
