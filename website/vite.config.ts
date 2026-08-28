import { defineConfig, loadEnv, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import { createSeoArtifacts } from "./seo.js";

const seoPlugin = (publicSiteUrl: string | undefined): Plugin => {
  const artifacts = createSeoArtifacts(publicSiteUrl);
  return {
    name: "palisade-seo-artifacts",
    transformIndexHtml(html) {
      const transformed = html
        .replace('<meta name="robots" content="noindex, nofollow" data-palisade-seo />', artifacts.head)
        .replaceAll('content="/palisade-social-card.png"', `content="${artifacts.publicSiteUrl ? new URL("palisade-social-card.png", artifacts.publicSiteUrl) : "/palisade-social-card.png"}"`);
      return transformed;
    },
    generateBundle() {
      this.emitFile({ type: "asset", fileName: "robots.txt", source: artifacts.robots });
      this.emitFile({ type: "asset", fileName: "llms.txt", source: artifacts.llms });
      if (artifacts.sitemap) this.emitFile({ type: "asset", fileName: "sitemap.xml", source: artifacts.sitemap });
    },
  };
};

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, ".", "");
  return {
    plugins: [react(), seoPlugin(env.VITE_PUBLIC_SITE_URL)],
    publicDir: "../brand/exports",
    build: {
      outDir: "dist",
      emptyOutDir: true,
      sourcemap: false,
    },
  };
});
