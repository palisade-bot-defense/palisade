export type SeoArtifacts = {
  publicSiteUrl: string | null;
  head: string;
  robots: string;
  sitemap: string | null;
  llms: string;
};

export const normalizePublicSiteUrl = (raw: string | undefined): string | null => {
  const value = raw?.trim();
  if (!value) return null;
  const url = new URL(value);
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash || url.pathname !== "/") {
    throw new Error("VITE_PUBLIC_SITE_URL must be an HTTPS origin URL ending in /");
  }
  return url.toString();
};

export const createSeoArtifacts = (rawPublicSiteUrl: string | undefined): SeoArtifacts => {
  const publicSiteUrl = normalizePublicSiteUrl(rawPublicSiteUrl);
  const repository = "https://github.com/palisade-bot-defense/palisade";
  const description = "Explainable bot defense with private shadow measurement, reversible enforcement, and locally controlled evidence.";
  const llms = [
    "# PALISADE",
    "",
    `> ${description}`,
    "",
    "PALISADE is self-hostable bot-defense infrastructure. It separates automation, abuse intent, and account continuity; starts in shadow mode; and requires signed, reversible rollout approval before risky enforcement.",
    "",
    "## Facts",
    "",
    "- Product: PALISADE bot defense",
    "- Core license: AGPL-3.0-only",
    "- Browser sensor license: Apache-2.0",
    "- Data model: closed, normalized signals; no cross-site identity graph",
    "- Availability: open-source core available; managed service is early access",
    `- Source and technical documentation: ${repository}`,
    ...(publicSiteUrl ? [`- Official product page: ${publicSiteUrl}`] : []),
    "",
  ].join("\n");

  if (!publicSiteUrl) {
    return {
      publicSiteUrl: null,
      head: '<meta name="robots" content="noindex, nofollow" data-palisade-seo />',
      robots: "User-agent: *\nDisallow: /\n",
      sitemap: null,
      llms,
    };
  }

  const structuredData = JSON.stringify({
    "@context": "https://schema.org",
    "@type": "SoftwareSourceCode",
    name: "PALISADE",
    description,
    url: publicSiteUrl,
    codeRepository: repository,
    license: ["https://www.gnu.org/licenses/agpl-3.0.html", "https://www.apache.org/licenses/LICENSE-2.0"],
    programmingLanguage: ["Go", "TypeScript"],
  }).replaceAll("<", "\\u003c");
  const socialImage = new URL("palisade-social-card.png", publicSiteUrl).toString();
  const head = [
    '<meta name="robots" content="index, follow, max-image-preview:large, max-snippet:-1, max-video-preview:-1" data-palisade-seo />',
    `<link rel="canonical" href="${publicSiteUrl}" />`,
    `<meta property="og:url" content="${publicSiteUrl}" />`,
    `<meta property="og:image:secure_url" content="${socialImage}" />`,
    `<script type="application/ld+json">${structuredData}</script>`,
  ].join("\n    ");
  return {
    publicSiteUrl,
    head,
    robots: `User-agent: *\nAllow: /\n\nSitemap: ${new URL("sitemap.xml", publicSiteUrl)}\n`,
    sitemap: `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n  <url><loc>${publicSiteUrl}</loc></url>\n</urlset>\n`,
    llms,
  };
};
