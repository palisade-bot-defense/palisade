# PALISADE project website

This package is the public open-source project website. It is deliberately
separate from the embedded Operator Console under `dashboard/`: the public site
has no access to decisions, health routes, shadow records or deployment
configuration.

## Local use

```sh
pnpm --filter @palisade-human-trust/website dev
pnpm --filter @palisade-human-trust/website test
pnpm --filter @palisade-human-trust/website build
```

The production output is written to `website/dist/`. Brand files are sourced
from the repository's existing `brand/` package; no external font, image,
analytics, form or contact service is loaded.

## SEO and answer-engine metadata

Set the reviewed canonical HTTPS origin, including its trailing slash:

```sh
VITE_PUBLIC_SITE_URL='https://palisade.example/' \
  pnpm --filter @palisade-human-trust/website build
```

The build then emits a canonical URL, absolute social image, Open Graph URL,
`SoftwareSourceCode` JSON-LD, `robots.txt`, `sitemap.xml` and a factual
`llms.txt`. Without this variable, the build deliberately emits `noindex,
nofollow`, a disallowing `robots.txt` and no sitemap. This makes an accidental
preview deployment fail closed instead of competing with the reviewed domain.
Robots directives describe crawl policy; they do not authenticate crawlers.
Network identity and allowlisting are handled separately by the trusted origin
adapter documented in [`docs/CRAWLER_IDENTITY.md`](../docs/CRAWLER_IDENTITY.md).

## Publication gate

Before publishing, review the canonical URL, trademark/name usage, hosting
security headers, accessibility and every maturity statement. The site may
describe only code and documentation present in the public repository.

The current site stores nothing and sends nothing to PALISADE. If analytics,
forms, consent-dependent storage or third-party embeds are added later, their
data flow and legal basis require a new privacy review before release.
