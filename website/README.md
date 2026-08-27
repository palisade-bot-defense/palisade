# PALISADE public website

This package is the public business website. It is deliberately separate from
the embedded operational dashboard under `dashboard/`: the public site has no
access to decisions, health routes, shadow records or customer configuration.

## Local use

```sh
pnpm --filter @palisade-bot-defense/website dev
pnpm --filter @palisade-bot-defense/website test
pnpm --filter @palisade-bot-defense/website build
```

The production output is written to `website/dist/`. Brand files are sourced
from the repository's existing `brand/` package; no external font, image,
analytics or form service is loaded.

## Contact configuration

The call to action reads `VITE_CONTACT_URL` at build time:

```sh
VITE_CONTACT_URL='mailto:private-contact@example.com' \
  pnpm --filter @palisade-bot-defense/website build
```

Use a private company-controlled email or scheduling URL. Do not include API
keys, customer details or tracking parameters. With no value configured the
site links to the public repository and explicitly says that a private channel
has not yet been added; it never invents an address.

## Public-launch gate

Do not publish the commercial site until all of the following are supplied and
reviewed:

- private business contact channel;
- legal entity/operator identity and required German `Impressum` details;
- privacy notice naming the controller and actual hosting provider;
- trademark/name review for the intended commercial territories;
- final hosting region, security headers and incident contact;
- confirmation that every Managed/Pilot availability claim matches staffed
  operations and signed customer terms.

The current site stores nothing and sends nothing to PALISADE. If analytics,
contact forms, consent-dependent storage or third-party embeds are added later,
their data flow and legal basis require a new privacy review before release.
