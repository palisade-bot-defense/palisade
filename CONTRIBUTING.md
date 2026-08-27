# Contributing

PALISADE welcomes defensive research, detector improvements, replay fixtures, documentation and integrations. The published core is AGPL-3.0-only and the browser sensor is Apache-2.0; see [`LICENSING.md`](LICENSING.md) for the exact scope.

## Before contributing

The software licenses are active. The separate contributor agreement and its acceptance process are still under legal review. Until that governance step is finalized, use issues for design discussion and do not submit substantive external code.

When substantive external contributions open:

1. Keep changes narrowly scoped and include tests.
2. Add stable reason codes for every new detector signal.
3. Never collect raw keystrokes, form values, DOM text, full URLs with query strings or exact pointer paths.
4. Demonstrate detector changes on labeled replay data and report false-positive impact.
5. Run `go test -race ./...`, `go vet ./...`, `pnpm typecheck`, `pnpm test` and `pnpm build`.
6. Do not include live credentials, customer traffic, bypass details for real targets or personal data.

Changes must preserve the separation between automation, intent and continuity. A high automation score alone is not sufficient evidence of abuse.
