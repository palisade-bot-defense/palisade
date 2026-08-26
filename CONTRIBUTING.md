# Contributing

PALISADE welcomes defensive research, detector improvements, replay fixtures, documentation and integrations once the final license and contributor agreement are active.

## Before contributing

The project license and CLA are still pending the exact legal rights holder. Until both are finalized, use issues for design discussion and do not submit substantive code.

When contributions open:

1. Keep changes narrowly scoped and include tests.
2. Add stable reason codes for every new detector signal.
3. Never collect raw keystrokes, form values, DOM text, full URLs with query strings or exact pointer paths.
4. Demonstrate detector changes on labeled replay data and report false-positive impact.
5. Run `go test -race ./...`, `go vet ./...`, `pnpm typecheck`, `pnpm test` and `pnpm build`.
6. Do not include live credentials, customer traffic, bypass details for real targets or personal data.

Changes must preserve the separation between automation, intent and continuity. A high automation score alone is not sufficient evidence of abuse.
