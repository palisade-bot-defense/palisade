# Contributing

PALISADE welcomes defensive research, detector improvements, replay fixtures, documentation and integrations. The published core is AGPL-3.0-only and the browser sensor is Apache-2.0; see [`LICENSING.md`](LICENSING.md) for the exact scope.

## Before contributing

Contributions are licensed under the same license that covers the affected
path: AGPL-3.0-only by default, or Apache-2.0 under `sensor/`. You retain your
copyright; PALISADE does not require copyright assignment or a separate
contributor license agreement. By submitting a contribution, you confirm that
you have the right to provide it under that applicable license.

1. Keep changes narrowly scoped and include tests.
2. Add stable reason codes for every new detector signal.
3. Never collect raw keystrokes, form values, DOM text, full URLs with query strings or exact pointer paths.
4. Demonstrate detector changes on synthetic or properly scrubbed labeled replay data and report false-positive impact; never commit raw deployment data.
5. Run `go test -race ./...`, `go vet ./...`, `pnpm typecheck`, `pnpm test` and `pnpm build`.
6. Do not include live credentials, customer traffic, bypass details for real targets or personal data.

Changes must preserve the separation between automation, intent and continuity. A high automation score alone is not sufficient evidence of abuse.
