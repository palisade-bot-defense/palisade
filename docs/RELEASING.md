# Local release process

PALISADE does not use GitHub Actions. Release verification and artifact creation
run on a maintainer-controlled machine from a clean checkout. Nothing in the
scripts uploads code, telemetry, artifacts or test results.

## Required toolchain

- Go 1.27.x;
- Node.js 24.x;
- pnpm 11.24.x;
- Python 3;
- Git plus a configured GPG or SSH signing identity;
- `sha256sum` or macOS `shasum`.

Dependencies remain pinned by `go.sum` and `pnpm-lock.yaml`. Restore them before
disconnecting the build host if the release must run without network access.

## Verify a candidate

```sh
make verify
```

`scripts/verify-local.sh` restores the frozen JavaScript lockfile, runs Go tests
with the race detector, coverage and vet, executes the offline evaluator, runs
all TypeScript tests/typechecks/builds, confirms generated embedded dashboard
assets match Git, then runs license and staged-index privacy guards.

The release machine must support owner-only Unix file modes because encrypted
logs, imports and rollout artifacts intentionally fail closed when those modes
cannot be verified. Run the release on macOS or Linux, not Windows.

## Create and verify the signed tag

After review and a clean successful verification:

```sh
git tag -s v0.2.0 -m "PALISADE v0.2.0"
git tag -v v0.2.0
```

Do not push the tag yet. `release-local.sh` requires the signed tag to point
exactly at `HEAD` and refuses a dirty worktree or an existing output directory.

Preview the artifact matrix:

```sh
make release-plan VERSION=0.2.0
```

Build locally:

```sh
make release VERSION=0.2.0
```

The default output is `dist/release/0.2.0/` and contains:

- an uncompressed deterministic `git archive` source tar;
- static Go binaries for Linux amd64/arm64, macOS amd64/arm64 and Windows amd64;
- deterministic release metadata containing version, commit, source epoch and
  Go version;
- `SHA256SUMS` covering every artifact except the checksum file itself.

The build uses `CGO_ENABLED=0`, `-trimpath`, read-only Go module resolution and
version injection. The output directory is ignored by Git and the script never
deletes or overwrites an existing directory.

## Independent reproduction

At least one second maintainer should check out the same signed tag, use the
same Go patch release, run `make release VERSION=...` and compare
`SHA256SUMS`. Investigate every mismatch before publication. The uncompressed
source archive and Go binaries are the reproducibility boundary; container image identity can
also depend on the builder and base-image digest and is not covered by this
claim.

Only after review should a maintainer push the signed tag and manually publish
the verified files. Uploading is intentionally outside the script so local
verification never implies authority to change GitHub release state.

## Failure and cleanup

A failed build may leave a partial ignored output directory. Inspect it, then
remove that exact `dist/release/<version>/` directory manually before retrying.
The script performs no recursive cleanup itself. If a tag must change, create a
new version; do not move a published release tag.
