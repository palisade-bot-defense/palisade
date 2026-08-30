# Local release process

Runbook contract: `palisade.runbook.release.v1`.

PALISADE does not use GitHub Actions. Release verification and artifact creation
run on a maintainer-controlled machine from a clean checkout. Nothing in the
scripts uploads code, telemetry, artifacts or test results.

## Required toolchain

- Go 1.27.x;
- Node.js 24.x;
- pnpm 11.24.x;
- Python 3;
- Git plus a configured signed-tag identity;
- OpenSSH `ssh-keygen` and a separate release-signing key;
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

The default output is `dist/release/0.2.0/` and initially contains:

- an uncompressed deterministic `git archive` source tar;
- static Go binaries for Linux amd64/arm64, macOS amd64/arm64 and Windows amd64;
- deterministic release metadata containing version, commit, source epoch and
  Go version;
- `SHA256SUMS` covering every artifact except the checksum file itself.

The build uses `CGO_ENABLED=0`, `-trimpath`, read-only Go module resolution and
version injection. The output directory is ignored by Git and the script never
deletes or overwrites an existing directory. This output is an unsigned candidate
and is not publishable yet.

## Sign the exact candidate

The release preparer's SSH key must be stored outside Git and outside every
operator deployment. Its public key and stable identity must already be reviewed
in [`maintainers/release-allowed-signers`](../maintainers/release-allowed-signers)
using the OpenSSH allowed-signers format. The repository intentionally contains no
enrolled release key during bootstrap; do not claim a verified binary release
until that changes through normal review.

Sign the checksum manifest with the dedicated `palisade-release` namespace:

```sh
make release-sign \
  VERSION=0.2.0 \
  SIGNER=maintainer@example \
  KEY_FILE=/private/local/palisade-release-key
```

The command refuses to overwrite an existing signature and creates
`SHA256SUMS.sig` plus the public `RELEASE-SIGNER` identity. It never creates,
uploads or copies a private key.

Verify the exact artifact set, closed metadata, source archive paths, every
checksum, the signature namespace and the pinned signer:

```sh
make release-verify VERSION=0.2.0
```

Consumers should obtain `maintainers/release-allowed-signers` from the verified
signed source tag, not from the same unauthenticated download location as the
candidate binaries.

## Independent reproduction

At least one second maintainer must check out the same signed tag on a separate
maintainer-controlled host, use the same Go patch release and run `make release
VERSION=...`. Keep both complete unsigned candidate directories until the
comparison finishes. The release preparer then runs:

```sh
install -d -m 700 /private/local/palisade-release-review
make release-compare \
  VERSION=0.2.0 \
  PREPARER=/private/local/preparer/0.2.0 \
  REPRODUCER=/private/local/reproducer/0.2.0 \
  OUTPUT=/private/local/palisade-release-review/reproduction-0.2.0.json
make release-reproduction-verify \
  REPORT=/private/local/palisade-release-review/reproduction-0.2.0.json
```

The comparison requires the exact seven unsigned artifacts and canonical
`SHA256SUMS` in each directory, recomputes every digest, validates the closed
metadata and safe source archive, requires byte identity, and verifies that the
annotated signed source tag points to a commit reachable from the checkout. The
attestation is create-only `0600` in an owner-only directory outside every Git
worktree. Review it locally before deciding whether it is suitable for release
notes. It contains artifact names, hashes, sizes and fixed limitations, but no
host identity, key material, logs, deployment configuration or traffic data.

The tool proves equality of the two directories supplied to it. It does not
prove that different people or hosts produced them, that build caches were
independent, or that custody was separate. Record those facts through maintainer
review. Candidate directories must be owner-controlled and immutable for the
duration of comparison; the tool binds every read to the original regular file
identity and rejects concurrent changes. Container image identity and deployment
configuration remain outside the reproducibility boundary. Never accept a
mismatch: investigate it and make a new release candidate.

Only after an independently reviewed comparison agrees may the preparer sign
the checksum manifest. The reproducer then runs `make release-verify
VERSION=...` against that signed candidate. Only after both records agree should
a maintainer push the signed tag and manually publish the verified files.
Uploading remains intentionally outside every script so local verification
never implies authority to change GitHub release state.

Record the two maintainers, clean-host platforms, exact Go patch version,
attestation digest, verification time and the absence of mismatches in the
release notes. Never attach build caches, private keys, operator configuration,
logs or evaluation datasets.

## Signing-key incident and release rollback

If a signing key may be exposed, stop publication, remove its public key in a new
reviewed commit and publish a security notice. Do not delete evidence, replace
artifacts in place or move an existing tag. Rebuild from a known-good commit with a
new key and a new version. Operators roll back by verifying and installing an
earlier independently reproduced release; their local policies, logs and rollout
keys are not project release keys and must not be uploaded during support.

## Failure and cleanup

A failed build or signature step may leave a partial ignored output directory. Inspect it, then
remove that exact `dist/release/<version>/` directory manually before retrying.
The script performs no recursive cleanup itself. If a tag must change, create a
new version; do not move a published release tag.
