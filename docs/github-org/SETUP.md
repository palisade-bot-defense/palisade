# GitHub organization profile setup

GitHub renders an organization profile only from `profile/README.md` on the default branch of a public repository named `.github` owned by that organization. A profile file inside the `palisade` product repository does not activate the organization profile.

## Publication target

- Organization: `palisade-human-trust`
- Required repository: `https://github.com/palisade-human-trust/.github`
- Required visibility: public
- Target file: `profile/README.md`
- Maintained source in this repository: [`profile/README.md`](profile/README.md)

Copy the maintained source byte-for-byte to the target repository. Do not copy raw datasets, evaluation exports, local logs, keys, or generated private artifacts into the organization repository.

## Organization rename

The organization was renamed from `palisade-bot-defense` to
`palisade-human-trust` when PALISADE was repositioned from bot defense to a
proof-of-human protocol. The repository already uses the new slug throughout,
including the Go module path, protobuf `go_package` options, npm scopes and the
container image path.

Two consequences are not fixed by this repository:

- GitHub redirects the old organization URLs only until someone else claims
  `palisade-bot-defense`. Claim or retire the old name deliberately rather than
  relying on the redirect, and treat `raw.githubusercontent.com` links under the
  old slug as already broken.
- `ghcr.io/palisade-human-trust/palisade` does not exist until the package is
  re-published or transferred under the new organization. GHCR does not follow
  the rename.

## Organization metadata

Use these values unless the rights holder approves different public wording:

| Field | Value |
|---|---|
| Display name | `PALISADE` |
| Short description | `Proof of human presence with explainable, privacy-limited decisions.` |
| Website | `https://github.com/palisade-human-trust/palisade` |
| Primary pinned repository | `palisade` |
| Avatar source | `brand/exports/palisade-mark-512.png` from the `palisade` repository |
| Social preview source | `brand/exports/palisade-social-card.png` from the `palisade` repository |

Do not publish a legal entity name, support address or public security email until those values are authoritative. The organization profile must retain the prototype notice and the AGPL-3.0-only core / Apache-2.0 sensor license split.

## Verification checklist

1. Confirm the target repository owner is exactly `palisade-human-trust` and its name is exactly `.github`.
2. Confirm `profile/README.md` is on the target repository's default branch.
3. Open the organization overview and verify the logo, table, notices, and all repository links render correctly.
4. Confirm the vulnerability link opens a private advisory form, not a public issue.
5. Confirm the organization profile contains no external tracking image, credential, personal data, raw traffic, deployment hostname, or private contact detail.
6. Pin only repositories that are public and ready to represent the organization.
7. Recheck the license, contribution, and production-status wording whenever those gates change.
