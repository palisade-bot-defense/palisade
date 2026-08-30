# Maintainer and project operations

PALISADE is in bootstrap governance. Repository administrators currently perform
triage, security response and release preparation, but that administrative access
does not by itself make a release independently verified or production-supported.
No private deployment, traffic dataset or operator key is a project dependency.

## Public roles

| Role | Authority | Required separation |
|---|---|---|
| Triage maintainer | Classify public issues and review narrowly scoped changes | Must redirect vulnerabilities and private data away from public issues |
| Security responder | Access private reports, coordinate a fix and publish the advisory | Must not request raw production traffic; a reporter and responder cannot alone declare release verification complete |
| Release preparer | Select a clean reviewed commit, create the signed source tag and build candidate artifacts | Cannot independently attest reproducibility of their own build |
| Release verifier | Rebuild the same signed tag and compare the exact artifact checksums | Uses a separate clean host and signing identity from the preparer |

One person may perform routine triage and development. A release described as
independently reproduced requires two distinct people and two clean builds. Until
that separation and a reviewed key in
[`maintainers/release-allowed-signers`](maintainers/release-allowed-signers) exist,
the project may publish source snapshots but must not claim a verified binary
release or production support.

## Change authority

- Normal changes use public review and the repository's local verification gates.
- Detector and policy changes must include stable reason codes, synthetic tests
  and an explicit false-positive risk assessment.
- Changes to privacy boundaries, release keys, supported versions, default
  enforcement or vulnerability handling require maintainer review separate from
  the author when a second maintainer is available.
- No maintainer may use project access to obtain an operator's raw logs, keys,
  identifiers or private evaluation dataset.

## Release and key continuity

Release signing uses namespaced OpenSSH signatures over the exact `SHA256SUMS`
file. Public keys are pinned in the signed source tree. Private keys remain outside
Git and outside operator deployments; hardware-backed keys are preferred.

Adding, rotating or revoking a key requires a reviewed change recording the
identity, reason and effective release. A suspected key compromise freezes binary
publication immediately. Maintainers remove the key on a new reviewed commit,
publish a security notice, create a new version and never move an existing tag.
Already downloaded artifacts remain untrusted until independently rebuilt from a
known-good signed source tag.

## Bootstrap and succession

The next governance milestone is to enroll at least one independent release
verifier and one additional security responder. If the only administrator becomes
unavailable, enforcement policy does not change: installations continue using
their local keys and the last locally verified artifacts. No PALISADE service or
private deployment is required to transfer the public repository.

See [SECURITY.md](SECURITY.md) for disclosure handling and
[docs/RELEASING.md](docs/RELEASING.md) for executable release and rollback steps.
