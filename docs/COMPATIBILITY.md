# Compatibility policy

Contract version: `palisade.compatibility-policy.v1`.

PALISADE freezes only the public surfaces listed in
[`compatibility-freeze-v1.json`](../manifests/compatibility-freeze-v1.json).
A filename containing `v1` is not, by itself, a support promise. Historical,
draft and internal files that are absent from the manifest remain outside the
v1 compatibility boundary.

## Stability classes

- `stable_current` is the version emitted or consumed by the current release.
  Required fields, enum meanings, authentication rules, field numbers and
  privacy invariants cannot be removed, renamed, weakened or reinterpreted
  within that version.
- `legacy_read` is accepted only for authenticated local read/migration. New
  output never uses it. It receives security fixes but no new fields or
  capabilities and may be removed only in a new major release with a documented
  offline migration.
- Unlisted historical versions have no runtime support promise. Their presence
  in Git preserves project history, not compatibility.

## Change rules

Closed enums and objects are intentionally fail-closed. Adding an enum value,
required or optional field, endpoint, protobuf field, evidence meaning or
cross-field invariant therefore requires a new contract version unless the
specific contract already defines an extension mechanism. Older adapters must
reject an unknown value instead of guessing.

Within a frozen version, only clarifications that do not change accepted bytes,
wire meaning, trust, privacy, failure policy or operator safety are compatible.
Such a clarification still updates the manifest hash and must be labelled as a
non-semantic compatibility change in review. A semantic change requires:

1. a new schema/contract identifier and file rather than in-place replacement;
2. a documented old-to-new migration and explicit reader/writer support matrix;
3. poisoning, downgrade and mixed-version tests;
4. updated OpenAPI/protobuf/catalog representations where applicable;
5. a new freeze manifest version before a stable release consumes it.

Protobuf numbers and enum numeric values are never reused. Removed values stay
reserved in the next protobuf version. HTTP clients may depend only on the
published OpenAPI contract, not undocumented response fields or CLI log text.
Go packages under `pkg/` follow semantic versioning at the module level; exported
API removals require a new major module version even when an equivalent helper
exists elsewhere.

## Persisted artifacts and migrations

Every persisted or exchanged artifact carries its own `schema_version`.
Readers reject unknown versions. Writers emit only the manifest's current
version. A migration must be local, deterministic, bounded and create-only; it
must never upload private artifacts or overwrite its input. Until such a
migration exists, the old version remains either `legacy_read` or unsupported,
as recorded by the manifest.

Current Shadow writers emit v3 records while authenticated v1/v2 records remain
`legacy_read`. Current analysis emits v4 reports and does not accept historical
v1-v3 reports for rollout review; operators regenerate them locally from the
encrypted record stream. Current rollout plans are v2 and reviews are v4.

## Deprecation and support window

A stable contract is deprecated only in a signed release note and this policy.
Deprecation does not change validation. Removal requires the next major release,
at least one prior minor release carrying the replacement, and a tested local
migration or an explicit statement that no safe migration is possible.
Security may require immediate rejection of a version; that exception must be
documented as a security break with operator rollback instructions.

## Frozen safety documents

The manifest also pins the threat model and operator runbooks used for Shadow
collection, rollout, challenge integration, origin/reverse-proxy integration,
privacy review and releases. Their hashes make safety-relevant drift visible;
they are not evidence of independent security, legal or accessibility review.

Run the local gate with:

```sh
make compatibility-check
```

The check validates the closed manifest, exact file hashes, unique paths,
stability classes and required coverage. It performs no network access.
