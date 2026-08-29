# Signed local runtime artifacts

PALISADE can load operator-signed policy and detector configuration without a
project cloud, runtime download or data export. Crawler registries and rollout
plans retain their existing versioned wire formats; all four artifact families
share the same operational lifecycle below.

| Family | Schema | Mutable content | Runtime failure policy |
|---|---|---|---|
| Crawler registry | `palisade.crawler-registry.v1` | reviewed crawler identities and canonical address prefixes | unknown crawler after signed expiry |
| Policy bundle | `palisade.policy-bundle.v1` in `palisade.local-artifact.v1` | bounded numeric thresholds for the compiled progressive profile | decision path stops after signed expiry |
| Detector bundle | `palisade.detector-bundle.v1` in `palisade.local-artifact.v1` | ordered subset of compiled detector IDs | decision path stops after signed expiry |
| Rollout plan | `palisade.rollout-plan.v2` | measured endpoint, cohort, action, duration and friction maxima | enforcement returns to shadow after signed expiry |

The local-artifact signature is Ed25519 over a domain-separated canonical JSON
document. Metadata binds the artifact type, stable ID, strictly increasing
revision, UTC issue and expiry timestamps, and a 16-character SHA-256 public-key
identifier. Documents are at most 64 KiB, may be issued no more than five
minutes in the future and may live for at most 31 days.

## No executable configuration

Policy artifacts cannot contain CEL, JavaScript, URLs, headers or arbitrary
reason codes. They select the compiled `transparent-progressive-v1` profile and
set seven finite thresholds between 0.05 and 0.99. Within each risk dimension,
`elevated < step_up < high` is mandatory. Multi-source abuse ordering, verified
crawler boundaries and action progression remain compiled invariants.

Detector artifacts cannot contain plugins, module paths, expressions, weights
or upstream endpoints. They select an ordered, non-empty, duplicate-free subset
of the detector IDs compiled into that PALISADE release. Unknown IDs fail
startup. Changing either bundle requires a new `policy_version` or
`model_version`; those versions are emitted with every decision and must match
any signed rollout plan.

## Create artifacts locally

Start from `policies/defaults/policy-bundle.json` and
`detectors/defaults/detector-bundle.json`. Create a dedicated offline approval
key in an owner-only directory outside all Git worktrees:

```sh
palisade artifact-keygen \
  --private-key /srv/palisade-secrets/config.private \
  --public-key /srv/palisade-secrets/config.public
```

After changing the stable version and reviewing the closed JSON payload, create
a new revision. The command validates the payload before signing and refuses to
overwrite an existing output:

```sh
palisade prepare-local-artifact \
  --type policy_bundle \
  --payload ./policy-bundle.json \
  --private-key /srv/palisade-secrets/config.private \
  --output /srv/palisade-config/policy.signed.json \
  --revision 1 \
  --lifetime 168h
```

Use `detector_bundle` for the detector example. Deploy only the public key and
signed document to the PALISADE host. The document, key and their parent
directories must be owner-only, canonical, symlink-free and outside every Git
worktree.

Verify the exact staged document before activation:

```sh
palisade verify-local-artifact \
  --type policy_bundle \
  --artifact /srv/palisade-config/policy.signed.json \
  --public-key /srv/palisade-secrets/config.public
```

```sh
palisade serve \
  --policy-bundle /srv/palisade-config/policy.signed.json \
  --policy-public-key /srv/palisade-secrets/config.public \
  --detector-bundle /srv/palisade-config/detectors.signed.json \
  --detector-public-key /srv/palisade-secrets/config.public \
  # ...normal production flags
```

Policy and detector documents are validated at startup. Their earliest expiry
becomes a hard decision deadline; PALISADE does not silently keep using stale
configuration. Rotate by preparing a higher revision under a new output path,
reviewing it, atomically updating deployment configuration and restarting the
process. Roll back by signing the previous closed payload under a new, higher
revision and a new version string. Never reuse a lower revision or a version
that has already described different behavior.

The current process does not hot-reload policy or detector artifacts. This
keeps one process bound to one reportable policy/model pair; a supervised
restart is the explicit activation and rollback boundary. Consequently, a cold
start has no persistent local revision checkpoint: it trusts the configured
public key, signature and current expiry. Deployment tooling must keep the
highest accepted revision as local release state. This limitation is the same
cold-start boundary documented for crawler registries and is not disguised as
cross-restart rollback protection.
