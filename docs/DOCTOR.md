# Production environment preflight

`palisade doctor` validates the three base production credentials with the
same functions used by `palisade serve`. It performs no network request, opens
no deployment file and writes no state.

Generate every credential independently. Each API and admin credential must
contain 32–4096 bytes without ASCII whitespace or control characters. The HMAC
key must be unpadded base64url that decodes to 32–4096 bytes.

```sh
export PALISADE_HMAC_KEY="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')"
export PALISADE_API_KEY="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')"
export PALISADE_ADMIN_KEY="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')"

palisade doctor
```

On success the command reports only closed status values:

```text
PALISADE doctor
version: 0.1.0-dev
go: go1.27.0
scope: production_environment_only
production_secrets: valid
secret_separation: valid
default_runtime_mode: shadow
result: valid
```

It never prints a credential, its encoding, its length or a partial digest.
Missing, malformed, placeholder, reused, control-character-containing and
oversized values fail before any success output is written. Positional
arguments are rejected rather than silently ignored.

## Deliberate limits

`result: valid` means only that the base production environment passed the
credential checks used at server startup. It does not inspect or certify:

- signed policy, detector or rollout artifacts;
- shadow-log directories, encryption-key files or retention settings;
- proxy ranges, TLS termination, DNS, firewall or container configuration;
- the optional aggregate analysis report;
- detector efficacy, false-positive rates or readiness for enforcement.

Validate those inputs through their documented commands and start in Shadow.
Use the [Operator Shadow drill](OPERATOR_SHADOW_DRILL.md),
[local TLS deployment tests](TLS_DEPLOYMENT_TESTS.md),
[rollout guide](ROLLOUT.md) and [EU deployment checklist](privacy/DEPLOYMENT_CHECKLIST.md)
for the remaining local and deployment-owned checks.
