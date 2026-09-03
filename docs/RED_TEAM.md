# Synthetic red-team baseline

PALISADE's public red-team baseline is a deterministic, local test exercise. It
covers the eight roadmap categories without traffic captures, external targets,
configured external targets or private deployment configuration. Passing it proves only
that the named regression controls behave as specified.

The closed suite is
[`examples/redteam/suite-v2.json`](../examples/redteam/suite-v2.json), validated
against [`schemas/red-team-suite-v2.schema.json`](../schemas/red-team-suite-v2.schema.json).
Every scenario points to an executable synthetic Go test. A repository contract
fails if a scenario disappears, changes category/expected behavior or references
a removed test.

Four scenarios were added in v2 for the attacks the v0.9 exit gate names by
hand: device-credential replay, attestation relay across a session, action or
evidence class, issuer signing-key compromise, and a revocation that never
arrives because the trust list expired. Three of the four point at controls that
were already tested; the fourth points at a test written because a run against
real hardware found a counter that could be erased, which this suite had not
been asking about. A scenario here records an adversary objective and the tests
that refuse it — it is not evidence that the objective was thought of first.

## Plan and execute

Prerequisites are the repository's pinned Go 1.27 toolchain and an already
restored module cache. The runner sets `GOPROXY=off`, `GOSUMDB=off`,
`GOTOOLCHAIN=local` and read-only module resolution.

Inspect the exact package/test plan without executing it:

```sh
make red-team-plan
```

Run all sixteen scenarios:

```sh
make red-team
```

The runner prints package-level commands and aggregate scenario/category counts.
It creates no result file, performs no scanning and has no target argument.
`GOPROXY=off` prevents dependency downloads but is not a general network sandbox.
Run the exercise on a disconnected host or with an operating-system/container
network sandbox; PALISADE's local release verification uses the same restriction.

## Machine-readable findings

A public synthetic findings record can be created only from a clean commit and
only after all sixteen named controls pass. The generator records the exact
source commit, suite digest, Go environment, closed scenario results and fixed
limitations. It never captures command output, hostnames, paths, targets,
traffic or operator configuration.

Create the owner-only report outside every Git worktree:

```sh
mkdir -m 700 /safe/local/red-team-output
make red-team-report OUTPUT=/safe/local/red-team-output/findings.json
```

The output is create-only and mode `0600`. Review it before copying the bounded
aggregate JSON into a public evidence directory. Verify any reviewed copy with:

```sh
make red-team-verify REPORT=/path/to/findings.json
```

The verifier recomputes the suite hash, requires all scenario identities and
test references in suite order, checks the exact source commit is reachable,
and rejects changed limitations or a partial/failed result presented as a
passing baseline. Operating-system network isolation remains an operator
boundary and is deliberately not claimed by the JSON record.

The first reviewed [public synthetic findings record](../reports/red-team/synthetic-findings-25aaba7.json)
binds 12 passed controls across all six categories to source commit `25aaba7`.
It was executed with Go 1.27.0 in a network-disabled Linux/arm64 container. The
JSON deliberately attests only the module-download restriction because generic
network isolation is supplied and verified by the operator, not the runner.

## Exercise record

Copy [`red-team/EXERCISE_TEMPLATE.md`](red-team/EXERCISE_TEMPLATE.md) into the
release's public evidence directory only after review. Record source commit,
toolchain, tester, command result, findings and limitations. Do not paste raw
logs, private paths, credentials, operator configuration or deployment traffic.

A failed scenario blocks a release candidate until the control is fixed or the
finding is explicitly accepted with severity, owner, mitigation and expiry.
Passing synthetic tests cannot close the roadmap's independent review gate or
substitute for confirmed-human/confirmed-abuse deployment evaluation.
