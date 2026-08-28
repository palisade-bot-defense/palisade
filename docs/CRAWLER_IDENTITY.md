# Crawler identity and SEO/GEO safety

PALISADE protects indexability without turning a spoofable header into an
allowlist. There is no complete, permanent global list of every legitimate SEO
or answer-engine crawler: vendors add products, change networks, share egress
and sometimes provide no machine-verifiable identity. PALISADE therefore
reports a crawler as either **verified for a narrow purpose** or **unknown**. It
does not claim perfect recognition.

## Trust chain

A public crawler qualifies only when all of these are true:

1. the origin adapter observes a crawler-specific user-agent product token;
2. the normalized client address matches a locally maintained vendor network,
   or another trusted adapter supplies `fcrdns_ua` or `http_signature` proof;
3. the purpose is one of `search_indexer`, `answer_engine`,
   `user_triggered_agent` or `preview`;
4. the deployment classified the route as `public_content`, `compare_index` or
   `other_public`; and
5. independent intent, policy-alert and decoy signals remain below their normal
   thresholds.

`training_crawler`, `monitoring` and `other` remain ordinary policy-controlled
automation. `compare_noindex`, `login`, `account`, `checkout`,
`challenge_worker` and `other` never receive the crawler exception. A crawler
that touches a decoy or trips an intent rule can still be challenged or
blocked. This separates identity from authorization.

## Signed local registry

Production deployments should transform authenticated crawler publications in
an offline or deployment-controlled publisher, review the normalized entries,
and sign the complete registry. The private Ed25519 key stays with that
publisher. The origin process receives only the public key and the signed local
JSON document described by
[`crawler-registry-v1.schema.json`](../schemas/crawler-registry-v1.schema.json).
It performs no vendor fetch, DNS lookup or other network request while handling
an application request.

Load the registry before serving traffic, pass it to the middleware, publish one
closed status snapshot and then start the watcher:

```go
registry, err := palisadehttp.NewSignedCrawlerRegistry(verificationKey)
if err != nil { /* fail deployment */ }
if err := registry.UpdateSignedFile(
    "/etc/palisade/crawler-registry.json",
    time.Now().UTC(),
); err != nil { /* fail deployment */ }

guard, err := palisadehttp.New(palisadehttp.Config{
    // normal PALISADE configuration omitted
    TrustedProxyCIDRs: []string{"203.0.113.0/24"},
    TrustedClientIPHeader: "CF-Connecting-IP",
    TrustedProtoHeader: "X-Forwarded-Proto",
    CrawlerRegistry: registry,
    CrawlerRegistryReporting: true,
    CrawlerRegistryReportTTL: 5*time.Minute,
})
if err != nil { /* fail deployment */ }

reportCtx, cancelReport := context.WithTimeout(context.Background(), 3*time.Second)
if err := guard.ReportCrawlerRegistryStatus(reportCtx); err != nil { /* alert */ }
cancelReport()

watchCtx, stopWatching := context.WithCancel(context.Background())
defer stopWatching()
go func() {
    if err := registry.WatchSignedFile(
        watchCtx,
        "/etc/palisade/crawler-registry.json",
        time.Minute,
        func(event palisadehttp.CrawlerRegistryReloadEvent) {
            ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
            defer cancel()
            if err := guard.ReportCrawlerRegistryStatus(ctx); err != nil { /* alert */ }
        },
    ); err != nil {
        // Watcher stopped unexpectedly: alert local operations.
    }
}()
```

The initial watcher load must succeed. Every later update must have a strictly
increasing revision, a valid Ed25519 signature, canonical UTC timestamps and a
signed lifetime of at most 31 days. The document and registry sizes are bounded.
Only a completely parsed and validated snapshot is swapped into the concurrent
request path. A rejected or partially written update leaves the last known-good
snapshot active, but only until its signed expiry. An expired or empty registry
classifies every crawler claim as `unknown`.

The increasing-revision check protects the lifetime of one origin process. On
cold start there is no trusted local revision checkpoint, so the signed expiry
is the hard replay bound. Deployments that require stricter restart protection
must retain the accepted revision in their own authenticated deployment state
and refuse to publish an older file before starting PALISADE.

`CrawlerRegistryStatus` and `CrawlerRegistryReloadEvent` expose only the closed
state, revision, timestamps, SHA-256 digest and aggregate entry/prefix counts.
They contain no address, user-agent token, vendor name or source path. Keep the
callback fast and non-blocking. Operators should alert on `rejected`, `expired`
and an approaching `expires_at`; `unchanged/same_document` is an ordinary poll.

The adapter sends registry health only when the deployment explicitly calls
`ReportCrawlerRegistryStatus`. Reporting every bounded watcher poll supplies a
heartbeat without exposing the watched path. The authenticated report uses a
random per-process source epoch, monotonic sequence and a closed `valid_until`
deadline. The reporting TTL defaults to five minutes and must be between one
minute and 25 hours; keep the watcher interval comfortably shorter than that
TTL. PALISADE discards a source after its deadline so stopped or restarted
origin processes cannot leave stale health behind. The Operator Console
aggregates current, expired, empty and static sources, revision drift, distinct
snapshot digests and the earliest signed expiry. It never receives registry
entries.

### Local publisher CLI

Keep the publisher directory owner-only and outside every Git worktree. Generate
the signing key pair once:

```sh
palisade crawler-registry-keygen \
  --private-key /private/local/palisade-crawlers/publisher.private \
  --public-key /private/local/palisade-crawlers/publisher.public
```

Create a reviewed entries array matching
[`crawler-registry-entries-v1.schema.json`](../schemas/crawler-registry-entries-v1.schema.json),
then sign and atomically publish it:

```sh
palisade crawler-registry-sign \
  --entries /private/local/palisade-crawlers/reviewed-entries.json \
  --private-key /private/local/palisade-crawlers/publisher.private \
  --output /private/local/palisade-crawlers/crawler-registry.json \
  --revision 1 \
  --valid-for 168h

palisade crawler-registry-inspect \
  --registry /private/local/palisade-crawlers/crawler-registry.json \
  --public-key /private/local/palisade-crawlers/publisher.public
```

Signing validates the closed entries, derives canonical whole-second UTC issue
and expiry times, verifies the resulting signature, requires a 10-minute to
31-day lifetime and refuses to replace a registry unless the existing artifact
was signed by the same key and the revision increases. Publication is a synced
same-directory temporary file followed by an atomic rename. Inputs, keys and
outputs must be canonical owner-only regular files; symlinks and Git worktrees
are rejected.

`EncodeSignedCrawlerRegistry` remains available as a deterministic signing
primitive for a custom offline publisher. Neither API is a vendor downloader:
the publisher remains responsible for authenticated source retrieval, purpose
mapping, review and increasing revisions. Never copy the private key into the
origin image, configuration repository or registry document. Deployment- or
community-maintained inputs must enter through this same signed, reviewed
boundary.

For a fixed test or tightly controlled immutable deployment,
`NewCrawlerRegistry` remains available. Registry construction rejects empty,
private, loopback, non-canonical and excessive inputs. Matching always requires
both network and product token. Multiple matching identities are ambiguous and
fail closed to `unknown` rather than depending on rule order.

The adapter trusts a forwarding header only when the direct TCP peer is inside
an explicitly configured proxy CIDR. Direct clients cannot spoof
`CF-Connecting-IP` or `X-Real-IP`; those headers are ignored for identity. The
selected address and user-agent are used transiently inside the origin process
and are never sent to PALISADE, stored in its shadow log or shown in its admin
summary.

## Registry operations

- Fetch vendor registries outside the request hot path using TLS and the
  vendor's authenticated publication channel.
- Normalize and review sources before signing; the verifier validates the
  signature, schema, canonical CIDRs, entry counts, class mapping, revision and
  signed freshness deadline before atomically replacing its snapshot.
- Keep the last known-good registry only until its signed expiry, then downgrade
  affected identities to `unknown`; never keep a stale allow forever.
- Record only aggregate update status, version/digest and counts. Do not log
  request addresses or user-agent strings.
- Test additions with known-positive vendor fixtures, wrong-network claims,
  wrong-UA addresses, overlapping identities, IPv4/IPv6 and trusted-proxy
  poisoning cases.

Forward-confirmed reverse DNS can complement vendors that publish documented
DNS suffixes: reverse lookup, suffix allowlist, then forward lookup and require
the original address in the result. It must use the deployment's approved local
resolver, strict timeouts, bounded caching and asynchronous refresh. It is not
in the request hot path because blocking DNS harms availability and may disclose
client addresses to a resolver. HTTP Message Signatures are preferred when a
vendor offers a stable authenticated profile.

## SEO/GEO content behavior

Crawler verification does not replace `robots.txt`, canonical URLs, sitemaps,
structured data or HTTP caching. Robots directives express crawl preference;
they do not authenticate a bot. The public PALISADE website emits its canonical
and machine-readable artifacts only when a reviewed public site URL is supplied
at build time. Deployments should map indexable and noindex routes from their
server-owned route table, never from a browser header or query parameter.

Operational acceptance requires separate measurements for verified search
indexers, verified answer-engine retrieval, unknown automation and humans:
crawl success/status, challenge rate, index coverage, rendered metadata,
latency, registry freshness and false-whitelist attempts. The release gate is
zero challenge/block responses for verified eligible crawlers on indexable
routes unless independent abuse intent is present; it is not “allow every bot.”
