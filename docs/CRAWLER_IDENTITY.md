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

## Reference Go adapter

Build an immutable registry from an authenticated vendor publication during a
controlled deployment step, then pass it to the middleware:

```go
registry, err := palisadehttp.NewCrawlerRegistry([]palisadehttp.CrawlerIdentity{
    {
        Name: "vendor-search",
        Class: palisadehttp.CrawlerClassSearchIndexer,
        UserAgentTokens: []string{"VendorSearchBot"},
        CIDRs: verifiedVendorCIDRs,
    },
    {
        Name: "vendor-answer-retrieval",
        Class: palisadehttp.CrawlerClassAnswerEngine,
        UserAgentTokens: []string{"VendorAnswerBot"},
        CIDRs: verifiedVendorCIDRs,
    },
})
if err != nil { /* fail deployment */ }

guard, err := palisadehttp.New(palisadehttp.Config{
    // normal PALISADE configuration omitted
    TrustedProxyCIDRs: []string{"203.0.113.0/24"},
    TrustedClientIPHeader: "CF-Connecting-IP",
    TrustedProtoHeader: "X-Forwarded-Proto",
    CrawlerRegistry: registry,
})
```

The documentation CIDR above is not a real vendor range. Production CIDRs must
come from an authenticated vendor source. Registry construction rejects empty,
private, loopback, non-canonical and excessive inputs. Matching requires both
network and product token. Multiple matching identities are ambiguous and fail
closed to `unknown` rather than depending on rule order.

The adapter trusts a forwarding header only when the direct TCP peer is inside
an explicitly configured proxy CIDR. Direct clients cannot spoof
`CF-Connecting-IP` or `X-Real-IP`; those headers are ignored for identity. The
selected address and user-agent are used transiently inside the origin process
and are never sent to PALISADE, stored in its shadow log or shown in its admin
summary.

## Registry operations

- Fetch vendor registries outside the request hot path using TLS and the
  vendor's authenticated publication channel.
- Validate schema, canonical CIDRs, entry counts, class mapping and a freshness
  deadline before atomically replacing the in-memory registry.
- Keep the last known-good registry for a bounded grace period. After expiry,
  downgrade affected identities to `unknown`; never keep a stale allow forever.
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
