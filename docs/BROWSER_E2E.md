# Local real-browser challenge test

The `palisade.browser-e2e.challenge.v1` exercise runs the published Go origin
middleware in a real local Chrome or Chromium process. It uses only synthetic
values and loopback listeners. It does not read deployment logs, contact a
PALISADE service on the internet or produce an efficacy report.

Run it from the repository root:

```sh
make browser-e2e
```

The default runner requires Node.js 24 or newer, Go 1.27 or newer and a local
Google Chrome/Chromium installation. On macOS it discovers the standard Google
Chrome application path. On Linux it checks `/usr/bin/google-chrome` and
`/usr/bin/chromium`. Set `PALISADE_BROWSER_BIN` to use another executable. A
prebuilt local test fixture may be supplied with `PALISADE_FIXTURE_BIN`; that
binary must be built from the current checkout.

## What the browser proves

The runner starts a random-port `127.0.0.1` fixture, opens the protected route
as `http://localhost:<port>` and verifies all of the following through the
Chrome DevTools Protocol:

1. a closed canary-shaped challenge response renders the actual adapter-owned
   HTML, CSS and JavaScript;
2. the document language, accessible name and description, polite live status,
   enabled keyboard button and alternative-method control are present;
3. CSP, anti-framing and no-store response headers reach the browser;
4. the session and pending cookies remain host-only, `Secure`, `HttpOnly`,
   correctly `SameSite` and path-scoped to `/`;
5. metadata, verification and redemption cross the same-origin adapter routes;
6. the browser reload reaches the protected handler exactly once with the
   one-time redemption grant and clears both pending capabilities;
7. a later request is evaluated again and cannot reuse that grant;
8. the second challenge reaches the configured alternative verification path;
9. every observed HTTP(S) browser request stays on `localhost` or `127.0.0.1`.

Chrome is also started with background networking disabled and an unreachable
proxy for non-loopback destinations. The observed-request assertion is the
test oracle; the command-line flags are defense in depth rather than evidence
by themselves. Temporary browser profiles are deleted after success or failure.

## Deliberate limits

This is a single-process adapter and browser contract. It does not establish:

- reverse-proxy header trust or production TLS termination behavior;
- state sharing, failover or one-time redemption across multiple replicas;
- capacity under sustained browser load;
- assistive-technology compatibility beyond the checked semantic DOM contract;
- accessibility, abandonment or false-positive rates for real people;
- production detection efficacy or safety to enable automatic blocking.

Those claims require their own deployment environments and linked outcomes.
The synthetic fixture intentionally exposes only aggregate call counts. It
does not persist or expose a browser URL, address, cookie, token or request
body; fixed synthetic capabilities exist only in process for the exercised
handshake.
