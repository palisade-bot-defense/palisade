# Security policy

PALISADE is security software and handles adversarial input. Treat every bypass, panic, token flaw, unsafe default and privacy leak as security-sensitive.

## Reporting

Do not open public issues containing an exploitable bypass, proof-of-concept against a real deployment, secrets, personal data or production attack traffic. Use GitHub's **Security → Report a vulnerability** private reporting flow for this repository.

Include the affected version, deployment shape, impact, minimal reproduction and any proposed mitigation. Remove production tokens, IP addresses, account identifiers and raw traffic.

GitHub private vulnerability reporting is the current authoritative intake. If
that channel is unavailable, do not post sensitive details publicly; publish only
a non-sensitive request for maintainer contact. The project does not operate a
private log-upload service and maintainers must not ask reporters to transfer raw
production traffic.

## Response process

1. A security responder acknowledges the private report and checks whether it
   contains secrets or personal data that should be removed.
2. The responder assigns impact and exploitability: critical for unauthenticated
   enforcement bypass, key compromise, remote code execution or raw-data
   disclosure; high for practical cross-session replay, fail-open enforcement or
   persistent denial of service; medium/low for bounded or defense-in-depth flaws.
3. Reproduction uses a synthetic fixture or a reporter-controlled minimal case.
   Real targets are never tested without explicit authorization.
4. A private fix receives focused regression, privacy-boundary and compatibility
   tests. Release verification follows [docs/RELEASING.md](docs/RELEASING.md); a
   security fix does not bypass signing or independent reproduction.
5. Maintainers coordinate publication after a fixed version or mitigation is
   available. The advisory credits the reporter if requested and states affected
   versions, impact, remediation and remaining limitations without publishing
   operator data.

Acknowledgement within two business days and initial triage within five business
days are project targets, not guaranteed support SLAs. Maintainers and reporters
should agree on disclosure timing; 90 days is the default maximum embargo unless
active exploitation, reporter safety or a dependency response justifies a
different date. An imminent risk may require an earlier minimal advisory.

Suspected release-signing compromise freezes binary publication immediately and
uses the key-rotation and new-version procedure in
[MAINTAINERS.md](MAINTAINERS.md). Published tags are never moved to hide an
incident.

## Supported versions

No production-supported release exists yet. Security fixes currently target the default branch. The prototype must run with the default `--mode shadow` behind an existing reverse proxy and rate limiter; `--mode enforce` is not approved for production use. When releases begin, this section will list an explicit support window; absence from that list means no security-maintenance promise.

The backend-only `/v1/session` endpoint requires the API bearer credential. An origin adapter must forward its `Set-Cookie` response to the browser and pass the cookie back to PALISADE. Enable `--require-session-cookie` only after that path is verified; a missing or tampered cookie then fails the PALISADE API request closed. The surrounding shadow integration should still define an explicit availability fallback so a PALISADE outage does not silently become a site-wide denial of service.

The optional local shadow sink also fails closed at startup: its key and directory must be owner-only, outside all Git worktrees and internally consistent with one encryption key. Use a dedicated owner-controlled parent directory. Files are AES-GCM authenticated and counters expose missing or reordered records within a retained file, but ordinary filesystem deletion, whole-file rollback and tail truncation are not prevented by encryption. Use host audit controls or an independent protected backup when deletion resistance is required. Never expose `POST /v1/outcome` directly to a browser; it is a backend-only bearer-authenticated label channel.

## Safe research

Only test systems you own or are authorized to assess. Synthetic and captured datasets must be scrubbed and access-controlled. Coordinated disclosure is expected before publishing bypass details.
