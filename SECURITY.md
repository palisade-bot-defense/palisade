# Security policy

PALISADE is security software and handles adversarial input. Treat every bypass, panic, token flaw, unsafe default and privacy leak as security-sensitive.

## Reporting

Do not open public issues containing an exploitable bypass, proof-of-concept against a real deployment, secrets, personal data or production attack traffic. Use GitHub's **Security → Report a vulnerability** private reporting flow for this repository.

Include the affected version, deployment shape, impact, minimal reproduction and any proposed mitigation. Remove production tokens, IP addresses, account identifiers and raw traffic.

## Supported versions

No production-supported release exists yet. Security fixes currently target the default branch. The prototype must run with the default `--mode shadow` behind an existing reverse proxy and rate limiter; `--mode enforce` is not approved for production use.

The backend-only `/v1/session` endpoint requires the API bearer credential. An origin adapter must forward its `Set-Cookie` response to the browser and pass the cookie back to PALISADE. Enable `--require-session-cookie` only after that path is verified; a missing or tampered cookie then fails the PALISADE API request closed. The surrounding shadow integration should still define an explicit availability fallback so a PALISADE outage does not silently become a site-wide denial of service.

The optional local shadow sink also fails closed at startup: its key and directory must be owner-only, outside all Git worktrees and internally consistent with one encryption key. Use a dedicated owner-controlled parent directory. Files are AES-GCM authenticated and counters expose missing or reordered records within a retained file, but ordinary filesystem deletion, whole-file rollback and tail truncation are not prevented by encryption. Use host audit controls or an independent protected backup when deletion resistance is required. Never expose `POST /v1/outcome` directly to a browser; it is a backend-only bearer-authenticated label channel.

## Safe research

Only test systems you own or are authorized to assess. Synthetic and captured datasets must be scrubbed and access-controlled. Coordinated disclosure is expected before publishing bypass details.
