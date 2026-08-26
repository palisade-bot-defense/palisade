# Security policy

PALISADE is security software and handles adversarial input. Treat every bypass, panic, token flaw, unsafe default and privacy leak as security-sensitive.

## Reporting

Do not open public issues containing an exploitable bypass, proof-of-concept against a real deployment, secrets, personal data or attack traffic from Strain DB. Use GitHub's **Security → Report a vulnerability** private reporting flow for this repository.

Include the affected version, deployment shape, impact, minimal reproduction and any proposed mitigation. Remove production tokens, IP addresses, account identifiers and raw traffic.

## Supported versions

No production-supported release exists yet. Security fixes currently target the default branch. The prototype must run in shadow mode behind an existing reverse proxy and rate limiter.

## Safe research

Only test systems you own or are authorized to assess. Synthetic and captured datasets must be scrubbed and access-controlled. Coordinated disclosure is expected before publishing bypass details.
