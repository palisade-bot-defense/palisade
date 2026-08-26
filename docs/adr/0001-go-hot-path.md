# ADR 0001: Go for the decision hot path

Status: accepted

PALISADE uses Go for request handling, evidence normalization, score fusion, policy evaluation, replay and integrations. Go provides a small deployable artifact, predictable resource use, strong concurrency primitives and an approachable contributor experience for defensive infrastructure.

TypeScript is used for the browser sensor and dashboard. Python may be added for offline evaluation only; it is not part of request-time decisions.
