# ADR 0003: Separate automation, intent and continuity

Status: accepted

A single bot score confuses automation with abuse and harms accessibility tools, search engines and legitimate integrations. PALISADE fuses evidence into automation risk, abuse intent risk and account continuity. CEL policy maps the three dimensions plus endpoint context to allow, observe, throttle, challenge or block.

Detector evidence is typed, confidence-weighted, time-bounded and identified by a stable reason code. Policies and model weights are versioned independently.
