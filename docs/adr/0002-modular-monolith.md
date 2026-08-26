# ADR 0002: Start as a modular monolith

Status: accepted

The first releases remain one Go process with explicit internal module boundaries. This keeps local setup and incident response simple while detector contracts, reason codes, policy inputs and replay formats evolve.

PostgreSQL/Valkey are candidates only when persistence and shared state become necessary. NATS and ClickHouse are later scale options, not baseline dependencies. A module is split only after measurements show an independent scaling, availability or ownership need.
