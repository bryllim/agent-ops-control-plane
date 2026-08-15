# Agent Ops Control Plane

A governed tool-execution layer for AI agents with least-privilege policy checks, approval gates, idempotency, tamper-evident audit records, and rate limits.

> Reference implementation published in 2026. The commit history reflects the actual build and publication timeline.

## Why it exists

As agents gain access to production systems, authorization must depend on the actor, tool, arguments, risk, and environment—not merely whether a function exists. This project models those controls as a small, inspectable policy engine.

## Status

The initial release is an embeddable control-plane core with no external services required.

## License

MIT
