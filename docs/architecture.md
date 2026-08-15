# Architecture decisions

## Default deny

Tool registration does not grant permission to use a tool. Calls need a matching allow rule, and explicit denies win when roles overlap.

## Scoped approvals

An approval is bound to a tool and idempotency key with an expiry. This prevents a human approval for one operation from becoming a reusable bearer credential.

## Tamper evidence

Every audit record includes the previous record hash. This detects mutation or reordering inside one process. Production deployments should sign records and export them to append-only storage.

## Threat boundaries

This library governs invocation; it does not sandbox tool code. Production handlers still need network isolation, secret scoping, request validation, and infrastructure-level authorization.

## Production extensions

- Store idempotency results and rate-limit counters in a shared database.
- Use signed approval receipts from an identity provider.
- Compile rules from a policy language such as Cedar or Rego.
- Export decision traces to a security information and event management system.
