# Threat model

## Assets and trust boundaries

The assets are approved action intent, tenant isolation within the caller contract, execution budgets, durable workflow state, and evidence connecting an external ticket to its approved payload. The trusted computing base consists of the runtime process, adapter, database permissions, configured connector, and principal source.

The example CLI hardcodes synthetic identities. The browser lets the viewer switch roles. Neither implements real user authentication. No credential or production customer data is included. The HTTP fixture binds only to `127.0.0.1`, rejects browser Origin headers and unexpected Host values, and exposes only health, lookup, and bounded synthetic ticket creation. It is a test service, not a deployable public API.

| Failure / attack                 | Implemented response                                                                           | Remaining boundary                                                                                  |
| -------------------------------- | ---------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| Malformed or cyclic plan         | Bounded structural validation, fixed node/tool registry.                                       | Typed library callers are trusted to pass the documented shape; no public JSON-plan API is exposed. |
| Wrong tenant or caller role      | Core checks tenant and operation-specific role; stores scope by tenant/run.                    | Roles/IDs must be authenticated by an embedding application.                                        |
| Self-approval under another role | Creator/observed worker principal IDs cannot approve.                                          | An identity provider must prevent the same person manufacturing unrelated identities.               |
| Changed approved intent          | Argument/tool/policy digests and current dispatch check invalidate queued approval.            | Already admitted remote requests cannot be recalled.                                                |
| Expired approval or lease        | Time read after write-lock acquisition, fencing token and revision checks.                     | Trusted single-host clock; local fence cannot cancel remote I/O.                                    |
| Crash or lost acknowledgement    | Persisted inflight marker, durable lookup, stable idempotency key and exact digest.            | Arbitrary connectors may not offer durable idempotency or definitive lookup.                        |
| Unknown non-idempotent effect    | Halt; reviewer reconciliation only from matching remote evidence.                              | No automatic compensation or retry; missing/ambiguous evidence remains halted.                      |
| Duplicate competing execution    | Lease ownership/CAS prevents competing local admission; idempotency protects synthetic effect. | No claim of distributed consensus or global scheduler fairness.                                     |
| Corrupted audit/snapshot/outbox  | Hash-chain verification and cross-store comparison; append-only SQL triggers.                  | A database owner can rewrite and rehash the entire history.                                         |
| Oversized HTTP response          | Incremental byte cap, timeout, fatal UTF-8, redirects refused.                                 | Fixture runs on trusted loopback, not an internet connector gateway.                                |
| Browser HTML injection           | User-visible strings are assigned with `textContent`; no evaluated input.                      | DevTools and same-origin scripts have control over the local simulation.                            |

Budgets are deliberately synthetic, with capped steps and attempts. There is no token-metering or billing guarantee. This project does not include secrets, cloud deployment, a public API, prompt-injection classifiers, exploit automation, or uncontrolled tool execution.

Potential production extensions include authenticated identity/role provenance, signed or externally anchored event checkpoints, per-tenant encryption/key management, real connector contracts with conformance tests, multi-action compensation semantics, and operational metrics. Those are design directions, not implemented features.
