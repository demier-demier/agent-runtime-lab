# Architecture decisions

## ADR 001 — Pure transition core, durable adapters

**Decision:** Put state validation, approval binding, budgets, recovery semantics, and hash chaining in one pure TypeScript module. Node/SQLite and browser/IndexedDB adapters import it directly.

**Reason:** The demo should exercise the actual decision logic. Keeping storage and network effects outside the core makes failure transitions independently testable. The browser remains an explicitly local simulation; equal transition code does not imply equal operational guarantees.

## ADR 002 — Transactional outbox and pessimistic write admission

**Decision:** Persist approval/outbox and dispatch/inflight/budget together under a SQLite writer transaction. Use an expiring lease with increasing fence token plus revision CAS. Evaluate the clock after waiting for the writer lock.

**Reason:** Durable admission must precede a remote effect, and a stale worker must not overwrite another worker's state. A local transaction cannot include an arbitrary HTTP side effect. The fence governs local commits; connector semantics govern remote duplication.

## ADR 003 — Stable keys and explicit unknown outcomes

**Decision:** Use a stable idempotency key derived from run/node/tenant/payload. Require exact receipt digest matching. For connectors without an idempotency contract, interrupted execution enters `unknown` and requires reviewer reconciliation.

**Reason:** Retrying on every exception is unsafe when a response can be lost after the effect succeeds. The fixture demonstrates one effect under its durable idempotency contract. No generic exactly-once claim is made.

## ADR 004 — Bounded synthetic planner and execution units

**Decision:** Use an explicit synthetic plan with one side-effect node, up to 16 total DAG nodes, and fixed tool semantics. Track synthetic execution units, steps, attempts, and event bounds.

**Reason:** A small, inspectable workload makes the hard infrastructure behavior observable without API keys, unverifiable model claims, or uncontrolled tool execution. A future model planner can propose this schema but cannot bypass validation or approval.

## ADR 005 — Hash-linked evidence, not signed provenance

**Decision:** Maintain SHA-256 event links plus snapshot/log/outbox consistency and append-only SQL triggers. Do not describe them as tamper-proof or authenticated.

**Reason:** Hashes detect inconsistencies but not a privileged adversary who rewrites an entire chain. External anchoring/signatures require separate trust and key-management decisions.
