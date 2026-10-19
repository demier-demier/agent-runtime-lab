# Agent Runtime Lab

**A durable execution runtime for agent workflows, built to expose what happens when an approved action meets a crash, a policy change, or a competing worker.**

**[Open the interactive demo →](https://bernardo-demier-ai-lab.fancy-fly-9200.chatgpt.site/agent-runtime-lab/)** · [Observed fault report](artifacts/observed-fault-matrix.json) · [Architecture](docs/architecture.md) · [Threat model](docs/threat-model.md)

Research an incident → propose a ticket → obtain independent approval → execute → verify the receipt. The runtime persists each decision and makes the uncertain cases visible. The browser demo uses the **same TypeScript transition core** as the SQLite worker; it is an executable lab, not a recorded trace.

The planner and ticket service are deterministic synthetic fixtures. This project demonstrates **AI execution infrastructure**, independent of the model that proposes a plan. It does not call an LLM, pretend that rules are inference, or use employer/customer data.

## Try the failure boundary in two minutes

1. Click **Run to next gate**.
2. Choose **Reviewer** and approve the exact action.
3. Choose **Worker** and click **Interrupt after ticket write**.
4. Reload the page: the run restores from IndexedDB with one persisted effect and no checkpoint.
5. Click **Recover**, then **Execute one step**. The receipt is reconciled without another write.

Repeat with **Non-idempotent connector**. Recovery stops in `unknown`; an independent reviewer must reconcile the actual stored receipt. Explore a constrained budget, expiry, policy revocation, changed arguments, and tool-version changes. Export the computed run as JSON.

Browser identities, policy ownership, and the remote ticket service are simulations within one browser origin. IndexedDB transactions provide local persistence/CAS, not real authentication or distributed isolation. The Node integration suite separately starts actual worker and HTTP connector processes with separate SQLite databases.

## What is implemented

| Layer                   | Concrete behavior                                                                                                                                                                                         |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Validated planning      | A bounded 4–16 node DAG with dependency/cycle validation, research branches, and exactly one proposal → write → verification sequence. No arbitrary code or shell tools.                                  |
| Policy & human approval | Tenant/principal role gates, independent reviewer identity, capability checks, expiry, and a digest binding the exact payload, tool contract, run, node, tenant, and policy revision.                     |
| Durable execution       | SQLite WAL with `synchronous=FULL`; snapshot, immutable event rows, and transactional outbox updated in one transaction.                                                                                  |
| Worker coordination     | Expiring leases, increasing fence tokens, and revision CAS. Lease and approval time are checked after acquiring the write lock. Stale workers cannot checkpoint or renew.                                 |
| Recovery                | Stable idempotency key and matching payload digest; existing remote receipts are verified before recording completion. Missing idempotent effects can retry with the same key, bounded to three attempts. |
| Unknown outcomes        | A connector without an idempotency contract is never retried automatically after an interrupted dispatch. A reviewer must reconcile the remote receipt.                                                   |
| Evidence                | SHA-256 linked event records, snapshot/log/outbox consistency checks, JSON exports, and an observed fault report produced by running the system.                                                          |
| Browser lab             | Shared core, transactional IndexedDB persistence, local effect store, editable policy/arguments, interruption injection, recovery, hash verification, and run export. No runtime CDN or API calls.        |

Cost budgets are **synthetic execution units**: one unit per local research/proposal/verification node and three for the ticket fixture. They are not dollars, tokens, or measured model usage. Step and dispatch-attempt limits are independent.

## Run locally

Node **22.16+ or 24** is required; CI runs both supported major lines. `node:sqlite` may emit an experimental warning on these versions.

```sh
npm ci
npm test
npm run demo
```

To reproduce the external crash boundary and save measured evidence:

```sh
npm run evaluate
```

This starts a separate loopback HTTP connector process with its own durable database, then starts/stops actual worker processes. It covers:

- process exit after remote commit but before the runtime checkpoint;
- lost HTTP acknowledgement after remote commit;
- restart after admission but before any remote write;
- a non-idempotent unknown outcome and reviewer reconciliation;
- two competing workers attempting the same action.

The command asserts outcomes and writes [artifacts/observed-fault-matrix.json](artifacts/observed-fault-matrix.json). Environment, time, process exit codes, observed effect counts, and event chains come from that run. Durations are local observations, **not a performance benchmark**. Temporary databases and connector processes are cleaned up.

```sh
npm run typecheck
npm run web:build
python3 -m http.server 8080 --directory web/dist
```

Open `http://localhost:8080`. The parent “All demos” navigation is intended for the public portfolio hub.

### CLI / library surface

```sh
# Terminal A: a synthetic external system, separate from runtime storage
node build/cli.js serve --db .runtime/remote.sqlite --port 8779

# Terminal B: create a run, then advance research/proposal/approval gate
node build/cli.js init --db .runtime/run.sqlite --run example
node build/cli.js step --db .runtime/run.sqlite --run example
node build/cli.js step --db .runtime/run.sqlite --run example
node build/cli.js step --db .runtime/run.sqlite --run example
node build/cli.js approve --db .runtime/run.sqlite --run example
node build/cli.js step --db .runtime/run.sqlite --run example --crash-after-effect
# Wait for the 5-second lease to expire, then recover and verify
node build/cli.js step --db .runtime/run.sqlite --run example
node build/cli.js step --db .runtime/run.sqlite --run example
node build/cli.js inspect --db .runtime/run.sqlite --run example
```

Use `--non-idempotent` on `init` for the uncertain connector case. After recovery enters `unknown`, the `reconcile` command queries remote evidence and submits it under the synthetic reviewer identity. The CLI is a local lab, **not an authenticated multi-user service**.

Library entry points are `build/core.js`, `build/sqlite.js`, and `build/worker.js`; generated TypeScript declarations are included in `build/`. `transition` is pure. `SqliteStore.update` combines validation with a locked, fenced persistence operation. `tick` advances one durable unit and delegates only the closed synthetic ticket action to the connector interface.

## Honest boundaries

Authorization linearizes at the atomic `dispatch.started` transition. A later revocation cannot recall a request already admitted or in flight. A lease fences local commits; it cannot revoke a packet already sent to a remote system.

This does **not** guarantee exactly-once effects for arbitrary APIs. The observed single effect depends on the synthetic connector’s durable idempotency contract. Hash chains detect inconsistency in a trusted store; an attacker able to rewrite the entire store can rehash it. Authentication, signed attestations, credential vaults, multi-host scheduling, production connectors, compensation, multiple side effects per plan, and LLM planning are outside this implementation.

See [state invariants and recovery semantics](docs/architecture.md), [ADRs](docs/decisions.md), [threat model](docs/threat-model.md), and [data provenance](PROVENANCE.md).

MIT licensed. Built by Bernardo Demier.
