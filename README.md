# Agent Runtime Lab

**A durable execution runtime for agent workflows, built to expose what happens when an approved action meets a crash, a policy change, or a competing worker.**

**[Open the interactive demo →](https://bernardo-demier-ai-lab.fancy-fly-9200.chatgpt.site/agent-runtime-lab/)** · [Observed fault report](artifacts/observed-fault-matrix.json) · [Architecture](docs/architecture.md) · [Threat model](docs/threat-model.md)

**[Inspect the public KEV application →](https://bernardo-demier-ai-lab.fancy-fly-9200.chatgpt.site/agent-runtime-lab/kev.html)** — real public evidence, a recorded local model draft, crash/recovery results, browser file-hash verification, and downloadable analyst deliverables. This page inspects a recorded run; use the interactive lab above to exercise state transitions.

Research an incident → propose a ticket → obtain independent approval → execute → verify the receipt. The runtime persists each decision and makes the uncertain cases visible. The browser demo uses the **same TypeScript transition core** as the SQLite worker; it is an executable lab, not a recorded trace.

The browser planner and ticket service are deterministic synthetic fixtures. The Node runtime also supports a **real analyst workflow**: public CISA KEV evidence from [Policy RAG Lab](https://github.com/demier-demier/policy-rag-lab) → exact report preview → approval → versioned Markdown/JSON files → file-hash verification. An optional model draft can be imported with model, prompt, citation, and usage provenance. This runtime makes no hidden model calls and uses no employer/customer data.

## Real application: an approved vulnerability review

An analyst can turn retrieved public vulnerability evidence into a traceable review packet, while keeping **known exploitation** separate from **unconfirmed applicability to their assets**. The result is an actual local file deliverable, published through the same SQLite checkpoint, approval, lease, and outbox engine used by the failure lab.

```sh
# Build both projects; export a packet using Policy RAG Lab's KEV command first.
npm ci
npm run build
node build/cli.js review preview \
  --packet ../policy-rag-lab/data/kev/example-packet.json \
  --output .runtime/reviews --run kev-review-001

# Read the complete report in the preview; copy its exact "binding" value.
node build/cli.js review approve --run kev-review-001 --binding COPY_PREVIEW_BINDING
node build/cli.js review execute --run kev-review-001
node build/cli.js review verify --run kev-review-001
```

The output directory contains `review-<idempotency-key>/review.md`, `review.json`, and a hash manifest. Approval expires after five minutes. A new packet, destination, or draft requires a new run and approval. Existing artifacts are never silently overwritten; changed or unrelated files block recovery. Analysts should make working copies for annotations and retain the original evidence artifact.

No asset inventory is supplied by this example. It does not establish affected versions, exposure, a local severity, or an organizational remediation deadline. It does not scan or patch systems. The CLI's role labels demonstrate the authorization boundary; they are **not authenticated human identities**.

See the [complete KEV workflow and optional model-draft contract](docs/kev-review.md). The online browser demo continues to use synthetic tickets; this file-producing integration runs locally.

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
| Public-data application | Validated CISA KEV evidence packet, optional citation-bound model draft, exact-byte approval, versioned filesystem delivery, and actual file-hash verification at recovery and completion.                |

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

Library entry points are `build/core.js`, `build/sqlite.js`, `build/worker.js`, and `build/kev-review.js`; generated TypeScript declarations are included in `build/`. `transition` is pure. `SqliteStore.update` combines validation with a locked, fenced persistence operation. `tick` advances one durable unit and delegates the closed ticket or review-publication action to its connector.

## Honest boundaries

Authorization linearizes at the atomic `dispatch.started` transition. A later revocation cannot recall a request already admitted or in flight. A lease fences local commits; it cannot revoke a packet already sent to a remote system.

This does **not** guarantee exactly-once effects for arbitrary APIs. The observed single effect depends on the connector's idempotency contract: a durable synthetic ticket record or a verified local review directory. Hash chains detect inconsistency in a trusted store; an attacker able to rewrite the entire store can rehash it. Authentication, signed attestations, credential vaults, multi-host scheduling, hosted production services, compensation, multiple side effects per plan, and LLM planning are outside this implementation.

See [state invariants and recovery semantics](docs/architecture.md), [ADRs](docs/decisions.md), [threat model](docs/threat-model.md), and [data provenance](PROVENANCE.md).

MIT licensed. Built by Bernardo Demier.
