# Public KEV evidence to an approved analyst artifact

This application answers a bounded operational question: **which retrieved records should an analyst inspect, what is the source evidence, and what remains unknown before remediation?** It produces versioned Markdown and JSON that can be handed to an analyst or attached to an organization's own case system.

## Input and retrieval

Clone [Policy RAG Lab](https://github.com/demier-demier/policy-rag-lab) beside this repository and follow its KEV ingestion/retrieval instructions. Its export performs authorized retrieval and receipt revalidation before emitting `kev-evidence/v1`. For an initial run, use its checked-in `data/kev/example-packet.json` snapshot. For current operational review, refresh the catalog and repeat retrieval; a checked-in snapshot is historical evidence.

Runtime accepts 1–12 documents, a bounded packet, exact source metadata, CVE IDs, catalog record fields and SHA-256 text hashes. It preserves retrieval metadata in the delivered JSON. Source text and model claims are rendered as escaped text in Markdown. It never executes instructions found in documents.

The source must be the official CISA JSON URL or a commit-pinned `cisagov/kev-data` GitHub mirror. This is provenance validation, **not a signature or independent re-fetch**. A local administrator can forge a complete packet and its hashes; source authenticity is outside this offline connector.

## Preview → approve → execute → verify

```sh
npm ci
npm run build
node build/cli.js review preview \
  --packet ../policy-rag-lab/data/kev/example-packet.json \
  --output .runtime/reviews --run public-kev-001
```

`preview` persists the exact report bytes, evidence hash, optional draft hash, absolute destination and plan. It advances the existing research/proposal nodes to the approval gate. It does not publish a report. The JSON response includes the complete Markdown and report object; inspect both before approving.

```sh
node build/cli.js review approve --run public-kev-001 --binding EXACT_PREVIEW_BINDING
node build/cli.js review execute --run public-kev-001
node build/cli.js review verify --run public-kev-001
node build/cli.js review inspect --run public-kev-001
```

Shared options are `--db PATH` (default `.runtime/kev.sqlite`) and `--tenant NAME` (default `analyst`). Approval is bound to exact content, destination, tool contract, run, tenant and policy. The approval is valid for five minutes. A blocked expired proposal can be inspected and re-approved using its current binding. Use a new run ID for changed input/draft or output.

The `review.publish` connector writes:

- `review.md`: readable source excerpts, citations, unconfirmed applicability, and an analyst checklist.
- `review.json`: source packet, retrieval metadata, provenance, and optional model draft.
- `manifest.json`: actual SHA-256 of each deliverable and approved payload digest.
- `.owner.json`: ownership marker for this exact publication's idempotency key.

Every output lives under `review-<idempotency-key>/`. A retry verifies the original files instead of rewriting them. Recovery and the final verification node read actual bytes. `verify` also rechecks completed runs, so a later manual edit is detected. Make an annotated copy rather than editing an evidence artifact in place.

## Failure recovery and filesystem limits

```sh
node build/cli.js review execute --run public-kev-001 --crash-after-effect
# Wait for the default five-second lease to expire.
node build/cli.js review execute --run public-kev-001
node build/cli.js review verify --run public-kev-001
```

The first process deliberately exits with code 86 after durable files exist but before the runtime receipt checkpoint. The next process reconciles the actual manifest and file hashes. An interrupted partial delivery may create only the missing files in an owned directory. It never replaces existing bytes. Corruption, unknown ownership, or a symlink blocks the operation.

Files are written to fsynced temporary inodes and linked into place without replacement. The manifest is published last. A crash between creating the directory and its ownership marker leaves an unowned directory; recovery deliberately stops for inspection instead of adopting it. Temporary `.pending-*` inodes may remain after an abrupt process death. The connector uses a trusted local filesystem on macOS/Linux and does not protect against a privileged process concurrently replacing parent directories, rollback of the entire storage system, or filesystem/hardware loss. SQLite leases fence checkpoints, not arbitrary external writes.

No remote API, vulnerability scan, patch, shell execution, or automatic asset-match claim is part of this workflow. CISA `dueDate` remains a catalog field; organizational deadlines require separate review. Local reviewer/operator labels are not authentication, and automated evaluation approval is not a human review.

## Optional real model draft

Provide `--draft FILE` during preview. The runtime never invokes a model implicitly. The separate generator should emit:

```json
{
  "schemaVersion": "kev-draft/v1",
  "model": "actual-model-id",
  "provider": "actual-provider-or-local-runtime",
  "generatedAt": "2026-10-19T12:00:00.000Z",
  "promptSha256": "64-character SHA-256 of the exact submitted prompt",
  "evidenceSha256": "64-character canonical packet SHA-256",
  "claims": [
    {
      "text": "Draft recommendation for analyst review",
      "citations": ["CVE-YYYY-NNNN"]
    }
  ],
  "usage": { "inputTokens": 0, "outputTokens": 0, "durationMs": 0 }
}
```

The zero usage values above are schema examples; supply measured values, not estimates presented as measurements. Extra provenance fields are retained. `canonicalEvidence()` from `build/kev-review.js` recursively sorts object keys, preserves array order, and uses JSON scalar serialization (including finite fractional scores). The hash is `sha256Bytes(canonicalEvidence(packet))`.

Every claim must cite an actual supplied document ID, and the packet hash must match. These checks do not establish semantic correctness. The draft is explicitly marked **unverified suggestions**, and cannot change applicability from `unconfirmed`. The reviewer must inspect the full exact output before publication.

## Reproduce measured delivery

```sh
node scripts/evaluate-kev.mjs \
  --packet ../policy-rag-lab/data/kev/example-packet.json \
  --draft ../policy-rag-lab/data/kev/example-draft.json
```

This script uses a temporary local store, starts a real crash-injected worker, restarts it, checks one unchanged publication and verifies the event chain. It exports observed evidence and the exact review under `artifacts/kev-review/`. Approval inside this evaluation is explicitly automated test approval. The integration tests additionally cover tampered files, unrelated directories, symlinks, missing outputs, changed approval bindings and draft citation/evidence mismatch.

The published observation includes a real local Qwen3-0.6B draft from the companion [generation workflow](https://github.com/demier-demier/policy-rag-lab/blob/main/docs/kev-generation.md). The same evidence packet is bound to that draft and to the approved report. The observed crash exited with code 86; recovery verified one publication, unchanged file inode and modification time, and a valid ten-event chain. These results describe this executed case, not every possible filesystem failure.
