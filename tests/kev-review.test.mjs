import test from "node:test";
import assert from "node:assert/strict";
import {
  readFileSync,
  writeFileSync,
  readdirSync,
  mkdirSync,
  statSync,
  unlinkSync,
  symlinkSync,
} from "node:fs";
import { join } from "node:path";
import { SqliteStore } from "../build/sqlite.js";
import { transition, verifyChain } from "../build/core.js";
import { apply, tick } from "../build/worker.js";
import {
  canonicalEvidence,
  CISA_KEV_URL,
  fileReviewConnector,
  inspectPublication,
  makeReviewRun,
  sha256Bytes,
  validatePacket,
  validateDraft,
} from "../build/kev-review.js";
import { workspace, child, sleep } from "./helpers.mjs";

const operator = { tenant: "analyst", id: "operator", role: "operator" };
const worker = { tenant: "analyst", id: "review-worker", role: "worker" };
const reviewer = { tenant: "analyst", id: "reviewer", role: "reviewer" };
function packet() {
  const text =
    "Synthetic test record; not a real finding. Confirm affected versions before taking action.";
  return {
    schemaVersion: "kev-evidence/v1",
    generatedAt: "2026-10-19T00:00:00Z",
    query: "synthetic test fixture",
    source: {
      url: CISA_KEV_URL,
      retrievedAt: "2026-10-19T00:00:00Z",
      sha256: "a".repeat(64),
      catalogVersion: "test-only",
    },
    documents: [
      {
        id: "kev-test-1",
        cveID: "CVE-2026-99999",
        title: "Synthetic test record",
        text,
        sourceUrl:
          "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        contentSha256: sha256Bytes(text),
        record: {
          vendorProject: "Synthetic",
          product: "Test",
          dateAdded: "2026-10-01",
          dueDate: "2026-10-22",
          requiredAction: "Check vendor guidance.",
          knownRansomwareCampaignUse: "Unknown",
        },
      },
    ],
    retrieval: { ranking: [{ score: 0.84 }] },
  };
}
async function setup() {
  const w = await workspace();
  const output = join(w.dir, "reviews");
  const store = new SqliteStore(w.db);
  store.create(
    makeReviewRun("kev-test", operator, Date.now(), packet(), output),
  );
  const connector = fileReviewConnector();
  for (let i = 0; i < 3; i++)
    await tick(store, "analyst", "kev-test", connector, {
      owner: "review-worker",
    });
  return {
    ...w,
    store,
    output,
    connector,
    get: () => store.load("analyst", "kev-test"),
    close: async () => {
      store.close();
      await w.cleanup();
    },
  };
}
function approve(w) {
  return apply(w.store, "analyst", "kev-test", reviewer, {
    type: "approve",
    expectedBinding: w.get().proposal.binding,
  });
}
const exec = (w, command, args = []) =>
  child(["review", command, "--db", w.db, "--run", "kev-test", ...args]).done;

test("public evidence validation verifies text hashes and preserves fractional retrieval scores", () => {
  const value = packet();
  assert.equal(validatePacket(value).retrieval.ranking[0].score, 0.84);
  value.documents[0].text += " changed";
  assert.throws(() => validatePacket(value), /SHA-256 mismatch/);
});
test("missing ransomware source field remains null and renders Not supplied", async () => {
  const w = await workspace();
  try {
    const p = packet();
    p.documents[0].record.knownRansomwareCampaignUse = null;
    const run = makeReviewRun(
      "null-source",
      operator,
      Date.now(),
      p,
      join(w.dir, "reviews"),
    );
    assert.equal(
      JSON.parse(run.plan.review.json).evidence.documents[0].record
        .knownRansomwareCampaignUse,
      null,
    );
    assert.match(run.plan.review.markdown, /catalog field\): Not supplied/);
  } finally {
    await w.cleanup();
  }
});
test("review preview uses runtime gate, binds output bytes, and creates no publication", async () => {
  const w = await setup();
  try {
    assert.equal(w.get().status, "awaiting_approval");
    assert.deepEqual(readdirSync(w.output), []);
    assert.match(w.get().plan.review.markdown, /Applicability.*UNCONFIRMED/);
    assert.equal(
      JSON.parse(w.get().plan.review.json).applicability,
      "unconfirmed",
    );
    assert.throws(
      () =>
        apply(w.store, "analyst", "kev-test", reviewer, { type: "approve" }),
      /exact preview binding/,
    );
    assert.throws(
      () =>
        apply(w.store, "analyst", "kev-test", reviewer, {
          type: "approve",
          expectedBinding: "0".repeat(64),
        }),
      /exact preview binding/,
    );
    const original = w.get().proposal.binding;
    const edited = apply(w.store, "analyst", "kev-test", operator, {
      type: "edit",
      title: "Changed review label",
    });
    assert.notEqual(edited.proposal.binding, original);
    assert.throws(
      () =>
        apply(w.store, "analyst", "kev-test", reviewer, {
          type: "approve",
          expectedBinding: original,
        }),
      /exact preview binding/,
    );
  } finally {
    await w.close();
  }
});
test("CLI preview, approve, execute, verify writes exact versioned files once", async () => {
  const w = await workspace();
  try {
    const input = join(w.dir, "packet.json");
    const output = join(w.dir, "reviews");
    writeFileSync(input, JSON.stringify(packet()));
    const preview = await exec(w, "preview", [
      "--packet",
      input,
      "--output",
      output,
    ]);
    assert.equal(preview.code, 0, preview.stderr);
    const proposed = JSON.parse(preview.stdout);
    assert.equal(proposed.status, "awaiting_approval");
    assert.equal(
      (await exec(w, "approve", ["--binding", proposed.binding])).code,
      0,
    );
    const execution = await exec(w, "execute");
    assert.equal(execution.code, 0, execution.stderr);
    const published = JSON.parse(execution.stdout);
    assert.equal(published.status, "completed");
    const path = published.publication.path;
    const before = statSync(join(path, "review.md"));
    assert.equal(
      readFileSync(join(path, "review.md"), "utf8"),
      proposed.markdown,
    );
    assert.deepEqual(
      JSON.parse(readFileSync(join(path, "review.json"), "utf8")),
      proposed.report,
    );
    assert.equal((await exec(w, "execute")).code, 0);
    assert.equal((await exec(w, "verify")).code, 0);
    const after = statSync(join(path, "review.md"));
    assert.equal(after.ino, before.ino);
    assert.equal(after.mtimeMs, before.mtimeMs);
    assert.equal(readdirSync(output).length, 1);
  } finally {
    await w.cleanup();
  }
});
test("real process death after file publication recovers hashes without rewriting artifacts", async () => {
  const w = await setup();
  try {
    approve(w);
    const crash = await exec(w, "execute", [
      "--crash-after-effect",
      "--lease-ms",
      "100",
    ]);
    assert.equal(crash.code, 86, crash.stderr);
    assert.equal(w.get().outbox.status, "inflight");
    const observed = inspectPublication(w.get().outbox.action);
    const before = statSync(join(observed.path, "review.md"));
    await sleep(150);
    const resumed = await exec(w, "execute");
    assert.equal(resumed.code, 0, resumed.stderr);
    assert.equal(w.get().status, "completed");
    assert(w.get().events.some((e) => e.type === "recovery.receipt_verified"));
    assert.equal(w.get().outbox.attempts, 1);
    assert.equal(
      statSync(join(observed.path, "review.md")).mtimeMs,
      before.mtimeMs,
    );
    assert.equal(verifyChain(w.get().events).valid, true);
  } finally {
    await w.close();
  }
});
test("restart rejects tampered file instead of overwriting it or recording completion", async () => {
  const w = await setup();
  try {
    approve(w);
    assert.equal(
      (await exec(w, "execute", ["--crash-after-effect", "--lease-ms", "100"]))
        .code,
      86,
    );
    const observed = inspectPublication(w.get().outbox.action);
    writeFileSync(join(observed.path, "review.md"), "analyst changed this");
    await sleep(150);
    const resumed = await exec(w, "execute");
    assert.equal(resumed.code, 1);
    assert.match(resumed.stderr, /artifact changed/);
    assert.equal(
      readFileSync(join(observed.path, "review.md"), "utf8"),
      "analyst changed this",
    );
    assert.equal(w.get().outbox.status, "inflight");
  } finally {
    await w.close();
  }
});
test("unrelated preexisting destination is never adopted or overwritten", async () => {
  const w = await setup();
  try {
    approve(w);
    const path = join(w.output, `review-${w.get().outbox.action.key}`);
    mkdirSync(path);
    writeFileSync(join(path, "notes.txt"), "unrelated material");
    await assert.rejects(
      () =>
        tick(w.store, "analyst", "kev-test", w.connector, {
          owner: "review-worker",
        }),
      /ENOENT/,
    );
    assert.deepEqual(readdirSync(path), ["notes.txt"]);
    assert.equal(
      readFileSync(join(path, "notes.txt"), "utf8"),
      "unrelated material",
    );
  } finally {
    await w.close();
  }
});
test("owned partial delivery resumes only missing files and preserves existing bytes", async () => {
  const w = await setup();
  try {
    approve(w);
    const action = w.get().outbox.action;
    await w.connector.submit(action);
    const observed = inspectPublication(action);
    const original = statSync(join(observed.path, "review.md"));
    unlinkSync(join(observed.path, "manifest.json"));
    unlinkSync(join(observed.path, "review.json"));
    assert.equal(await w.connector.lookup(action), null);
    await w.connector.submit(action);
    assert.equal(statSync(join(observed.path, "review.md")).ino, original.ino);
    assert.deepEqual(inspectPublication(action).files, observed.files);
  } finally {
    await w.close();
  }
});
test("artifact symlink cannot satisfy verification or alter another file", async () => {
  const w = await setup();
  try {
    approve(w);
    const action = w.get().outbox.action;
    await w.connector.submit(action);
    const observed = inspectPublication(action);
    const other = join(w.dir, "unrelated.md");
    writeFileSync(other, action.args.review.markdown);
    unlinkSync(join(observed.path, "review.md"));
    symlinkSync(other, join(observed.path, "review.md"));
    assert.throws(() => inspectPublication(action), /ELOOP/);
    await assert.rejects(() => w.connector.submit(action), /ELOOP/);
    assert.equal(readFileSync(other, "utf8"), action.args.review.markdown);
  } finally {
    await w.close();
  }
});
test("symlink publication directory is rejected without writing into its target", async () => {
  const w = await setup();
  try {
    approve(w);
    const action = w.get().outbox.action;
    const unrelated = join(w.dir, "unrelated-directory");
    mkdirSync(unrelated);
    writeFileSync(join(unrelated, "notes.txt"), "keep this");
    symlinkSync(unrelated, join(w.output, `review-${action.key}`));
    await assert.rejects(
      () => w.connector.submit(action),
      /approved real directory/,
    );
    assert.deepEqual(readdirSync(unrelated), ["notes.txt"]);
    assert.equal(
      readFileSync(join(unrelated, "notes.txt"), "utf8"),
      "keep this",
    );
  } finally {
    await w.close();
  }
});
test("a foreign ownership marker is rejected and left unchanged", async () => {
  const w = await setup();
  try {
    approve(w);
    const action = w.get().outbox.action;
    const path = join(w.output, `review-${action.key}`);
    mkdirSync(path);
    const foreign = JSON.stringify({ key: "foreign", payloadDigest: "other" });
    writeFileSync(join(path, ".owner.json"), foreign);
    await assert.rejects(() => w.connector.submit(action), /not owned/);
    assert.equal(readFileSync(join(path, ".owner.json"), "utf8"), foreign);
    assert.deepEqual(readdirSync(path), [".owner.json"]);
  } finally {
    await w.close();
  }
});
test("verification node checks actual artifact again after receipt checkpoint", async () => {
  const w = await setup();
  try {
    approve(w);
    await tick(w.store, "analyst", "kev-test", w.connector, {
      owner: "review-worker",
    });
    const observed = inspectPublication(w.get().outbox.action);
    writeFileSync(join(observed.path, "review.json"), "{}");
    await assert.rejects(
      () =>
        tick(w.store, "analyst", "kev-test", w.connector, {
          owner: "review-worker",
        }),
      /artifact changed/,
    );
    assert.notEqual(w.get().status, "completed");
  } finally {
    await w.close();
  }
});
test("revoked review capability prevents filesystem publication", async () => {
  const w = await setup();
  try {
    approve(w);
    apply(w.store, "analyst", "kev-test", operator, {
      type: "policy",
      policy: { ...w.get().policy, revision: 2, capabilities: [] },
    });
    assert.equal(w.get().approval, null);
    assert.throws(() => approve(w), /revoked/);
    assert.deepEqual(readdirSync(w.output), []);
  } finally {
    await w.close();
  }
});
test("model drafts require matching evidence and known citations; remain suggestions", async () => {
  const w = await workspace();
  try {
    const p = packet();
    const draft = {
      schemaVersion: "kev-draft/v1",
      model: "synthetic-test-model",
      provider: "fixture",
      generatedAt: p.generatedAt,
      promptSha256: "b".repeat(64),
      evidenceSha256: sha256Bytes(canonicalEvidence(p)),
      claims: [
        { text: "Check product versions.", citations: [p.documents[0].id] },
      ],
      usage: { durationMs: 12.34, inputTokens: 123, outputTokens: 12 },
      modelRevision: "fixture",
    };
    assert.equal(validateDraft(draft, p).usage.durationMs, 12.34);
    const run = makeReviewRun(
      "draft-test",
      operator,
      Date.now(),
      p,
      join(w.dir, "reviews"),
      draft,
    );
    assert.match(run.plan.review.markdown, /unverified suggestions/);
    assert.equal(JSON.parse(run.plan.review.json).applicability, "unconfirmed");
    draft.claims[0].citations = ["missing-doc"];
    assert.throws(() => validateDraft(draft, p), /unknown citations/);
    draft.claims[0].citations = [p.documents[0].id];
    draft.evidenceSha256 = "0".repeat(64);
    assert.throws(() => validateDraft(draft, p), /different evidence/);
  } finally {
    await w.cleanup();
  }
});
