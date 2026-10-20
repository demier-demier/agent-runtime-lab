import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { SqliteStore } from "../build/sqlite.js";
import { verifyChain } from "../build/core.js";
const option = (name) => {
  const i = process.argv.indexOf(`--${name}`);
  return i < 0 ? null : process.argv[i + 1];
};
const packetPath = option("packet");
if (!packetPath)
  throw new Error(
    "Usage: node scripts/evaluate-kev.mjs --packet FILE [--draft FILE]",
  );
const draftPath = option("draft");
const temporary = mkdtempSync(join(tmpdir(), "observed-kev-review-"));
const db = join(temporary, "runtime.sqlite");
const output = join(temporary, "reviews");
const runId = "observed-public-kev-review";
const reportDir = resolve("artifacts/kev-review");
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
function cli(command, args = [], expected = 0) {
  const result = spawnSync(
    process.execPath,
    [
      resolve("build/cli.js"),
      "review",
      command,
      "--db",
      db,
      "--run",
      runId,
      ...args,
    ],
    { encoding: "utf8", timeout: 15_000 },
  );
  assert.equal(result.status, expected, `${command}: ${result.stderr}`);
  return result;
}
try {
  const preview = JSON.parse(
    cli("preview", [
      "--packet",
      resolve(packetPath),
      "--output",
      output,
      ...(draftPath ? ["--draft", resolve(draftPath)] : []),
    ]).stdout,
  );
  assert.equal(preview.status, "awaiting_approval");
  assert.deepEqual(readdirSync(output), []);
  cli("approve", ["--binding", preview.binding]);
  const crash = cli(
    "execute",
    ["--crash-after-effect", "--lease-ms", "200"],
    86,
  );
  let store = new SqliteStore(db);
  const interrupted = store.load("analyst", runId);
  assert.equal(interrupted.outbox.status, "inflight");
  store.close();
  const directories = readdirSync(output);
  assert.equal(directories.length, 1);
  const published = join(output, directories[0]);
  const before = statSync(join(published, "review.md"));
  await new Promise((resolve) => setTimeout(resolve, 250));
  const resumed = JSON.parse(cli("execute").stdout);
  const verification = JSON.parse(cli("verify").stdout);
  store = new SqliteStore(db);
  const final = store.load("analyst", runId);
  store.close();
  const after = statSync(join(published, "review.md"));
  assert.equal(resumed.status, "completed");
  assert.equal(final.outbox.attempts, 1);
  assert.equal(verifyChain(final.events).valid, true);
  assert.equal(after.ino, before.ino);
  assert.equal(after.mtimeMs, before.mtimeMs);
  assert(final.events.some((e) => e.type === "recovery.receipt_verified"));
  const markdown = readFileSync(join(published, "review.md"));
  const json = readFileSync(join(published, "review.json"));
  assert.equal(markdown.toString("utf8"), preview.markdown);
  assert.deepEqual(JSON.parse(json), preview.report);
  const source = JSON.parse(readFileSync(resolve(packetPath), "utf8"));
  const result = {
    schemaVersion: "observed-kev-workflow/v1",
    observedAt: new Date().toISOString(),
    environment: {
      node: process.version,
      platform: process.platform,
      architecture: process.arch,
    },
    approvalMode: "automated-integration-evaluation-not-human-review",
    source: source.source,
    query: source.query,
    documentIds: source.documents.map((d) => d.id),
    evidenceSha256: preview.evidenceSha256,
    draftSha256: preview.draftSha256,
    modelDraft: preview.report.modelDraft
      ? {
          model: preview.report.modelDraft.model,
          provider: preview.report.modelDraft.provider,
          usage: preview.report.modelDraft.usage,
        }
      : null,
    crashExitCode: crash.status,
    interruptedOutboxStatus: interrupted.outbox.status,
    resumedStatus: resumed.status,
    finalVerificationStatus: verification.status,
    publicationCount: readdirSync(output).length,
    dispatchAttempts: final.outbox.attempts,
    originalFileInodePreserved: before.ino === after.ino,
    originalFileMtimePreserved: before.mtimeMs === after.mtimeMs,
    artifactHashes: { "review.md": hash(markdown), "review.json": hash(json) },
    evidenceChain: verifyChain(final.events),
    eventTypes: final.events.map((e) => e.type),
    applicability: "unconfirmed",
    scansPerformed: 0,
    patchesApplied: 0,
  };
  mkdirSync(reportDir, { recursive: true });
  writeFileSync(join(reportDir, "review.md"), markdown);
  writeFileSync(join(reportDir, "review.json"), json);
  writeFileSync(
    join(reportDir, "observed-delivery.json"),
    JSON.stringify(result, null, 2) + "\n",
  );
  console.log(JSON.stringify(result, null, 2));
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
