import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { platform, arch } from "node:os";
import { performance } from "node:perf_hooks";
import { SqliteStore } from "../build/sqlite.js";
import { httpConnector } from "../build/connector.js";
import { apply } from "../build/worker.js";
import { verifyChain } from "../build/core.js";
import {
  workspace,
  seed,
  fixture,
  workerChild,
  sleep,
  reviewer,
  worker,
} from "../tests/helpers.mjs";

const results = [];
for (const scenario of [
  "crash-after-remote-commit",
  "lost-http-acknowledgement",
  "restart-before-http-write",
  "non-idempotent-unknown",
  "competing-workers",
]) {
  const work = await workspace();
  let remote;
  const started = performance.now();
  const exits = [];
  try {
    seed(work.db, scenario !== "non-idempotent-unknown");
    remote = await fixture(
      work.external,
      scenario === "competing-workers" ? 600 : 0,
    );
    let observedUnknown = false;
    if (
      scenario === "crash-after-remote-commit" ||
      scenario === "non-idempotent-unknown"
    ) {
      const stopped = await workerChild(work.db, remote.url, [
        "--crash-after-effect",
        "--lease-ms",
        "300",
      ]).done;
      exits.push(stopped.code);
      assert.equal(stopped.code, 86);
      await sleep(350);
    } else if (scenario === "lost-http-acknowledgement") {
      const lost = await workerChild(work.db, remote.url, ["--drop-ack"]).done;
      exits.push(lost.code);
      assert.equal(lost.code, 1);
    } else if (scenario === "restart-before-http-write") {
      const store = new SqliteStore(work.db);
      apply(store, "demo", "r1", worker, { type: "dispatch" });
      store.close();
    } else {
      const workers = await Promise.all([
        workerChild(work.db, remote.url, ["--owner", "worker-a"]).done,
        workerChild(work.db, remote.url, ["--owner", "worker-b"]).done,
      ]);
      exits.push(...workers.map((w) => w.code));
      assert.equal(workers.filter((w) => w.code === 0).length, 1);
      assert(workers.some((w) => w.stderr.includes("LEASE_BUSY")));
    }
    if (scenario !== "competing-workers") {
      const recovery = await workerChild(work.db, remote.url).done;
      exits.push(recovery.code);
      assert.equal(recovery.code, 0, recovery.stderr);
    }
    if (scenario === "non-idempotent-unknown") {
      const store = new SqliteStore(work.db);
      const state = store.load("demo", "r1");
      assert.equal(state.status, "unknown");
      observedUnknown = true;
      const blocked = await workerChild(work.db, remote.url).done;
      exits.push(blocked.code);
      assert.equal(blocked.code, 1);
      const receipt = await httpConnector(remote.url).lookup(
        state.outbox.action,
      );
      apply(store, "demo", "r1", reviewer, { type: "reconcile", receipt });
      store.close();
    }
    for (let i = 0; i < 2; i++) {
      const store = new SqliteStore(work.db);
      const state = store.load("demo", "r1");
      store.close();
      if (state.status === "completed") break;
      const progressed = await workerChild(work.db, remote.url).done;
      exits.push(progressed.code);
      assert.equal(progressed.code, 0, progressed.stderr);
    }
    const store = new SqliteStore(work.db);
    const run = store.load("demo", "r1");
    store.close();
    const effects = (await (await fetch(remote.url + "/health")).json())
      .effects;
    assert.equal(run.status, "completed");
    assert.equal(effects, 1);
    assert.equal(verifyChain(run.events).valid, true);
    results.push({
      scenario,
      passed: true,
      observed: {
        status: run.status,
        remoteEffects: effects,
        dispatchAttempts: run.outbox.attempts,
        executionUnits: run.spent,
        observedUnknown,
        processExitCodes: exits,
        elapsedMs: Math.round(performance.now() - started),
        integrity: verifyChain(run.events),
      },
      evidence: run.events,
    });
    console.log(
      `${scenario}: PASS · ${effects} durable remote effect · ${run.outbox.attempts} dispatch attempt(s)`,
    );
  } finally {
    await remote?.stop();
    await work.cleanup();
  }
}
const report = {
  format: "agent-runtime-observed-fault-matrix-v1",
  generatedAt: new Date().toISOString(),
  environment: {
    node: process.version,
    platform: platform(),
    architecture: arch(),
  },
  scope:
    "Observed local synthetic HTTP connector / separate SQLite database / separate worker processes. Durations are one local run, not a performance benchmark. No LLM, tokens, money, or production reliability claim.",
  results,
};
await mkdir("artifacts", { recursive: true });
await writeFile(
  "artifacts/observed-fault-matrix.json",
  JSON.stringify(report, null, 2) + "\n",
);
console.log("Saved artifacts/observed-fault-matrix.json");
