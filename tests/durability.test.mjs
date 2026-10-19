import test from "node:test";
import assert from "node:assert/strict";
import { SqliteStore } from "../build/sqlite.js";
import { TicketStore, httpConnector } from "../build/connector.js";
import { createRun, transition, verifyChain } from "../build/core.js";
import { apply } from "../build/worker.js";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createServer } from "node:http";
import {
  workspace,
  seed,
  fixture,
  workerChild,
  sleep,
  operator,
  reviewer,
  worker,
} from "./helpers.mjs";

test("SQLite snapshot, event log, and outbox survive connection restart", async () => {
  const w = await workspace();
  try {
    seed(w.db);
    const s = new SqliteStore(w.db);
    const run = s.load("demo", "r1");
    assert.equal(run.outbox.status, "pending");
    assert.equal(
      s.db.prepare("SELECT count(*) n FROM events").get().n,
      run.events.length,
    );
    assert.equal(s.db.prepare("SELECT count(*) n FROM outbox").get().n, 1);
    assert.throws(() => s.load("other-tenant", "r1"), /not found/);
    s.close();
  } finally {
    await w.cleanup();
  }
});
test("expired fencing token cannot renew, commit, or release the new owner", async () => {
  const w = await workspace();
  const s = new SqliteStore(w.db);
  try {
    s.create(createRun("r1", operator, 1000));
    const a = s.acquire("demo", "r1", "a", 1000, 50);
    const before = s.load("demo", "r1");
    const next = transition(before, { type: "step" }, worker, 1051);
    assert.throws(() => s.renew(a, 1051), /STALE/);
    const b = s.acquire("demo", "r1", "b", 1051, 1000);
    assert.throws(() => s.commit(a, before.revision, next, 1052), /STALE/);
    s.release(a);
    s.assertLease(b, 1052);
    s.commit(b, before.revision, next, 1052);
    assert.throws(() => s.commit(b, before.revision, next, 1053), /REVISION/);
  } finally {
    s.close();
    await w.cleanup();
  }
});
test("append-only SQL triggers prevent rewriting evidence records", async () => {
  const w = await workspace();
  const s = new SqliteStore(w.db);
  try {
    s.create(createRun("r1", operator, 1000));
    assert.throws(
      () => s.db.exec("UPDATE events SET record='{}'"),
      /append-only/,
    );
    assert.throws(() => s.db.exec("DELETE FROM events"), /append-only/);
  } finally {
    s.close();
    await w.cleanup();
  }
});
test("snapshot/outbox corruption is detected on read", async () => {
  const w = await workspace();
  try {
    seed(w.db);
    const s = new SqliteStore(w.db);
    s.db.exec("UPDATE outbox SET record='null'");
    assert.throws(() => s.load("demo", "r1"), /outbox/);
    s.close();
  } finally {
    await w.cleanup();
  }
});
test("actual worker process exits after remote HTTP commit; restart records one existing effect", async () => {
  const w = await workspace();
  let f;
  try {
    seed(w.db);
    f = await fixture(w.external);
    const crashed = await workerChild(w.db, f.url, [
      "--crash-after-effect",
      "--lease-ms",
      "300",
    ]).done;
    assert.equal(crashed.code, 86, crashed.stderr);
    let s = new SqliteStore(w.db);
    assert.equal(s.load("demo", "r1").outbox.status, "inflight");
    s.close();
    await sleep(350);
    const recovered = await workerChild(w.db, f.url).done;
    assert.equal(recovered.code, 0, recovered.stderr);
    const completed = await workerChild(w.db, f.url).done;
    assert.equal(completed.code, 0, completed.stderr);
    s = new SqliteStore(w.db);
    const result = s.load("demo", "r1");
    assert.equal(result.status, "completed");
    assert.equal(result.outbox.attempts, 1);
    assert(result.events.some((e) => e.type === "recovery.receipt_verified"));
    assert.equal(verifyChain(result.events).valid, true);
    s.close();
    assert.equal((await (await fetch(f.url + "/health")).json()).effects, 1);
  } finally {
    await f?.stop();
    await w.cleanup();
  }
});
test("remote acknowledgement loss leaves inflight evidence and recovery does not duplicate", async () => {
  const w = await workspace();
  let f;
  try {
    seed(w.db);
    f = await fixture(w.external);
    const lost = await workerChild(w.db, f.url, ["--drop-ack"]).done;
    assert.equal(lost.code, 1);
    const recovered = await workerChild(w.db, f.url).done;
    assert.equal(recovered.code, 0, recovered.stderr);
    assert.equal((await (await fetch(f.url + "/health")).json()).effects, 1);
    const s = new SqliteStore(w.db);
    assert.equal(s.load("demo", "r1").outbox.status, "delivered");
    s.close();
  } finally {
    await f?.stop();
    await w.cleanup();
  }
});
test("two separate workers compete over one persisted lease; only one effect is dispatched", async () => {
  const w = await workspace();
  let f;
  try {
    seed(w.db);
    f = await fixture(w.external, 600);
    const a = workerChild(w.db, f.url, ["--owner", "worker-a"]);
    const b = workerChild(w.db, f.url, ["--owner", "worker-b"]);
    const results = await Promise.all([a.done, b.done]);
    assert.equal(
      results.filter((r) => r.code === 0).length,
      1,
      JSON.stringify(results),
    );
    assert(results.some((r) => r.stderr.includes("LEASE_BUSY")));
    assert.equal((await (await fetch(f.url + "/health")).json()).effects, 1);
  } finally {
    await f?.stop();
    await w.cleanup();
  }
});
test("non-idempotent crash halts automatic recovery until an independent reviewer reconciles", async () => {
  const w = await workspace();
  let f;
  try {
    seed(w.db, false);
    f = await fixture(w.external);
    assert.equal(
      (
        await workerChild(w.db, f.url, [
          "--crash-after-effect",
          "--lease-ms",
          "300",
        ]).done
      ).code,
      86,
    );
    await sleep(350);
    assert.equal((await workerChild(w.db, f.url).done).code, 0);
    const blocked = await workerChild(w.db, f.url).done;
    assert.equal(blocked.code, 1);
    assert(blocked.stderr.includes("reconcile"));
    const s = new SqliteStore(w.db);
    const state = s.load("demo", "r1");
    assert.equal(state.status, "unknown");
    const proof = await httpConnector(f.url).lookup(state.outbox.action);
    apply(s, "demo", "r1", reviewer, { type: "reconcile", receipt: proof });
    assert.equal(s.load("demo", "r1").outbox.status, "delivered");
    s.close();
    assert.equal((await (await fetch(f.url + "/health")).json()).effects, 1);
  } finally {
    await f?.stop();
    await w.cleanup();
  }
});
test("synthetic connector rejects idempotency-key reuse with a different valid payload", () => {
  const store = new TicketStore(":memory:");
  try {
    let s = createRun("r1", operator, 1000);
    for (let i = 0; i < 3; i++)
      s = transition(s, { type: "step" }, worker, 1001 + i);
    const a = s.proposal;
    store.create(a);
    let changed = transition(
      s,
      { type: "edit", title: "Different payload" },
      operator,
      1010,
    ).proposal;
    changed = { ...changed, key: a.key };
    assert.throws(() => store.create(changed), /IDEMPOTENCY_CONFLICT/);
    assert.equal(store.count(), 1);
  } finally {
    store.close();
  }
});
test("SQLite checks lease expiry after waiting for a competing writer lock", async () => {
  const w = await workspace();
  let s;
  try {
    seed(w.db);
    s = new SqliteStore(w.db);
    const lease = s.acquire("demo", "r1", "waiting-worker", Date.now, 400);
    const p = spawn(process.execPath, ["scripts/hold-lock.mjs", w.db, "550"], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    await once(p.stdout, "data");
    const previous = s.load("demo", "r1");
    assert.throws(
      () => s.update(lease, previous.revision, worker, { type: "dispatch" }),
      /STALE_LEASE/,
    );
    assert.equal(s.load("demo", "r1").outbox.status, "pending");
  } finally {
    s?.close();
    await w.cleanup();
  }
});
test("an event insertion failure rolls back snapshot and outbox in the same transaction", async () => {
  const w = await workspace();
  let s;
  try {
    seed(w.db);
    s = new SqliteStore(w.db);
    const previous = s.load("demo", "r1");
    s.db.exec(
      "CREATE TRIGGER fault_events BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'injected disk failure'); END;",
    );
    assert.throws(
      () => apply(s, "demo", "r1", worker, { type: "dispatch" }),
      /injected/,
    );
    const after = s.load("demo", "r1");
    assert.deepEqual(after, previous);
    assert.equal(after.outbox.status, "pending");
  } finally {
    s?.close();
    await w.cleanup();
  }
});
test("restart after admission before HTTP write retries the stable key and produces one effect", async () => {
  const w = await workspace();
  let f;
  try {
    seed(w.db);
    const s = new SqliteStore(w.db);
    const pending = s.load("demo", "r1");
    apply(s, "demo", "r1", worker, { type: "dispatch" });
    s.close();
    f = await fixture(w.external);
    const recovered = await workerChild(w.db, f.url).done;
    assert.equal(recovered.code, 0, recovered.stderr);
    const retry = await workerChild(w.db, f.url).done;
    assert.equal(retry.code, 0, retry.stderr);
    const restored = new SqliteStore(w.db);
    const after = restored.load("demo", "r1");
    assert.equal(after.outbox.action.key, pending.outbox.action.key);
    assert.equal(after.outbox.attempts, 2);
    assert.equal(after.spent, 5);
    restored.close();
    assert.equal((await (await fetch(f.url + "/health")).json()).effects, 1);
  } finally {
    await f?.stop();
    await w.cleanup();
  }
});
test("bounded connector response reader cancels oversized and malformed UTF-8 bodies", async () => {
  for (const payload of [Buffer.alloc(40_000, "x"), Buffer.from([0xff])]) {
    const server = createServer((_req, res) => res.end(payload));
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      await assert.rejects(
        httpConnector(`http://127.0.0.1:${server.address().port}`).lookup({
          tenant: "demo",
          key: "x",
        }),
        /bound|encoded/,
      );
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  }
});
test("integrity reads use one database snapshot while another connection commits", async () => {
  const w = await workspace();
  let reader, writer;
  try {
    seed(w.db);
    reader = new SqliteStore(w.db);
    writer = new SqliteStore(w.db);
    const before = reader.load("demo", "r1");
    const prepare = reader.db.prepare.bind(reader.db);
    let injected = false;
    reader.db.prepare = (sql) => {
      const statement = prepare(sql);
      if (!injected && sql.startsWith("SELECT snapshot,digest")) {
        return {
          get(...args) {
            const row = statement.get(...args);
            injected = true;
            apply(writer, "demo", "r1", worker, { type: "dispatch" });
            return row;
          },
        };
      }
      return statement;
    };
    assert.deepEqual(reader.load("demo", "r1"), before);
    assert.equal(reader.load("demo", "r1").outbox.status, "inflight");
  } finally {
    reader?.close();
    writer?.close();
    await w.cleanup();
  }
});
