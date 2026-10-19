import "fake-indexeddb/auto";
import test from "node:test";
import assert from "node:assert/strict";
import { BrowserStore } from "../build/indexeddb.js";
import { createRun, transition } from "../build/core.js";
import { operator, reviewer, worker, approved, receipt } from "./helpers.mjs";

async function open() {
  return BrowserStore.open(`test-${crypto.randomUUID()}`);
}
test("IndexedDB persists the same core transitions and restores after reopen", async () => {
  let store = await open();
  const name = store.db.name;
  try {
    await store.reset(createRun("r1", operator, 1000));
    let state = await store.active();
    const lease = await store.acquire(state, "a", () => 1000);
    state = await store.update(
      lease,
      state.revision,
      worker,
      { type: "step" },
      () => 1001,
    );
    await store.release(lease);
    store.close();
    store = await BrowserStore.open(name);
    assert.deepEqual(await store.active(), state);
  } finally {
    store.close();
  }
});
test("IndexedDB preserves useful core errors and rolls back the state", async () => {
  const store = await open();
  try {
    await store.reset(approved());
    const state = await store.active();
    const lease = await store.acquire(state, "a", () => 1011);
    await assert.rejects(
      store.update(
        lease,
        state.revision,
        reviewer,
        { type: "dispatch" },
        () => 1020,
      ),
      /Role is not authorized/,
    );
    assert.deepEqual(await store.active(), state);
    await store.release(lease);
  } finally {
    store.close();
  }
});
test("competing browser tabs cannot acquire an active lease; stale revision fails", async () => {
  const store = await open();
  try {
    await store.reset(createRun("r1", operator, 1000));
    const state = await store.active();
    const a = await store.acquire(state, "a", () => 1000);
    await assert.rejects(store.acquire(state, "b", () => 1001));
    await store.update(a, 0, worker, { type: "step" }, () => 1002);
    await assert.rejects(
      store.update(a, 0, worker, { type: "step" }, () => 1003),
      /revision/,
    );
    await store.release(a);
  } finally {
    store.close();
  }
});
test("an IndexedDB external effect survives an interrupted checkpoint and is looked up by digest", async () => {
  const store = await open();
  try {
    const inflight = transition(approved(), { type: "dispatch" }, worker, 1020);
    await store.reset(inflight);
    const effect = await store.effect(inflight.outbox.action);
    assert.equal((await store.active()).outbox.status, "inflight");
    assert.equal((await store.effects()).length, 1);
    const proof = await store.lookup(inflight.outbox.action);
    assert.deepEqual(proof, effect);
    assert.deepEqual(await store.effect(inflight.outbox.action), effect);
    assert.equal((await store.effects()).length, 1);
    const lease = await store.acquire(inflight, "a", () => 1030);
    const next = await store.update(
      lease,
      inflight.revision,
      worker,
      { type: "recover", receipt: proof },
      () => 1031,
    );
    assert.equal(next.outbox.status, "delivered");
    await store.release(lease);
  } finally {
    store.close();
  }
});
test("browser lease expiry is checked when its transaction executes", async () => {
  const store = await open();
  try {
    await store.reset(createRun("r1", operator, 1000));
    const state = await store.active();
    const a = await store.acquire(state, "a", () => 1000);
    await assert.rejects(
      store.update(a, 0, worker, { type: "step" }, () => 6000),
      /Stale browser lease/,
    );
    const b = await store.acquire(state, "b", () => 6000);
    await store.release(a);
    const next = await store.update(b, 0, worker, { type: "step" }, () => 6001);
    assert.equal(next.revision, 1);
    await store.release(b);
  } finally {
    store.close();
  }
});
