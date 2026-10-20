import {
  canonical,
  invariant,
  type Command,
  type Principal,
  type Run,
} from "./core.js";
import { SqliteStore, type Lease } from "./sqlite.js";
import type { Connector } from "./connector.js";
export interface WorkerOptions {
  owner: string;
  now?: () => number;
  leaseMs?: number;
  afterEffect?: () => void;
}
export function apply(
  store: SqliteStore,
  tenant: string,
  id: string,
  actor: Principal,
  command: Command,
  clock: number | (() => number) = Date.now,
): Run {
  const lease = store.acquire(
    tenant,
    id,
    `${actor.id}-${crypto.randomUUID()}`,
    clock,
  );
  try {
    const previous = store.load(tenant, id);
    return store.update(lease, previous.revision, actor, command, clock);
  } finally {
    store.release(lease);
  }
}
/** One durable unit of progress. Network I/O is outside the SQLite transaction. */
export async function tick(
  store: SqliteStore,
  tenant: string,
  id: string,
  connector: Connector,
  options: WorkerOptions,
): Promise<Run> {
  const now = options.now ?? Date.now;
  const lease: Lease = store.acquire(
    tenant,
    id,
    options.owner,
    now,
    options.leaseMs ?? 5000,
  );
  const actor: Principal = { tenant, id: options.owner, role: "worker" };
  let state = store.load(tenant, id);
  const commit = (cmd: Command) => {
    state = store.update(lease, state.revision, actor, cmd, now);
  };
  try {
    if (state.outbox?.status === "inflight") {
      const receipt = state.outbox.action.tool.idempotent
        ? await connector.lookup(state.outbox.action)
        : null;
      commit({ type: "recover", receipt });
      return state;
    }
    if (state.outbox?.status === "pending") {
      commit({ type: "dispatch" });
      if ((state as Run).outbox?.status !== "inflight") return state;
      store.assertLease(lease, now());
      const receipt = await connector.submit(state.outbox.action);
      options.afterEffect?.();
      commit({ type: "complete", receipt });
      return state;
    }
    invariant(
      state.status !== "unknown",
      "Unknown outcome: a reviewer must reconcile remote evidence",
    );
    if (
      state.tool.name === "review.publish" &&
      state.outbox?.status === "delivered"
    ) {
      const observed = await connector.lookup(state.outbox.action);
      invariant(
        observed && canonical(observed) === canonical(state.outbox.receipt),
        "Published review is missing or changed",
      );
    }
    commit({ type: "step" });
    return state;
  } finally {
    store.release(lease);
  }
}
