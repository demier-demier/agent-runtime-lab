import {
  assertCommit,
  canonical,
  digest,
  invariant,
  transition,
  verifyChain,
  type Action,
  type Command,
  type Principal,
  type Receipt,
  type Run,
} from "./core.js";
interface Row {
  state: Run;
  owner: string | null;
  fence: number;
  expires: number;
}
export interface BrowserLease {
  key: string;
  owner: string;
  fence: number;
}
const scope = (run: Run) => `${run.tenant}/${run.id}`;
export class BrowserStore {
  constructor(readonly db: IDBDatabase) {}
  static open(name = "agent-runtime-lab-v1"): Promise<BrowserStore> {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(name, 1);
      req.onupgradeneeded = () => {
        for (const key of ["runs", "events", "outbox", "effects", "meta"])
          req.result.createObjectStore(key);
      };
      req.onsuccess = () => resolve(new BrowserStore(req.result));
      req.onerror = () => reject(req.error);
    });
  }
  private transaction<T>(
    stores: string[],
    action: (tx: IDBTransaction, done: (result: T) => void) => void,
    mode: IDBTransactionMode = "readwrite",
  ): Promise<T> {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(stores, mode);
      let result: T;
      let failure: Error | null = null;
      tx.oncomplete = () => resolve(result);
      tx.onerror = () => reject(failure ?? tx.error);
      tx.onabort = () =>
        reject(
          failure ??
            (tx as IDBTransaction & { userError?: Error }).userError ??
            tx.error ??
            new Error(
              "IndexedDB transaction rejected; a competing tab may hold the lease.",
            ),
        );
      try {
        action(tx, (value) => (result = value));
      } catch (e) {
        failure = e as Error;
        tx.abort();
      }
    });
  }
  private write(tx: IDBTransaction, row: Row, previous?: Run) {
    if (previous) assertCommit(previous, row.state);
    const key = scope(row.state);
    tx.objectStore("runs").put(row, key);
    for (const event of row.state.events.slice(previous?.events.length ?? 0))
      tx.objectStore("events").add(
        event,
        `${key}/${String(event.seq).padStart(4, "0")}`,
      );
    if (row.state.outbox) tx.objectStore("outbox").put(row.state.outbox, key);
    else tx.objectStore("outbox").delete(key);
  }
  /** New run explicitly clears this demo's prior browser data. */
  reset(run: Run) {
    return this.transaction<void>(
      ["runs", "events", "outbox", "effects", "meta"],
      (tx) => {
        for (const name of ["runs", "events", "outbox", "effects", "meta"])
          tx.objectStore(name).clear();
        this.write(tx, { state: run, owner: null, fence: 0, expires: 0 });
        tx.objectStore("meta").put(scope(run), "active");
      },
    );
  }
  active(): Promise<Run | null> {
    return this.transaction(
      ["runs", "events", "outbox", "meta"],
      (tx, done) => {
        const req = tx.objectStore("meta").get("active");
        req.onsuccess = () => {
          if (!req.result) return done(null);
          const key = req.result;
          const row = tx.objectStore("runs").get(key);
          row.onsuccess = () => {
            const state = (row.result as Row)?.state;
            if (!state) return done(null);
            const events = tx
              .objectStore("events")
              .getAll(IDBKeyRange.bound(`${key}/`, `${key}/\uffff`));
            const outbox = tx.objectStore("outbox").get(key);
            outbox.onsuccess = () => {
              try {
                invariant(
                  verifyChain(state.events).valid &&
                    canonical(events.result) === canonical(state.events) &&
                    canonical(outbox.result ?? null) ===
                      canonical(state.outbox),
                  "Browser persistence integrity check failed",
                );
                done(state);
              } catch {
                tx.abort();
              }
            };
          };
        };
      },
      "readonly",
    );
  }
  acquire(run: Run, owner: string, clock = Date.now): Promise<BrowserLease> {
    return this.transaction(["runs"], (tx, done) => {
      const key = scope(run);
      const req = tx.objectStore("runs").get(key);
      req.onsuccess = () => {
        const row = req.result as Row;
        const now = clock();
        if (!row || row.expires > now) return tx.abort();
        row.owner = owner;
        row.fence++;
        row.expires = now + 5000;
        tx.objectStore("runs").put(row, key);
        done({ key, owner, fence: row.fence });
      };
    });
  }
  update(
    lease: BrowserLease,
    expectedRevision: number,
    actor: Principal,
    command: Command,
    clock = Date.now,
  ): Promise<Run> {
    return this.transaction(["runs", "events", "outbox"], (tx, done) => {
      const req = tx.objectStore("runs").get(lease.key);
      req.onsuccess = () => {
        try {
          const row = req.result as Row;
          const now = clock();
          invariant(
            row &&
              row.owner === lease.owner &&
              row.fence === lease.fence &&
              row.expires > now,
            "Stale browser lease",
          );
          invariant(
            row.state.revision === expectedRevision,
            "Browser revision conflict",
          );
          const previous = row.state;
          const next = transition(previous, command, actor, now);
          this.write(tx, { ...row, state: next }, previous);
          done(next);
        } catch (error) {
          (tx as IDBTransaction & { userError?: Error }).userError =
            error as Error;
          tx.abort();
        }
      };
    });
  }
  release(lease: BrowserLease) {
    return this.transaction<void>(["runs"], (tx) => {
      const req = tx.objectStore("runs").get(lease.key);
      req.onsuccess = () => {
        const row = req.result as Row;
        if (row && row.owner === lease.owner && row.fence === lease.fence) {
          row.owner = null;
          row.expires = 0;
          tx.objectStore("runs").put(row, lease.key);
        }
      };
    });
  }
  effect(action: Action): Promise<Receipt> {
    return this.transaction(["effects"], (tx, done) => {
      const key = `${action.tenant}/${action.key}`;
      const req = tx.objectStore("effects").get(key);
      req.onsuccess = () => {
        const existing = req.result as Receipt | undefined;
        if (existing && existing.payloadDigest !== action.payloadDigest)
          return tx.abort();
        if (existing && action.tool.idempotent) return done(existing);
        const receipt = {
          tenant: action.tenant,
          key: action.key,
          payloadDigest: action.payloadDigest,
          ticketId: `syn-${crypto.randomUUID()}`,
        };
        // Separate transaction from the run checkpoint creates a genuine browser interruption window.
        tx.objectStore("effects").put(
          receipt,
          action.tool.idempotent ? key : `${key}/${receipt.ticketId}`,
        );
        done(receipt);
      };
    });
  }
  effects(): Promise<Receipt[]> {
    return this.transaction(
      ["effects"],
      (tx, done) => {
        const req = tx.objectStore("effects").getAll();
        req.onsuccess = () => done(req.result);
      },
      "readonly",
    );
  }
  async lookup(action: Action): Promise<Receipt | null> {
    const matches = (await this.effects()).filter(
      (r) => r.tenant === action.tenant && r.key === action.key,
    );
    invariant(
      matches.length <= 1,
      "Ambiguous browser evidence requires investigation",
    );
    if (matches[0])
      invariant(
        matches[0].payloadDigest === action.payloadDigest,
        "Payload digest mismatch",
      );
    return matches[0] ?? null;
  }
  close() {
    this.db.close();
  }
}
