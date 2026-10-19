import { DatabaseSync } from "node:sqlite";
import {
  assertCommit,
  canonical,
  digest,
  invariant,
  transition,
  verifyChain,
  type Command,
  type Principal,
  type Run,
} from "./core.js";
type Clock = number | (() => number);
const readClock = (clock: Clock) =>
  typeof clock === "number" ? clock : clock();
export interface Lease {
  tenant: string;
  runId: string;
  owner: string;
  fence: number;
  expiresAt: number;
}
export class SqliteStore {
  readonly db: DatabaseSync;
  private transactionActive = false;
  constructor(path: string) {
    this.db = new DatabaseSync(path);
    this.db
      .exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;
      CREATE TABLE IF NOT EXISTS runs(tenant TEXT NOT NULL, id TEXT NOT NULL, revision INTEGER NOT NULL, snapshot TEXT NOT NULL, digest TEXT NOT NULL, owner TEXT, fence INTEGER NOT NULL DEFAULT 0, expires INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(tenant,id)) STRICT;
      CREATE TABLE IF NOT EXISTS events(tenant TEXT NOT NULL, run_id TEXT NOT NULL, seq INTEGER NOT NULL, record TEXT NOT NULL, PRIMARY KEY(tenant,run_id,seq), FOREIGN KEY(tenant,run_id) REFERENCES runs(tenant,id)) STRICT;
      CREATE TABLE IF NOT EXISTS outbox(tenant TEXT NOT NULL, run_id TEXT NOT NULL, action_key TEXT NOT NULL, status TEXT NOT NULL, record TEXT NOT NULL, PRIMARY KEY(tenant,run_id), FOREIGN KEY(tenant,run_id) REFERENCES runs(tenant,id)) STRICT;
      CREATE TRIGGER IF NOT EXISTS immutable_events_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'Evidence is append-only'); END;
      CREATE TRIGGER IF NOT EXISTS immutable_events_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'Evidence is append-only'); END;`);
  }
  transaction<T>(fn: () => T, mode: "write" | "read" = "write"): T {
    this.db.exec(mode === "write" ? "BEGIN IMMEDIATE" : "BEGIN");
    this.transactionActive = true;
    try {
      const result = fn();
      this.db.exec("COMMIT");
      return result;
    } catch (e) {
      this.db.exec("ROLLBACK");
      throw e;
    } finally {
      this.transactionActive = false;
    }
  }
  create(run: Run) {
    invariant(
      run.revision === 0 && verifyChain(run.events).valid,
      "Invalid initial run",
    );
    this.transaction(() => {
      this.db
        .prepare(
          "INSERT INTO runs(tenant,id,revision,snapshot,digest) VALUES(?,?,?,?,?)",
        )
        .run(run.tenant, run.id, run.revision, canonical(run), digest(run));
      for (const e of run.events)
        this.db
          .prepare("INSERT INTO events VALUES(?,?,?,?)")
          .run(run.tenant, run.id, e.seq, canonical(e));
    });
  }
  load(tenant: string, id: string): Run {
    // All consistency reads must see one SQLite snapshot while another worker commits.
    if (!this.transactionActive)
      return this.transaction(() => this.load(tenant, id), "read");
    const row = this.db
      .prepare("SELECT snapshot,digest FROM runs WHERE tenant=? AND id=?")
      .get(tenant, id);
    invariant(row, "Run not found in this tenant");
    const run = JSON.parse(row.snapshot as string) as Run;
    invariant(
      digest(run) === row.digest &&
        run.tenant === tenant &&
        run.id === id &&
        verifyChain(run.events).valid,
      "Stored snapshot integrity check failed",
    );
    const records = this.db
      .prepare(
        "SELECT record FROM events WHERE tenant=? AND run_id=? ORDER BY seq",
      )
      .all(tenant, id)
      .map((r) => JSON.parse(r.record as string));
    invariant(
      canonical(records) === canonical(run.events),
      "Snapshot and durable event log disagree",
    );
    const outbox = this.db
      .prepare("SELECT record FROM outbox WHERE tenant=? AND run_id=?")
      .get(tenant, id);
    invariant(
      canonical(outbox ? JSON.parse(outbox.record as string) : null) ===
        canonical(run.outbox),
      "Snapshot and outbox disagree",
    );
    return run;
  }
  acquire(
    tenant: string,
    runId: string,
    owner: string,
    clock: Clock = Date.now,
    ttlMs = 5000,
  ): Lease {
    invariant(
      Number.isSafeInteger(ttlMs) && ttlMs >= 50 && ttlMs <= 30_000,
      "Invalid lease TTL",
    );
    return this.transaction(() => {
      const now = readClock(clock);
      const row = this.db
        .prepare("SELECT owner,fence,expires FROM runs WHERE tenant=? AND id=?")
        .get(tenant, runId);
      invariant(row, "Run not found");
      invariant(
        Number(row.expires) <= now,
        "LEASE_BUSY: another worker holds the run",
      );
      const lease = {
        tenant,
        runId,
        owner,
        fence: Number(row.fence) + 1,
        expiresAt: now + ttlMs,
      };
      this.db
        .prepare(
          "UPDATE runs SET owner=?,fence=?,expires=? WHERE tenant=? AND id=?",
        )
        .run(owner, lease.fence, lease.expiresAt, tenant, runId);
      return lease;
    });
  }
  assertLease(lease: Lease, now: number) {
    const row = this.db
      .prepare("SELECT owner,fence,expires FROM runs WHERE tenant=? AND id=?")
      .get(lease.tenant, lease.runId);
    invariant(
      row &&
        row.owner === lease.owner &&
        Number(row.fence) === lease.fence &&
        Number(row.expires) > now,
      "STALE_LEASE: fencing token or expiry rejected",
    );
  }
  renew(lease: Lease, clock: Clock = Date.now, ttlMs = 5000): Lease {
    invariant(
      Number.isSafeInteger(ttlMs) && ttlMs >= 50 && ttlMs <= 30_000,
      "Invalid lease TTL",
    );
    return this.transaction(() => {
      const now = readClock(clock);
      this.assertLease(lease, now);
      const next = { ...lease, expiresAt: now + ttlMs };
      this.db
        .prepare(
          "UPDATE runs SET expires=? WHERE tenant=? AND id=? AND fence=?",
        )
        .run(next.expiresAt, lease.tenant, lease.runId, lease.fence);
      return next;
    });
  }
  private write(
    lease: Lease,
    expectedRevision: number,
    previous: Run,
    next: Run,
  ) {
    invariant(previous.revision === expectedRevision, "REVISION_CONFLICT");
    assertCommit(previous, next);
    const changed = this.db
      .prepare(
        "UPDATE runs SET revision=?,snapshot=?,digest=? WHERE tenant=? AND id=? AND revision=? AND fence=?",
      )
      .run(
        next.revision,
        canonical(next),
        digest(next),
        lease.tenant,
        lease.runId,
        expectedRevision,
        lease.fence,
      );
    invariant(Number(changed.changes) === 1, "REVISION_CONFLICT");
    for (const e of next.events.slice(previous.events.length))
      this.db
        .prepare("INSERT INTO events VALUES(?,?,?,?)")
        .run(next.tenant, next.id, e.seq, canonical(e));
    if (next.outbox)
      this.db
        .prepare(
          "INSERT INTO outbox VALUES(?,?,?,?,?) ON CONFLICT(tenant,run_id) DO UPDATE SET action_key=excluded.action_key,status=excluded.status,record=excluded.record",
        )
        .run(
          next.tenant,
          next.id,
          next.outbox.action.key,
          next.outbox.status,
          canonical(next.outbox),
        );
    else
      this.db
        .prepare("DELETE FROM outbox WHERE tenant=? AND run_id=?")
        .run(next.tenant, next.id);
  }
  commit(
    lease: Lease,
    expectedRevision: number,
    next: Run,
    clock: Clock = Date.now,
  ) {
    this.transaction(() => {
      this.assertLease(lease, readClock(clock));
      this.write(
        lease,
        expectedRevision,
        this.load(lease.tenant, lease.runId),
        next,
      );
    });
  }
  /** Authorization time is read after acquiring SQLite's write lock. */
  update(
    lease: Lease,
    expectedRevision: number,
    actor: Principal,
    command: Command,
    clock: Clock = Date.now,
  ): Run {
    return this.transaction(() => {
      const now = readClock(clock);
      this.assertLease(lease, now);
      const previous = this.load(lease.tenant, lease.runId);
      invariant(previous.revision === expectedRevision, "REVISION_CONFLICT");
      const next = transition(previous, command, actor, now);
      this.write(lease, expectedRevision, previous, next);
      return next;
    });
  }
  release(lease: Lease) {
    this.db
      .prepare(
        "UPDATE runs SET owner=NULL,expires=0 WHERE tenant=? AND id=? AND owner=? AND fence=?",
      )
      .run(lease.tenant, lease.runId, lease.owner, lease.fence);
  }
  close() {
    this.db.close();
  }
}
