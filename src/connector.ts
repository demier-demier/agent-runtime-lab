import { DatabaseSync } from "node:sqlite";
import { createServer, type Server } from "node:http";
import { randomUUID } from "node:crypto";
import { digest, invariant, type Action, type Receipt } from "./core.js";

/** A synthetic remote system. Its database must be separate from the runtime database. */
export class TicketStore {
  readonly db: DatabaseSync;
  constructor(path: string) {
    this.db = new DatabaseSync(path);
    this.db
      .exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
    CREATE TABLE IF NOT EXISTS tickets(ticket_id TEXT PRIMARY KEY,tenant TEXT NOT NULL,action_key TEXT NOT NULL,payload_digest TEXT NOT NULL,payload TEXT NOT NULL) STRICT;
    CREATE TABLE IF NOT EXISTS idempotency(tenant TEXT NOT NULL,action_key TEXT NOT NULL,payload_digest TEXT NOT NULL,ticket_id TEXT NOT NULL,PRIMARY KEY(tenant,action_key)) STRICT;`);
  }
  create(action: Action): Receipt {
    invariant(
      action?.tool?.name === "ticket.create" &&
        typeof action.tool.idempotent === "boolean" &&
        /^[a-f0-9]{64}$/.test(action.key),
      "Invalid synthetic action",
    );
    invariant(
      action.payloadDigest ===
        digest({ tenant: action.tenant, tool: action.tool, args: action.args }),
      "Invalid payload digest",
    );
    invariant(
      action.tenant.length <= 64 && action.args.title.length <= 180,
      "Invalid synthetic payload",
    );
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const previous = this.db
        .prepare(
          "SELECT payload_digest FROM tickets WHERE tenant=? AND action_key=?",
        )
        .all(action.tenant, action.key);
      invariant(
        previous.every((row) => row.payload_digest === action.payloadDigest),
        "IDEMPOTENCY_CONFLICT: key reused for a different payload",
      );
      if (action.tool.idempotent) {
        const existing = this.db
          .prepare(
            "SELECT ticket_id,payload_digest FROM idempotency WHERE tenant=? AND action_key=?",
          )
          .get(action.tenant, action.key);
        if (existing) {
          invariant(
            existing.payload_digest === action.payloadDigest,
            "IDEMPOTENCY_CONFLICT: key reused for a different payload",
          );
          this.db.exec("COMMIT");
          return {
            tenant: action.tenant,
            key: action.key,
            payloadDigest: action.payloadDigest,
            ticketId: existing.ticket_id as string,
          };
        }
      }
      const ticketId = `syn-${randomUUID()}`;
      this.db
        .prepare("INSERT INTO tickets VALUES(?,?,?,?,?)")
        .run(
          ticketId,
          action.tenant,
          action.key,
          action.payloadDigest,
          JSON.stringify(action.args),
        );
      if (action.tool.idempotent)
        this.db
          .prepare("INSERT INTO idempotency VALUES(?,?,?,?)")
          .run(action.tenant, action.key, action.payloadDigest, ticketId);
      this.db.exec("COMMIT");
      return {
        tenant: action.tenant,
        key: action.key,
        payloadDigest: action.payloadDigest,
        ticketId,
      };
    } catch (e) {
      this.db.exec("ROLLBACK");
      throw e;
    }
  }
  lookup(tenant: string, key: string): Receipt | null {
    const rows = this.db
      .prepare(
        "SELECT ticket_id,payload_digest FROM tickets WHERE tenant=? AND action_key=?",
      )
      .all(tenant, key);
    invariant(
      rows.length <= 1,
      "Ambiguous remote evidence requires manual investigation",
    );
    return rows[0]
      ? {
          tenant,
          key,
          ticketId: rows[0].ticket_id as string,
          payloadDigest: rows[0].payload_digest as string,
        }
      : null;
  }
  count() {
    return Number(
      this.db.prepare("SELECT count(*) AS n FROM tickets").get()!.n,
    );
  }
  close() {
    this.db.close();
  }
}
export function serveTickets(
  store: TicketStore,
  port = 0,
  responseDelayMs = 0,
): Promise<{ server: Server; url: string }> {
  invariant(
    Number.isSafeInteger(responseDelayMs) &&
      responseDelayMs >= 0 &&
      responseDelayMs <= 1000,
    "Invalid response delay",
  );
  const server = createServer(async (req, res) => {
    res.setHeader("Content-Type", "application/json");
    res.setHeader("Cache-Control", "no-store");
    // This fixture is loopback-only and has no browser CORS support or caller identity service.
    try {
      invariant(
        !req.headers.origin,
        "Browser-origin requests are not accepted",
      );
      const host = String(req.headers.host ?? "");
      invariant(/^127\.0\.0\.1:\d+$/.test(host), "Unexpected Host");
      const url = new URL(req.url!, `http://${host}`);
      if (req.method === "GET" && url.pathname === "/health")
        return void res.end(
          JSON.stringify({ ok: true, effects: store.count() }),
        );
      if (req.method === "GET" && url.pathname === "/lookup")
        return void res.end(
          JSON.stringify(
            store.lookup(
              url.searchParams.get("tenant") ?? "",
              url.searchParams.get("key") ?? "",
            ),
          ),
        );
      invariant(
        req.method === "POST" && url.pathname === "/tickets",
        "Unsupported fixture route",
      );
      let size = 0;
      const chunks: Buffer[] = [];
      for await (const chunk of req) {
        size += chunk.length;
        invariant(size <= 32_768, "Request is too large");
        chunks.push(chunk);
      }
      const body = new TextDecoder("utf-8", { fatal: true }).decode(
        Buffer.concat(chunks),
      );
      const receipt = store.create(JSON.parse(body));
      if (req.headers["x-demo-drop-ack"] === "yes")
        return void req.socket.destroy();
      if (responseDelayMs)
        await new Promise((resolve) => setTimeout(resolve, responseDelayMs));
      res.end(JSON.stringify(receipt));
    } catch (e) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: (e as Error).message }));
    }
  });
  return new Promise((resolve) =>
    server.listen(port, "127.0.0.1", () =>
      resolve({
        server,
        url: `http://127.0.0.1:${(server.address() as { port: number }).port}`,
      }),
    ),
  );
}
export interface Connector {
  submit(action: Action): Promise<Receipt>;
  lookup(action: Action): Promise<Receipt | null>;
}
export function httpConnector(base: string, dropAck = false): Connector {
  const parsed = new URL(base);
  invariant(
    parsed.protocol === "http:" &&
      parsed.hostname === "127.0.0.1" &&
      parsed.pathname === "/" &&
      !parsed.username &&
      !parsed.password &&
      !parsed.search &&
      !parsed.hash,
    "Synthetic connector must be an exact loopback origin",
  );
  const request = async (path: string, init?: RequestInit) => {
    const r = await fetch(new URL(path, base), {
      ...init,
      redirect: "error",
      signal: AbortSignal.timeout(2500),
    });
    invariant(r.ok, `Synthetic connector returned HTTP ${r.status}`);
    invariant(r.body, "Empty connector response");
    const reader = r.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.length;
        invariant(size <= 32_768, "Connector response exceeds bound");
        chunks.push(value);
      }
    } catch (error) {
      await reader.cancel();
      throw error;
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.length;
    }
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  };
  return {
    submit: (action) =>
      request("/tickets", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(dropAck ? { "x-demo-drop-ack": "yes" } : {}),
        },
        body: JSON.stringify(action),
      }),
    lookup: (action) =>
      request(
        `/lookup?tenant=${encodeURIComponent(action.tenant)}&key=${encodeURIComponent(action.key)}`,
      ),
  };
}
