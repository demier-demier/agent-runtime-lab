import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { createRun, DEFAULT_TOOL, verifyChain } from "./core.js";
import { SqliteStore } from "./sqlite.js";
import { TicketStore, serveTickets, httpConnector } from "./connector.js";
import { apply, tick } from "./worker.js";

const [command = "help", ...args] = process.argv.slice(2);
const option = (name: string, fallback: string) => {
  const i = args.indexOf(`--${name}`);
  return i < 0 ? fallback : (args[i + 1] ?? fallback);
};
const db = resolve(option("db", ".runtime/runs.sqlite"));
const tenant = option("tenant", "demo");
const id = option("run", "research-demo");
const actor = (role: "reviewer" | "operator") => ({ tenant, id: role, role });
try {
  if (command === "serve") {
    const path = resolve(option("db", ".runtime/remote-tickets.sqlite"));
    mkdirSync(dirname(path), { recursive: true });
    const tickets = new TicketStore(path);
    const { server, url } = await serveTickets(
      tickets,
      Number(option("port", "0")),
      Number(option("delay-ms", "0")),
    );
    console.log(JSON.stringify({ url }));
    const close = () =>
      server.close(() => {
        tickets.close();
        process.exit(0);
      });
    process.on("SIGTERM", close);
    process.on("SIGINT", close);
  } else if (command === "help") {
    console.log(
      "Agent Runtime Lab\n  demo\n  init | approve | step | inspect | reconcile --db PATH --run ID --tenant TENANT\n  step --connector http://127.0.0.1:PORT [--crash-after-effect] [--drop-ack]\n  serve --db SEPARATE_TICKET_DB [--port 0]\n  init [--non-idempotent]\nAll identities and tickets are synthetic fixtures.",
    );
  } else if (command === "demo") {
    mkdirSync(dirname(db), { recursive: true });
    const runtime = new SqliteStore(db);
    const tickets = new TicketStore(resolve(".runtime/remote-tickets.sqlite"));
    const { server, url } = await serveTickets(tickets);
    try {
      const runId = `demo-${Date.now()}`;
      runtime.create(createRun(runId, actor("operator"), Date.now()));
      for (let i = 0; i < 3; i++)
        await tick(runtime, tenant, runId, httpConnector(url), {
          owner: "worker-demo",
        });
      apply(runtime, tenant, runId, actor("reviewer"), { type: "approve" });
      await tick(runtime, tenant, runId, httpConnector(url), {
        owner: "worker-demo",
      });
      await tick(runtime, tenant, runId, httpConnector(url), {
        owner: "worker-demo",
      });
      console.log(JSON.stringify(runtime.load(tenant, runId), null, 2));
    } finally {
      server.close();
      tickets.close();
      runtime.close();
    }
  } else {
    mkdirSync(dirname(db), { recursive: true });
    const store = new SqliteStore(db);
    try {
      if (command === "init")
        store.create(
          createRun(id, actor("operator"), Date.now(), undefined, undefined, {
            ...DEFAULT_TOOL,
            idempotent: !args.includes("--non-idempotent"),
          }),
        );
      else if (command === "approve")
        apply(store, tenant, id, actor("reviewer"), { type: "approve" });
      else if (command === "step")
        await tick(
          store,
          tenant,
          id,
          httpConnector(
            option("connector", "http://127.0.0.1:8779"),
            args.includes("--drop-ack"),
          ),
          {
            owner: option("owner", "worker-cli"),
            leaseMs: Number(option("lease-ms", "5000")),
            afterEffect: args.includes("--crash-after-effect")
              ? () => process.exit(86)
              : undefined,
          },
        );
      else if (command === "reconcile") {
        const state = store.load(tenant, id);
        const receipt =
          state.outbox &&
          (await httpConnector(
            option("connector", "http://127.0.0.1:8779"),
          ).lookup(state.outbox.action));
        if (!receipt) throw new Error("No remote receipt to reconcile");
        apply(store, tenant, id, actor("reviewer"), {
          type: "reconcile",
          receipt,
        });
      } else if (command !== "inspect")
        throw new Error("Unknown command; run help");
      const state = store.load(tenant, id);
      console.log(
        JSON.stringify(
          { ...state, integrity: verifyChain(state.events) },
          null,
          2,
        ),
      );
    } finally {
      store.close();
    }
  }
} catch (e) {
  console.error(JSON.stringify({ error: (e as Error).message }));
  process.exitCode = 1;
}
