import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createRun, transition, DEFAULT_TOOL } from "../build/core.js";
import { SqliteStore } from "../build/sqlite.js";
import { apply } from "../build/worker.js";
export const operator = { tenant: "demo", id: "operator", role: "operator" };
export const worker = { tenant: "demo", id: "worker", role: "worker" };
export const reviewer = { tenant: "demo", id: "reviewer", role: "reviewer" };
export function proposal(options = {}) {
  let s = createRun(
    "r1",
    operator,
    1000,
    undefined,
    options.policy,
    options.tool,
  );
  for (let i = 0; i < 3; i++)
    s = transition(s, { type: "step" }, worker, 1001 + i);
  return s;
}
export function approved(options) {
  return transition(proposal(options), { type: "approve" }, reviewer, 1010);
}
export const receipt = (s) => ({
  tenant: s.tenant,
  key: s.outbox.action.key,
  payloadDigest: s.outbox.action.payloadDigest,
  ticketId: "syn-test-1",
});
export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
export async function workspace() {
  const dir = await mkdtemp(join(tmpdir(), "agent-runtime-"));
  return {
    dir,
    db: join(dir, "runs.sqlite"),
    external: join(dir, "tickets.sqlite"),
    cleanup: () => rm(dir, { recursive: true, force: true }),
  };
}
export function seed(db, idempotent = true) {
  const s = new SqliteStore(db);
  s.create(
    createRun("r1", operator, Date.now(), undefined, undefined, {
      ...DEFAULT_TOOL,
      idempotent,
    }),
  );
  for (let i = 0; i < 3; i++) apply(s, "demo", "r1", worker, { type: "step" });
  apply(s, "demo", "r1", reviewer, { type: "approve" });
  s.close();
}
export function child(args) {
  const p = spawn(process.execPath, [resolve("build/cli.js"), ...args], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "",
    stderr = "";
  p.stdout.on("data", (d) => (stdout += d));
  p.stderr.on("data", (d) => (stderr += d));
  return {
    process: p,
    done: once(p, "exit").then(([code, signal]) => ({
      code,
      signal,
      stdout,
      stderr,
    })),
  };
}
export async function fixture(path, delayMs = 0) {
  const c = child(["serve", "--db", path, "--delay-ms", String(delayMs)]);
  const line = await new Promise((resolve, reject) => {
    let text = "";
    const timer = setTimeout(
      () => reject(new Error("Fixture startup timed out")),
      5000,
    );
    c.process.stdout.on("data", (d) => {
      text += d;
      if (text.includes("\n")) {
        clearTimeout(timer);
        resolve(text.split("\n")[0]);
      }
    });
    c.process.once("exit", () => {
      clearTimeout(timer);
      reject(new Error("Fixture exited before startup"));
    });
  });
  return {
    url: JSON.parse(line).url,
    stop: async () => {
      c.process.kill("SIGTERM");
      await c.done;
    },
  };
}
export function workerChild(db, url, extra = []) {
  return child([
    "step",
    "--db",
    db,
    "--run",
    "r1",
    "--connector",
    url,
    ...extra,
  ]);
}
