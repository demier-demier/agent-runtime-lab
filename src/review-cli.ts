import { mkdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { invariant, verifyChain, type Principal, type Run } from "./core.js";
import {
  fileReviewConnector,
  inspectPublication,
  makeReviewRun,
} from "./kev-review.js";
import { SqliteStore } from "./sqlite.js";
import { apply, tick } from "./worker.js";

export async function reviewCli(args: string[]) {
  const [command = "help", ...options] = args;
  const option = (name: string, fallback?: string): string => {
    const i = options.indexOf(`--${name}`);
    if (i < 0) {
      invariant(fallback !== undefined, `Missing --${name}`);
      return fallback;
    }
    invariant(
      options[i + 1] && !options[i + 1].startsWith("--"),
      `Missing value for --${name}`,
    );
    return options[i + 1];
  };
  if (command === "help") {
    console.log(`Public KEV evidence → approved local vulnerability review
  review preview --packet FILE --output DIR --run ID [--draft FILE]
  review approve --run ID --binding EXACT_PREVIEW_BINDING
  review execute --run ID [--crash-after-effect] [--lease-ms 5000]
  review verify --run ID
  review inspect --run ID
Shared: --db PATH (default .runtime/kev.sqlite) --tenant NAME (default analyst)
Preview persists exact Markdown/JSON bytes but does not publish. Approval expires after 5 minutes.
Local CLI role labels are not authenticated identities. No scan, patch or remote write occurs.`);
    return;
  }
  invariant(
    ["preview", "approve", "execute", "verify", "inspect"].includes(command),
    "Unknown review command",
  );
  const db = resolve(option("db", ".runtime/kev.sqlite"));
  const tenant = option("tenant", "analyst");
  const id = option("run");
  const actor = (role: "operator" | "reviewer"): Principal => ({
    tenant,
    id: role,
    role,
  });
  mkdirSync(dirname(db), { recursive: true });
  const store = new SqliteStore(db);
  const connector = fileReviewConnector();
  try {
    if (command === "preview") {
      const parse = (path: string) => {
        const bytes = readFileSync(resolve(path));
        invariant(bytes.byteLength <= 256_000, "Input JSON exceeds 256 KB");
        return JSON.parse(bytes.toString("utf8"));
      };
      const run = makeReviewRun(
        id,
        actor("operator"),
        Date.now(),
        parse(option("packet")),
        option("output"),
        options.includes("--draft") ? parse(option("draft")) : undefined,
      );
      store.create(run);
      for (let n = 0; n < 3; n++)
        await tick(store, tenant, id, connector, { owner: "preview-worker" });
    } else {
      invariant(
        store.load(tenant, id).tool.name === "review.publish",
        "Not a KEV review run",
      );
      if (command === "approve")
        apply(store, tenant, id, actor("reviewer"), {
          type: "approve",
          expectedBinding: option("binding"),
        });
      if (command === "execute") {
        // A resumed process may first reconcile the inflight receipt, then verify.
        for (let n = 0; n < 4; n++) {
          const before = store.load(tenant, id);
          if (before.status === "completed") break;
          invariant(
            !["awaiting_approval", "blocked", "denied", "unknown"].includes(
              before.status,
            ),
            `Cannot execute ${before.status} review; inspect and obtain fresh approval if eligible`,
          );
          await tick(store, tenant, id, connector, {
            owner: option("worker", "review-worker"),
            leaseMs: Number(option("lease-ms", "5000")),
            afterEffect: options.includes("--crash-after-effect")
              ? () => process.exit(86)
              : undefined,
          });
        }
      }
    }
    const state = store.load(tenant, id);
    let observed = null;
    if (command === "verify" || command === "execute") {
      invariant(
        state.status === "completed" && state.outbox?.status === "delivered",
        "Review has not completed",
      );
      observed = inspectPublication(state.outbox.action);
      invariant(observed, "Completed review files are missing");
    }
    console.log(
      JSON.stringify(
        summary(
          state,
          observed,
          command === "preview" || command === "inspect",
        ),
        null,
        2,
      ),
    );
  } finally {
    store.close();
  }
}
function summary(state: Run, publication: unknown, includePreview: boolean) {
  return {
    runId: state.id,
    tenant: state.tenant,
    status: state.status,
    revision: state.revision,
    evidenceSha256: state.plan.review!.evidenceSha256,
    draftSha256: state.plan.review!.draftSha256,
    binding: state.proposal?.binding ?? null,
    outputDirectory: state.plan.review!.outputDirectory,
    approval: state.approval,
    outboxStatus: state.outbox?.status ?? null,
    integrity: verifyChain(state.events),
    publication,
    ...(includePreview
      ? {
          markdown: state.plan.review!.markdown,
          report: JSON.parse(state.plan.review!.json),
        }
      : {}),
  };
}
