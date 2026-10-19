import {
  createRun,
  DEFAULT_POLICY,
  DEFAULT_TOOL,
  fixturePlan,
  transition,
  verifyChain,
  type Command,
  type Principal,
  type Role,
  type Run,
} from "../src/core.js";
import { BrowserStore, type BrowserLease } from "../src/indexeddb.js";
const element = <T extends HTMLElement>(id: string) =>
  document.getElementById(id) as T;
const roleSelect = element<HTMLSelectElement>("role");
let store: BrowserStore;
let state: Run;
let busy = false;
let renderedTitle = "";
const owner = `tab-${crypto.randomUUID()}`;
const principal = (): Principal => ({
  tenant: state.tenant,
  id: `${roleSelect.value}-demo`,
  role: roleSelect.value as Role,
});
function notice(message: string, error = false) {
  const n = element("notice");
  n.textContent = message;
  n.classList.toggle("error", error);
}
function node(tag: string, className: string, text = "") {
  const el = document.createElement(tag);
  el.className = className;
  el.textContent = text;
  return el;
}
function pair(
  container: HTMLElement,
  label: string,
  value: string,
  mono = false,
) {
  const row = node("div", "kv");
  row.append(node("span", "", label), node("span", mono ? "mono" : "", value));
  container.append(row);
}
function messageFor(s: Run) {
  if (s.status === "completed")
    return "Verified. The run completed with one persisted ticket. Export the decision trail or start a different failure scenario.";
  if (s.status === "denied")
    return "The reviewer denied this action. This run is terminal; start a new run to explore another decision.";
  if (s.status === "unknown")
    return "Unknown outcome. Automatic retries are stopped. Switch to Reviewer and reconcile the persisted remote evidence.";
  if (s.status === "awaiting_approval")
    return s.policy.capabilities.length
      ? "Human gate reached. Switch to Reviewer, inspect the exact request, and approve or deny it."
      : "Write capability is revoked. An Operator must restore it before a Reviewer can grant fresh approval.";
  if (s.status === "blocked")
    return "Dispatch blocked. Check the approval expiry and current policy. A fresh independent approval may be required.";
  if (s.outbox?.status === "inflight")
    return "The write was interrupted before checkpointing. Recover will inspect durable evidence instead of blindly repeating it.";
  if (s.outbox?.status === "pending")
    return "Approval persisted and action enqueued. Switch to Worker to execute, or interrupt after the ticket write.";
  if (s.outbox?.status === "delivered")
    return "The receipt is persisted. Execute the verification node to complete the workflow.";
  return "Ready. Execute one step to inspect each transition, or Run to next gate to reach human review.";
}
async function render() {
  element("status").textContent = state.status.replaceAll("_", " ");
  element("budget").textContent = `${state.spent} / ${state.policy.maxCost}`;
  element("events-count").textContent = String(state.events.length);
  element("run-id").textContent =
    `rev ${state.revision} · ${state.id.slice(-8)}`;
  const graph = element("graph");
  graph.replaceChildren();
  const labels: Record<string, string> = {
    research: "Gather evidence",
    propose: "Build proposal",
    ticket: "Create ticket",
    verify: "Verify receipt",
  };
  for (const n of state.plan.nodes) {
    const card = node("div", `node ${state.nodes[n.id]}`);
    card.append(
      node("div", "node-kind", n.kind),
      node("h3", "", labels[n.kind]),
      node("div", "node-status", state.nodes[n.id]),
    );
    graph.append(card);
  }
  const proposal = element("proposal");
  proposal.replaceChildren();
  if (state.proposal) {
    proposal.append(node("div", "action-title", state.proposal.args.title));
    pair(
      proposal,
      "Tool",
      `${state.proposal.tool.name} @ ${state.proposal.tool.version}`,
    );
    pair(proposal, "Priority", state.proposal.args.priority);
    pair(proposal, "Binding", state.proposal.binding.slice(0, 24) + "…", true);
    pair(
      proposal,
      "Approval",
      state.approval
        ? `${state.approval.reviewer} · ${state.approval.expiresAt > Date.now() ? "expires " + new Date(state.approval.expiresAt).toLocaleTimeString() : "EXPIRED"}`
        : "Not approved",
    );
    pair(
      proposal,
      "Policy",
      `revision ${state.policy.revision} · ${state.policy.capabilities.length ? "write allowed" : "write revoked"}`,
    );
  } else
    proposal.append(
      node(
        "p",
        "empty",
        state.findings[0] ??
          "Advance the plan to generate an approval request.",
      ),
    );
  const outbox = element("outbox");
  outbox.replaceChildren();
  if (state.outbox) {
    outbox.append(node("span", "tag", state.outbox.status.toUpperCase()));
    pair(outbox, "Attempts", String(state.outbox.attempts));
    pair(
      outbox,
      "Idempotent",
      state.outbox.action.tool.idempotent
        ? "Yes · stable key + payload digest"
        : "No · unknown outcomes need review",
    );
    pair(outbox, "Key", state.outbox.action.key.slice(0, 24) + "…", true);
    pair(
      outbox,
      "Receipt",
      state.outbox.receipt?.ticketId ?? "Not checkpointed",
      true,
    );
  } else
    outbox.append(
      node(
        "p",
        "empty",
        "No action has been admitted. Approval and enqueue happen in one transaction.",
      ),
    );
  const chain = verifyChain(state.events);
  element("chain").textContent =
    `${chain.valid ? "✓ Hash chain valid" : "✕ Invalid evidence chain"} · ${state.events.length} linked events · head ${chain.head.slice(0, 18)}…`;
  const trace = element("trace");
  trace.replaceChildren();
  for (const e of [...state.events].reverse()) {
    const row = node("div", "trace-row");
    const info = node("div", "");
    info.append(
      node("div", "trace-name", e.type),
      node("div", "trace-data", JSON.stringify(e.data)),
    );
    row.append(
      node("span", "trace-index", String(e.seq).padStart(2, "0")),
      info,
      node("span", "trace-role", e.role),
    );
    trace.append(row);
  }
  const receipts = await store.effects();
  element("effects-count").textContent = String(receipts.length);
  const effects = element("effects");
  effects.replaceChildren();
  if (!receipts.length)
    effects.append(
      node(
        "p",
        "empty",
        "No tickets yet. Approval alone does not create an effect.",
      ),
    );
  for (const receipt of receipts) {
    const card = node("div", "ticket");
    card.append(
      node("strong", "", receipt.ticketId),
      node("div", "mono", `Approved payload digest: ${receipt.payloadDigest}`),
      node(
        "div",
        "mono",
        `Tenant: ${receipt.tenant} · Key: ${receipt.key.slice(0, 24)}…`,
      ),
    );
    effects.append(card);
  }
  element("policy").textContent = state.policy.capabilities.length
    ? "Revoke write capability"
    : "Restore write capability";
  if (renderedTitle !== state.plan.ticket.title) {
    element<HTMLInputElement>("title").value = state.plan.ticket.title;
    renderedTitle = state.plan.ticket.title;
  }
  const terminal = ["completed", "denied"].includes(state.status);
  for (const id of [
    "step",
    "run",
    "approve",
    "deny",
    "crash",
    "recover",
    "reconcile",
    "edit",
    "policy",
    "tool",
    "expire",
  ])
    element<HTMLButtonElement>(id).disabled = busy || terminal;
}
async function withLease(fn: (lease: BrowserLease) => Promise<void>) {
  const lease = await store.acquire(state, owner);
  try {
    await fn(lease);
  } finally {
    await store.release(lease);
  }
}
async function apply(command: Command) {
  await withLease(async (lease) => {
    state = await store.update(lease, state.revision, principal(), command);
  });
}
async function tick(crash = false) {
  await withLease(async (lease) => {
    const save = async (command: Command) => {
      state = await store.update(lease, state.revision, principal(), command);
    };
    if (state.outbox?.status === "inflight") {
      await save({
        type: "recover",
        receipt: state.outbox.action.tool.idempotent
          ? await store.lookup(state.outbox.action)
          : null,
      });
      return;
    }
    if (state.outbox?.status === "pending") {
      await save({ type: "dispatch" });
      if ((state as Run).outbox?.status !== "inflight") return;
      const receipt = await store.effect(state.outbox.action);
      if (!crash) await save({ type: "complete", receipt });
      return;
    }
    if (crash)
      throw new Error(
        "Reach the approval gate and approve the action before injecting an interruption.",
      );
    await save({ type: "step" });
  });
}
async function start() {
  const scenario = element<HTMLSelectElement>("scenario").value;
  state = createRun(
    `run-${crypto.randomUUID()}`,
    { tenant: "demo", id: "operator-demo", role: "operator" },
    Date.now(),
    fixturePlan(),
    { ...DEFAULT_POLICY, maxCost: scenario === "budget" ? 4 : 8 },
    { ...DEFAULT_TOOL, idempotent: scenario !== "uncertain" },
  );
  await store.reset(state);
  roleSelect.value = "worker";
  notice(messageFor(state));
}
function bind(id: string, fn: () => Promise<void>) {
  element(id).addEventListener("click", async () => {
    if (busy) return;
    busy = true;
    try {
      await render();
      await fn();
      notice(messageFor(state));
    } catch (error) {
      const latest = await store.active();
      if (latest) state = latest;
      notice(
        (error as Error)?.message ||
          "Transaction rejected. Check the simulated identity, current gate, or another open tab.",
        true,
      );
    } finally {
      busy = false;
      await render();
    }
  });
}
async function main() {
  store = await BrowserStore.open();
  const saved = await store.active();
  if (saved) {
    state = saved;
    notice(`Restored from IndexedDB. ${messageFor(state)}`);
  } else await start();
  await render();
  bind("new", start);
  bind("step", () => tick());
  bind("run", async () => {
    for (let i = 0; i < 16; i++) {
      if (
        [
          "completed",
          "denied",
          "unknown",
          "awaiting_approval",
          "blocked",
        ].includes(state.status)
      )
        break;
      await tick();
    }
  });
  bind("approve", () => apply({ type: "approve" }));
  bind("deny", () =>
    apply({ type: "deny", reason: "Reviewer declined the synthetic action" }),
  );
  bind("crash", () => tick(true));
  bind("recover", async () => {
    if (state.outbox?.status !== "inflight")
      throw new Error("There is no interrupted dispatch to recover.");
    await tick();
  });
  bind("reconcile", async () => {
    if (state.status !== "unknown" || !state.outbox)
      throw new Error(
        "Reconciliation is only available for an unknown outcome.",
      );
    const receipt = await store.lookup(state.outbox.action);
    if (!receipt)
      throw new Error(
        "No persisted remote evidence was found. Keep this run halted.",
      );
    await apply({ type: "reconcile", receipt });
  });
  bind("policy", () =>
    apply({
      type: "policy",
      policy: {
        ...state.policy,
        revision: state.policy.revision + 1,
        capabilities: state.policy.capabilities.length ? [] : ["tickets:write"],
      },
    }),
  );
  bind("edit", () =>
    apply({ type: "edit", title: element<HTMLInputElement>("title").value }),
  );
  bind("tool", () =>
    apply({
      type: "tool",
      tool: {
        ...state.tool,
        version: `${Number(state.tool.version.split(".")[0]) + 1}.0.0`,
      },
    }),
  );
  bind("expire", () => apply({ type: "expire-approval" }));
  element("verify").addEventListener("click", () => {
    const result = verifyChain(state.events);
    notice(
      `${result.valid ? "Verified" : "Invalid"}: ${state.events.length} linked event records. This detects inconsistency, not a malicious party capable of rewriting and rehashing the whole store.`,
    );
  });
  element("export").addEventListener("click", async () => {
    const report = {
      format: "agent-runtime-browser-run-v1",
      generatedAt: new Date().toISOString(),
      scope:
        "Browser identity and external connector simulation; deterministic synthetic planning; no LLM execution",
      run: state,
      effects: await store.effects(),
      integrity: verifyChain(state.events),
    };
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }),
    );
    const a = document.createElement("a");
    a.href = url;
    a.download = `${state.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });
  document.addEventListener("visibilitychange", async () => {
    if (!document.hidden && !busy) {
      const latest = await store.active();
      if (latest) {
        state = latest;
        await render();
      }
    }
  });
}
main().catch((error) =>
  notice(
    `Browser storage unavailable: ${(error as Error).message}. This demo needs IndexedDB; try a regular browser tab with local storage enabled.`,
    true,
  ),
);
