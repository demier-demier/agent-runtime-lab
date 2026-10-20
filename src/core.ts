import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

export type Json =
  | null
  | boolean
  | number
  | string
  | Json[]
  | { [key: string]: Json };
export type Role = "worker" | "reviewer" | "operator";
export interface Principal {
  tenant: string;
  id: string;
  role: Role;
}
export interface Policy {
  revision: number;
  capabilities: string[];
  maxCost: number;
  maxSteps: number;
  approvalTtlMs: number;
}
export interface Tool {
  name: "ticket.create" | "review.publish";
  version: string;
  capability: "tickets:write" | "reviews:write";
  idempotent: boolean;
  cost: number;
}
/** Exact bytes and destination approved for a local vulnerability review. */
export interface ReviewPayload {
  schemaVersion: "kev-publication/v1";
  evidenceSha256: string;
  draftSha256: string | null;
  outputDirectory: string;
  markdown: string;
  json: string;
}
export type NodeKind = "research" | "propose" | "ticket" | "verify";
export interface PlanNode {
  id: string;
  kind: NodeKind;
  dependsOn: string[];
}
export interface Plan {
  nodes: PlanNode[];
  incident: { service: string; failures: number; windowMinutes: number };
  ticket: { title: string; priority: "normal" | "high" };
  review?: ReviewPayload;
}
export interface Action {
  id: string;
  nodeId: string;
  tenant: string;
  tool: Tool;
  args: {
    title: string;
    priority: string;
    service: string;
    evidence: string[];
    review?: ReviewPayload;
  };
  payloadDigest: string;
  binding: string;
  key: string;
}
export interface Approval {
  binding: string;
  reviewer: string;
  expiresAt: number;
  issuedAt: number;
}
export interface Receipt {
  ticketId: string;
  key: string;
  payloadDigest: string;
  tenant: string;
}
export interface Outbox {
  action: Action;
  status: "pending" | "inflight" | "unknown" | "delivered";
  attempts: number;
  reserved: boolean;
  receipt: Receipt | null;
}
export interface EvidenceEvent {
  seq: number;
  at: number;
  type: string;
  principal: string;
  role: Role;
  data: Json;
  previous: string;
  hash: string;
}
export interface Run {
  schema: 1;
  id: string;
  tenant: string;
  revision: number;
  plan: Plan;
  policy: Policy;
  tool: Tool;
  status:
    | "running"
    | "awaiting_approval"
    | "blocked"
    | "unknown"
    | "completed"
    | "denied";
  nodes: Record<
    string,
    "pending" | "done" | "waiting" | "queued" | "unknown" | "blocked"
  >;
  findings: string[];
  proposal: Action | null;
  approval: Approval | null;
  outbox: Outbox | null;
  spent: number;
  steps: number;
  events: EvidenceEvent[];
}
export type Command =
  | { type: "step" }
  | { type: "approve"; expectedBinding?: string }
  | { type: "deny"; reason: string }
  | { type: "dispatch" }
  | { type: "complete"; receipt: Receipt }
  | { type: "recover"; receipt: Receipt | null }
  | { type: "reconcile"; receipt: Receipt }
  | { type: "policy"; policy: Policy }
  | { type: "tool"; tool: Tool }
  | { type: "edit"; title: string }
  | { type: "expire-approval" };

export const ZERO = "0".repeat(64);
export const DEFAULT_POLICY: Policy = {
  revision: 1,
  capabilities: ["tickets:write"],
  maxCost: 8,
  maxSteps: 12,
  approvalTtlMs: 120_000,
};
export const DEFAULT_TOOL: Tool = {
  name: "ticket.create",
  version: "1.0.0",
  capability: "tickets:write",
  idempotent: true,
  cost: 3,
};
export function invariant(
  condition: unknown,
  message: string,
): asserts condition {
  if (!condition) throw new Error(message);
}
export function canonical(value: unknown): string {
  let count = 0;
  const walk = (v: unknown, depth: number): string => {
    invariant(
      ++count <= 50_000 && depth <= 32,
      "JSON structure exceeds limits",
    );
    if (v === null || typeof v === "boolean") return JSON.stringify(v);
    if (typeof v === "number") {
      invariant(
        Number.isSafeInteger(v),
        "Only safe integer JSON numbers are supported",
      );
      return String(v);
    }
    if (typeof v === "string") {
      invariant(v.length <= 50_000, "String exceeds limits");
      return JSON.stringify(v);
    }
    if (Array.isArray(v))
      return "[" + v.map((x) => walk(x, depth + 1)).join(",") + "]";
    invariant(
      typeof v === "object" &&
        v !== null &&
        Object.getPrototypeOf(v) === Object.prototype,
      "Expected a plain JSON object",
    );
    return (
      "{" +
      Object.keys(v)
        .sort()
        .map(
          (k) =>
            JSON.stringify(k) +
            ":" +
            walk((v as Record<string, unknown>)[k], depth + 1),
        )
        .join(",") +
      "}"
    );
  };
  return walk(value, 0);
}
export function digest(v: unknown): string {
  return bytesToHex(sha256(new TextEncoder().encode(canonical(v))));
}
function bounded(
  value: unknown,
  name: string,
  max = 120,
): asserts value is string {
  invariant(
    typeof value === "string" &&
      value.trim().length > 0 &&
      value.length <= max &&
      !/[\u0000-\u001f]/u.test(value),
    `Invalid ${name}`,
  );
}
function id(value: unknown, name: string) {
  bounded(value, name, 64);
  invariant(/^[a-zA-Z0-9_-]+$/.test(value), `Invalid ${name}`);
}
function integer(v: number, min: number, max: number, name: string) {
  invariant(Number.isSafeInteger(v) && v >= min && v <= max, `Invalid ${name}`);
}
export function validatePlan(plan: Plan): void {
  invariant(
    plan &&
      Array.isArray(plan.nodes) &&
      plan.nodes.length >= 4 &&
      plan.nodes.length <= 16,
    "Plan needs 4–16 nodes",
  );
  const map = new Map<string, PlanNode>();
  for (const n of plan.nodes) {
    id(n.id, "node ID");
    invariant(!map.has(n.id), "Duplicate node ID");
    invariant(
      ["research", "propose", "ticket", "verify"].includes(n.kind),
      "Unsupported node kind",
    );
    invariant(
      Array.isArray(n.dependsOn) &&
        n.dependsOn.length <= 16 &&
        new Set(n.dependsOn).size === n.dependsOn.length,
      "Invalid dependencies",
    );
    map.set(n.id, n);
  }
  for (const n of plan.nodes)
    for (const dep of n.dependsOn)
      invariant(map.has(dep) && dep !== n.id, "Missing or self dependency");
  const done = new Set<string>();
  for (let i = 0; i < plan.nodes.length; i++)
    for (const n of plan.nodes)
      if (n.dependsOn.every((d) => done.has(d))) done.add(n.id);
  invariant(done.size === map.size, "Plan contains a cycle");
  // This runtime deliberately supports one side effect per plan; complex DAG validation is not arbitrary code execution.
  for (const kind of ["propose", "ticket", "verify"])
    invariant(
      plan.nodes.filter((n) => n.kind === kind).length === 1,
      `Exactly one ${kind} node is required`,
    );
  const ancestors = (node: PlanNode): Set<string> => {
    const seen = new Set<string>();
    const visit = (n: PlanNode) => {
      for (const d of n.dependsOn)
        if (!seen.has(d)) {
          seen.add(d);
          visit(map.get(d)!);
        }
    };
    visit(node);
    return seen;
  };
  const proposal = plan.nodes.find((n) => n.kind === "propose")!;
  const ticket = plan.nodes.find((n) => n.kind === "ticket")!;
  const verify = plan.nodes.find((n) => n.kind === "verify")!;
  invariant(
    plan.nodes
      .filter((n) => n.kind === "research")
      .every((n) => ancestors(proposal).has(n.id)),
    "Research must precede proposal",
  );
  invariant(
    ancestors(ticket).has(proposal.id) && ancestors(verify).has(ticket.id),
    "Required proposal → ticket → verify ordering is missing",
  );
  bounded(plan.incident.service, "service", 80);
  integer(plan.incident.failures, 0, 100_000, "failure count");
  integer(plan.incident.windowMinutes, 1, 1440, "window");
  bounded(plan.ticket.title, "ticket title", 180);
  invariant(
    ["normal", "high"].includes(plan.ticket.priority),
    "Invalid priority",
  );
  if (plan.review) {
    const r = plan.review;
    invariant(
      r.schemaVersion === "kev-publication/v1",
      "Invalid review schema",
    );
    invariant(
      /^[a-f0-9]{64}$/.test(r.evidenceSha256),
      "Invalid evidence digest",
    );
    invariant(
      r.draftSha256 === null || /^[a-f0-9]{64}$/.test(r.draftSha256),
      "Invalid draft digest",
    );
    bounded(r.outputDirectory, "output directory", 4096);
    invariant(
      r.outputDirectory.startsWith("/"),
      "Review output must be absolute",
    );
    for (const text of [r.markdown, r.json])
      invariant(
        typeof text === "string" && text.length > 0 && text.length <= 50_000,
        "Invalid review content length",
      );
    invariant(
      JSON.parse(r.json).schemaVersion === "kev-review/v1",
      "Invalid report schema",
    );
  }
}
export function validatePolicy(p: Policy) {
  integer(p.revision, 1, 1_000_000, "policy revision");
  invariant(
    Array.isArray(p.capabilities) &&
      p.capabilities.length <= 8 &&
      p.capabilities.every((c) =>
        ["tickets:write", "reviews:write"].includes(c),
      ),
    "Invalid capabilities",
  );
  integer(p.maxCost, 0, 1000, "cost budget");
  integer(p.maxSteps, 1, 100, "step budget");
  integer(p.approvalTtlMs, 1000, 300_000, "approval TTL");
}
export function validateTool(t: Tool) {
  invariant(
    ((t.name === "ticket.create" && t.capability === "tickets:write") ||
      (t.name === "review.publish" &&
        t.capability === "reviews:write" &&
        t.idempotent)) &&
      typeof t.idempotent === "boolean",
    "Unsupported tool contract",
  );
  bounded(t.version, "tool version", 32);
  integer(t.cost, 1, 100, "tool cost");
}
export function fixturePlan(): Plan {
  return {
    nodes: [
      { id: "research", kind: "research", dependsOn: [] },
      { id: "propose", kind: "propose", dependsOn: ["research"] },
      { id: "ticket", kind: "ticket", dependsOn: ["propose"] },
      { id: "verify", kind: "verify", dependsOn: ["ticket"] },
    ],
    incident: { service: "search-index", failures: 14, windowMinutes: 5 },
    ticket: {
      title: "Investigate elevated search-index failures",
      priority: "high",
    },
  };
}
function append(
  run: Run,
  at: number,
  principal: Principal,
  type: string,
  data: Json,
): void {
  invariant(run.events.length < 512, "Evidence event limit reached");
  const record = {
    seq: run.events.length + 1,
    at,
    type,
    principal: principal.id,
    role: principal.role,
    data,
    previous: run.events.at(-1)?.hash ?? ZERO,
  };
  run.events.push({ ...record, hash: digest(record) });
}
export function verifyChain(events: EvidenceEvent[]): {
  valid: boolean;
  failedAt: number | null;
  head: string;
} {
  let previous = ZERO;
  for (let i = 0; i < events.length; i++) {
    const { hash, ...record } = events[i];
    if (
      record.seq !== i + 1 ||
      record.previous !== previous ||
      digest(record) !== hash
    )
      return { valid: false, failedAt: i + 1, head: previous };
    previous = hash;
  }
  return { valid: true, failedAt: null, head: previous };
}
function authorize(run: Run, actor: Principal, roles: Role[]) {
  id(actor.id, "principal");
  invariant(actor.tenant === run.tenant, "Tenant mismatch");
  invariant(
    roles.includes(actor.role),
    "Role is not authorized for this operation",
  );
}
function independentReviewer(run: Run, actor: Principal) {
  invariant(
    !run.events.some(
      (event) =>
        event.principal === actor.id &&
        (event.role === "worker" || event.type === "run.created"),
    ),
    "Reviewer must be independent of the creator and workers",
  );
}
export function createRun(
  runId: string,
  actor: Principal,
  now: number,
  plan = fixturePlan(),
  policy = DEFAULT_POLICY,
  tool = DEFAULT_TOOL,
): Run {
  id(runId, "run ID");
  id(actor.tenant, "tenant");
  id(actor.id, "principal");
  invariant(actor.role === "operator", "Only an operator can create runs");
  integer(now, 0, Number.MAX_SAFE_INTEGER, "timestamp");
  validatePlan(plan);
  validatePolicy(policy);
  validateTool(tool);
  invariant(
    Boolean(plan.review) === (tool.name === "review.publish"),
    "Plan and tool contract mismatch",
  );
  const run: Run = {
    schema: 1,
    id: runId,
    tenant: actor.tenant,
    revision: 0,
    plan: structuredClone(plan),
    policy: structuredClone(policy),
    tool: structuredClone(tool),
    status: "running",
    nodes: Object.fromEntries(plan.nodes.map((n) => [n.id, "pending"])),
    findings: [],
    proposal: null,
    approval: null,
    outbox: null,
    spent: 0,
    steps: 0,
    events: [],
  };
  append(run, now, actor, "run.created", {
    planDigest: digest(plan),
    policyDigest: digest(policy),
    planner: plan.review
      ? "public-kev-review-v1"
      : "deterministic-synthetic-v1",
  });
  return run;
}
export function actionFor(run: Run, nodeId: string): Action {
  const args = {
    ...run.plan.ticket,
    service: run.plan.incident.service,
    evidence: [...run.findings],
    ...(run.plan.review ? { review: structuredClone(run.plan.review) } : {}),
  };
  const payloadDigest = digest({ tenant: run.tenant, tool: run.tool, args });
  const binding = digest({
    runId: run.id,
    tenant: run.tenant,
    nodeId,
    payloadDigest,
    policy: run.policy,
  });
  return {
    id: `${run.id}-${nodeId}`,
    nodeId,
    tenant: run.tenant,
    tool: structuredClone(run.tool),
    args,
    payloadDigest,
    binding,
    key: digest({ runId: run.id, nodeId, tenant: run.tenant, payloadDigest }),
  };
}
function budget(run: Run, cost: number) {
  invariant(run.steps + 1 <= run.policy.maxSteps, "Step budget exhausted");
  invariant(run.spent + cost <= run.policy.maxCost, "Cost budget exhausted");
}
function receiptMatches(run: Run, receipt: Receipt) {
  const a = run.outbox!.action;
  bounded(receipt.ticketId, "ticket ID", 80);
  invariant(
    receipt.tenant === run.tenant &&
      receipt.payloadDigest === a.payloadDigest &&
      receipt.key === a.key,
    "Receipt does not match tenant, idempotency key, and approved payload digest",
  );
}
function invalidatePending(run: Run) {
  if (
    run.outbox &&
    ["inflight", "unknown", "delivered"].includes(run.outbox.status)
  )
    return;
  if (run.proposal) {
    const n = run.proposal.nodeId;
    run.proposal = actionFor(run, n);
    run.approval = null;
    run.outbox = null;
    run.nodes[n] = "waiting";
    run.status = "awaiting_approval";
  }
}
export function transition(
  current: Run,
  command: Command,
  actor: Principal,
  now: number,
): Run {
  integer(now, 0, Number.MAX_SAFE_INTEGER, "timestamp");
  invariant(now >= (current.events.at(-1)?.at ?? 0), "Clock moved backward");
  invariant(verifyChain(current.events).valid, "Evidence chain is invalid");
  invariant(
    !["completed", "denied"].includes(current.status),
    `A ${current.status} run is terminal; create a new run`,
  );
  const run = structuredClone(current);
  const event = (type: string, data: Json = {}) =>
    append(run, now, actor, type, data);
  if (command.type === "step") {
    authorize(run, actor, ["worker"]);
    invariant(
      !["completed", "denied", "unknown"].includes(run.status),
      `Cannot step a ${run.status} run`,
    );
    const n = run.plan.nodes.find(
      (n) =>
        run.nodes[n.id] === "pending" &&
        n.dependsOn.every((d) => run.nodes[d] === "done"),
    );
    invariant(
      n,
      "No ready node: approval, dispatch, or reconciliation is required",
    );
    if (n.kind === "ticket") {
      run.proposal = actionFor(run, n.id);
      run.approval = null;
      run.nodes[n.id] = "waiting";
      run.status = "awaiting_approval";
      event("action.proposed", {
        nodeId: n.id,
        binding: run.proposal.binding,
        payloadDigest: run.proposal.payloadDigest,
      });
    } else {
      budget(run, 1);
      run.steps++;
      run.spent++;
      if (n.kind === "research")
        run.findings.push(
          run.plan.review
            ? `Public KEV evidence packet SHA-256 ${run.plan.review.evidenceSha256}; applicability to the analyst's environment remains unconfirmed.`
            : `${run.plan.incident.failures} synthetic failures in ${run.plan.incident.windowMinutes} minutes for ${run.plan.incident.service}`,
        );
      if (n.kind === "propose")
        invariant(run.findings.length > 0, "Proposal needs research evidence");
      if (n.kind === "verify") {
        invariant(
          run.outbox?.status === "delivered" && run.outbox.receipt,
          "Verification needs a persisted receipt",
        );
        receiptMatches(run, run.outbox.receipt);
      }
      run.nodes[n.id] = "done";
      event("node.completed", { nodeId: n.id, kind: n.kind, cost: 1 });
      if (Object.values(run.nodes).every((s) => s === "done")) {
        run.status = "completed";
        event("run.completed", { spent: run.spent, steps: run.steps });
      }
    }
  } else if (command.type === "approve") {
    authorize(run, actor, ["reviewer"]);
    invariant(
      run.proposal && ["awaiting_approval", "blocked"].includes(run.status),
      "No approvable proposal",
    );
    independentReviewer(run, actor);
    invariant(
      !run.outbox || run.outbox.status === "pending",
      "Cannot approve an unresolved dispatched action",
    );
    invariant(
      run.policy.capabilities.includes(run.tool.capability),
      "Capability is revoked",
    );
    const action = actionFor(run, run.proposal.nodeId);
    invariant(
      run.tool.name !== "review.publish" ||
        command.expectedBinding === action.binding,
      "Review approval requires the exact preview binding",
    );
    run.proposal = action;
    run.approval = {
      binding: action.binding,
      reviewer: actor.id,
      issuedAt: now,
      expiresAt: now + run.policy.approvalTtlMs,
    };
    run.outbox = {
      action,
      status: "pending",
      attempts: run.outbox?.attempts ?? 0,
      reserved: run.outbox?.reserved ?? false,
      receipt: null,
    };
    run.nodes[action.nodeId] = "queued";
    run.status = "running";
    event("approval.granted", {
      binding: action.binding,
      expiresAt: run.approval.expiresAt,
      reviewer: actor.id,
    });
    event("outbox.enqueued", { key: action.key });
  } else if (command.type === "deny") {
    authorize(run, actor, ["reviewer"]);
    bounded(command.reason, "denial reason", 180);
    invariant(
      run.proposal &&
        !["inflight", "unknown", "delivered"].includes(
          run.outbox?.status ?? "",
        ),
      "Cannot deny a dispatched action",
    );
    run.status = "denied";
    run.nodes[run.proposal.nodeId] = "blocked";
    run.outbox = null;
    run.approval = null;
    event("approval.denied", { reason: command.reason });
  } else if (command.type === "dispatch") {
    authorize(run, actor, ["worker"]);
    invariant(run.outbox?.status === "pending", "No pending outbox action");
    const a = run.outbox.action;
    const reason = !run.policy.capabilities.includes(run.tool.capability)
      ? "capability_revoked"
      : actionFor(run, a.nodeId).binding !== a.binding
        ? "action_or_policy_changed"
        : !run.approval || run.approval.binding !== a.binding
          ? "approval_mismatch"
          : run.approval.expiresAt <= now
            ? "approval_expired"
            : null;
    if (reason) {
      run.status = "blocked";
      run.nodes[a.nodeId] = "blocked";
      event("dispatch.blocked", { reason });
    } else {
      invariant(run.outbox.attempts < 3, "Dispatch attempt limit reached");
      budget(run, run.outbox.reserved ? 0 : a.tool.cost);
      run.steps++;
      if (!run.outbox.reserved) run.spent += a.tool.cost;
      run.outbox.reserved = true;
      run.outbox.attempts++;
      run.outbox.status = "inflight";
      event("dispatch.started", {
        key: a.key,
        payloadDigest: a.payloadDigest,
        attempt: run.outbox.attempts,
      });
    }
  } else if (command.type === "complete" || command.type === "reconcile") {
    authorize(
      run,
      actor,
      command.type === "reconcile" ? ["reviewer"] : ["worker"],
    );
    if (command.type === "reconcile") independentReviewer(run, actor);
    invariant(
      run.outbox &&
        (command.type === "reconcile"
          ? run.outbox.status === "unknown"
          : run.outbox.status === "inflight"),
      "No matching unresolved dispatch",
    );
    receiptMatches(run, command.receipt);
    run.outbox.receipt = structuredClone(command.receipt);
    run.outbox.status = "delivered";
    run.nodes[run.outbox.action.nodeId] = "done";
    run.status = "running";
    event(
      command.type === "reconcile" ? "action.reconciled" : "action.completed",
      { receipt: command.receipt as unknown as Json },
    );
  } else if (command.type === "recover") {
    authorize(run, actor, ["worker"]);
    invariant(run.outbox?.status === "inflight", "No interrupted dispatch");
    if (!run.outbox.action.tool.idempotent) {
      run.outbox.status = "unknown";
      run.status = "unknown";
      run.nodes[run.outbox.action.nodeId] = "unknown";
      event("recovery.requires_reconciliation", {
        reason: "connector_has_no_idempotency_contract",
      });
    } else if (command.receipt) {
      receiptMatches(run, command.receipt);
      run.outbox.receipt = structuredClone(command.receipt);
      run.outbox.status = "delivered";
      run.nodes[run.outbox.action.nodeId] = "done";
      run.status = "running";
      event("recovery.receipt_verified", {
        receipt: command.receipt as unknown as Json,
      });
    } else {
      run.outbox.status = "pending";
      run.status = "running";
      event("recovery.retry_ready", {
        key: run.outbox.action.key,
        note: "same key; policy and approval checked again at dispatch",
      });
    }
  } else if (command.type === "policy") {
    authorize(run, actor, ["operator"]);
    validatePolicy(command.policy);
    invariant(
      command.policy.revision > run.policy.revision,
      "Policy revision must increase",
    );
    run.policy = structuredClone(command.policy);
    invalidatePending(run);
    event("policy.changed", {
      policyDigest: digest(run.policy),
      revision: run.policy.revision,
      capabilities: run.policy.capabilities,
    });
  } else if (command.type === "tool") {
    authorize(run, actor, ["operator"]);
    validateTool(command.tool);
    invariant(
      Boolean(run.plan.review) === (command.tool.name === "review.publish"),
      "Plan and tool contract mismatch",
    );
    run.tool = structuredClone(command.tool);
    invalidatePending(run);
    event("tool.changed", {
      toolDigest: digest(run.tool),
      version: run.tool.version,
    });
  } else if (command.type === "edit") {
    authorize(run, actor, ["operator"]);
    bounded(command.title, "ticket title", 180);
    invariant(
      !run.outbox || run.outbox.status === "pending",
      "Cannot edit a dispatched action",
    );
    run.plan.ticket.title = command.title;
    invalidatePending(run);
    event("proposal.edited", { planDigest: digest(run.plan) });
  } else if (command.type === "expire-approval") {
    authorize(run, actor, ["operator"]);
    invariant(
      run.approval && (!run.outbox || run.outbox.status === "pending"),
      "No pending approval to expire",
    );
    run.approval.expiresAt = now;
    event("approval.expired_by_operator");
  } else {
    throw new Error("Unsupported command");
  }
  run.revision++;
  return run;
}

/** Persistence adapters must check the previous snapshot, not trust caller-supplied events. */
export function assertCommit(previous: Run, next: Run) {
  invariant(
    previous.id === next.id &&
      previous.tenant === next.tenant &&
      next.revision === previous.revision + 1,
    "Snapshot revision or scope mismatch",
  );
  invariant(
    next.events.length > previous.events.length &&
      canonical(next.events.slice(0, previous.events.length)) ===
        canonical(previous.events),
    "Evidence history must be append-only",
  );
  invariant(verifyChain(next.events).valid, "Invalid event chain");
}
