import test from "node:test";
import assert from "node:assert/strict";
import {
  createRun,
  transition,
  fixturePlan,
  validatePlan,
  validatePolicy,
  canonical,
  digest,
  verifyChain,
  DEFAULT_POLICY,
  DEFAULT_TOOL,
} from "../build/core.js";
import {
  operator,
  reviewer,
  worker,
  proposal,
  approved,
  receipt,
} from "./helpers.mjs";

test("happy path produces a fully verified four-node DAG and exact budget accounting", () => {
  let s = approved();
  s = transition(s, { type: "dispatch" }, worker, 1020);
  s = transition(s, { type: "complete", receipt: receipt(s) }, worker, 1030);
  s = transition(s, { type: "step" }, worker, 1040);
  assert.equal(s.status, "completed");
  assert.equal(s.spent, 6);
  assert.equal(s.steps, 4);
  assert.equal(verifyChain(s.events).valid, true);
});
for (const [label, mutate] of [
  ["cycle", (p) => p.nodes[0].dependsOn.push("verify")],
  ["missing dependency", (p) => p.nodes[0].dependsOn.push("missing")],
  ["duplicate ID", (p) => (p.nodes[1].id = p.nodes[0].id)],
  ["unsupported kind", (p) => (p.nodes[0].kind = "shell")],
  ["bypassed approval sequence", (p) => (p.nodes[2].dependsOn = ["research"])],
  [
    "too many nodes",
    (p) => (p.nodes = Array.from({ length: 17 }, () => p.nodes[0])),
  ],
  ["unbounded title", (p) => (p.ticket.title = "x".repeat(181))],
  [
    "unsafe integer",
    (p) => (p.incident.failures = Number.MAX_SAFE_INTEGER + 1),
  ],
])
  test(`plan rejects ${label}`, () => {
    const p = fixturePlan();
    mutate(p);
    assert.throws(() => validatePlan(p));
  });
test("an additional research branch must complete before proposal", () => {
  const p = fixturePlan();
  p.nodes.unshift({ id: "research_b", kind: "research", dependsOn: [] });
  p.nodes.find((n) => n.kind === "propose").dependsOn.push("research_b");
  let s = createRun("branch", operator, 1000, p);
  s = transition(s, { type: "step" }, worker, 1001);
  s = transition(s, { type: "step" }, worker, 1002);
  assert.equal(s.findings.length, 2);
  assert.equal(s.nodes.propose, "pending");
});
for (const field of ["maxCost", "maxSteps", "approvalTtlMs"])
  test(`policy rejects invalid ${field}`, () =>
    assert.throws(() => validatePolicy({ ...DEFAULT_POLICY, [field]: -1 })));
test("canonical digest is key-order independent and rejects non-JSON numbers", () => {
  assert.equal(digest({ b: 1, a: 2 }), digest({ a: 2, b: 1 }));
  assert.throws(() => canonical({ n: NaN }));
  assert.throws(() => canonical({ n: 1.1 }));
});
test("depth bound rejects an adversarial nested structure", () => {
  let value = {};
  for (let i = 0; i < 34; i++) value = { x: value };
  assert.throws(() => digest(value), /limits/);
});
test("tenant and role gates reject unauthorized approvals", () => {
  const s = proposal();
  assert.throws(
    () =>
      transition(
        s,
        { type: "approve" },
        { ...reviewer, tenant: "elsewhere" },
        1010,
      ),
    /Tenant/,
  );
  assert.throws(() => transition(s, { type: "approve" }, worker, 1010), /Role/);
});
test("creator and a worker cannot approve under a different role label", () => {
  const s = proposal();
  for (const id of ["operator", "worker"])
    assert.throws(
      () => transition(s, { type: "approve" }, { ...reviewer, id }, 1010),
      /independent/,
    );
});
test("unapproved actions cannot be dispatched", () =>
  assert.throws(
    () => transition(proposal(), { type: "dispatch" }, worker, 1010),
    /pending/,
  ));
for (const [label, command] of [
  ["arguments", { type: "edit", title: "Changed approved payload" }],
  ["policy", { type: "policy", policy: { ...DEFAULT_POLICY, revision: 2 } }],
  [
    "tool version",
    { type: "tool", tool: { ...DEFAULT_TOOL, version: "2.0.0" } },
  ],
])
  test(`${label} changes invalidate the existing approval and outbox`, () => {
    const before = approved();
    const s = transition(before, command, operator, 1011);
    assert.equal(s.approval, null);
    assert.equal(s.outbox, null);
    assert.notEqual(s.proposal.binding, before.proposal.binding);
    assert.throws(() => transition(s, { type: "dispatch" }, worker, 1020));
  });
test("expired approval blocks execution and does not consume budget", () => {
  const s = transition(approved(), { type: "dispatch" }, worker, 122000);
  assert.equal(s.status, "blocked");
  assert.equal(s.spent, 2);
  assert.equal(s.outbox.status, "pending");
});
test("a new independent approval can replace an expired approval", () => {
  let s = transition(approved(), { type: "dispatch" }, worker, 122000);
  s = transition(s, { type: "approve" }, reviewer, 122010);
  s = transition(s, { type: "dispatch" }, worker, 122020);
  assert.equal(s.outbox.status, "inflight");
});
test("current capability revocation prevents new dispatch", () => {
  let s = approved();
  s = transition(
    s,
    { type: "policy", policy: { ...s.policy, revision: 2, capabilities: [] } },
    operator,
    1011,
  );
  assert.throws(
    () => transition(s, { type: "approve" }, reviewer, 1012),
    /revoked/,
  );
});
test("denial is terminal through policy, tool, edit, or reapproval", () => {
  const s = transition(
    proposal(),
    { type: "deny", reason: "Insufficient evidence" },
    reviewer,
    1010,
  );
  for (const command of [
    { type: "approve" },
    { type: "policy", policy: { ...DEFAULT_POLICY, revision: 2 } },
    { type: "tool", tool: DEFAULT_TOOL },
    { type: "edit", title: "retry" },
  ])
    assert.throws(() => transition(s, command, operator, 1020), /terminal/);
});
test("cost and step budgets stop work before side effects", () => {
  for (const policy of [
    { ...DEFAULT_POLICY, maxCost: 4 },
    { ...DEFAULT_POLICY, maxSteps: 2 },
  ])
    assert.throws(
      () =>
        transition(approved({ policy }), { type: "dispatch" }, worker, 1020),
      /budget/,
    );
});
test("receipt must match tenant, key, and payload digest", () => {
  const s = transition(approved(), { type: "dispatch" }, worker, 1020);
  for (const field of ["tenant", "key", "payloadDigest"])
    assert.throws(
      () =>
        transition(
          s,
          { type: "complete", receipt: { ...receipt(s), [field]: "wrong" } },
          worker,
          1030,
        ),
      /match/,
    );
});
test("idempotent recovery verifies an existing receipt without a new dispatch", () => {
  const s = transition(approved(), { type: "dispatch" }, worker, 1020);
  const recovered = transition(
    s,
    { type: "recover", receipt: receipt(s) },
    worker,
    1030,
  );
  assert.equal(recovered.outbox.status, "delivered");
  assert.equal(recovered.outbox.attempts, 1);
});
test("missing idempotent receipt preserves key and reserves cost only once", () => {
  let s = transition(approved(), { type: "dispatch" }, worker, 1020);
  const key = s.outbox.action.key;
  s = transition(s, { type: "recover", receipt: null }, worker, 1030);
  s = transition(s, { type: "dispatch" }, worker, 1040);
  assert.equal(s.outbox.action.key, key);
  assert.equal(s.outbox.attempts, 2);
  assert.equal(s.spent, 5);
});
test("non-idempotent uncertainty requires reviewer reconciliation even if a receipt is supplied to recovery", () => {
  let s = transition(
    approved({ tool: { ...DEFAULT_TOOL, idempotent: false } }),
    { type: "dispatch" },
    worker,
    1020,
  );
  const proof = receipt(s);
  s = transition(s, { type: "recover", receipt: proof }, worker, 1030);
  assert.equal(s.status, "unknown");
  assert.throws(() => transition(s, { type: "dispatch" }, worker, 1040));
  assert.throws(
    () => transition(s, { type: "reconcile", receipt: proof }, worker, 1040),
    /Role/,
  );
  for (const id of [worker.id, operator.id]) {
    assert.throws(
      () =>
        transition(
          s,
          { type: "reconcile", receipt: proof },
          { ...reviewer, id },
          1040,
        ),
      /independent/,
    );
  }
  s = transition(s, { type: "reconcile", receipt: proof }, reviewer, 1040);
  assert.equal(s.outbox.status, "delivered");
});
test("inflight policy revocation can record an admitted effect but cannot erase it", () => {
  let s = transition(approved(), { type: "dispatch" }, worker, 1020);
  const proof = receipt(s);
  s = transition(
    s,
    {
      type: "policy",
      policy: { ...DEFAULT_POLICY, revision: 2, capabilities: [] },
    },
    operator,
    1021,
  );
  s = transition(s, { type: "complete", receipt: proof }, worker, 1030);
  assert.equal(s.outbox.status, "delivered");
  assert.equal(s.policy.capabilities.length, 0);
});
test("hash verification detects modified, reordered, and omitted evidence", () => {
  const events = approved().events;
  const edited = structuredClone(events);
  edited[1].data = { fake: true };
  assert.equal(verifyChain(edited).valid, false);
  assert.equal(verifyChain(events.slice(1)).valid, false);
  assert.equal(verifyChain([...events].reverse()).valid, false);
});
test("backwards clocks fail closed", () =>
  assert.throws(
    () => transition(approved(), { type: "dispatch" }, worker, 1),
    /backward/,
  ));
test("repeated uncertain idempotent dispatches stop at a bounded attempt count", () => {
  let s = approved();
  for (let i = 0; i < 3; i++) {
    s = transition(s, { type: "dispatch" }, worker, 1020 + i * 2);
    s = transition(s, { type: "recover", receipt: null }, worker, 1021 + i * 2);
  }
  assert.throws(
    () => transition(s, { type: "dispatch" }, worker, 1030),
    /attempt limit/,
  );
  assert.equal(s.spent, 5);
  assert.equal(s.outbox.attempts, 3);
});
