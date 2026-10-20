import { createHash, randomUUID } from "node:crypto";
import {
  constants,
  closeSync,
  existsSync,
  fstatSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import {
  canonical,
  createRun,
  DEFAULT_POLICY,
  digest,
  fixturePlan,
  invariant,
  type Action,
  type Principal,
  type Receipt,
  type ReviewPayload,
  type Run,
} from "./core.js";
import type { Connector } from "./connector.js";

export const CISA_KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
export interface KevDocument {
  id: string;
  cveID: string;
  title: string;
  text: string;
  sourceUrl: string;
  contentSha256: string;
  record: {
    vendorProject: string;
    product: string;
    dateAdded: string;
    dueDate: string;
    requiredAction: string;
    knownRansomwareCampaignUse: string | null;
  };
}
export interface EvidencePacket {
  schemaVersion: "kev-evidence/v1";
  generatedAt: string;
  query: string;
  source: {
    url: string;
    retrievedAt: string;
    sha256: string;
    catalogVersion: string;
  };
  documents: KevDocument[];
  [key: string]: unknown;
}
export interface ReviewDraft {
  schemaVersion: "kev-draft/v1";
  model: string;
  provider: string;
  generatedAt: string;
  promptSha256: string;
  evidenceSha256: string;
  claims: { text: string; citations: string[] }[];
  usage?: unknown;
}
export const sha256Bytes = (text: string | Buffer): string =>
  createHash("sha256").update(text).digest("hex");
/** Canonical public evidence allows finite ranking scores and model timings. */
export function canonicalEvidence(value: unknown): string {
  let count = 0;
  const walk = (v: unknown, depth: number): string => {
    invariant(
      ++count <= 50_000 && depth <= 24,
      "Evidence JSON exceeds structural limits",
    );
    if (v === null || typeof v === "boolean" || typeof v === "string")
      return JSON.stringify(v);
    if (typeof v === "number") {
      invariant(Number.isFinite(v), "Non-finite evidence number");
      return JSON.stringify(v);
    }
    if (Array.isArray(v))
      return "[" + v.map((x) => walk(x, depth + 1)).join(",") + "]";
    invariant(
      v &&
        typeof v === "object" &&
        Object.getPrototypeOf(v) === Object.prototype,
      "Expected plain evidence JSON",
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
const hashPattern = /^[a-f0-9]{64}$/;
function text(
  value: unknown,
  name: string,
  max = 2000,
): asserts value is string {
  invariant(
    typeof value === "string" &&
      value.trim().length > 0 &&
      value.length <= max &&
      !/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/u.test(value),
    `Invalid ${name}`,
  );
}
function timestamp(value: unknown, name: string) {
  text(value, name, 64);
  invariant(Number.isFinite(Date.parse(value)), `Invalid ${name}`);
}
function https(value: unknown, name: string) {
  text(value, name, 2048);
  const url = new URL(value);
  invariant(
    url.protocol === "https:" &&
      !url.username &&
      !url.password &&
      !/[\s<>"`]/u.test(value),
    `Invalid ${name}`,
  );
}
export function validatePacket(value: unknown): EvidencePacket {
  invariant(
    value && typeof value === "object" && !Array.isArray(value),
    "Expected evidence packet",
  );
  const packet = value as EvidencePacket;
  invariant(
    packet.schemaVersion === "kev-evidence/v1",
    "Expected kev-evidence/v1",
  );
  timestamp(packet.generatedAt, "packet generation timestamp");
  text(packet.query, "query", 1000);
  invariant(
    packet.source &&
      (packet.source.url === CISA_KEV_URL ||
        /^https:\/\/raw\.githubusercontent\.com\/cisagov\/kev-data\/[a-f0-9]{40}\/known_exploited_vulnerabilities\.json$/.test(
          packet.source.url,
        )),
    "Expected official CISA KEV catalog URL or pinned official GitHub mirror",
  );
  timestamp(packet.source.retrievedAt, "source retrieval timestamp");
  invariant(hashPattern.test(packet.source.sha256), "Invalid catalog SHA-256");
  text(packet.source.catalogVersion, "catalog version", 100);
  invariant(
    Array.isArray(packet.documents) &&
      packet.documents.length >= 1 &&
      packet.documents.length <= 12,
    "Expected 1–12 retrieved documents",
  );
  const ids = new Set<string>();
  const cves = new Set<string>();
  for (const doc of packet.documents) {
    text(doc.id, "document ID", 120);
    invariant(
      /^[a-zA-Z0-9_.:-]+$/.test(doc.id) && !ids.has(doc.id),
      "Invalid or duplicate document ID",
    );
    invariant(
      /^CVE-\d{4}-\d{4,}$/.test(doc.cveID) && !cves.has(doc.cveID),
      "Invalid or duplicate CVE",
    );
    ids.add(doc.id);
    cves.add(doc.cveID);
    text(doc.title, "document title", 1000);
    text(doc.text, "document text", 12_000);
    invariant(
      hashPattern.test(doc.contentSha256) &&
        sha256Bytes(doc.text) === doc.contentSha256,
      "Document content SHA-256 mismatch",
    );
    https(doc.sourceUrl, "document source URL");
    invariant(
      doc.record && typeof doc.record === "object",
      "Missing KEV record",
    );
    for (const key of [
      "vendorProject",
      "product",
      "dateAdded",
      "dueDate",
      "requiredAction",
    ] as const)
      text(doc.record[key], `record ${key}`, 4000);
    if (doc.record.knownRansomwareCampaignUse !== null)
      text(
        doc.record.knownRansomwareCampaignUse,
        "record knownRansomwareCampaignUse",
        4000,
      );
    for (const key of ["dateAdded", "dueDate"] as const)
      invariant(
        /^\d{4}-\d{2}-\d{2}$/.test(doc.record[key]) &&
          Number.isFinite(Date.parse(doc.record[key])),
        `Invalid ${key}`,
      );
  }
  invariant(
    canonicalEvidence(packet).length <= 35_000,
    "Evidence packet exceeds 35 KB; retrieve fewer documents",
  );
  return structuredClone(packet);
}
export function validateDraft(
  value: unknown,
  packet: EvidencePacket,
): ReviewDraft {
  invariant(value && typeof value === "object", "Expected model draft");
  const draft = value as ReviewDraft;
  invariant(draft.schemaVersion === "kev-draft/v1", "Expected kev-draft/v1");
  text(draft.model, "model", 200);
  text(draft.provider, "provider", 200);
  timestamp(draft.generatedAt, "draft timestamp");
  invariant(hashPattern.test(draft.promptSha256), "Invalid prompt digest");
  invariant(
    draft.evidenceSha256 === sha256Bytes(canonicalEvidence(packet)),
    "Draft belongs to different evidence",
  );
  invariant(
    Array.isArray(draft.claims) &&
      draft.claims.length >= 1 &&
      draft.claims.length <= 12,
    "Expected 1–12 draft claims",
  );
  const ids = new Set(packet.documents.map((d) => d.id));
  for (const claim of draft.claims) {
    text(claim.text, "draft claim", 1500);
    invariant(
      Array.isArray(claim.citations) &&
        claim.citations.length >= 1 &&
        claim.citations.every((id) => ids.has(id)),
      "Draft claim has missing or unknown citations",
    );
  }
  invariant(canonicalEvidence(draft).length <= 8_000, "Draft exceeds 8 KB");
  return structuredClone(draft);
}
// Render public source/model text as text, not active HTML or Markdown directives.
const md = (s: string) =>
  s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/[\\`*_{}\[\]()#+!|]/g, "\\$&")
    .replace(/\r?\n/g, " ");

export function makeReviewRun(
  runId: string,
  actor: Principal,
  now: number,
  value: unknown,
  outputDirectory: string,
  draftValue?: unknown,
): Run {
  const packet = validatePacket(value);
  const draft =
    draftValue === undefined ? null : validateDraft(draftValue, packet);
  mkdirSync(resolve(outputDirectory), { recursive: true });
  const output = realpathSync(resolve(outputDirectory));
  const evidenceSha256 = sha256Bytes(canonicalEvidence(packet));
  const report = {
    schemaVersion: "kev-review/v1",
    runId,
    tenant: actor.tenant,
    createdAt: new Date(now).toISOString(),
    evidenceSha256,
    applicability: "unconfirmed",
    scope:
      "Public CISA KEV evidence selected by the query. No asset inventory was matched; no vulnerability scan, patch, or ticket-system update was performed.",
    deadlineScope:
      "CISA dueDate applies to the relevant federal directive scope; it is not asserted as this analyst's organizational deadline.",
    evidence: packet,
    analystChecks: [
      "Confirm the product and affected version against an authorized asset inventory and vendor advisory.",
      "Check exposure, mitigations, ownership, and maintenance constraints before assigning a local priority.",
      "Confirm the current vendor remediation and record an organization-specific owner and due date.",
    ],
    modelDraft: draft,
    modelDraftStatus: draft
      ? "unverified-suggestion-citations-checkable-not-factual-verification"
      : "not-used",
  };
  const lines = [
    "# Vulnerability review — public KEV evidence",
    "",
    `Run: ${runId} · Created: ${report.createdAt}`,
    "",
    "**Applicability to your environment: UNCONFIRMED.** A KEV listing means known exploitation, not proof that an asset you operate is affected.",
    "",
    `Query: ${md(packet.query)}`,
    "",
    `Catalog: ${packet.source.url}`,
    `Catalog version: ${md(packet.source.catalogVersion)}`,
    `Retrieved: ${packet.source.retrievedAt}`,
    `Catalog SHA-256: \`${packet.source.sha256}\``,
    `Evidence packet SHA-256: \`${evidenceSha256}\``,
    "",
    "## Evidence to review",
    "",
  ];
  for (const d of packet.documents) {
    lines.push(
      `### ${d.cveID} — ${md(d.title)}`,
      "",
      `Citation ID: \`${d.id}\``,
      `Vendor/product: ${md(d.record.vendorProject)} / ${md(d.record.product)}`,
      `KEV added: ${d.record.dateAdded} · CISA due date: ${d.record.dueDate}`,
      `Known ransomware campaign use (catalog field): ${d.record.knownRansomwareCampaignUse === null ? "Not supplied" : md(d.record.knownRansomwareCampaignUse)}`,
      "",
      `Required action (catalog text): ${md(d.record.requiredAction)}`,
      "",
      `Source: <${d.sourceUrl}>`,
      `Document SHA-256: \`${d.contentSha256}\``,
      "",
      `Source excerpt: ${md(d.text)}`,
      "",
      "Local asset/version match: **not assessed**. Owner, exposure, local priority and remediation status: **not assessed**.",
      "",
    );
  }
  lines.push(
    "## Analyst checklist",
    "",
    ...report.analystChecks.map((x) => `- [ ] ${x}`),
    "",
    "CISA catalog due dates do not automatically become deadlines for your organization. Validate applicability and consult the current vendor guidance.",
    "",
  );
  if (draft) {
    lines.push(
      "## Optional model draft — unverified suggestions",
      "",
      `Model: ${md(draft.model)} · Provider: ${md(draft.provider)}`,
      `Prompt SHA-256: \`${draft.promptSha256}\``,
      "",
      "Citations identify supplied evidence; their presence does not verify the truth or completeness of a model claim. The analyst must review every suggestion.",
      "",
    );
    for (const claim of draft.claims)
      lines.push(
        `- ${md(claim.text)} [citation IDs: ${claim.citations.map(md).join(", ")}]`,
      );
    lines.push("");
  }
  lines.push(
    "## Delivery scope",
    "",
    report.scope,
    "",
    "This is a versioned evidence artifact. Approval records review of these exact bytes and destination; it is not an approval to patch systems or confirmation of asset exposure.",
    "",
  );
  const review: ReviewPayload = {
    schemaVersion: "kev-publication/v1",
    evidenceSha256,
    draftSha256: draft ? sha256Bytes(canonicalEvidence(draft)) : null,
    outputDirectory: output,
    markdown: lines.join("\n"),
    json: JSON.stringify(report, null, 2) + "\n",
  };
  const plan = fixturePlan();
  plan.incident = {
    service: "public-kev-review",
    failures: 0,
    windowMinutes: 1,
  };
  plan.ticket = {
    title: `Review ${packet.documents.length} public KEV records`,
    priority: "normal",
  };
  plan.review = review;
  return createRun(
    runId,
    actor,
    now,
    plan,
    {
      ...DEFAULT_POLICY,
      capabilities: ["reviews:write"],
      approvalTtlMs: 300_000,
    },
    {
      name: "review.publish",
      capability: "reviews:write",
      version: "1.0.0",
      idempotent: true,
      cost: 3,
    },
  );
}

interface Manifest {
  schemaVersion: "kev-delivery/v1";
  tenant: string;
  key: string;
  payloadDigest: string;
  files: Record<string, string>;
}
function directory(path: string) {
  const info = lstatSync(path);
  invariant(
    info.isDirectory() && !info.isSymbolicLink() && realpathSync(path) === path,
    "Review directory is not the approved real directory",
  );
}
function readRegular(path: string): Buffer {
  const fd = openSync(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const info = fstatSync(fd);
    invariant(
      info.isFile() && info.size <= 256_000,
      "Expected a bounded regular artifact",
    );
    return readFileSync(fd);
  } finally {
    closeSync(fd);
  }
}
function syncDirectory(path: string) {
  const fd = openSync(path, constants.O_RDONLY);
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}
function exclusiveFile(path: string, bytes: string) {
  // A fully fsynced temporary inode is linked without replacement. A crash cannot
  // leave a partial published file. The trusted local parent is not a sandbox.
  const temp = join(dirname(path), `.pending-${randomUUID()}`);
  const fd = openSync(
    temp,
    constants.O_WRONLY |
      constants.O_CREAT |
      constants.O_EXCL |
      constants.O_NOFOLLOW,
    0o600,
  );
  try {
    writeFileSync(fd, bytes, "utf8");
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  try {
    linkSync(temp, path);
    syncDirectory(dirname(path));
  } finally {
    unlinkSync(temp);
  }
}
function publication(action: Action) {
  invariant(
    action.tool.name === "review.publish" &&
      action.tool.idempotent &&
      action.args.review,
    "Not a review publication action",
  );
  invariant(
    hashPattern.test(action.key) &&
      action.payloadDigest ===
        digest({ tenant: action.tenant, tool: action.tool, args: action.args }),
    "Review payload digest mismatch",
  );
  const payload = action.args.review;
  directory(payload.outputDirectory);
  const files: Record<string, string> = {
    "review.md": payload.markdown,
    "review.json": payload.json,
  };
  const manifest: Manifest = {
    schemaVersion: "kev-delivery/v1",
    tenant: action.tenant,
    key: action.key,
    payloadDigest: action.payloadDigest,
    files: Object.fromEntries(
      Object.entries(files).map(([name, body]) => [name, sha256Bytes(body)]),
    ),
  };
  return {
    path: join(payload.outputDirectory, `review-${action.key}`),
    files,
    manifest,
  };
}
function verifyOwner(path: string, manifest: Manifest) {
  directory(path);
  invariant(
    readRegular(join(path, ".owner.json")).toString("utf8") ===
      canonical(manifest) + "\n",
    "Existing directory is not owned by this approved publication",
  );
}
function receipt(action: Action): Receipt {
  return {
    tenant: action.tenant,
    key: action.key,
    payloadDigest: action.payloadDigest,
    ticketId: `review-${action.key}`,
  };
}
export function inspectPublication(
  action: Action,
): { path: string; files: Record<string, string>; receipt: Receipt } | null {
  const pub = publication(action);
  if (!existsSync(pub.path)) return null;
  verifyOwner(pub.path, pub.manifest);
  let missing = false;
  for (const [name, hash] of Object.entries(pub.manifest.files)) {
    const path = join(pub.path, name);
    if (!existsSync(path)) {
      missing = true;
      continue;
    }
    invariant(
      sha256Bytes(readRegular(path)) === hash,
      `Published artifact changed: ${name}`,
    );
  }
  const marker = join(pub.path, "manifest.json");
  if (!existsSync(marker)) return null;
  invariant(
    !missing &&
      readRegular(marker).toString("utf8") === canonical(pub.manifest) + "\n",
    "Publication manifest or files changed",
  );
  return {
    path: pub.path,
    files: pub.manifest.files,
    receipt: receipt(action),
  };
}
/** Only creates this action's directory; never replaces an existing artifact. */
export function fileReviewConnector(): Connector {
  return {
    async lookup(action) {
      return inspectPublication(action)?.receipt ?? null;
    },
    async submit(action) {
      const pub = publication(action);
      if (existsSync(pub.path)) {
        verifyOwner(pub.path, pub.manifest);
        const existing = inspectPublication(action);
        if (existing) return existing.receipt;
      } else {
        mkdirSync(pub.path, { mode: 0o700 });
        syncDirectory(dirname(pub.path));
        exclusiveFile(
          join(pub.path, ".owner.json"),
          canonical(pub.manifest) + "\n",
        );
      }
      for (const [name, body] of Object.entries(pub.files)) {
        const path = join(pub.path, name);
        if (!existsSync(path)) exclusiveFile(path, body);
        invariant(
          sha256Bytes(readRegular(path)) === pub.manifest.files[name],
          `Existing artifact changed: ${name}`,
        );
      }
      exclusiveFile(
        join(pub.path, "manifest.json"),
        canonical(pub.manifest) + "\n",
      );
      const verified = inspectPublication(action);
      invariant(verified, "Publication verification failed");
      return verified.receipt;
    },
  };
}
