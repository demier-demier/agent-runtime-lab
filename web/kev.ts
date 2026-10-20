interface KevRecord {
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
interface EvidenceReport {
  schemaVersion: string;
  evidenceSha256: string;
  evidence: {
    query: string;
    documents: KevRecord[];
    source: {
      url: string;
      retrievedAt: string;
      sha256: string;
      catalogVersion: string;
      totalRecords?: number;
      license?: string;
    };
  };
  modelDraft: {
    model: string;
    provider: string;
    claims: { text: string; citations: string[] }[];
    usage?: {
      inputTokens?: number;
      outputTokens?: number;
      durationMs?: number;
      networkFetchCalls?: number;
    };
    validation?: { citationAssignment?: string };
  } | null;
}
interface ObservedDelivery {
  schemaVersion: string;
  observedAt: string;
  finalVerificationStatus: string;
  publicationCount: number;
  dispatchAttempts: number;
  crashExitCode: number;
  interruptedOutboxStatus: string;
  resumedStatus: string;
  originalFileInodePreserved: boolean;
  originalFileMtimePreserved: boolean;
  artifactHashes: Record<string, string>;
  evidenceChain: { valid: boolean; head: string };
  eventTypes: string[];
}
const el = <T extends HTMLElement = HTMLElement>(id: string) => {
  const found = document.getElementById(id);
  if (!found) throw new Error(`Missing page element: ${id}`);
  return found as T;
};
const set = (id: string, value: unknown) => {
  el(id).textContent = String(value);
};
function node(tag: string, value?: string, className?: string): HTMLElement {
  const result = document.createElement(tag);
  if (value !== undefined) result.textContent = value;
  if (className) result.className = className;
  return result;
}
function safeLink(url: string, title: string): HTMLAnchorElement {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:" || parsed.username || parsed.password)
    throw new Error("Invalid public source URL");
  const a = document.createElement("a");
  a.textContent = title;
  a.href = parsed.href;
  a.target = "_blank";
  a.rel = "noopener noreferrer";
  return a;
}
async function sha256(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}
async function fetchBytes(name: string): Promise<Uint8Array<ArrayBuffer>> {
  const response = await fetch(`./kev-data/${name}`, { cache: "no-store" });
  if (!response.ok) throw new Error(`${name}: HTTP ${response.status}`);
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.byteLength > 512_000)
    throw new Error(`${name} exceeds viewer limit`);
  return bytes;
}
const decode = (bytes: Uint8Array) =>
  new TextDecoder("utf-8", { fatal: true }).decode(bytes);
function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    const result = JSON.stringify(value);
    if (result === undefined) throw new Error("Invalid evidence JSON");
    return result;
  }
  if (Array.isArray(value))
    return "[" + value.map(canonicalJson).join(",") + "]";
  return (
    "{" +
    Object.keys(value)
      .sort()
      .map(
        (key) =>
          JSON.stringify(key) +
          ":" +
          canonicalJson((value as Record<string, unknown>)[key]),
      )
      .join(",") +
    "}"
  );
}
function facts(target: HTMLElement, entries: [string, string][]) {
  for (const [key, value] of entries) {
    const row = node("div");
    row.append(node("dt", key), node("dd", value));
    target.append(row);
  }
}
let report: EvidenceReport | null = null;
let checking = false;

function renderRecords() {
  if (!report) return;
  const query = el<HTMLInputElement>("record-filter")
    .value.trim()
    .toLowerCase();
  const selected = report.evidence.documents.filter((d) =>
    [d.cveID, d.title, d.record.vendorProject, d.record.product]
      .join(" ")
      .toLowerCase()
      .includes(query),
  );
  const target = el("records");
  target.replaceChildren();
  set(
    "filter-count",
    `${selected.length} of ${report.evidence.documents.length} retrieved records`,
  );
  for (const d of selected) {
    const details = node("details", undefined, "record");
    const summary = node("summary");
    summary.append(
      node("strong", d.cveID, "record-title"),
      node(
        "span",
        `${d.record.vendorProject} / ${d.record.product}`,
        "record-product",
      ),
    );
    const body = node("div", undefined, "record-body");
    body.append(
      node(
        "p",
        `Added to KEV: ${d.record.dateAdded} · CISA due date: ${d.record.dueDate}`,
      ),
      node(
        "p",
        `Ransomware campaign use: ${d.record.knownRansomwareCampaignUse ?? "Not supplied"}`,
      ),
      node("p", d.text, "excerpt"),
      node("p", `Catalog required action: ${d.record.requiredAction}`),
      safeLink(d.sourceUrl, "Inspect the CISA source ↗"),
      node(
        "p",
        "Local asset match, exposure and remediation status: not assessed.",
      ),
    );
    details.append(summary, body);
    target.append(details);
  }
  if (!selected.length)
    target.append(node("p", "No retrieved records match this filter.", "hint"));
}

function renderDraft(value: EvidenceReport["modelDraft"]) {
  const target = el("draft-content");
  target.replaceChildren();
  if (!value) {
    target.append(
      node("p", "This recorded delivery did not use a model draft.", "hint"),
    );
    return;
  }
  target.append(
    node("p", value.model, "model-name"),
    node("p", `Recorded provider: ${value.provider}`, "hint"),
  );
  for (const claim of value.claims) {
    const block = node("div", undefined, "model-claim");
    block.append(
      node("p", claim.text),
      node("p", `Citation IDs: ${claim.citations.join(", ")}`, "citations"),
    );
    target.append(block);
  }
  const usage = value.usage;
  if (usage) {
    const list = node("dl", undefined, "facts");
    const entries: [string, string][] = [];
    if (usage.inputTokens !== undefined && usage.outputTokens !== undefined)
      entries.push([
        "Tokens",
        `${usage.inputTokens} input / ${usage.outputTokens} output`,
      ]);
    if (usage.durationMs !== undefined)
      entries.push([
        "Generation",
        `${(usage.durationMs / 1000).toFixed(2)} s in this local run`,
      ]);
    if (usage.networkFetchCalls !== undefined)
      entries.push([
        "Network calls",
        `${usage.networkFetchCalls} during measured inference`,
      ]);
    facts(list, entries);
    target.append(list);
  }
  target.append(
    node(
      "p",
      "This is recorded output from a local model, not live browser inference. Citations identify supplied evidence; they do not prove semantic accuracy or applicability.",
      "hint",
    ),
  );
  if (
    value.validation?.citationAssignment ===
    "single-input-source-bound-by-application"
  )
    target.append(
      node(
        "p",
        "Citation assignment: the application bound the single supplied source to this draft.",
        "hint",
      ),
    );
}

async function loadAndVerify() {
  if (checking) return;
  checking = true;
  const button = el<HTMLButtonElement>("verify-files");
  button.disabled = true;
  el("notice").classList.remove("error");
  set("notice", "Reading the published files and recomputing their hashes…");
  try {
    const [observedBytes, jsonBytes, markdownBytes] = await Promise.all([
      fetchBytes("observed-delivery.json"),
      fetchBytes("review.json"),
      fetchBytes("review.md"),
    ]);
    const observed = JSON.parse(decode(observedBytes)) as ObservedDelivery;
    const candidate = JSON.parse(decode(jsonBytes)) as EvidenceReport;
    if (
      observed.schemaVersion !== "observed-kev-workflow/v1" ||
      candidate.schemaVersion !== "kev-review/v1"
    )
      throw new Error("Unrecognized evidence schema");
    const hashes = await Promise.all([
      sha256(jsonBytes),
      sha256(markdownBytes),
    ]);
    const pairs: [string, string][] = [
      ["review.json", hashes[0]],
      ["review.md", hashes[1]],
    ];
    for (const [name, hash] of pairs)
      if (observed.artifactHashes[name] !== hash)
        throw new Error(`${name} differs from the published execution record`);
    const packetHash = await sha256(
      new TextEncoder().encode(canonicalJson(candidate.evidence)),
    );
    if (packetHash !== candidate.evidenceSha256)
      throw new Error("Evidence packet digest does not match");
    for (const d of candidate.evidence.documents) {
      if ((await sha256(new TextEncoder().encode(d.text))) !== d.contentSha256)
        throw new Error(`Source text digest mismatch: ${d.id}`);
    }
    report = candidate;
    set("final-state", observed.finalVerificationStatus);
    set("publication-count", observed.publicationCount);
    set("attempt-count", observed.dispatchAttempts);
    set("document-count", candidate.evidence.documents.length);
    set(
      "observed-at",
      `Observed ${observed.observedAt.replace("T", " ").replace("Z", " UTC")}`,
    );
    set(
      "crash-observation",
      `Process exit ${observed.crashExitCode}, after files were written. The persisted outbox still read “${observed.interruptedOutboxStatus}”.`,
    );
    set(
      "recovery-observation",
      `Restart reached “${observed.resumedStatus}” with ${observed.publicationCount} publication and ${observed.dispatchAttempts} dispatch attempt.`,
    );
    set(
      "file-observation",
      `Original file inode preserved: ${observed.originalFileInodePreserved ? "yes" : "no"}. Modification time preserved: ${observed.originalFileMtimePreserved ? "yes" : "no"}.`,
    );
    set(
      "chain-observation",
      `Recorded chain verification: ${observed.evidenceChain.valid ? "valid" : "invalid"}. ${observed.eventTypes.length} persisted events.`,
    );
    const events = el("event-sequence");
    events.replaceChildren(
      ...observed.eventTypes.map((type) => node("li", type)),
    );
    set("query", candidate.evidence.query);
    const source = candidate.evidence.source;
    const provenance = el("source-facts");
    provenance.replaceChildren();
    facts(provenance, [
      ["Catalog", source.catalogVersion],
      ["Retrieved", source.retrievedAt.replace("T", " ").replace("Z", " UTC")],
      [
        "Source records",
        source.totalRecords?.toLocaleString("en-US") ?? "Not supplied",
      ],
      ["License", source.license ?? "See source"],
    ]);
    const link = safeLink(source.url, "Open the exact source snapshot ↗");
    el<HTMLAnchorElement>("catalog-source").href = link.href;
    set("catalog-hash", source.sha256);
    set("packet-hash", packetHash);
    renderRecords();
    renderDraft(candidate.modelDraft);
    set("report-preview", decode(markdownBytes));
    const checks = el("hash-checks");
    checks.replaceChildren();
    for (const [name, hash] of pairs) {
      const check = node("div", undefined, "hash-check");
      check.append(
        node("span", `✓ ${name} — SHA-256 matches the execution record`),
        node("code", hash),
      );
      checks.append(check);
    }
    set(
      "notice",
      `Verified in this browser: both downloadable report files, the evidence packet and ${candidate.evidence.documents.length} source-text hashes match. Execution results below are from the recorded local run.`,
    );
  } catch (error) {
    el("notice").classList.add("error");
    set(
      "notice",
      `Evidence could not be verified: ${(error as Error).message}. Use the source repository to inspect the published files.`,
    );
    el("hash-checks").replaceChildren();
  } finally {
    checking = false;
    button.disabled = false;
  }
}
el("record-filter").addEventListener("input", renderRecords);
el("verify-files").addEventListener("click", () => void loadAndVerify());
void loadAndVerify();
