// Provena proof-bundle verifier for browsers and Node (WebCrypto only, no dependencies).
// Mirrors provena.core.verify; shares the golden vectors in tests/vectors. Full-mode bundles are
// replayed through the same state-machine rules as the Python reference (replayState below).
// RFC 3161 anchor tokens are verified here too (static/rfc3161.js).

import { inspectToken } from "./rfc3161.js";

const subtle = globalThis.crypto.subtle;
const te = new TextEncoder();

export const TAGS = {
  ENTRY_SIG: "provena/entry/v1", ENTRY_HASH: "provena/entry-hash/v1",
  COMMIT: "provena/commit/v1", AGENT_ID: "provena/agent-id/v1",
  AGENT_CARD: "provena/agent-card/v1", STH: "provena/sth/v1", COSIG: "provena/cosig/v1",
  HEAD_ID: "provena/head-id/v1", ANCHOR_LEAF: "provena/anchor-leaf/v1",
  SELF_ANCHOR: "provena/self-anchor/v1", CREDENTIAL: "provena/credential/v1",
  SET: "provena/set/v1", LOG_ROTATION: "provena/log-rotation/v1",
};

class VerificationError extends Error {}
const need = (cond, msg) => { if (!cond) throw new VerificationError(msg); };

// -- encodings ----------------------------------------------------------------------------------

export const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export function unhex(s) {
  need(typeof s === "string" && s.length % 2 === 0 && /^[0-9a-f]*$/.test(s), "bad hex");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}
export function unb64u(s) {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
}
function b32lower(bytes) {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  let bits = 0, value = 0, out = "";
  for (const byte of bytes) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += alphabet[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

// -- canonical JSON (RFC 8785 subset, no floats) ------------------------------------------------

// Lone surrogates have no UTF-8 encoding; Python rejects them, so must we.
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
const needWellFormed = (s) => need(!LONE_SURROGATE.test(s), "string is not valid Unicode");

export function canonicalize(v) {
  if (v === null || typeof v === "boolean") return JSON.stringify(v);
  if (typeof v === "number") {
    need(Number.isInteger(v) && Math.abs(v) <= Number.MAX_SAFE_INTEGER, "non-integer number");
    return String(v);
  }
  if (typeof v === "string") { needWellFormed(v); return JSON.stringify(v); }
  if (Array.isArray(v)) return "[" + v.map(canonicalize).join(",") + "]";
  if (typeof v === "object") {
    const keys = Object.keys(v).sort(); // JS sorts by UTF-16 code units, as JCS requires
    keys.forEach(needWellFormed);
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(v[k])).join(",") + "}";
  }
  throw new VerificationError("unsupported JSON value");
}
const canon = (v) => te.encode(canonicalize(v));

// -- hashing and signatures ---------------------------------------------------------------------

export async function sha256(bytes) {
  return new Uint8Array(await subtle.digest("SHA-256", bytes));
}
const tagBytes = (tag) => concat(Uint8Array.of(te.encode(tag).length), te.encode(tag));
export async function tagged(tag, ...parts) { return sha256(concat(tagBytes(tag), ...parts)); }

async function edVerify(pub, tag, payload, sig) {
  const key = await subtle.importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]);
  return subtle.verify({ name: "Ed25519" }, key, sig, concat(tagBytes(tag), payload));
}

export async function agentId(signPub) {
  return "pv1a" + b32lower(await tagged(TAGS.AGENT_ID, signPub)).slice(0, 32);
}

export async function verifyCard(card) {
  const body = { ...card };
  delete body.sig;
  const pub = unhex(card.sign);
  need((await agentId(pub)) === card.id, "agent id does not match signing key");
  need(await edVerify(pub, TAGS.AGENT_CARD, canon(body), unhex(card.sig)),
    `bad agent card signature for ${card.id}`);
  return { id: card.id, sign: pub, kem: unhex(card.kem) };
}

// -- entries ------------------------------------------------------------------------------------

const FIELDS = ["v", "project", "kind", "author", "prev", "refs", "body", "sealed", "ts", "sig"];
const KINDS = ["genesis", "entity", "activity", "plan", "reveal", "attest", "member", "key",
  "redact", "grant", "meta"];

export async function entryHash(entry) { return hex(await tagged(TAGS.ENTRY_HASH, canon(entry))); }
async function entryLeaf(entry) { return leafHash(unhex(await entryHash(entry))); }

// Mirrors provena.core.entries.check_shape exactly (structure at the trust boundary).
const HEX64_RE = /^[0-9a-f]{64}$/;
const isHex64 = (v) => typeof v === "string" && HEX64_RE.test(v);
function checkShape(e) {
  need(e !== null && typeof e === "object" && !Array.isArray(e) &&
    Object.keys(e).sort().join() === [...FIELDS].sort().join(), "entry: wrong field set");
  need(e.v === 1 && KINDS.includes(e.kind), "entry: bad version or kind");
  need((e.kind === "genesis") === (e.project === null), "entry: project/genesis mismatch");
  for (const f of ["project", "prev"]) {
    need(e[f] === null || isHex64(e[f]), `entry: ${f} must be a hex sha256 or null`);
  }
  need(Array.isArray(e.refs) && e.refs.every(isHex64), "entry: refs must be hex sha256 strings");
  need(e.body !== null && typeof e.body === "object" && !Array.isArray(e.body),
    "entry: body must be an object");
  need(e.sealed === null || typeof e.sealed === "string", "entry: sealed must be a string or null");
  need(Number.isSafeInteger(e.ts) && e.ts >= 0, "entry: ts must be a non-negative integer");
  need(typeof e.sig === "string" && /^[0-9a-f]{128}$/.test(e.sig), "entry: malformed signature");
  canonicalize(e); // every nested value must be canonicalizable
}

async function verifyEntrySig(entry, pub) {
  checkShape(entry);
  need(pub.id === entry.author, "entry: author key mismatch");
  const unsigned = { ...entry };
  delete unsigned.sig;
  need(await edVerify(pub.sign, TAGS.ENTRY_SIG, canon(unsigned), unhex(entry.sig)),
    `bad entry signature by ${entry.author}`);
}

// -- Merkle (RFC 9162) --------------------------------------------------------------------------

export const leafHash = (data) => sha256(concat(Uint8Array.of(0), data));
const nodeHash = (l, r) => sha256(concat(Uint8Array.of(1), l, r));

export async function merkleRoot(leaves) {
  if (leaves.length === 0) return sha256(new Uint8Array());
  if (leaves.length === 1) return leaves[0];
  let k = 1;
  while (k << 1 < leaves.length) k <<= 1;
  return nodeHash(await merkleRoot(leaves.slice(0, k)), await merkleRoot(leaves.slice(k)));
}

// Indexes must be integers below 2^31: the shifts below are 32-bit in JavaScript.
const isIdx = (n) => Number.isInteger(n) && n >= 0 && n < 2 ** 31;

export async function verifyInclusion(leaf, index, size, proof, root) {
  need(isIdx(index) && isIdx(size) && index < size, "inclusion: index out of range");
  let fn = index, sn = size - 1, r = leaf;
  for (const p of proof) {
    need(sn !== 0, "inclusion: proof too long");
    if (fn & 1 || fn === sn) {
      r = await nodeHash(p, r);
      if (!(fn & 1)) while (!(fn & 1) && fn !== 0) { fn >>= 1; sn >>= 1; }
    } else r = await nodeHash(r, p);
    fn >>= 1; sn >>= 1;
  }
  need(sn === 0 && eq(r, root), "inclusion: root mismatch");
}

export async function verifyConsistency(first, second, firstRoot, secondRoot, proof) {
  need(isIdx(first) && isIdx(second) && first > 0 && first <= second,
    "consistency: invalid sizes");
  if (first === second) {
    need(proof.length === 0 && eq(firstRoot, secondRoot), "consistency: equal sizes differ");
    return;
  }
  const path = [...proof];
  if ((first & (first - 1)) === 0) path.unshift(firstRoot);
  need(path.length > 0, "consistency: empty proof");
  let fn = first - 1, sn = second - 1;
  while (fn & 1) { fn >>= 1; sn >>= 1; }
  let fr = path[0], sr = path[0];
  for (const c of path.slice(1)) {
    need(sn !== 0, "consistency: proof too long");
    if (fn & 1 || fn === sn) {
      fr = await nodeHash(c, fr); sr = await nodeHash(c, sr);
      if (!(fn & 1)) while (!(fn & 1) && fn !== 0) { fn >>= 1; sn >>= 1; }
    } else sr = await nodeHash(sr, c);
    fn >>= 1; sn >>= 1;
  }
  need(sn === 0 && eq(fr, firstRoot) && eq(sr, secondRoot), "consistency: root mismatch");
}

// -- heads, cosignatures, anchors ---------------------------------------------------------------

const HEAD_FIELDS = ["v", "project", "size", "root", "time", "signer"];
const pick = (o, keys) => Object.fromEntries(keys.map((k) => [k, o[k]]));

async function verifyHead(head, pub) {
  need(Object.keys(head).sort().join() === [...HEAD_FIELDS, "sig"].sort().join(),
    "tree head: malformed");
  need(Number.isSafeInteger(head.size) && Number.isSafeInteger(head.time), "tree head: bad numbers");
  need(head.v === 1 && head.signer === pub.id, "tree head: malformed or wrong signer");
  need(await edVerify(pub.sign, TAGS.STH, canon(pick(head, HEAD_FIELDS)), unhex(head.sig)),
    "tree head: bad signature");
}
const headId = async (head) => hex(await tagged(TAGS.HEAD_ID, canon(head)));

async function verifyCosig(c, head, pub) {
  need(c.witness === pub.id && c.head === (await headId(head)), "cosignature: wrong head/witness");
  need(await edVerify(pub.sign, TAGS.COSIG, canon(pick(c, ["v", "head", "witness", "time"])),
    unhex(c.sig)), "cosignature: bad signature");
}

const anchorLeaf = async (head) => leafHash(await tagged(TAGS.ANCHOR_LEAF, canon(head)));


// -- state machine replay (mirrors provena.core.state; full bundles only) ------------------------
// Proves authorization: every entry was written by an active member allowed to write it, author
// chains are unbroken, keys/epochs/wraps follow the rules. Kept rule-for-rule with the Python
// reference; tests/test_js_verifier.py replays the same rule-breaking logs through both.

const ROLES = ["owner", "maintainer", "contributor", "reviewer", "viewer"];
const WRITERS = ["owner", "maintainer", "contributor"];
const ADMINS = ["owner", "maintainer"];
const ATTEST_TYPES = ["review", "replicate", "calibration", "endorse", "dispute", "capture",
  "operator"];
const HEX64 = /^[0-9a-f]{64}$/;
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const sameSet = (keys, set) => keys.length === set.size && keys.every((k) => set.has(k));
const META_LIMITS = { title: 200, description: 4000, license: 64 };

// Lengths count Unicode code points, as Python's len() does (not UTF-16 units).
const cpLen = (str) => [...str].length;
const BODY_FIELDS = {
  genesis: ["policy", "members", "epoch", "wraps", "meta"],
  entity: ["commitment", "cid", "size", "epoch", "dek", "capture"],
  plan: ["commitment", "cid", "size", "epoch", "dek"],
  activity: ["used", "generated", "plan", "epoch", "external"],
  reveal: ["target", "salt", "plain_sha256", "dek", "name"],
  attest: ["target", "type", "verdict", "epoch"],
  redact: ["target", "reason"],
  grant: ["target", "to", "wrap"],
  meta: ["title", "description", "license", "tags"],
  member: ["action", "card", "role", "wraps", "agent", "epoch"],
  key: ["action", "epoch", "wraps", "card", "epoch_wraps"],
};
// ADR 0009: rules 2 only add fields and actions; rules 1 stay frozen.
const RULES_VERSIONS = [1, 2];
const BODY_FIELDS_V2 = { ...BODY_FIELDS,
  activity: [...BODY_FIELDS.activity, "status", "commitment"],
  reveal: [...BODY_FIELDS.reveal, "details"],
  member: [...BODY_FIELDS.member, "epoch_wraps"] };
const STEP_STATUS = ["ok", "failed"];
// a revealed step must not contradict its public status (exit code 0 = ok, else failed)
const statusMatches = (status, d) => !Number.isInteger(d.exit_code) ||
  status === (d.exit_code === 0 ? "ok" : "failed");
const checkBodyFields = (e, rules = 1) => need(Object.keys(e.body).every((k) =>
  (rules === 1 ? BODY_FIELDS : BODY_FIELDS_V2)[e.kind].includes(k)),
`${e.kind} body has unknown fields`);
// the tables docs/spec/rules.json fixes (tests compare them)
export const RULES_TABLES = { ROLES, ATTEST_TYPES, META_LIMITS, BODY_FIELDS, BODY_FIELDS_V2,
  RULES_VERSIONS, STEP_STATUS };

function checkCapture(c) {
  need(isObj(c) && Object.keys(c).every((k) => ["by", "file_mtime", "observed"].includes(k)),
    "capture must be {by, file_mtime, observed}");
  need(c.by === undefined || typeof c.by === "string", "capture.by must be a string");
  for (const k of ["file_mtime", "observed"]) {
    need(c[k] === undefined || (Number.isSafeInteger(c[k]) && c[k] >= 0), `capture.${k} invalid`);
  }
}

function checkMeta(m) {
  need(isObj(m), "meta must be an object");
  need(Object.keys(m).every((k) => Object.hasOwn(META_LIMITS, k) || k === "tags"),
    "meta: unknown field");
  for (const [k, lim] of Object.entries(META_LIMITS)) {
    if (Object.hasOwn(m, k)) need(typeof m[k] === "string" && cpLen(m[k]) <= lim, `meta.${k} invalid`);
  }
  const tags = Object.hasOwn(m, "tags") ? m.tags : [];
  need(Array.isArray(tags) && tags.length <= 20 &&
    tags.every((t) => typeof t === "string" && cpLen(t) > 0 && cpLen(t) <= 40), "meta.tags invalid");
}

export async function replayState(log) {
  need(log.length > 0, "empty log");
  const st = { members: new Map(), epoch: 0, wraps: new Map(), entries: new Map(),
    position: new Map(), heads: new Map(), reveals: new Map(), redacted: new Set(),
    cids: new Set(), generatedBy: new Set(), project: null };
  const active = () => new Set([...st.members].filter(([, m]) => m.active).map(([id]) => id));
  const roleOf = (id) => { const m = st.members.get(id); return m && m.active ? m.role : null; };
  const addMember = async (card, role) => {
    need(isObj(card), "member card required");
    need(ROLES.includes(role), "unknown role");
    const pub = await verifyCard(card);
    need(!st.members.has(pub.id), "agent was already a member");
    st.members.set(pub.id, { pub, role, active: true });
    return pub;
  };
  const member = (id) => { const m = st.members.get(id); need(m && m.active, "not an active member"); return m; };
  const ownerLeft = () => need([...st.members.values()].some((m) => m.active && m.role === "owner"),
    "a project must keep at least one owner");
  const setWraps = (epoch, wraps) => {
    need(isObj(wraps) && Object.values(wraps).every((v) => typeof v === "string"), "wraps invalid");
    need(sameSet(Object.keys(wraps), active()), "epoch key must be wrapped for exactly the active members");
    st.wraps.set(epoch, { ...wraps });
  };
  const rotate = (epoch, wraps) => {
    need(Number.isInteger(epoch) && epoch === st.epoch + 1, "key epochs must increase by one");
    setWraps(epoch, wraps);
    st.epoch = epoch;
  };
  const target = (h, kinds, what) => {
    need(typeof h === "string" && HEX64.test(h), `${what} must be hex sha256`);
    const t = st.entries.get(h);
    need(t, `${what} not found in project`);
    need(kinds.includes(t.kind), `${what} has the wrong kind`);
    return t;
  };
  const contentBody = (b, requireBlob) => {
    need(typeof b.commitment === "string" && HEX64.test(b.commitment), "commitment must be hex");
    const hasBlob = b.cid !== undefined && b.cid !== null;
    need(hasBlob || !requireBlob, "entity requires a cid");
    if (hasBlob) {
      need(typeof b.cid === "string" && HEX64.test(b.cid), "cid must be hex");
      need(!st.cids.has(b.cid), "cid is already registered in this project");
      need(Number.isInteger(b.size) && b.size >= 0, "size must be int");
      need(typeof b.dek === "string", "dek wrap required with a blob");
      need(Number.isInteger(b.epoch) && b.epoch === st.epoch, "new content must use the current epoch");
    }
  };
  const record = async (e, h, successor) => {
    st.entries.set(h, e);
    st.position.set(h, st.position.size);
    st.heads.set(e.author, h);
    if (successor) st.heads.set(successor, h);
    if ((e.kind === "entity" || e.kind === "plan") && e.body.cid != null) st.cids.add(e.body.cid);
    if (e.kind === "activity") for (const g of e.body.generated || []) st.generatedBy.add(g);
  };

  // genesis
  const g = log[0];
  checkShape(g);
  need(g.kind === "genesis", "first entry must be genesis");
  need(g.prev === null && g.refs.length === 0, "genesis has no prev/refs");
  const policy = g.body.policy;
  need(isObj(policy) && Object.keys(policy).every((k) =>
    ["visibility", "witnesses", "rules"].includes(k)) &&
    ["private", "public"].includes(policy.visibility), "genesis: bad policy");
  need(policy.witnesses === undefined || Number.isInteger(policy.witnesses), "genesis: witnesses");
  const rules = Object.hasOwn(policy, "rules") ? policy.rules : 1;  // null is not "absent"
  need(RULES_VERSIONS.includes(rules), `genesis: unknown ledger rules ${rules}`);
  checkBodyFields(g, rules);
  st.project = await entryHash(g);
  for (const m of g.body.members || []) await addMember(m.card, m.role);
  const ga = st.members.get(g.author);
  need(ga && ga.role === "owner", "genesis author must be an owner");
  await verifyEntrySig(g, ga.pub);
  if (Object.hasOwn(g.body, "meta")) checkMeta(g.body.meta);
  setWraps(0, g.body.wraps);
  await record(g, st.project);

  for (const e of log.slice(1)) {
    checkShape(e);
    const h = await entryHash(e);
    need(!st.entries.has(h), "duplicate entry");
    need(e.project === st.project, "entry belongs to another project");
    need(e.kind !== "genesis", "second genesis");
    checkBodyFields(e, rules);
    const role = roleOf(e.author);
    need(role !== null, `author ${e.author} is not an active member`);
    await verifyEntrySig(e, st.members.get(e.author).pub);
    need(e.prev === (st.heads.get(e.author) ?? null), "prev does not match the author's chain");
    for (const r of e.refs) need(st.entries.has(r), "ref is not in this project");
    if (e.sealed !== null) {
      need(e.body.epoch !== undefined && e.body.epoch !== null, "sealed entries must name epoch");
    }
    if (e.body.epoch !== undefined && e.body.epoch !== null && e.sealed !== null) {
      need(Number.isInteger(e.body.epoch) && st.wraps.has(e.body.epoch), "unknown epoch");
    }
    const b = e.body;
    let successor = null;
    switch (e.kind) {
      case "entity":
        need(WRITERS.includes(role), "role cannot register data");
        if (Object.hasOwn(b, "capture")) checkCapture(b.capture);
        contentBody(b, true);
        break;
      case "plan": need(WRITERS.includes(role), "role cannot register plans"); contentBody(b, false); break;
      case "activity": {
        need(WRITERS.includes(role), "role cannot record activities");
        for (const key of ["used", "generated"]) {
          const items = b[key] === undefined ? [] : b[key];
          need(Array.isArray(items), `activity.${key} must be a list`);
          for (const t of items) { target(t, ["entity"], `activity.${key}`); need(e.refs.includes(t), "targets must be in refs"); }
        }
        const used = b.used || [], gen = b.generated || [];
        const ext = b.external === undefined ? [] : b.external;
        need(Array.isArray(ext) && ext.length <= 100 && ext.every((x) => isObj(x) &&
          Object.keys(x).sort().join() === "entry,project" && isHex64(x.project) &&
          isHex64(x.entry) && x.project !== st.project),
        "activity.external must list {project, entry} of other projects");
        need(used.length > 0 || gen.length > 0 || ext.length > 0,
          "activity must use or generate something");
        for (const x of gen) {
          need(!st.generatedBy.has(x), "entity was already generated by another activity");
          need(ADMINS.includes(role) || st.entries.get(x).author === e.author,
            "only the entity's author or an admin can record what generated it");
        }
        if (b.plan !== undefined && b.plan !== null) {
          target(b.plan, ["plan"], "activity.plan");
          need(e.refs.includes(b.plan), "activity.plan must be listed in refs");
          const at = st.position.get(b.plan);
          need(gen.every((x) => st.position.get(x) > at), "generated entities must follow the plan");
        }
        need(!used.some((u) => gen.includes(u)), "an entity cannot be both used and generated");
        if (rules >= 2) {
          need(STEP_STATUS.includes(b.status), "activity.status must be ok|failed");
          need(isHex64(b.commitment), "activity.commitment must be hex sha256");
        }
        break;
      }
      case "reveal": {
        const t = target(b.target, rules >= 2 ? ["entity", "plan", "activity"] : ["entity", "plan"],
          "reveal.target");
        need(ADMINS.includes(role) || t.author === e.author, "only the author or an admin can reveal");
        const earlier = st.reveals.get(b.target);
        if (earlier !== undefined) {
          need(rules >= 2 && t.kind !== "activity" && !earlier.dek && b.dek &&
            b.salt === earlier.salt && b.plain_sha256 === earlier.plain_sha256, "already revealed");
        }
        if (t.kind === "activity") {
          need(Object.hasOwn(t.body, "commitment"), "this activity has no commitment to open");
          need(!b.dek, "an activity has no content key");
          if (Object.hasOwn(b, "details")) {
            need(isObj(b.details), "reveal.details must be an object");
            need(hex(await sha256(new TextEncoder().encode(canonicalize(b.details)))) ===
              b.plain_sha256, "reveal.details do not match the opened commitment");
            need(statusMatches(t.body.status, b.details),
              "the step's public status contradicts its revealed exit code");
          }
        } else need(!Object.hasOwn(b, "details"), "only an activity reveal carries details");
        need(!st.redacted.has(b.target), "cannot reveal redacted content");
        need(e.refs.includes(b.target), "reveal.target must be listed in refs");
        need(!Object.hasOwn(b, "name") || (typeof b.name === "string" && cpLen(b.name) > 0 &&
          cpLen(b.name) <= 255), "reveal.name must be a short string");
        need(typeof b.salt === "string" && HEX64.test(b.salt) && typeof b.plain_sha256 === "string" &&
          HEX64.test(b.plain_sha256), "reveal opening must be hex");
        need(hex(await tagged(TAGS.COMMIT, unhex(b.salt), unhex(b.plain_sha256))) === t.body.commitment,
          "commitment opening does not match");
        st.reveals.set(b.target, { ...(earlier || {}), ...b });
        break;
      }
      case "attest":
        need(role !== "viewer", "viewers cannot attest");
        target(b.target, KINDS, "attest.target");
        need(e.refs.includes(b.target), "attest.target must be listed in refs");
        need(ATTEST_TYPES.includes(b.type), "attest.type invalid");
        need([undefined, null, "pass", "fail", "inconclusive"].includes(b.verdict), "attest.verdict invalid");
        break;
      case "redact": {
        const t = target(b.target, ["entity", "plan"], "redact.target");
        need(ADMINS.includes(role) || t.author === e.author, "only the author or an admin can redact");
        need(e.refs.includes(b.target), "redact.target must be listed in refs");
        need(typeof b.reason === "string" && b.reason.length > 0, "redact.reason required");
        st.redacted.add(b.target);
        break;
      }
      case "grant": {
        const t = target(b.target, ["entity", "plan"], "grant.target");
        need(ADMINS.includes(role) || t.author === e.author, "only the author or an admin can share");
        need(e.refs.includes(b.target), "grant.target must be listed in refs");
        need(!st.redacted.has(b.target), "cannot share redacted content");
        need(typeof b.wrap === "string", "grant.wrap required");
        need(isObj(b.to), "grant.to must be a card");
        await verifyCard(b.to);
        break;
      }
      case "meta": need(ADMINS.includes(role), "only owners/maintainers edit the project card"); checkMeta(b); break;
      case "member": {
        need(ADMINS.includes(role), "only owners/maintainers manage members");
        if (b.action === "add") {
          need(role === "owner" || b.role !== "owner", "only owners can add owners");
          const pub = await addMember(b.card, b.role);
          need(isObj(b.wraps) && sameSet(Object.keys(b.wraps), new Set([pub.id])),
            "member.add must wrap the current epoch key for the new member only");
          st.wraps.get(st.epoch)[pub.id] = b.wraps[pub.id];
        } else if (b.action === "remove") {
          const t = member(b.agent);
          need(role === "owner" || t.role !== "owner", "only owners can remove owners");
          t.active = false;
          ownerLeft();
          rotate(b.epoch, b.wraps);
        } else if (b.action === "role") {
          const t = member(b.agent);
          need(ROLES.includes(b.role), "unknown role");
          need(role === "owner" || (t.role !== "owner" && b.role !== "owner"),
            "only owners can grant or change owner");
          t.role = b.role;
          ownerLeft();
        } else if (b.action === "rewrap" && rules >= 2) {
          const t = member(b.agent);
          need(t.active, "rewrap is for an active member");
          const readable = new Set([...st.wraps].filter(([, w]) => Object.hasOwn(w, e.author))
            .map(([ep]) => String(ep)));
          need(isObj(b.epoch_wraps) && Object.keys(b.epoch_wraps).length > 0 &&
            Object.keys(b.epoch_wraps).every((ep) => readable.has(ep)),
          "member.rewrap may only share epoch keys its author can read");
          for (const [ep, w] of Object.entries(b.epoch_wraps)) {
            need(typeof w === "string", "member.rewrap wraps must be sealed keys");
            const wraps = st.wraps.get(Number(ep));
            need(!Object.hasOwn(wraps, t.pub.id), `member already holds the key of epoch ${ep}`);
            wraps[t.pub.id] = w;
          }
        } else throw new VerificationError("unknown member action");
        break;
      }
      case "key": {
        if (b.action === "rotate") {
          need(ADMINS.includes(role), "only owners/maintainers rotate project keys");
          rotate(b.epoch, b.wraps);
        } else if (b.action === "succeed") {
          const old = st.members.get(e.author);
          const pub = await addMember(b.card, old.role);
          old.active = false;
          const readable = new Set([...st.wraps].filter(([, w]) => Object.hasOwn(w, e.author))
            .map(([ep]) => String(ep)));
          need(isObj(b.epoch_wraps) && sameSet(Object.keys(b.epoch_wraps), readable),
            "key.succeed must re-wrap exactly the epoch keys the old key could read");
          for (const [ep, w] of Object.entries(b.epoch_wraps)) st.wraps.get(Number(ep))[pub.id] = w;
          successor = pub.id;
        } else throw new VerificationError("unknown key action");
        break;
      }
      default: throw new VerificationError("unknown kind");
    }
    await record(e, h, successor);
  }
  return st;
}

// -- bundle verification ------------------------------------------------------------------------

const CLOCK_SKEW_MS = 300000; // tolerated hub-vs-TSA clock difference
const iso = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");

function keyIntros(entry) {
  const b = entry.body;
  if (entry.kind === "genesis") return b.members.map((m) => m.card);
  if ((entry.kind === "member" && b.action === "add") ||
      (entry.kind === "key" && b.action === "succeed")) return [b.card];
  return [];
}

export async function verifyBundle(bundle, opts = {}) {
  const report = { ok: false, trust: "", facts: [], notes: [], errors: [], verified: {},
    preregistration: [],
    project: bundle && bundle.project,
    targets: bundle && Array.isArray(bundle.targets) ? bundle.targets : [] };
  try {
    opts = await followRotations(bundle, report, opts);
    await verify(bundle, report, opts);
    await credentialFacts(bundle, report, opts.trustedOrgs || []);
    await externalFacts(bundle, report, opts);
    report.ok = true;
  } catch (e) {
    report.errors.push(String(e.message || e));
  }
  return report;
}

// -- hub log key rotation (ADR 0010; mirrors provena.core.rotation) -----------------------------

const ROTATION_FIELDS = ["v", "old", "new", "time"];
const MAX_CHAIN = 64;

export async function verifyRotation(stmt) {
  need(stmt !== null && typeof stmt === "object" && !Array.isArray(stmt) &&
    Object.keys(stmt).sort().join() === [...ROTATION_FIELDS, "sig_old", "sig_new"].sort().join() &&
    stmt.v === 1 && Number.isSafeInteger(stmt.time) && stmt.time >= 0,
    "log rotation: malformed statement");
  const oldPub = await verifyCard(stmt.old), newPub = await verifyCard(stmt.new);
  need(stmt.old.kind === "hub" && stmt.new.kind === "hub" && oldPub.id !== newPub.id,
    "log rotation: both keys must be distinct hub keys");
  const msg = canon(Object.fromEntries(ROTATION_FIELDS.map((k) => [k, stmt[k]])));
  need(await edVerify(oldPub.sign, TAGS.LOG_ROTATION, msg, unhex(stmt.sig_old)),
    `bad signature from ${oldPub.id}`);
  need(await edVerify(newPub.sign, TAGS.LOG_ROTATION, msg, unhex(stmt.sig_new)),
    `bad signature from ${newPub.id}`);
  return [oldPub.id, newPub.id];
}

async function followRotations(bundle, report, opts) {
  const statements = bundle.log_rotations ?? []; // absent or null; `{}` is malformed
  need(Array.isArray(statements), "log_rotations must be a list");
  if (!statements.length) return opts;
  need(statements.length <= MAX_CHAIN, "log rotation: too many statements");
  const next = new Map();
  for (const stmt of statements) {
    const [o, n] = await verifyRotation(stmt);
    need(!next.has(o) || next.get(o) === n, `log rotation: key ${o} was handed to two successors`);
    next.set(o, n);
  }
  const trusted = [...(opts.trustedLogs || [])];
  const added = new Map();
  for (const root of trusted) {
    let at = root;
    for (let steps = 0; next.has(at) && steps < MAX_CHAIN; steps++) {
      at = next.get(at);
      if (!trusted.includes(at) && !added.has(at)) added.set(at, root);
    }
  }
  for (const [n, root] of [...added].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    report.notes.push(`log key ${n} is trusted as the successor of ${root} ` +
      "(hand-over signed by both keys)");
  }
  return { ...opts, trustedLogs: [...trusted, ...added.keys()] };
}

// Validity and trust are separate: the trust level depends only on keys the caller trusts
// (log ids, witness ids, TSA certificate SHA-256 fingerprints), never on the bundle itself.
async function verify(bundle, report,
  { trustedLogs = [], trustedWitnesses = [], trustedTsas = [], contents = {} }) {
  need(bundle.format === "provena-bundle/1", "unknown bundle format");
  const head = bundle.head;
  const signer = await verifyCard(bundle.head_signer);
  await verifyHead(head, signer);
  need(head.project === bundle.project, "head is for another project");

  const items = [...bundle.entries].sort((a, b) => a.index - b.index);
  need(items.length && items[0].index === 0, "bundle must include the genesis entry");
  need((await entryHash(items[0].entry)) === bundle.project, "genesis does not match project");
  const root = unhex(head.root);
  const indexed = new Map();
  let fullState = null;
  if (bundle.mode === "full") {
    need(items.map((it) => it.index).join() === [...Array(head.size).keys()].join(),
      "full bundle must contain every entry up to the head");
    const leaves = [];
    for (const it of items) leaves.push(await entryLeaf(it.entry));
    need(eq(await merkleRoot(leaves), root), "entries do not hash to the head root");
    fullState = await replayState(items.map((it) => it.entry)); // proves authorization
  } else {
    for (const it of items) {
      checkShape(it.entry);
      await verifyInclusion(await entryLeaf(it.entry), it.index, head.size,
        it.proof.map(unhex), root);
    }
    report.notes.push("selective bundle: membership/revocation at signing time is not proven " +
      "(use a full bundle for that)");
  }
  for (const it of items) indexed.set(await entryHash(it.entry), [it.index, it.entry]);

  const keys = new Map();
  for (const it of items) {
    if (it.entry.kind === "genesis" && it.index !== 0) continue; // only the project's own genesis
    for (const card of keyIntros(it.entry)) {
      if (!keys.has(card.id)) keys.set(card.id, [it.index, await verifyCard(card)]);
    }
  }
  for (const [h, [i, e]] of indexed) {
    need((e.kind === "genesis" && i === 0) || e.project === bundle.project,
      `entry ${h.slice(0, 12)} foreign`);
    need(keys.has(e.author), `no proven key for author ${e.author}`);
    const [introIndex, pub] = keys.get(e.author);
    need(introIndex <= i, `author key of ${h.slice(0, 12)} introduced after the entry`);
    await verifyEntrySig(e, pub);
    if (e.prev && indexed.has(e.prev)) {
      need(indexed.get(e.prev)[0] < i, `entry ${h.slice(0, 12)} precedes its own prev entry`);
    }
    report.verified[h] = i;
  }
  const members = fullState ? new Set(fullState.members.keys()) : new Set(keys.keys());
  report.trust = trustedLogs.includes(signer.id) ? "log-sequenced"
    : members.has(signer.id) ? "self-sequenced" : "unverified";
  const when = iso(head.time);
  report.facts.push(`log head: ${head.size} entries, root ${head.root.slice(0, 16)}…, signed by ` +
    `${signer.id} with time ${when}`);
  if (report.trust === "self-sequenced") {
    report.notes.push("the head is signed by a project member: its time is the author's own claim");
  } else if (report.trust === "unverified") {
    report.notes.push(`the head signer ${signer.id} is not a log you trust: order and times ` +
      "are its unverified claim");
  }
  // Signed entry timestamps (SET): per-entry sequencing times from the head's own log.
  const SET_FIELDS = ["v", "project", "index", "entry_hash", "integrated_time", "signer"];
  for (const it of items) {
    const r = it.receipt;
    if (r === undefined) continue;
    need(isObj(r) && Object.keys(r).sort().join() === [...SET_FIELDS, "sig"].sort().join() &&
      r.signer === signer.id, "SET: malformed or wrong signer");
    need(await edVerify(signer.sign, TAGS.SET, canon(pick(r, SET_FIELDS)), unhex(r.sig)),
      "SET: bad signature");
    const h = await entryHash(it.entry);
    need(r.project === bundle.project && r.index === it.index && r.entry_hash === h,
      "receipt does not match its entry");
    need(Number.isSafeInteger(r.integrated_time) && r.integrated_time <= head.time,
      "receipt is dated after the head");
    if (bundle.targets.includes(h)) {
      const what = `entry ${h.slice(0, 12)} was sequenced at ${iso(r.integrated_time)} (signed receipt)`;
      if (report.trust === "log-sequenced") report.facts.push(what);
      else report.notes.push(`${what} — signer not trusted`);
    }
  }
  const ordered = report.trust === "log-sequenced";
  const orderFact = (msg) => (ordered ? report.facts : report.notes).push(msg);
  for (const t of bundle.targets) {
    need(indexed.has(t), `target ${t.slice(0, 12)} not proven by this bundle`);
    const [i, e] = indexed.get(t);
    report.facts.push(ordered
      ? `entry ${t.slice(0, 12)} (${e.kind}) by ${e.author} is #${i}, existing no later than ` +
        `${when} (per trusted log)`
      : `entry ${t.slice(0, 12)} (${e.kind}) signed by ${e.author} belongs to this project`);
  }
  if (!ordered) {
    report.notes.push("log positions and order (#n, plan-before-result) are asserted by an " +
      "untrusted head signer and are reported as notes");
  }
  for (const [h, [i, e]] of [...indexed].sort((a, b) => a[1][0] - b[1][0])) {
    const b = e.body;
    if (e.kind === "activity") {
      if (b.plan && indexed.has(b.plan)) {
        const pi = indexed.get(b.plan)[0];
        need(pi < i, "plan must precede the activity citing it");
        const gen = b.generated || [];
        const holds = gen.every((g) => indexed.has(g) && indexed.get(g)[0] > pi);
        const lacking = gen.filter((g) => !indexed.has(g)).length;
        report.preregistration.push({ plan: b.plan, activity: h, holds, ordered,
          proven: holds && ordered,
          target: report.targets.includes(h) || gen.some((g) => report.targets.includes(g)),
          reason: holds ? (ordered ? null : "order-unproven")
            : lacking ? "outputs-not-in-bundle" : "output-before-plan" });
        if (holds) {
          orderFact(`plan ${b.plan.slice(0, 12)} (#${pi}) was registered before activity ` +
            `${h.slice(0, 12)} (#${i}) and before all of its outputs: preregistration holds`);
        } else {
          const missing = gen.filter((g) => !indexed.has(g)).length;
          const why = missing ? `${missing} of its outputs are not in this bundle (prove them ` +
            "too, or use a full bundle)" : "an output was registered before the plan";
          report.notes.push(`activity ${h.slice(0, 12)} cites plan ${b.plan.slice(0, 12)}, but ` +
            `${why}: preregistration NOT shown`);
        }
      }
    } else if (e.kind === "attest" && indexed.has(b.target)) {
      report.facts.push(`${b.type} attestation by ${e.author} on ${b.target.slice(0, 12)}` +
        (b.verdict ? `, verdict ${b.verdict}` : ""));
    } else if (e.kind === "grant" && indexed.has(b.target)) {
      report.facts.push(`access to ${b.target.slice(0, 12)} was granted to ${b.to.id} (#${i})`);
    } else if (e.kind === "redact" && indexed.has(b.target)) {
      report.facts.push(`entry ${b.target.slice(0, 12)} was redacted (${b.reason})`);
    }
  }

  const openings = { ...(bundle.openings || {}) };
  for (const [, [, e]] of indexed) {
    if (e.kind === "reveal" && indexed.has(e.body.target) && !openings[e.body.target]) {
      openings[e.body.target] = e.body;
    }
  }
  for (const [h, o] of Object.entries(openings)) {
    need(indexed.has(h), `opening for unproven entry ${h.slice(0, 12)}`);
    const target = indexed.get(h)[1];
    const plain = unhex(o.plain_sha256);
    need(hex(await tagged(TAGS.COMMIT, unhex(o.salt), plain)) === target.body.commitment,
      "commitment opening does not match");
    // embedded plaintext and a file the verifier supplies are each checked
    const checks = [["embedded content", o.content ? unb64u(o.content) : undefined],
      ["supplied content", contents[h]]].filter(([, c]) => c !== undefined);
    for (const [label, content] of checks) {
      need(eq(await sha256(content), plain),
        `${label} for ${h.slice(0, 12)} does not match its commitment`);
      report.facts.push(`${label} of ${h.slice(0, 12)} (${content.length} bytes) matches its ` +
        "commitment");
    }
    if (o.details !== undefined) {  // selective bundles do not replay the state machine
      need(target.kind === "activity" && isObj(o.details) &&
        hex(await sha256(new TextEncoder().encode(canonicalize(o.details)))) === o.plain_sha256,
      `opened details of ${h.slice(0, 12)} do not match its commitment`);
      need(statusMatches(target.body.status, o.details),
        `step ${h.slice(0, 12)}: public status contradicts its revealed exit code`);
    }
    if (target.kind === "activity" && isObj(o.details)) {
      const d = o.details;
      report.facts.push(`step ${h.slice(0, 12)} (${target.body.status}) opened: exit code ` +
        `${d.exit_code ?? "?"}, command ${JSON.stringify(d.command ?? null)}` +
        (d.model ? `, model ${d.model}` : ""));
    } else if (checks.length === 0) {
      report.facts.push(`commitment of ${h.slice(0, 12)} opens to plaintext sha256 ` +
        `${o.plain_sha256.slice(0, 16)}…`);
    }
  }
  const unopened = Object.keys(contents).filter((h) => !openings[h]).sort();
  need(unopened.length === 0, `content supplied for ${unopened.map((h) => h.slice(0, 12))
    .join(", ")}, which this bundle does not open: it cannot be checked (prove with --open)`);

  // Evidence on older (or equal) heads must be linked to the bundle head by consistency.
  const linked = async (item) => {
    const older = item.head || head;
    const log = await verifyCard(item.log_card || bundle.head_signer);
    need(log.id === older.signer && older.project === bundle.project, "evidence: wrong log");
    await verifyHead(older, log);
    need(older.size > 0 && older.size <= head.size, "evidence head is newer than the bundle head");
    need(older.time <= head.time, "evidence head is dated after the bundle head");
    await verifyConsistency(older.size, head.size, unhex(older.root), root,
      (item.consistency || []).map(unhex));
    return [older, log];
  };
  const targetIdx = bundle.targets.map((t) => indexed.get(t)[0]);
  const basedOnLog = ["log-sequenced", "witnessed"].includes(report.trust);
  const sizes = new Map();  // trusted witness -> largest head it cosigned
  for (const item of bundle.cosignatures || []) {
    const [cosigned, log] = await linked(item);
    const pub = await verifyCard(item.card);
    await verifyCosig(item.cosig, cosigned, pub);
    const what = `log head of size ${cosigned.size} cosigned by witness ${pub.id} at ` +
      iso(item.cosig.time);
    if (trustedLogs.includes(log.id) && trustedWitnesses.includes(pub.id)) {
      sizes.set(pub.id, Math.max(sizes.get(pub.id) || 0, cosigned.size));
      report.facts.push(what);
    } else {
      report.notes.push(`${what} — not counted: witness or log not in your trusted set`);
    }
  }
  // the project's own policy may ask for more than one independent witness
  const count = indexed.get(bundle.project)[1].body.policy.witnesses ?? 0;
  need(Number.isInteger(count), "genesis: witnesses");
  const required = Math.max(1, count);
  const covering = [...sizes.values()].filter((n) => targetIdx.every((i) => i < n)).length;
  if (basedOnLog && targetIdx.length && covering >= required) {
    report.trust = "witnessed";
  } else if (basedOnLog && targetIdx.length && covering) {
    report.notes.push(`the project's policy asks for ${required} witnesses; ${covering} ` +
      "trusted witness(es) cover the targets: not witnessed");
  }

  for (const item of bundle.anchors || []) {
    const [a, log] = await linked(item);
    const anchor = item.anchor;
    await verifyInclusion(await anchorLeaf(a), item.index, anchor.size, item.proof.map(unhex),
      unhex(anchor.digest));
    let at, issuer, trusted;
    if (anchor.provider === "self") {
      const r = anchor.receipt;
      need(r.digest === anchor.digest && r.signer === log.id, "self anchor mismatch");
      need(await edVerify(log.sign, TAGS.SELF_ANCHOR,
        canon(pick(r, ["digest", "time", "signer"])), unhex(r.sig)), "self anchor: bad signature");
      at = r.time; issuer = `hub ${log.id}`; trusted = trustedLogs.includes(log.id);
      report.notes.push("a `self` anchor is signed by the hub itself and adds no independent " +
        "time evidence");
    } else {
      need(anchor.provider === "rfc3161", `unknown anchor provider ${anchor.provider}`);
      const info = await inspectToken(unb64u(anchor.receipt.token), unhex(anchor.digest));
      at = info.time;
      issuer = `TSA ${info.subject}; cert sha256 ${info.fingerprint.slice(0, 16)}…`;
      trusted = trustedLogs.includes(log.id) && trustedTsas.includes(info.fingerprint);
      if (!trusted) issuer += ` (fingerprint ${info.fingerprint})`;
    }
    need(at >= a.time - CLOCK_SKEW_MS, "anchor time precedes the head it anchors");
    const covered = bundle.targets.filter((t) => indexed.get(t)[0] < a.size);
    for (const t of covered) {
      const claim = `entry ${t.slice(0, 12)} existed no later than ${iso(at)} ` +
        `(anchored via ${anchor.provider}: ${issuer})`;
      if (trusted) report.facts.push(claim);
      else report.notes.push(`${claim} — not counted: issuer or log not trusted`);
    }
    if (anchor.provider !== "self" && trusted && covered.length &&
        covered.length === bundle.targets.length &&
        ["log-sequenced", "witnessed"].includes(report.trust)) report.trust = "anchored";
  }
}

// -- identity credentials (mirrors provena.core.identity) ---------------------------------------

const CLAIMS = { name: 200, affiliation: 200, orcid: 19, email: 254, role: 100 };
// No control, bidi or zero-width characters (they can make a displayed name lie).
const invisible = (n) => (n >= 0x200b && n <= 0x200f) || (n >= 0x202a && n <= 0x202e) ||
  (n >= 0x2066 && n <= 0x2069) || n === 0xfeff || n === 0x2028 || n === 0x2029;
const plainText = (t) => [...t].every((c) => {
  const n = c.codePointAt(0);
  return n >= 0x20 && !(n >= 0x7f && n <= 0x9f) && !invisible(n);
});

async function verifyCredential(cred, issuerCard, atMs) {
  const fields = ["v", "issuer", "subject", "claims", "issued", "expires"];
  need(isObj(cred) && Object.keys(cred).sort().join() === [...fields, "sig"].sort().join() &&
    cred.v === 1, "credential: malformed");
  const issuer = await verifyCard(issuerCard);
  need(issuer.id === cred.issuer, "credential: issuer card does not match");
  need(issuerCard.kind === "org", "credential: issuer must be an org agent");
  const c = cred.claims;
  need(isObj(c) && Object.keys(c).length > 0 && Object.keys(c).every((k) => Object.hasOwn(CLAIMS, k)),
    "credential: unknown claims");
  for (const [k, v] of Object.entries(c)) {
    need(typeof v === "string" && cpLen(v) > 0 && cpLen(v) <= CLAIMS[k] && plainText(v),
      `credential: bad ${k}`);
  }
  if (Object.hasOwn(c, "orcid")) need(/^\d{4}-\d{4}-\d{4}-\d{3}[\dX]$/.test(c.orcid), "credential: ORCID");
  need(await edVerify(issuer.sign, TAGS.CREDENTIAL, canon(pick(cred, fields)), unhex(cred.sig)),
    "credential: bad signature");
  need(Number.isSafeInteger(cred.issued) && Number.isSafeInteger(cred.expires) &&
    cred.issued <= atMs && atMs <= cred.expires, "credential: not valid at the time in question");
  return issuer;
}

async function credentialFacts(bundle, report, trustedOrgs) {
  const authors = new Set(bundle.entries.map((it) => it.entry.author));
  const timeTrusted = ["log-sequenced", "witnessed", "anchored"].includes(report.trust);
  for (const item of bundle.credentials || []) {
    const cred = isObj(item) ? item.credential : null;
    if (!isObj(cred) || typeof cred.subject !== "string" || !authors.has(cred.subject)) continue;
    let issuer;
    try {
      issuer = await verifyCredential(cred, item.issuer_card, bundle.head.time);
    } catch (e) {
      report.notes.push(`credential for ${cred.subject} not accepted: ${e.message || e}`);
      continue;
    }
    const claims = Object.keys(cred.claims).sort().map((k) => `${k}: ${cred.claims[k]}`).join(", ");
    const what = `author ${cred.subject} is ${claims} per org ${issuer.id}`;
    if (!trustedOrgs.includes(issuer.id)) {
      report.notes.push(`${what} — not counted: org not in your trusted set`);
    } else if (!timeTrusted) {
      report.notes.push(`${what} — not counted: the head time it was checked at is not from a ` +
        "trusted log");
    } else report.facts.push(what);
  }
}

// -- inputs from other projects (activity.external + attached bundles) ---------------------------

async function externalFacts(bundle, report, opts) {
  const attached = bundle.external || [];
  need(!(opts._depth > 0) || attached.length === 0, "external bundles may not nest");
  need(attached.length <= 20, "too many external bundles");
  const reports = [];
  for (const sub of attached) {
    const r = await verifyBundle(sub, { ...opts, _depth: 1 });
    need(r.ok, `external bundle for project ${String(sub && sub.project).slice(0, 12)} is invalid: ` +
      r.errors.join("; "));
    reports.push(r);
  }
  for (const it of bundle.entries) {
    const e = it.entry;
    const h = await entryHash(e);
    if (e.kind !== "activity" || !Object.hasOwn(report.verified, h)) continue;
    const external = e.body.external === undefined ? [] : e.body.external;
    need(Array.isArray(external) && external.length <= 100 && external.every((x) => isObj(x) &&
      Object.keys(x).sort().join() === "entry,project" && isHex64(x.project) && isHex64(x.entry)),
    "activity.external is malformed");
    for (const x of external) {
      const proof = reports.find((r) => r.project === x.project &&
        Object.hasOwn(r.verified, x.entry) && r.targets.includes(x.entry));
      if (!proof) {
        report.notes.push(`activity ${h.slice(0, 12)} cites ${x.entry.slice(0, 12)} in project ` +
          `${x.project.slice(0, 12)}, but no attached bundle proves it`);
        continue;
      }
      const what = `activity ${h.slice(0, 12)} used entry ${x.entry.slice(0, 12)} of project ` +
        `${x.project.slice(0, 12)} (that project's evidence: ${proof.trust})`;
      if (["log-sequenced", "witnessed", "anchored"].includes(proof.trust)) report.facts.push(what);
      else report.notes.push(what);
    }
  }
}

// -- parsing bundles from text --------------------------------------------------------------------
// JSON.parse turns 1.0 into 1, but Python (and the spec) reject floats in signed structures. Scan
// the raw text first so both verifiers give the same verdict on the same file.

export function findFloatLiteral(text) {
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inString) {
      if (c === "\\") i++;
      else if (c === '"') inString = false;
      continue;
    }
    if (c === '"') { inString = true; continue; }
    if (c === "-" || (c >= "0" && c <= "9")) {
      let j = i;
      while (j < text.length && /[-+0-9.eE]/.test(text[j])) j++;
      if (/[.eE]/.test(text.slice(i, j))) return text.slice(i, j);
      i = j - 1;
    }
  }
  return null;
}

// A public project's whole log as a hub serves it (/v1/projects/{pid}/entries), checked in the
// reader's browser: the hub's card and signed tree head for project *pid*, the entries (whose
// genesis is *pid*) hashing to that head's root, and (with replay) every signature and rule.
export async function verifyPublicLog(pid, card, head, log, { replay = true } = {}) {
  const pub = await verifyCard(card);
  await verifyHead(head, pub);
  need(head.project === pid, "the signed head is for another project");
  need(log.length === head.size, "the log does not have as many entries as the signed head");
  need(log.length > 0 && (await entryHash(log[0])) === pid, "the log is of another project");
  const leaves = [];
  for (const e of log) leaves.push(await entryLeaf(e));
  need(eq(await merkleRoot(leaves), unhex(head.root)), "entries do not hash to the signed root");
  if (replay) await replayState(log);
  return { size: head.size, signer: pub.id, replayed: replay };
}

// One public entry as a hub serves it (/v1/projects/{pid}/entries/{hash}), checked in the
// browser: it hashes to *hash*, and an inclusion proof puts it at *index* under a tree head of
// project *pid* signed by the hub's card.
export async function verifyEntryInclusion(pid, hash, card, head, entry, index, proof) {
  const pub = await verifyCard(card);
  await verifyHead(head, pub);
  need(head.project === pid, "the signed head is for another project");
  checkShape(entry);
  need(index === 0 ? entry.project === null : entry.project === pid, "the entry is of another project");
  need((await entryHash(entry)) === hash, "the entry does not hash to its id");
  await verifyInclusion(await entryLeaf(entry), index, head.size, proof.map(unhex),
    unhex(head.root));
  return { index, size: head.size, time: head.time, signer: pub.id };
}

export async function verifyBundleText(text, opts = {}) {
  text = text.replace(/^\uFEFF/, "");
  const float = findFloatLiteral(text);
  if (float !== null) {
    return { ok: false, trust: "", facts: [], notes: [], verified: {},
      errors: [`CanonicalizationError: floats are not allowed in bundles (${float})`] };
  }
  return verifyBundle(JSON.parse(text), opts);
}

export { VerificationError };
