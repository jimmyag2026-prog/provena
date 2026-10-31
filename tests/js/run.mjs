// Runs the browser verifier under Node against cases written by tests/test_js_verifier.py.
import { readFileSync } from "node:fs";
import * as v from "../../src/provena/server/static/verifier.js";
import { inspectToken } from "../../src/provena/server/static/rfc3161.js";

const input = JSON.parse(readFileSync(process.argv[2], "utf8"));
const vec = input.vectors;
const checks = {};
checks.canonical = v.canonicalize(vec.canonical.input) === vec.canonical.output;
checks.tagged = v.hex(await v.tagged(vec.tagged_hash.tag,
  ...vec.tagged_hash.parts_hex.map(v.unhex))) === vec.tagged_hash.output;
checks.agent_id = (await v.agentId(v.unhex(vec.agent.sign_pub))) === vec.agent.id;
checks.card = (await v.verifyCard(vec.agent.card)).id === vec.agent.id;
const c = vec.commitment;
checks.commitment = v.hex(await v.tagged("provena/commit/v1", v.unhex(c.salt),
  v.unhex(c.plain_sha256))) === c.commitment;

const tokens = {};
for (const [name, t] of Object.entries(input.tokens || {})) {
  try {
    const info = await inspectToken(v.unhex(t.token), v.unhex(t.digest));
    tokens[name] = { ok: true, time: info.time, subject: info.subject };
  } catch (e) {
    tokens[name] = { ok: false, error: String(e.message || e) };
  }
}

const results = {};
const opts = (name) => {
  const o = { ...((input.options || {})[name] || {}) };
  if (o.contentsB64) {  // JSON cannot carry bytes
    o.contents = Object.fromEntries(Object.entries(o.contentsB64).map(([h, c]) => [h, v.unb64u(c)]));
    delete o.contentsB64;
  }
  return o;
};
for (const [name, bundle] of Object.entries(input.bundles)) {
  const r = await v.verifyBundle(bundle, opts(name));
  results[name] = { ok: r.ok, trust: r.trust, facts: r.facts, errors: r.errors,
    preregistration: r.preregistration };
}
for (const [name, text] of Object.entries(input.texts || {})) {
  const r = await v.verifyBundleText(text, (input.options || {})[name] || {});
  results[name] = { ok: r.ok, trust: r.trust, facts: r.facts, errors: r.errors };
}
const logs = {};
for (const [name, c] of Object.entries(input.logs || {})) {
  try {
    logs[name] = { ok: true, ...(await v.verifyPublicLog(c.pid, c.card, c.head, c.log)) };
  } catch (e) {
    logs[name] = { ok: false, error: String(e.message || e) };
  }
}
const entries = {};
for (const [name, args] of Object.entries(input.entries || {})) {
  try {
    entries[name] = { ok: true, ...(await v.verifyEntryInclusion(...args)) };
  } catch (e) {
    entries[name] = { ok: false, error: String(e.message || e) };
  }
}
console.log(JSON.stringify({ checks, results, tokens, logs, entries }));
