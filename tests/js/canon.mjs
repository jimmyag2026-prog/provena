// Canonicalize and hash JSON values with the browser verifier, for cross-language fuzzing.
import { readFileSync } from "node:fs";
import * as v from "../../src/provena/server/static/verifier.js";

const values = JSON.parse(readFileSync(process.argv[2], "utf8"));
const out = [];
for (const value of values) {
  try {
    const c = v.canonicalize(value);
    out.push({ canonical: c, hash: v.hex(await v.sha256(new TextEncoder().encode(c))) });
  } catch (e) {
    out.push({ error: String(e.message || e) });
  }
}
console.log(JSON.stringify(out));
