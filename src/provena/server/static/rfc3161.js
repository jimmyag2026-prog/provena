// RFC 3161 time-stamp token verification for the browser verifier (mirrors core/rfc3161.py).

const subtle = globalThis.crypto.subtle;
class TsaError extends Error {}
const need = (c, m) => { if (!c) throw new TsaError("rfc3161: " + m); };

// -- minimal DER ---------------------------------------------------------------------------------

function read(buf, pos) {
  need(pos + 2 <= buf.length, "DER truncated");
  const start = pos, tag = buf[pos];
  need((tag & 0x1f) !== 0x1f, "DER high tag");
  let len = buf[pos + 1];
  pos += 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    need(n > 0 && n <= 4 && pos + n <= buf.length, "DER bad length");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[pos + i];
    pos += n;
  }
  need(pos + len <= buf.length, "DER truncated value");
  return { tag, raw: buf.subarray(start, pos + len), content: buf.subarray(pos, pos + len),
    end: pos + len };
}
function children(node) {
  need(node.tag & 0x20, "DER primitive");
  const out = [];
  for (let p = 0; p < node.content.length;) { const n = read(node.content, p); out.push(n); p = n.end; }
  return out;
}
const child = (n, i) => { const c = children(n); need(i < c.length, "DER missing element"); return c[i]; };
const parse = (buf) => { const n = read(buf, 0); need(n.end === buf.length, "DER trailing"); return n; };
function oid(node) {
  need(node.tag === 0x06, "expected OID");
  const b = node.content;
  const parts = b[0] < 80 ? [Math.floor(b[0] / 40), b[0] % 40] : [2, b[0] - 80];
  let v = 0;
  for (const x of b.subarray(1)) { v = v * 128 + (x & 0x7f); if (!(x & 0x80)) { parts.push(v); v = 0; } }
  return parts.join(".");
}
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const bigint = (bytes) => bytes.reduce((n, x) => n * 256n + BigInt(x), 0n);

function timeOf(node) {
  const s = new TextDecoder().decode(node.content);
  need(s.endsWith("Z"), "time must be UTC");
  let full = s.slice(0, -1);
  if (node.tag === 0x17) full = (Number(full.slice(0, 2)) >= 50 ? "19" : "20") + full; // UTCTime
  const [main, frac = ""] = full.split(".");
  const t = Date.UTC(+main.slice(0, 4), +main.slice(4, 6) - 1, +main.slice(6, 8),
    +main.slice(8, 10), +main.slice(10, 12), +main.slice(12, 14));
  return t + (frac ? Number((frac + "000").slice(0, 3)) : 0);
}

const OID = {
  SIGNED_DATA: "1.2.840.113549.1.7.2", TSTINFO: "1.2.840.113549.1.9.16.1.4",
  CONTENT_TYPE: "1.2.840.113549.1.9.3", MESSAGE_DIGEST: "1.2.840.113549.1.9.4",
  SIGNING_CERT: "1.2.840.113549.1.9.16.2.12", SIGNING_CERT_V2: "1.2.840.113549.1.9.16.2.47",
  SHA256: "2.16.840.1.101.3.4.2.1", EKU: "2.5.29.37", SKI: "2.5.29.14",
  TIME_STAMPING: "1.3.6.1.5.5.7.3.8", RSA: "1.2.840.113549.1.1.1", EC: "1.2.840.10045.2.1",
  ED25519: "1.3.101.112", CN: "2.5.4.3",
};
const HASH = { "1.3.14.3.2.26": "SHA-1", [OID.SHA256]: "SHA-256",
  "2.16.840.1.101.3.4.2.2": "SHA-384", "2.16.840.1.101.3.4.2.3": "SHA-512" };
const CURVES = { "1.2.840.10045.3.1.7": ["P-256", 32], "1.3.132.0.34": ["P-384", 48],
  "1.3.132.0.35": ["P-521", 66] };

// -- X.509 (just what we need) ------------------------------------------------------------------

function parseCert(raw) {
  const tbs = child(parse(raw), 0);
  const f = children(tbs);
  const o = f[0].tag === 0xa0 ? 1 : 0; // optional [0] version
  const validity = children(f[o + 3]);
  const spki = f[o + 5];
  const algo = children(child(spki, 0));
  const cert = { serial: bigint(f[o].content), issuer: f[o + 2].raw, subject: f[o + 4],
    notBefore: timeOf(validity[0]), notAfter: timeOf(validity[1]), spki: spki.raw,
    keyAlg: oid(algo[0]), curve: algo[1] && algo[1].tag === 0x06 ? oid(algo[1]) : null,
    eku: null, ski: null, raw };
  const ext = f.slice(o + 6).find((n) => n.tag === 0xa3);
  for (const e of ext ? children(child(ext, 0)) : []) {
    const parts = children(e);
    const id = oid(parts[0]), value = parse(parts[parts.length - 1].content);
    if (id === OID.EKU) cert.eku = children(value).map(oid);
    if (id === OID.SKI) cert.ski = value.content;
  }
  return cert;
}
function commonName(cert) {
  for (const rdn of children(cert.subject)) {
    for (const atv of children(rdn)) {
      if (oid(child(atv, 0)) === OID.CN) return "CN=" + new TextDecoder().decode(child(atv, 1).content);
    }
  }
  return "(no CN)";
}

function ecdsaRaw(der, size) { // DER SEQUENCE{r,s} -> r||s fixed width (WebCrypto format)
  const [r, s] = children(parse(der)).map((n) => {
    let b = n.content;
    while (b.length > size && b[0] === 0) b = b.subarray(1);
    const out = new Uint8Array(size); out.set(b, size - b.length); return out;
  });
  const out = new Uint8Array(2 * size); out.set(r, 0); out.set(s, size); return out;
}

async function verifySig(cert, hashName, signature, data) {
  if (cert.keyAlg === OID.RSA) {
    const key = await subtle.importKey("spki", cert.spki,
      { name: "RSASSA-PKCS1-v1_5", hash: hashName }, false, ["verify"]);
    return subtle.verify("RSASSA-PKCS1-v1_5", key, signature, data);
  }
  if (cert.keyAlg === OID.EC) {
    need(cert.curve in CURVES, "unsupported curve");
    const [namedCurve, size] = CURVES[cert.curve];
    const key = await subtle.importKey("spki", cert.spki, { name: "ECDSA", namedCurve }, false,
      ["verify"]);
    return subtle.verify({ name: "ECDSA", hash: hashName }, key, ecdsaRaw(signature, size), data);
  }
  if (cert.keyAlg === OID.ED25519) {
    const key = await subtle.importKey("spki", cert.spki, { name: "Ed25519" }, false, ["verify"]);
    return subtle.verify({ name: "Ed25519" }, key, signature, data);
  }
  throw new TsaError("rfc3161: unsupported TSA key type");
}

// -- token ---------------------------------------------------------------------------------------

export async function inspectToken(token, digest) {
  const ci = parse(token);
  need(oid(child(ci, 0)) === OID.SIGNED_DATA, "not CMS SignedData");
  const parts = children(child(child(ci, 1), 0));
  const encap = parts[2];
  need(oid(child(encap, 0)) === OID.TSTINFO, "content is not a TSTInfo");
  const tstDer = child(child(encap, 1), 0).content;
  const certs = parts.slice(3, -1).filter((p) => p.tag === 0xa0)
    .flatMap((p) => children(p).map((n) => parseCert(n.raw)));
  const si = children(child(parts[parts.length - 1], 0));
  need(si[3].tag === 0xa0, "signed attributes required");
  const hashName = HASH[oid(child(si[2], 0))];
  need(hashName, "unsupported digest algorithm");

  const tst = children(parse(tstDer));
  need(oid(child(child(tst[2], 0), 0)) === OID.SHA256, "imprint must be SHA-256");
  need(eq(child(tst[2], 1).content, digest), "token is for a different digest");
  need(tst[4].tag === 0x18, "genTime missing");
  const time = timeOf(tst[4]);

  const attrs = new Map(children(si[3]).map((a) => [oid(child(a, 0)), child(child(a, 1), 0)]));
  need(attrs.has(OID.MESSAGE_DIGEST), "messageDigest attribute missing");
  const md = new Uint8Array(await subtle.digest(hashName, tstDer));
  need(eq(attrs.get(OID.MESSAGE_DIGEST).content, md), "messageDigest mismatch");
  if (attrs.has(OID.CONTENT_TYPE)) need(oid(attrs.get(OID.CONTENT_TYPE)) === OID.TSTINFO,
    "contentType mismatch");

  need(certs.length, "token carries no certificate");
  const sid = si[1];
  let cert;
  if (sid.tag === 0x30) {
    const issuer = child(sid, 0).raw, serial = bigint(child(sid, 1).content);
    cert = certs.find((c) => c.serial === serial && eq(c.issuer, issuer));
  } else if (sid.tag === 0x80) {
    cert = certs.find((c) => c.ski && eq(c.ski, sid.content));
  }
  need(cert, "signer certificate not found in token");
  // ESS signing-certificate attribute must name this exact certificate (RFC 3161 §2.4.1)
  let essAlg, essHash;
  if (attrs.has(OID.SIGNING_CERT_V2)) {
    let fields = children(child(child(attrs.get(OID.SIGNING_CERT_V2), 0), 0));
    essAlg = "SHA-256";
    if (fields[0].tag === 0x30) { essAlg = HASH[oid(child(fields[0], 0))]; fields = fields.slice(1); }
    essHash = fields[0].content;
  } else if (attrs.has(OID.SIGNING_CERT)) {
    essAlg = "SHA-1";
    essHash = child(child(child(attrs.get(OID.SIGNING_CERT), 0), 0), 0).content;
  } else {
    throw new TsaError("rfc3161: signingCertificate attribute missing");
  }
  need(essAlg, "unsupported signingCertificate hash");
  need(eq(new Uint8Array(await subtle.digest(essAlg, cert.raw)), essHash),
    "signingCertificate does not match the signer certificate");
  const signedSet = new Uint8Array(si[3].raw);
  signedSet[0] = 0x31; // [0] IMPLICIT -> SET OF
  need(await verifySig(cert, hashName, si[5].content, signedSet), "TSA signature invalid");
  need(cert.eku, "TSA certificate lacks extendedKeyUsage");
  need(cert.eku.includes(OID.TIME_STAMPING), "certificate not issued for time stamping");
  need(cert.notBefore <= time && time <= cert.notAfter,
    "genTime outside the TSA certificate's validity");
  const fp = new Uint8Array(await subtle.digest("SHA-256", cert.raw));
  return { time, subject: commonName(cert),
    fingerprint: Array.from(fp, (x) => x.toString(16).padStart(2, "0")).join("") };
}
