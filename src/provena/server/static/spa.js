// The hub's front end: a single-page app over its JSON API. Logs and entries are fetched and
// checked in the browser with verifier.js (hub card, signed tree head of the project, entries
// hashing to its root or an inclusion proof, every signature and ledger rule) rather than taken
// from a server-rendered page. This code is itself served by the hub, and the page says so: for
// a check that does not depend on the hub at all, use `provena verify`. Pages without
// JavaScript stay under /classic. All text goes in through textContent, never as HTML.
import { entryHash, verifyEntryInclusion, verifyPublicLog } from "./verifier.js";

const root = document.getElementById("spa");
const base = root.dataset.base || "";
const zh = document.documentElement.lang.startsWith("zh");
const T = (en, cn) => (zh ? cn : en);
const REPLAY_MAX = 20000;  // entries replayed in full in the browser
const FETCH_MAX = 200000;  // larger logs are not fetched here at all
const HEX64 = /^[0-9a-f]{64}$/;

function el(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "text") e.textContent = v; else if (k === "class") e.className = v;
    else e.setAttribute(k, v);
  }
  for (const c of children) e.append(c);
  return e;
}
const when = (ms) => (ms ? new Date(ms).toISOString().replace(".000Z", "Z") : "-");
const projectUrl = (pid) => `${base}/p/${pid}`;
const entryUrl = (pid, h) => `${base}/p/${pid}/e/${h}`;

async function get(path) {
  const r = await fetch(base + path, { headers: { accept: "application/json" } });
  if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
  return r.json();
}

function table(head, rows) {
  const t = el("table", {}, el("tr", {}, ...head.map((h) => el("th", { text: h }))));
  for (const r of rows) t.append(el("tr", {}, ...r.map((c) => (c instanceof Node ? el("td", {}, c)
    : el("td", { text: String(c) })))));
  return el("div", { class: "table-wrap" }, t);
}

function kv(rows) {
  const dl = el("dl", { class: "kv" });
  for (const [k, v] of rows) dl.append(el("dt", { text: k }), v instanceof Node ? el("dd", {}, v) : el("dd", { text: String(v) }));
  return el("div", { class: "card" }, dl);
}

function verdictCard(state, title, ...lines) {
  return el("div", { class: `card result ${state}` }, el("div", { class: "verdict", text: title }),
    ...lines.map((l) => el("p", { text: l })));
}
const SELF_NOTE = () => T("Whether you trust this hub's log key is your decision; times and order are only facts if you do. This page's code is served by the hub too: for a check independent of it, use `provena verify`.",
  "是否信任本 Hub 的日志公钥由你决定；只有信任它时，时间与顺序才是事实。本页代码也由该 Hub 提供：要不依赖它的核对，请用 `provena verify`。");

// -- home: verify a bundle, public projects, what the verdicts mean ---------------------------

const VERDICTS = [
  ["unverified", "Signatures check out, but the log that signed them is not one you trust.", "签名无误，但签署这本账的日志不是你信任的。"],
  ["self-sequenced", "Signed by their authors; time and order are the authors' own claim.", "由作者签名；时间和先后只是作者自己的说法。"],
  ["log-sequenced", "A log you trust recorded these entries in this order, no later than the times shown.", "你信任的日志按这个顺序记录了这些条目，时间不晚于所示时刻。"],
  ["witnessed", "As log-sequenced, and an independent witness confirmed the log was not forked.", "同上，并且独立见证人确认这本账没有分叉。"],
  ["anchored", "As witnessed/log-sequenced, and a time-stamp authority you trust dated the log.", "同上，并且你信任的时间戳机构为这本账盖了时间。"],
];

async function home() {
  const q = new URLSearchParams(location.search).get("q") || "";
  const cat = await get(`/v1/catalog${q ? `?q=${encodeURIComponent(q)}` : ""}`);
  const search = el("form", { class: "search", method: "get", action: `${base}/` },
    el("input", { id: "q", name: "q", type: "search", value: q, placeholder: T("Search public projects", "搜索公开项目") }),
    el("input", { type: "hidden", name: "lang", value: zh ? "zh" : "en" }),
    el("button", { type: "submit", text: T("Search", "搜索") }));
  const rows = cat.projects.map((p) => [
    el("a", { href: projectUrl(p.project), text: p.meta.title || p.project.slice(0, 16) + "…" }),
    p.meta.license || "", p.size, when(p.time)]);
  root.replaceChildren(
    el("h1", { text: T("Verifiable science", "可验证的科研") }),
    el("h2", { text: T("Verify a proof bundle", "核验证明包") }),
    el("div", { id: "drop", class: "card", tabindex: "0", role: "button" },
      el("strong", { text: T("Drop a .pvb file here, or click to choose one", "把 .pvb 文件拖到这里，或点击选择") }), el("br"),
      el("span", { class: "muted", text: T("Checked entirely in your browser; nothing is uploaded.", "完全在你的浏览器里核验，不上传任何内容。") })),
    el("input", { id: "file", type: "file", accept: ".pvb,application/json", hidden: "" }),
    el("div", { id: "result", class: "card result", hidden: "" }),
    el("h2", { text: T("Public projects", "公开项目") }), search,
    rows.length ? table([T("Project", "项目"), T("License", "许可"), T("Entries", "条目"), T("Last head", "最新树头")], rows)
      : el("p", { class: "muted", text: q ? T("No project matches.", "没有匹配的项目。") : T("No public projects yet.", "还没有公开项目。") }),
    el("p", { class: "muted", text: T(`${cat.private} private project(s) on this hub.`, `本 Hub 另有 ${cat.private} 个私有项目。`) }),
    el("h2", { text: T("What a verdict means", "结论的含义") }),
    kv(VERDICTS.map(([k, en, cn]) => [k, T(en, cn)])));
  await import("./app.js");  // the drop zone above (reads #drop, #file, #result, #trust)
}

// -- project ------------------------------------------------------------------------------------

async function fetchLog(pid, size) {
  const log = [];
  while (log.length < size) {
    const page = await get(`/v1/projects/${pid}/entries?start=${log.length}`);
    if (!page.entries.length) break;
    for (const it of page.entries) log.push(it.entry);
  }
  return log.slice(0, size);
}

async function project(pid) {
  const [view, hub] = await Promise.all([get(`/v1/projects/${pid}/overview`), get("/v1/hub")]);
  const m = view.meta || {};
  const status = verdictCard("", T("Checking in your browser…", "正在你的浏览器里核对…"));
  const parts = [];
  if (m.title) parts.push(el("h1", { text: m.title }));
  if (m.description) parts.push(el("p", { text: m.description }));
  parts.push(el("h1", { class: "mono", style: "font-size:1.2rem;overflow-wrap:anywhere", text: pid }), status,
    kv([[T("Visibility", "可见性"), view.visibility], [T("License", "许可"), m.license || "-"],
      [T("Entries", "条目"), view.head ? view.head.size : 0],
      [T("Head time", "树头时间"), view.head ? when(view.head.time) : "-"],
      [T("Witness cosignatures", "见证联署"), view.cosignatures],
      [T("Anchors", "锚定"), `${view.anchors.count} (${view.anchors.providers.join(", ") || "-"})`]]));
  if (view.visibility !== "public") {
    parts.push(el("p", { class: "muted", text: T("Private project: entries are visible to members only.", "私有项目：条目仅成员可见。") }));
    root.replaceChildren(...parts);
    status.replaceChildren(el("div", { class: "verdict", text: T("Not checked: the hub reports this project as private.", "未核对：Hub 报告该项目为私有。") }));
    return;
  }
  parts.push(el("p", { class: "muted", text: T("Title, counts, README, files, lineage and leaderboard are as the hub reports them; the ledger section is checked here.",
    "标题、计数、README、文件、血缘与排行榜均为 Hub 报告的内容；账本部分在此核对。") }));
  if (view.readme) parts.push(el("h2", { text: "README" }), el("pre", { class: "card readme", text: view.readme }));
  if (view.files.length) {
    parts.push(el("h2", { text: T("Published files", "已发布文件") }), table([T("Name", "名称"), T("Size", "大小"), ""],
      view.files.map((f) => [f.name, `${f.size.toLocaleString()} B`,
        el("a", { href: `${base}/p/${pid}/files/${f.entry}`, text: T("download", "下载") })])));
  }
  if (view.lineage.length) {
    const link = (h) => el("a", { class: "mono", href: entryUrl(pid, h), text: h.slice(0, 12) });
    const list = (hs) => { const s = el("span"); hs.forEach((h, i) => { if (i) s.append(" "); s.append(link(h)); }); return s; };
    parts.push(el("h2", { text: T("Provenance", "溯源") }), table([T("Step", "步骤"), T("Used", "输入"), T("Generated", "产出")],
      view.lineage.slice(-200).map((a) => [link(a.activity), list(a.used.filter((h) => HEX64.test(h))), list(a.generated.filter((h) => HEX64.test(h)))])));
  }
  if (view.leaderboard) {
    const b = view.leaderboard;
    parts.push(el("h2", { text: T("Leaderboard", "排行榜") }), table(["#", T("Team", "队伍"), T("On time", "按时"), T("Score", "分数"), T("Hub check", "Hub 核对")],
      b.rows.map((r, i) => {
        const c = b.check.rows.find((x) => x.index === i);
        return [i + 1, r.team.slice(0, 20), r.on_time ? T("yes", "是") : T("no", "否"),
          r.score === null ? "-" : r.score, c ? (c.ok === true ? "✓" : c.ok === false ? `✗ ${c.why}` : "–") : "–"];
      })),
    el("p", { class: "muted", text: T(`The hub's own verdict: ${b.check.verdict}${b.check.why ? " — " + b.check.why : ""}. Scores are the evaluator's claim; \`provena challenge audit\` checks without trusting the hub.`,
      `Hub 自己的结论：${b.check.verdict}${b.check.why ? "——" + b.check.why : ""}。分数是评审方的声明；不信任 Hub 时用 \`provena challenge audit\` 自查。`) }));
  }
  const ledger = el("div", {}, el("p", { class: "muted", text: T("Loading the log…", "正在加载账本…") }));
  parts.push(el("h2", { text: T("Ledger (as checked here)", "账本（本页核对过的）") }), ledger);
  root.replaceChildren(...parts);

  try {
    const head = view.head;
    if (!head) throw new Error(T("the hub has no signed tree head for this project", "Hub 没有该项目的签名树头"));
    if (head.size > FETCH_MAX) {
      status.replaceWith(verdictCard("", T("NOT CHECKED HERE", "未在此核对"),
        T(`${head.size} entries is more than this page fetches (${FETCH_MAX}); check it with \`provena clone\` and \`provena verify\`.`,
          `${head.size} 个条目超过本页的抓取上限（${FETCH_MAX}）；请用 \`provena clone\` 与 \`provena verify\` 核对。`)));
      ledger.replaceChildren();
      return;
    }
    const log = await fetchLog(pid, head.size);
    const res = await verifyPublicLog(pid, hub.card, head, log, { replay: log.length <= REPLAY_MAX });
    status.replaceWith(verdictCard(res.replayed ? "ok" : "", res.replayed ? T("CHECKED BY THIS PAGE", "本页已核对") : T("PARTLY CHECKED", "部分核对"),
      res.replayed ? T(`${res.size} entries of this project hash to the tree head signed by this hub's log key ${res.signer}; every signature and ledger rule replays.`,
        `本项目的 ${res.size} 个条目与本 Hub 日志公钥 ${res.signer} 签名的树头一致；每个签名与账本规则都重放通过。`)
        : T(`${res.size} entries of this project hash to the tree head signed by ${res.signer}. The log is too large to replay here: authors' signatures and ledger rules were NOT re-checked.`,
          `本项目的 ${res.size} 个条目与 ${res.signer} 签名的树头一致。账本太大，未在此重放：作者签名与账本规则没有复核。`),
      SELF_NOTE()));
    const hashes = await Promise.all(log.map(entryHash));
    ledger.replaceChildren(table(["#", T("Entry", "条目"), T("Kind", "类型"), T("Author", "作者"), T("Client time", "客户端时间")],
      log.map((e, i) => [i, el("a", { class: "mono", href: entryUrl(pid, hashes[i]), text: hashes[i].slice(0, 12) }),
        e.kind, e.author.slice(0, 16), when(e.ts)])));
  } catch (err) {
    status.replaceWith(verdictCard("bad", T("CHECK FAILED", "核对失败"), String(err.message || err)));
    ledger.replaceChildren();
  }
}

// -- entry (the citation landing page) --------------------------------------------------------

async function entry(pid, h) {
  let view;
  try {
    view = await get(`/v1/projects/${pid}/entries/${h}`);
  } catch {
    root.replaceChildren(el("h1", { text: T("No such entry in this project", "该项目中没有这个条目") }),
      el("p", {}, el("a", { href: projectUrl(pid), text: pid })));
    return;
  }
  const rows = [[T("Project", "项目"), el("a", { class: "mono", href: projectUrl(pid), text: pid })],
    [T("Entry", "条目"), el("span", { class: "mono", text: h })],
    [T("Position", "位置"), `#${view.index} ${T("of", "/")} ${view.size}`], [T("Kind", "类型"), view.kind],
    [T("Sequenced", "上链时间"), `${when(view.sequenced)} (${T("as the hub reports it", "Hub 报告的时间")})`]];
  if (view.entry) {
    rows.push([T("Author", "作者"), el("span", { class: "mono", text: view.entry.author })],
      [T("Status", "状态"), view.redacted ? T("redacted", "已撤回") : view.revealed ? T("revealed", "已公开") : T("sealed", "密封")]);
  }
  if (view.anchored) rows.push([T("Anchored", "锚定"), `${when(view.anchored.time)} ${T("via", "经")} ${view.anchored.provider}`]);
  const status = verdictCard("", T("Checking in your browser…", "正在你的浏览器里核对…"));
  root.replaceChildren(el("h1", { text: T("Ledger entry", "账本条目") }), status, kv(rows),
    el("p", { class: "muted", text: T("A citation of this entry says: it existed, unchanged, in this project's log no later than its sequencing time — if you trust the log key.",
      "引用这个条目即说明：它不晚于上链时间、以未经改动的形态存在于该项目的账本中——前提是你信任这把日志公钥。") }));
  if (!view.entry) {
    status.replaceWith(verdictCard("", T("Not checked: private project", "未核对：私有项目"),
      T("Only members can see the entry itself; position, kind and time above are as the hub reports them.", "只有成员能看到条目本身；上面的位置、类型与时间为 Hub 报告的内容。")));
    return;
  }
  try {
    const [hub, head] = await Promise.all([get("/v1/hub"), get(`/v1/projects/${pid}/sth`)]);
    const proof = await get(`/v1/projects/${pid}/proofs/inclusion?index=${view.index}&size=${head.size}`);
    const res = await verifyEntryInclusion(pid, h, hub.card, head, view.entry, view.index, proof.proof);
    status.replaceWith(verdictCard("ok", T("CHECKED BY THIS PAGE", "本页已核对"),
      T(`This ${view.entry.kind} entry hashes to ${h.slice(0, 12)}… and is entry #${res.index} of the ${res.size}-entry log whose tree head, signed by this hub's log key ${res.signer} at ${when(res.time)}, includes it: it existed no later than that time. The author's signature is not re-checked on this page (the project page replays the whole log).`,
        `该 ${view.entry.kind} 条目哈希为 ${h.slice(0, 12)}…，是本 Hub 日志公钥 ${res.signer} 于 ${when(res.time)} 签名的 ${res.size} 条账本树头所包含的第 ${res.index} 条：它不晚于该时刻存在。本页不复核作者签名（项目页会重放整本账）。`), SELF_NOTE()));
  } catch (err) {
    status.replaceWith(verdictCard("bad", T("CHECK FAILED", "核对失败"), String(err.message || err)));
  }
}

function notFound(pid) {
  root.replaceChildren(el("h1", { text: T("No such entry in this project", "该项目中没有这个条目") }),
    el("p", {}, el("a", { href: projectUrl(pid), text: pid })));
}

// -- routing: real paths (old #/p/… links still work) -----------------------------------------

async function route() {
  const path = location.pathname.slice(base.length).replace(/\/+$/, "") || "/";
  const hash = location.hash.match(/^#\/p\/([0-9a-f]{64})$/);
  const p = path.match(/^\/p\/([0-9a-f]{64})(?:\/e\/([^/]+))?$/);
  try {
    if (hash) await project(hash[1]);
    else if (p && p[2]) await (HEX64.test(p[2]) ? entry(p[1], p[2]) : notFound(p[1]));
    else if (p) await project(p[1]);
    else await home();
  } catch (err) {
    root.replaceChildren(el("p", { class: "bad", text: String(err.message || err) }));
  }
}
window.addEventListener("hashchange", route);
route();
