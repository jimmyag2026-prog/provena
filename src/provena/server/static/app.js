import { verifyBundleText } from "./verifier.js";

const drop = document.getElementById("drop");
const input = document.getElementById("file");
const out = document.getElementById("result");
// Trust only what this hub vouches for: its own log key and its TSA certificates.
const trust = JSON.parse(document.getElementById("trust").textContent);

const zh = document.documentElement.lang.startsWith("zh");
// What a trust level means to someone who has never heard of Merkle trees (ADR 0007 levels).
const MEANING = {
  unverified: ["Signatures check out, but nothing here dates or orders the records: the log that signed them is not one you trust.",
    "签名无误，但没有可信的时间和顺序：签署这本账的日志不是你信任的。"],
  "self-sequenced": ["Signed by their authors; time and order are only the authors' own claim.",
    "由作者签名；时间和先后只是作者自己的说法。"],
  "log-sequenced": ["A log you trust recorded these entries in this order, no later than the times shown.",
    "你信任的日志按这个顺序记录了这些条目，时间不晚于所示时刻。"],
  witnessed: ["As log-sequenced, and an independent witness confirmed the log was not forked.",
    "同上，并且独立见证人确认这本账没有分叉。"],
  anchored: ["As witnessed/log-sequenced, and a time-stamp authority you trust dated the log.",
    "同上，并且你信任的时间戳机构为这本账盖了时间。"],
};
const T = (en, cn) => (zh ? cn : en);

function render(report, name) {
  const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text; return e; };
  out.className = "card result " + (report.ok ? "ok" : "bad");
  out.replaceChildren();
  out.append(el("div", "verdict", report.ok ? `VALID · ${report.trust}` : "INVALID"),
    el("div", "muted mono", name));
  if (report.ok) {
    out.append(el("p", "", (MEANING[report.trust] || ["", ""])[zh ? 1 : 0]));
    const pre = report.preregistration || [];
    if (pre.length) {
      out.append(el("h3", "", T("Preregistration", "预注册")));
      const tbl = el("table", "");
      const head = el("tr", "");
      [T("plan", "方案"), T("step", "步骤"), T("result", "结论")].forEach((h) => head.append(el("th", "", h)));
      tbl.append(head);
      pre.forEach((r) => {
        const tr = el("tr", "");
        tr.append(el("td", "mono", r.plan.slice(0, 12)),
          el("td", "mono", r.activity.slice(0, 12) + (r.target ? "" : T(" (upstream)", "（上游）"))),
          el("td", r.proven ? "ok" : "bad", r.proven ? T("proven: the plan came first", "成立：方案在前")
            : r.holds ? T("holds by the author's own order only", "仅按作者自报顺序成立")
              : T("not shown", "未能证明") + (r.reason ? ` (${r.reason})` : "")));
        tbl.append(tr);
      });
      out.append(tbl);
    }
  }
  const list = el("ul", "");
  report.facts.forEach((f) => list.append(el("li", "fact", f)));
  report.notes.forEach((n) => list.append(el("li", "note", n)));
  report.errors.forEach((e) => list.append(el("li", "err", e)));
  out.append(el("h3", "", T("Details", "明细")), list);
  out.hidden = false;
}

async function handle(file) {
  try {
    render(await verifyBundleText(await file.text(), trust), file.name);
  } catch (e) {
    render({ ok: false, facts: [], notes: [], errors: ["not a readable bundle: " + e.message] },
      file.name);
  }
}

drop.addEventListener("click", () => input.click());
drop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") input.click(); });
input.addEventListener("change", () => input.files[0] && handle(input.files[0]));
drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
drop.addEventListener("dragleave", () => drop.classList.remove("over"));
drop.addEventListener("drop", (e) => {
  e.preventDefault(); drop.classList.remove("over");
  if (e.dataTransfer.files[0]) handle(e.dataTransfer.files[0]);
});
