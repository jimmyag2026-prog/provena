"""Server-rendered public pages: landing + bundle verifier, and the public project explorer."""

import hashlib
import json
import os
import re
import secrets
import threading
from contextlib import closing
from datetime import UTC, datetime
from html import escape
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.background import BackgroundTask

from provena import __version__
from provena.core import aead, commitment
from provena.core.encoding import unb64u
from provena.core.errors import VerificationError
from provena.server import challenge_check
from provena.server.graph import lineage_svg
from provena.server.hub import Hub

STATIC = Path(__file__).parent / "static"
# The front end is also served under a path that names its content, so a CDN or browser can
# never pair a new page with an old cached module (relative imports stay inside the same build).
BUILD = hashlib.sha256(b"".join(f.name.encode() + f.read_bytes()
                                for f in sorted(STATIC.iterdir()) if f.is_file())).hexdigest()[:12]
HEX64 = re.compile(r"[0-9a-f]{64}")
# Defense in depth: ledger text is untrusted, so no inline script may ever run on this origin.
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; "
       "frame-ancestors 'none'")


# Hub pages in English and Chinese. Ledger content is shown as written; verifier facts stay in
# English (they are precise technical statements).
T = {
    "tagline": ("A ledger of experimental data and process, kept encrypted and backed by proof. "
                "GitHub for code, Hugging Face for models, Provena for verifiable science.",
                "实验数据与实验过程的账本：内容加密，凭证明可验证。"
                "代码有 GitHub，模型有 Hugging Face，可验证的科学有 Provena。"),
    "headline": ("Verifiable science.", "可验证的科学。"),
    "verify_bundle": ("Verify a proof bundle", "验证证明包"),
    "drop": ("Drop a <code>.pvb</code> file here", "把 <code>.pvb</code> 文件拖到这里"),
    "drop_hint": ("Checked entirely in your browser: signatures, Merkle proofs, commitments, "
                  "witness cosignatures, time-stamp tokens. Nothing is uploaded.",
                  "完全在你的浏览器里校验：签名、Merkle 证明、承诺、见证人联署、时间戳。"
                  "不上传任何内容。"),
    "page_trust": ("This page trusts only this hub's log key and the time-stamp authorities it "
                   "anchors with. Anything else in a bundle is shown as an unverified claim; for "
                   "your own trust decisions use <code>provena verify</code> with "
                   "<code>provena trust</code>.",
                   "本页只信任本 Hub 的日志公钥及其锚定所用的时间戳机构；"
                   "证明包里的其他内容都作为未经验证的声明显示。"
                   "你自己的信任决定请用 <code>provena verify</code> 配合 "
                   "<code>provena trust</code>。"),
    "public_projects": ("Public projects", "公开项目"),
    "search_placeholder": ("Search public projects", "搜索公开项目"),
    "search": ("Search", "搜索"),
    "project": ("Project", "项目"), "license": ("License", "许可"),
    "entries": ("Entries", "条目数"), "last_head": ("Last head", "最新树头"),
    "no_match": ("No matching public projects.", "没有匹配的公开项目。"),
    "no_projects": ("No public projects on this hub yet.", "本 Hub 还没有公开项目。"),
    "private_count": ("{n} private project(s) (only their tree heads are public) and {m} "
                      "unlisted project(s) (public, reachable by id) are also sequenced here.",
                      "另有 {n} 个私有项目（只有树头公开）和 {m} 个未列出项目（公开，可按 id 访问）"
                      "在此排序。"),
    "verdicts": ("What a verdict means", "验证结论的含义"),
    "v_unverified": ("Cryptographically valid, but signed by a log this page does not trust: "
                     "order and times are claims.",
                     "密码学上成立，但签名的日志不受本页信任：顺序与时间只是声明。"),
    "v_self": ("Signed by a project member. Times are the author's own claim.",
               "由项目成员自签。时间是作者自己的说法。"),
    "v_log": ("Ordered and timed by this hub's log key.", "由本 Hub 的日志公钥排序并计时。"),
    "v_witnessed": ("Independent witnesses checked this log never forked before cosigning the "
                    "head.", "独立见证人确认该日志从未分叉后联署了树头。"),
    "v_anchored": ("An external RFC 3161 time-stamp authority dated the log head.",
                   "外部 RFC 3161 时间戳机构为日志树头加盖了时间。"),
    "log_key": ("log key", "日志公钥"),
    "no_entry": ("No such entry", "没有这个条目"),
    "ledger_entry": ("Ledger entry", "账本条目"),
    "entry": ("Entry", "条目"), "position": ("Position", "位置"), "of": ("of", "/"),
    "kind": ("Kind", "类型"), "sequenced": ("Sequenced", "排序时间"),
    "hub_time": ("hub log time", "Hub 日志时间"), "author": ("Author", "作者"),
    "commitment": ("Commitment", "承诺"), "status": ("Status", "状态"),
    "revealed": ("revealed", "已公开"), "redacted": ("redacted", "已销毁"),
    "sealed": ("sealed", "密封"), "anchored_row": ("Anchored", "锚定"), "via": ("via", "经"),
    "entry_note": ("This page confirms existence, position and time. Ask the authors for a proof "
                   "bundle (<code>.pvb</code>) to verify content and lineage independently.",
                   "本页只确认存在、位置与时间。如需独立验证内容与血缘，请向作者索取证明包"
                   "（<code>.pvb</code>）。"),
    "visibility": ("Visibility", "可见性"), "not_stated": ("not stated", "未声明"),
    "head_root": ("Head root", "树头根"), "head_time": ("Head time", "树头时间"),
    "witnesses": ("Witnesses", "见证人"),
    "cosigs": ("{n} cosignature(s) on the latest head", "最新树头上有 {n} 个联署"),
    "anchors": ("Anchors", "锚定"), "none_yet": ("none yet", "暂无"),
    "private_note": ("This project is private: entries are visible to members only. Ask an "
                     "author for a proof bundle.",
                     "这是私有项目：条目只对成员可见。请向作者索取证明包。"),
    "provenance": ("Provenance", "溯源"),
    "graph_note": ("Data → activity → outputs; plans feed the activities that cite them. "
                   "✓ revealed, ✗ redacted.",
                   "数据 → 步骤 → 产出；方案指向引用它的步骤。✓ 已公开，✗ 已销毁。"),
    "ledger": ("Ledger", "账本"), "client_time": ("Client time", "客户端时间"),
    "ledger_note": ("Content stays encrypted unless revealed. Client times are self-reported; "
                    "the log head time is the hub's.",
                    "内容除非公开否则一直加密。客户端时间为自报；树头时间来自 Hub。"),
    "attestations": ("{n} attestation(s)", "{n} 条证明"),
    "other_lang": ("中文", "English"),
    "files": ("Published files", "已发布文件"),
    "leaderboard": ("Leaderboard", "排行榜"),
    "lb_note": ("Published by agent <span class='mono'>{who}</span> as the output of scoring step "
                "{step}, which cites {n} entries of other projects. To check it without trusting "
                "this hub, re-derive teams, projects, prediction entries and on-time status with "
                "<code>provena challenge audit</code>; the scores are the publisher's claim.",
                "由 agent <span class='mono'>{who}</span> 发布，是评分步骤 {step} 的产出，"
                "该步骤引用了其他项目的 {n} 个条目。若不信任本 Hub，"
                "队伍、项目、预测条目与是否按时请用 "
                "<code>provena challenge audit</code> 重新推出；分数是发布者的声明。"),
    "hub_check": ("Hub check", "Hub 核对"),
    "no_js": ("This page needs JavaScript; the same content without it",
              "本页需要 JavaScript；不需要 JavaScript 的同一内容"),
    "spa_link": ("Check this project's whole log in your browser (needs JavaScript)",
                 "在你的浏览器里核对这个项目的整本账（需要 JavaScript）"),
    "lb_ok": ("This hub re-applied the rules of challenge {protocol} (organizer {org}) to its own "
              "logs and receipt times as of the scoring step: every row matches (team, prediction "
              "entry, on time), the truth was not disclosed early, and no registered team that "
              "submitted on time is missing.",
              "本 Hub 按挑战 {protocol}（组织方 {org}）的规则，用自己截至评分步骤的日志与回执时间"
              "重新核对：每一行都对得上（队伍、预测条目、是否按时），真值没有提前披露，"
              "也没有漏掉按时提交的报名队。"),
    "lb_ok_open": ("This hub re-applied the rules of challenge {protocol} (organizer {org}) to its "
                   "own logs and receipt times as of the scoring step: every row matches and the "
                   "truth was not disclosed early. Registration is open, so the hub cannot tell "
                   "whether an on-time submission was left off the board (a team can check with "
                   "<code>provena challenge audit --submission</code>).",
                   "本 Hub 按挑战 {protocol}（组织方 {org}）的规则核对：每一行都对得上，真值没有"
                   "提前披露。该挑战开放报名，Hub 无法判断是否有按时提交被漏掉"
                   "（队伍可用 <code>provena challenge audit --submission</code> 自查）。"),
    "lb_partial": ("This hub checked challenge {protocol} (organizer {org}) only in part: {why}. "
                   "The rows it could check are marked.",
                   "本 Hub 只核对了挑战 {protocol}（组织方 {org}）的一部分：{why}。"
                   "能核对的行已标出。"),
    "lb_fail": ("This hub re-applied the challenge rules to its own logs and receipt times and "
                "found a problem: {why}",
                "本 Hub 用自己的日志与回执时间重新套用挑战规则，发现问题：{why}"),
    "lb_unchecked": ("This hub could not check this leaderboard: {why}",
                     "本 Hub 无法核对这份排行榜：{why}"),
    "lb_absent": ("Registered but not on the board: {who}", "已报名但不在榜上：{who}"),
    "rank": ("#", "#"), "team": ("Team (agent)", "队伍（agent）"),
    "on_time": ("On time", "按时"),
    "score": ("Score", "分数"), "yes": ("yes", "是"), "no": ("no", "否"),
    "files_note": ("Published with their content key: anyone can download them; each download "
                   "is checked against its commitment on the ledger before it is served.",
                   "随内容密钥一起发布：任何人都可下载；每次下载前都会与账本上的承诺核对。"),
    "size": ("Size", "大小"), "download": ("download", "下载"), "name": ("Name", "名称"),
}


def _lang(request: Request) -> int:
    """0 = English, 1 = Chinese: `?lang=` wins, then Accept-Language."""
    forced = request.query_params.get("lang")
    if forced in ("en", "zh"):
        return 1 if forced == "zh" else 0
    accept = request.headers.get("accept-language", "").lower()
    return 1 if accept.startswith("zh") else 0


README_MAX = 64 * 1024
PUBLISHED_CACHE_BYTES = 5 * 1024**3  # verified-plaintext cache; oldest files evicted beyond it


def render_markdown(text: str) -> str:
    """A deliberately tiny, safe Markdown subset: everything is HTML-escaped first, then only
    headings, bullet lists, paragraphs and `code` spans become tags. No links, no images, no
    raw HTML — ledger text never becomes markup."""
    out, para, items = [], [], []

    def inline(t: str) -> str:
        return re.sub(r"`([^`]+)`", r"<code>\1</code>", escape(t))

    def flush():
        if para:
            out.append("<p>" + inline(" ".join(para)) + "</p>")
            para.clear()
        if items:
            out.append("<ul>" + "".join(f"<li>{inline(i)}</li>" for i in items) + "</ul>")
            items.clear()

    for line in text.splitlines():
        stripped = line.strip()
        heading = re.match(r"(#{1,4})\s+(.*)", stripped)
        if not stripped:
            flush()
        elif heading:
            flush()
            level = len(heading.group(1)) + 1  # page already has an h1
            out.append(f"<h{level}>{inline(heading.group(2))}</h{level}>")
        elif re.match(r"[-*]\s+", stripped):
            if para:
                flush()
            items.append(re.sub(r"^[-*]\s+", "", stripped))
        else:
            if items:
                flush()
            para.append(stripped)
    flush()
    return "\n".join(out)


def _when(ms: int) -> str:
    try:
        return datetime.fromtimestamp(ms / 1000, tz=UTC).strftime("%Y-%m-%d %H:%M UTC")
    except (OverflowError, OSError, ValueError):  # client timestamps are self-reported
        return "(invalid time)"


_ROOT_LINK = re.compile(r"""(href|src|action)=(["'])/(?!/)""")


_CLASSIC_LINK = re.compile(r"""(href|action)=(["'])/(p/[0-9a-f]{64}(?!/files/)|(?=["'?]))""")


def _page(title: str, body: str, hub: Hub, lang: int = 0, classic: bool = False) -> HTMLResponse:
    """*classic*: a server-rendered page (no JavaScript needed); its links stay classic."""
    other = "en" if lang else "zh"
    html = _page_html(title, body, hub, lang, other)
    if classic:
        html = _CLASSIC_LINK.sub(lambda m: f"{m[1]}={m[2]}/classic/{m[3]}".rstrip("/"), html)
    base = getattr(hub, "base_path", "")
    # behind a path prefix (Caddy `uri strip_prefix /provena`): site-absolute links get it back
    return HTMLResponse(_ROOT_LINK.sub(rf"\1=\2{base}/", html) if base else html)


def _page_html(title: str, body: str, hub: Hub, lang: int, other: str) -> str:
    return (f"""<!doctype html>
<html lang="{'zh-CN' if lang else 'en'}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)}</title><link rel="stylesheet" href="/static/style.css"></head>
<body><main>
<header class="top"><a class="brand" href="/?lang={'zh' if lang else 'en'}">Provena</a>
<span class="muted mono">{T["log_key"][lang]} {escape(hub.card["id"])} · v{__version__} ·
<a href="?lang={other}">{T["other_lang"][lang]}</a></span></header>
{body}
</main></body></html>""")


def _readme_card(hub: Hub, pid: str, state) -> str:
    """A README.md published with its key is shown as the project card (verified first)."""
    for h, rv in state.reveals.items():
        body = state.entries[h]["body"]
        name = (rv.get("name") or "").lower()
        if (not rv.get("dek") or name not in ("readme.md", "readme") or h in state.redacted
                or body.get("size", 0) > README_MAX + 4096 or not body.get("cid")
                or not hub.blob_owner(pid, body["cid"])):
            continue
        try:
            with closing(hub.storage.blobs_open(pid, body["cid"])) as src:
                plain = aead.decrypt_bytes(unb64u(rv["dek"]), src.read())
        except (VerificationError, ValueError):
            continue
        if hashlib.sha256(plain).hexdigest() == rv["plain_sha256"]:
            return ("<div class='card readme'>" + render_markdown(plain.decode("utf-8", "replace"))
                    + "</div>")
    return ""


LEADERBOARD_MAX = 256 * 1024


def _chunks(handle, size: int = 1 << 20):
    try:
        while chunk := handle.read(size):
            yield chunk
    finally:
        handle.close()


def _leaderboard_rows(plain: bytes) -> list[dict] | None:
    """Rows of a `provena challenge score` leaderboard, or None if it does not look like one."""
    def no_constant(token):
        raise ValueError(f"{token} is not a score")
    try:
        rows = json.loads(plain, parse_constant=no_constant)
    except ValueError:
        return None
    if not isinstance(rows, list) or len(rows) > 1000:
        return None
    for r in rows:
        if not (isinstance(r, dict) and isinstance(r.get("team"), str)
                and isinstance(r.get("project"), str) and HEX64.fullmatch(r["project"])
                and isinstance(r.get("on_time"), bool)
                and (r.get("score") is None or (isinstance(r["score"], int | float)
                                                and not isinstance(r["score"], bool)
                                                and abs(r["score"]) < 1e300))):
            return None
    # on-time rows first, always: a late submission never ranks above one that met the deadline
    return sorted(rows, key=lambda r: (not r["on_time"], r["score"] is None, -(r["score"] or 0)))


def _score(value) -> str:
    return "-" if value is None else f"{value:.4g}"


def leaderboard(hub: Hub, pid: str, state) -> dict | None:
    """The newest leaderboard.json published with its key by the author of the scoring step that
    generated it (a step citing other projects' entries), ranked, with the hub's own check of it
    (server.challenge_check). Its ciphertext is verified against the ledger."""
    revealer = {e["body"]["target"]: e["author"] for e in state.entries.values()
                if e["kind"] == "reveal" and e["body"].get("dek")}
    tries = 0
    for h in reversed(state.order):
        rv = state.reveals.get(h)
        if not rv or (rv.get("name") or "").lower() != "leaderboard.json":
            continue
        body = state.entries[h]["body"]
        step = state.generated_by.get(h)
        activity = state.entries[step] if step else None
        if (not rv.get("dek") or h in state.redacted or activity is None
                or not activity["body"].get("external")
                or revealer.get(h) != activity["author"]
                or body.get("size", 0) > LEADERBOARD_MAX + 4096
                or not body.get("cid") or not hub.blob_owner(pid, body["cid"])):
            continue
        tries += 1
        if tries > 2:  # bounded work per page view
            break
        try:
            with closing(hub.storage.blobs_open(pid, body["cid"])) as src:
                plain = aead.decrypt_bytes(unb64u(rv["dek"]), src.read())
        except (VerificationError, ValueError):
            continue
        if hashlib.sha256(plain).hexdigest() != rv["plain_sha256"]:
            continue
        rows = _leaderboard_rows(plain)
        if rows is None:
            continue
        scored_at = (hub.storage.entry_by_hash(pid, step) or {}).get("integrated_time", 0)
        return {"entry": h, "step": step, "evaluator": activity["author"],
                "cites": len(activity["body"]["external"]), "rows": rows,
                "check": challenge_check.check(hub, activity, rows, scored_at)}
    return None


def _leaderboard_card(hub: Hub, pid: str, state, t) -> str:
    board = leaderboard(hub, pid, state)
    if board is None:
        return ""
    h, step, rows, checked = board["entry"], board["step"], board["rows"], board["check"]
    note = t("lb_note", who=escape(board["evaluator"][:20]),
             step=f"<a class='mono' href='/p/{pid}/e/{step}'>{step[:12]}</a>",
             n=board["cites"])

    def mark(i: int, checked=checked) -> str:
        ok, why = checked["rows"].get(i, (None, ""))
        if ok is None:
            return f"<span class='muted' title='{escape(why)}'>–</span>"
        return "✓" if ok else f"<span class='bad' title='{escape(why)}'>✗ {escape(why)}</span>"

    trs = "".join(
        f"<tr><td>{i}</td><td class='mono'>{escape(r['team'][:20])}</td>"
        f"<td><a class='mono' href='/p/{r['project']}'>{r['project'][:12]}</a></td>"
        f"<td>{t('yes') if r['on_time'] else t('no')}</td>"
        f"<td>{_score(r['score'])}</td><td>{mark(i - 1)}</td></tr>"
        for i, r in enumerate(rows, 1))
    where = {"protocol": "", "org": ""}
    if checked["protocol"]:
        where = {"protocol": f"<a class='mono' href='/p/{checked['org']}/e/"
                             f"{checked['protocol']}'>{checked['protocol'][:12]}</a>",
                 "org": f"<a class='mono' href='/p/{checked['org']}'>"
                        f"{checked['org'][:12]}</a>"}
    why = escape(checked["why"])
    verdict = {"ok": t("lb_ok", **where), "ok-open": t("lb_ok_open", **where),
               "partial": t("lb_partial", why=why, **where),
               "fail": t("lb_fail", why=why),
               "unchecked": t("lb_unchecked", why=why)}[checked["verdict"]]
    if checked["verdict"] == "fail" and not checked["why"]:
        verdict = t("lb_fail", why=escape("; ".join(
            why for ok, why in checked["rows"].values() if ok is False)
            or "; ".join(a for a in checked["absent"] if "on time" in a)))
    absent = (f"<p class='muted'>{t('lb_absent', who=escape(', '.join(checked['absent'])))}"
              "</p>" if checked["absent"] else "")
    return (f"<h2>{t('leaderboard')}</h2><div class='table-wrap'><table><tr>"
            f"<th>{t('rank')}</th><th>{t('team')}</th><th>{t('project')}</th>"
            f"<th>{t('on_time')}</th><th>{t('score')}</th><th>{t('hub_check')}</th></tr>"
            f"{trs}</table></div><p class='verdict-{checked['verdict']}'>{verdict}</p>"
            f"{absent}<p class='muted'>{note} "
            f"<a class='mono' href='/p/{pid}/e/{h}'>{h[:12]}</a></p>")


# -- what the pages show, as data (GET /v1/catalog, /v1/projects/{pid}/overview) -------------

def catalog(hub: Hub, q: str = "", include_unlisted: bool = False) -> dict:
    """Public projects (title, tags, license, size, last head time); listings never load
    project state. Projects the operator unlisted are counted, not listed (a witness that
    enumerates the hub asks for them with include_unlisted; they are still public)."""
    rows, needle, private, unlisted = [], q.strip().lower(), 0, 0
    hidden = hub.unlisted_projects()
    for row in hub.storage.catalog():
        if row["visibility"] != "public":
            private += 1
            continue
        pid, m = row["project"], row["meta"]
        if pid in hidden:
            unlisted += 1
            if not include_unlisted:
                continue
        haystack = " ".join([pid, m.get("title", ""), m.get("description", ""),
                             *m.get("tags", [])]).lower()
        if needle and needle not in haystack:
            continue
        head = hub.storage.head(pid)
        rows.append({"project": pid, "meta": m, "size": head["size"] if head else 0,
                     "time": head["time"] if head else None, **({"unlisted": True}
                                                                 if pid in hidden else {})})
    return {"projects": rows, "private": private, "unlisted": unlisted}


def entry_rows(state) -> list[dict]:
    rows = []
    for i, h in enumerate(state.order):
        e = state.entries[h]
        target = e["body"].get("target")
        rows.append({"index": i, "hash": h, "kind": e["kind"], "author": e["author"],
                     "ts": e["ts"], "target": target if isinstance(target, str) else None,
                     "revealed": h in state.reveals, "redacted": h in state.redacted,
                     "attestations": len(state.attestations.get(h, []))})
    return rows


def published_files(state) -> list[dict]:
    return [{"entry": h, "name": rv.get("name") or h[:12],
             "size": state.entries[h]["body"].get("size", 0)}
            for h, rv in state.reveals.items() if rv.get("dek") and h not in state.redacted]


def entry_view(hub: Hub, pid: str, entry_hash: str) -> dict:
    """What the entry (citation) page shows. Private projects: position, kind and time only.
    Public: the entry itself, so a browser can hash it and check its inclusion proof."""
    state = hub._state(pid)
    meta = hub.storage.entry_by_hash(pid, entry_hash)
    if meta is None:
        raise HTTPException(404, "no such entry in this project")
    e = state.entries[entry_hash]
    out = {"project": pid, "hash": entry_hash, "index": meta["index"], "size": hub.size(pid),
           "kind": e["kind"], "sequenced": meta["integrated_time"],
           "visibility": state.policy["visibility"]}
    if state.policy["visibility"] == "public":
        out.update(entry=e, revealed=entry_hash in state.reveals,
                   redacted=entry_hash in state.redacted)
    anchored = [a for a in hub.anchors_for(pid) if a["head"]["size"] > meta["index"]]
    if anchored:
        first = min(anchored, key=lambda a: a["anchor"]["time"])
        out["anchored"] = {"time": first["anchor"]["time"], "provider": first["anchor"]["provider"]}
    return out


def readme_text(hub: Hub, pid: str, state) -> str | None:
    """A README published with its key, as plain text (verified against the ledger)."""
    for h, rv in state.reveals.items():
        body = state.entries[h]["body"]
        if (rv.get("dek") and (rv.get("name") or "").lower() in ("readme.md", "readme")
                and h not in state.redacted and body.get("cid")
                and body.get("size", 0) <= README_MAX + 4096 and hub.blob_owner(pid, body["cid"])):
            try:
                with closing(hub.storage.blobs_open(pid, body["cid"])) as src:
                    plain = aead.decrypt_bytes(unb64u(rv["dek"]), src.read())
            except (VerificationError, ValueError):
                continue
            if hashlib.sha256(plain).hexdigest() == rv["plain_sha256"]:
                return plain.decode("utf-8", "replace")
    return None


OVERVIEW_ENTRIES = 1000


def overview(hub: Hub, pid: str) -> dict:
    """Everything the project page shows. Private projects: the public summary only."""
    state = hub._state(pid)
    head = hub.storage.head(pid)
    anchors = hub.anchors_for(pid)
    public = state.policy["visibility"] == "public"
    out = {"project": pid, "visibility": state.policy["visibility"], "head": head,
           "cosignatures": len(hub.storage.cosignatures(pid, head["size"])) if head else 0,
           "anchors": {"count": len(anchors),
                       "providers": sorted({a["anchor"]["provider"] for a in anchors})},
           "meta": state.meta if public else {}}
    if public:  # the newest entries; the whole log pages through /v1/projects/{pid}/entries
        rows = entry_rows(state)
        out["entries_total"], out["entries"] = len(rows), rows[-OVERVIEW_ENTRIES:]
        out["files"] = published_files(state)
        out["readme"] = readme_text(hub, pid, state)
        out["lineage"] = [{"activity": h, "used": e["body"].get("used", []),
                           "generated": e["body"].get("generated", [])}
                          for h, e in ((h, state.entries[h]) for h in state.order)
                          if e["kind"] == "activity"]
        board = leaderboard(hub, pid, state)
        if board:
            check = board["check"]
            board = {k: board[k] for k in ("entry", "step", "evaluator", "cites", "rows")} | {
                "check": {
                **check, "rows": [{"index": i, "ok": ok, "why": why}
                                  for i, (ok, why) in sorted(check["rows"].items())]}}
        out["leaderboard"] = board
    return out


def install(app: FastAPI, hub: Hub) -> None:
    app.mount(f"/static/{BUILD}", StaticFiles(directory=STATIC), name="static-build")
    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    decrypt_slots = threading.BoundedSemaphore(4)
    poisoned: set[tuple[str, str]] = set()  # published content that fails verification

    @app.middleware("http")
    async def _security_headers(request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    def spa_shell(request: Request, classic: str) -> HTMLResponse:
        """The hub's pages are a single-page app over the JSON API (static/spa.js); the
        server-rendered pages stay under /classic for clients without JavaScript."""
        lang = _lang(request)
        trust = json.dumps({"trustedLogs": [hub.card["id"]],  # safe inside <script>:
                            "trustedTsas": hub.tsa_fingerprints()}).replace("</", "<\\/")
        body = (f"<div id='spa' data-base='{escape(hub.base_path)}'><p class='muted'>…</p></div>"
                f"<noscript><p><a href='{escape(classic)}'>{T['no_js'][lang]}</a></p></noscript>"
                f"<script id='trust' type='application/json'>{trust}</script>"
                f"<script type='module' src='/static/{BUILD}/spa.js'></script>")
        return _page("Provena Hub", body, hub, lang)

    @app.get("/", response_class=HTMLResponse)
    def home(request: Request):
        return spa_shell(request, "/classic")

    @app.get("/p/{pid}", response_class=HTMLResponse)
    def project_shell(request: Request, pid: str):
        if not hub.storage.catalog_has(pid):
            raise HTTPException(404, "unknown project")
        return spa_shell(request, f"/classic/p/{pid}")

    @app.get("/p/{pid}/e/{entry_hash}", response_class=HTMLResponse)
    def entry_shell(request: Request, pid: str, entry_hash: str):
        if not HEX64.fullmatch(entry_hash) or not hub.storage.catalog_has(pid):
            raise HTTPException(404, "unknown project")
        return spa_shell(request, f"/classic/p/{pid}/e/{entry_hash}")

    @app.get("/app")
    def app_moved(request: Request):  # the beta reader's address before it became the front end
        lang = request.query_params.get("lang")
        return RedirectResponse((hub.base_path or "") + "/" + (
            f"?lang={lang}" if lang in ("en", "zh") else ""), status_code=308)

    @app.get("/v1/projects/{pid}/entries/{entry_hash}")
    def entry_json(pid: str, entry_hash: str):
        return Response(json.dumps(entry_view(hub, pid, entry_hash)),
                        media_type="application/json")

    @app.get("/v1/catalog")
    def catalog_json(q: str = "", include: str = ""):  # plain JSON already: skip re-encoding
        listing = catalog(hub, q, include_unlisted=include == "unlisted")
        return Response(json.dumps(listing), media_type="application/json")

    @app.get("/v1/projects/{pid}/overview")
    def overview_json(pid: str):
        return Response(json.dumps(overview(hub, pid)), media_type="application/json")

    @app.get("/classic", response_class=HTMLResponse)
    def index(request: Request, q: str = ""):
        lang = _lang(request)

        def t(k, **kw):
            return T[k][lang].format(**kw)

        rows, needle = [], q.strip().lower()
        listing = catalog(hub, q)
        for row in listing["projects"]:
            pid, m = row["project"], row["meta"]
            title = escape(m.get("title") or pid[:16] + "…")
            tags = "".join(f"<span class='pill'>{escape(x)}</span> " for x in m.get("tags", []))
            rows.append(f"<tr><td><a href='/p/{pid}'>{title}</a><br>{tags}</td>"
                        f"<td>{escape(m.get('license', ''))}</td>"
                        f"<td>{row['size']}</td><td>{_when(row['time'])}</td></tr>")
        projects = (f"<div class='table-wrap'><table><tr><th>{t('project')}</th>"
                    f"<th>{t('license')}</th><th>{t('entries')}</th><th>{t('last_head')}</th>"
                    "</tr>" + "".join(rows) + "</table></div>") if rows else (
            f"<p class='muted'>{t('no_match') if needle else t('no_projects')}</p>")
        search = (f"<form class='search' method='get' action='/'><input id='q' name='q' "
                  f"type='search' placeholder='{t('search_placeholder')}' "
                  f"value='{escape(q)}'><input type='hidden' name='lang' "
                  f"value='{'zh' if lang else 'en'}'><button type='submit'>{t('search')}"
                  "</button></form>")
        private = listing["private"]
        trust_json = json.dumps({"trustedLogs": [hub.card["id"]],  # safe inside <script>:
                                 "trustedTsas": hub.tsa_fingerprints()}).replace("</", "<\\/")
        body = f"""
<h1>{t('headline')}</h1>
<p class="tagline">{t('tagline')}</p>

<h2>{t('verify_bundle')}</h2>
<div id="drop" class="card" tabindex="0" role="button">
  <strong>{t('drop')}</strong><br>
  <span class="muted">{t('drop_hint')}</span>
</div>
<p class="muted">{t('page_trust')}</p>
<script id="trust" type="application/json">{trust_json}</script>
<input id="file" type="file" accept=".pvb,application/json" hidden>
<div id="result" class="card result" hidden></div>

<h2>{t('public_projects')}</h2>
{search}{projects}
<p class="muted">{t('private_count', n=private, m=listing["unlisted"])}</p>

<h2>{t('verdicts')}</h2>
<div class="card"><dl class="kv">
<dt><span class="pill">unverified</span></dt><dd>{t('v_unverified')}</dd>
<dt><span class="pill">self-sequenced</span></dt><dd>{t('v_self')}</dd>
<dt><span class="pill">log-sequenced</span></dt><dd>{t('v_log')}</dd>
<dt><span class="pill">witnessed</span></dt><dd>{t('v_witnessed')}</dd>
<dt><span class="pill">anchored</span></dt><dd>{t('v_anchored')}</dd>
</dl></div>
<script type="module" src="/static/app.js"></script>"""
        return _page("Provena Hub", body, hub, lang, classic=True)

    @app.get("/classic/p/{pid}/e/{entry_hash}", response_class=HTMLResponse)
    def entry_page(request: Request, pid: str, entry_hash: str):
        """Citation landing page: confirms an entry exists and when it was sequenced. For
        private projects nothing beyond position, kind and time is shown."""
        lang = _lang(request)

        def t(k, **kw):
            return T[k][lang].format(**kw)

        state = hub._state(pid)
        meta = hub.storage.entry_by_hash(pid, entry_hash)
        if meta is None:
            return _page("Not found · Provena", f"<h1>{t('no_entry')}</h1>", hub, lang,
                         classic=True)
        e = state.entries[entry_hash]
        public = state.policy["visibility"] == "public"
        rows = [(t("project"), f"<a class='mono' href='/p/{pid}'>{pid}</a>"),
                (t("entry"), f"<span class='mono'>{entry_hash}</span>"),
                (t("position"), f"#{meta['index']} {t('of')} {hub.size(pid)}"),
                (t("kind"), escape(e["kind"])),
                (t("sequenced"), f"{_when(meta['integrated_time'])} ({t('hub_time')})")]
        if public:
            rows.append((t("author"), f"<span class='mono'>{escape(e['author'])}</span>"))
            commitment = e["body"].get("commitment")
            if e["kind"] in ("entity", "plan") and isinstance(commitment, str) and \
                    HEX64.fullmatch(commitment):  # other kinds carry arbitrary extra fields
                rows.append((t("commitment"), f"<span class='mono'>{commitment}</span>"))
            rows.append((t("status"), ", ".join(
                t(f) for f, on in (("revealed", entry_hash in state.reveals),
                                   ("redacted", entry_hash in state.redacted)) if on)
                or t("sealed")))
        anchored = [a for a in hub.anchors_for(pid) if a["head"]["size"] > meta["index"]]
        if anchored:
            first = min(anchored, key=lambda a: a["anchor"]["time"])
            rows.append((t("anchored_row"), f"{_when(first['anchor']['time'])} {t('via')} "
                                            f"{escape(first['anchor']['provider'])}"))
        dl = "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in rows)
        body = (f"<h1>{t('ledger_entry')}</h1><div class='card'><dl class='kv'>{dl}</dl></div>"
                f"<p class='muted'>{t('entry_note')}</p>")
        return _page(f"{entry_hash[:12]} · Provena", body, hub, lang, classic=True)

    @app.get("/p/{pid}/files/{entry_hash}")
    def published_file(pid: str, entry_hash: str):
        """Plaintext of content published *with its key*: the DEK is public on the ledger, so
        the hub decrypts, checks the plaintext against the commitment, and serves it."""
        state = hub._state(pid)
        reveal = state.reveals.get(entry_hash)
        cid = state.entries.get(entry_hash, {}).get("body", {}).get("cid")
        if not reveal or not reveal.get("dek") or not cid or not hub.blob_owner(pid, cid):
            return Response("not published with its key, redacted, or not stored here",
                            status_code=404)
        body = state.entries[entry_hash]["body"]
        cached = hub.storage.published_path(pid, cid)
        if (pid, cid) in poisoned:
            return Response("published content does not match its commitment", status_code=422)
        if not cached.exists():
            # decrypt + verify once, then serve the verified plaintext from the cache; cold
            # decryptions are capped so anonymous requests cannot pin the CPU and disk
            if not decrypt_slots.acquire(blocking=False):
                return Response("busy: try again shortly", status_code=503,
                                headers={"Retry-After": "5"})
            try:
                _decrypt_published(pid, cid, reveal, body, cached)
            except VerificationError:  # includes DecryptionError
                # reveal and blob are immutable: remember the mismatch instead of re-decrypting
                # up to a gigabyte for every request
                if len(poisoned) < 10_000:
                    poisoned.add((pid, cid))
                raise
            finally:
                decrypt_slots.release()

        try:  # hold the file open: a concurrent trim or shred may unlink the path meanwhile
            handle = cached.open("rb")
        except FileNotFoundError:  # redacted while decrypting, or evicted just now
            return Response("not available: try again", status_code=404)
        name = (reveal.get("name") or entry_hash[:12]).split("/")[-1]
        fallback = "".join(c for c in name if 0x20 <= ord(c) < 0x7F and c not in '"\\;') or "file"
        return StreamingResponse(
            _chunks(handle), media_type="application/octet-stream",
            background=BackgroundTask(handle.close), headers={
                "Content-Length": str(os.fstat(handle.fileno()).st_size),
                "Content-Disposition": f"attachment; filename=\"{fallback}\"; "
                                       f"filename*=UTF-8''{quote(name, safe='')}"})

    def _decrypt_published(pid: str, cid: str, reveal: dict, body: dict, dest) -> None:
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_name(dest.name + f".{secrets.token_hex(4)}.part")
        try:
            with tmp.open("wb") as dst, closing(hub.storage.blobs_open(pid, cid)) as src:
                info = aead.decrypt_stream(unb64u(reveal["dek"]), src, dst)
            if info.plain_sha256.hex() != reveal["plain_sha256"]:
                raise VerificationError("published content does not match the revealed hash")
            commitment.verify_opening(bytes.fromhex(body["commitment"]),
                                      bytes.fromhex(reveal["salt"]), info.plain_sha256)
            # under the sequencing lock: a redaction is either already applied (then nothing is
            # cached) or applied later (then its shred deletes this file) — never in between
            with hub._lock:
                if hub.blob_owner(pid, cid):
                    os.replace(tmp, dest)
        finally:
            tmp.unlink(missing_ok=True)
        hub.storage.trim_published(PUBLISHED_CACHE_BYTES)

    @app.get("/classic/p/{pid}", response_class=HTMLResponse)
    def project_page(request: Request, pid: str):
        lang = _lang(request)

        def t(k, **kw):
            return T[k][lang].format(**kw)

        state = hub._state(pid)
        head = hub.storage.head(pid)
        cosigs = hub.storage.cosignatures(pid, head["size"]) if head else []
        anchors = hub.anchors_for(pid)
        m = state.meta if state.policy["visibility"] == "public" else {}
        title_html = (f"<h1>{escape(m['title'])}</h1>" if m.get("title") else "")
        desc_html = (f"<p>{escape(m['description'])}</p>" if m.get("description") else "")
        providers = ", ".join(sorted({a["anchor"]["provider"] for a in anchors}))
        summary = f"""{title_html}{desc_html}
<h1 class="mono" style="font-size:1.2rem;overflow-wrap:anywhere">{pid}</h1>
<div class="card"><dl class="kv">
<dt>{t('visibility')}</dt><dd>{escape(state.policy["visibility"])}</dd>
<dt>{t('license')}</dt><dd>{escape(m.get("license") or t('not_stated'))}</dd>
<dt>{t('entries')}</dt><dd>{head["size"] if head else 0}</dd>
<dt>{t('head_root')}</dt><dd class="mono">{head["root"] if head else "-"}</dd>
<dt>{t('head_time')}</dt><dd>{_when(head["time"]) if head else "-"}</dd>
<dt>{t('witnesses')}</dt><dd>{t('cosigs', n=len(cosigs))}</dd>
<dt>{t('anchors')}</dt><dd>{len(anchors)} ({providers or t('none_yet')})</dd>
</dl></div>
<p class="muted"><a href="/p/{pid}">{t('spa_link')}</a></p>"""
        if state.policy["visibility"] != "public":
            body = summary + f"<p class='muted'>{t('private_note')}</p>"
            return _page("Private project · Provena", body, hub, lang, classic=True)
        rows = []
        for r in entry_rows(state):
            flags = ([t("revealed")] if r["revealed"] else []) + (
                [t("redacted")] if r["redacted"] else []) + (
                [t("attestations", n=r["attestations"])] if r["attestations"] else [])
            h, detail = r["hash"], f"→ {r['target'][:12]}" if r["target"] else ""
            rows.append(
                f"<tr><td>{r['index']}</td><td><a class='mono' href='/p/{pid}/e/{h}'>{h[:12]}"
                f"</a></td><td>{escape(r['kind'])}</td>"
                f"<td class='mono'>{escape(r['author'][:16])}</td><td>{_when(r['ts'])}</td>"
                f"<td class='mono'>{escape(detail)}</td>"
                f"<td>{''.join(f'<span class=pill>{f}</span> ' for f in flags)}</td></tr>")
        readme_html = _readme_card(hub, pid, state) + _leaderboard_card(hub, pid, state, t)
        files = []
        for f in published_files(state):
            h, name = f["entry"], escape(f["name"])
            files.append(f"<tr><td>{name}</td><td>{f['size']:,} B</td>"
                         f"<td><a href='/p/{pid}/files/{h}'>{t('download')}</a> · "
                         f"<a class='mono' href='/p/{pid}/e/{h}'>{h[:12]}</a></td></tr>")
        files_html = (f"<h2>{t('files')}</h2><div class='table-wrap'><table><tr>"
                      f"<th>{t('name')}</th><th>{t('size')}</th><th></th></tr>"
                      + "".join(files) + f"</table></div><p class='muted'>{t('files_note')}</p>"
                      ) if files else ""
        svg = lineage_svg(state)
        graph_html = (f"<h2>{t('provenance')}</h2><div class='card graph-wrap'>{svg}</div>"
                      f"<p class='muted'>{t('graph_note')}</p>") if svg else ""
        graph = readme_html + files_html + graph_html
        table = graph + (
            f"<h2>{t('ledger')}</h2><div class='table-wrap'><table><tr><th>#</th>"
            f"<th>{t('entry')}</th><th>{t('kind')}</th><th>{t('author')}</th>"
            f"<th>{t('client_time')}</th><th></th><th></th></tr>"
            + "".join(rows) + "</table></div>"
            f"<p class='muted'>{t('ledger_note')}</p>")
        return _page(f"{pid[:12]} · Provena", summary + table, hub, lang, classic=True)
