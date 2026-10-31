# ADR 0007: 信任等级只由验证方的信任集合决定

- Status: accepted · 2026-10-31 · 起因：独立安全审查 #1（critical）

## Context
v0.1 的验证器从证明包**自身**推断信任：头签名者不是项目成员就记为 `log-sequenced`，有任何联署就 `witnessed`，有任何结构正确的 RFC 3161 token 就 `anchored`。攻击者用一次性日志密钥 + 自造见证人 + 自签「DigiCert」TSA 证书，就能把真实条目包装成 `anchored` 并倒签到 2020 年；网页验证器同样中招。

## Decision
- **有效性 ≠ 可信度。** `VALID` 只表示签名与证明全部成立；信任等级只取决于验证方显式信任的三类集合：日志公钥、见证人公钥、TSA 证书 SHA-256 指纹。
- 等级：`unverified`（头签名者不受信且非成员）< `self-sequenced`（成员自签）< `log-sequenced`（受信日志）< `witnessed`（受信见证人联署了覆盖全部目标的受信日志头）< `anchored`（受信 TSA 的 token 覆盖全部目标）。
- 不受信者签的证据仍做完整密码学校验，但只作为 note（「not counted」）输出，绝不进 facts。
- 锚定时间早于被锚定头时间（超出 5 分钟时钟偏差）= 证据自相矛盾，直接判无效。
- CLI 用 `~/.provena/trust.json`（`provena trust add|remove|list`）；`provena remote` 钉住 Hub 时即信任其日志公钥；`--require LEVEL` 供脚本门禁。TSA 永不自动信任——它正是用来制衡 Hub 的。
- Hub 网页验证器只信任本 Hub 日志公钥与其锚定所用 TSA 指纹，并在页面上写明。

## Consequences
- 默认输出更保守：没有配置信任的用户看到 `unverified` / `self-sequenced`，这是正确的。
- 首次使用 RFC 3161 锚定时，用户需要从 note 中拿到 TSA 指纹并显式 `provena trust add tsa <fp>`。

## Amendment (2026-10-31): built-in defaults

A release may ship **built-in trusted ids** (`src/provena/trust_defaults.json`: today the public
trial hub's log key and the TSA it anchors with), so that a first `provena verify` of a bundle
from that hub is not stuck at `unverified`. This narrows "never automatic" deliberately and keeps
the decision with the verifier: the defaults are listed (`provena trust defaults`, marked in
`trust list`), each can be dropped (`provena trust remove log|tsa ID`), all can be switched off
(`provena trust defaults off`, `PROVENA_NO_DEFAULT_TRUST=1`), and verification output names a
built-in default when it made the difference. A default is a convenience for a trial, not a
recommendation to rely on it for anything that matters: compare the id out of band first.
