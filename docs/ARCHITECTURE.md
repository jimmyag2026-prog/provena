# Provena 整体架构方案

**Status: v0.2（与实现同步）** · 2026-10-31 · 真源：本文件（改架构先改它，走 PR）

> GitHub for code. Hugging Face for models. **Provena for verifiable science.**
> A ledger of experimental data and process, kept encrypted and backed by proof.

---

## 0. 一句话

Provena 是**实验数据与实验过程的账本**：每一份数据、每一步操作都以签名条目追加进一个只增不改的 Merkle 日志；内容在客户端加密，服务器只见密文和哈希；任何第三方拿到一个**证明包（proof bundle）**，就能离线验证「谁、在什么时间之前、按什么顺序、产生了哪份未被篡改的数据」——而不需要信任 Provena 本身。

## 1. 定位拆解 → 需求

| 定位关键词 | 必须做到 | 落在哪一层 |
|---|---|---|
| **ledger** | 只追加；历史被改写可被检测；删除也留痕 | Merkle 透明日志（RFC 9162 算法）+ 签名树头 + 一致性证明 + 见证人/外部锚定 |
| **experimental data** | 任意大小文件；内容寻址；去重 | 分块加密 blob store，`cid = sha256(ciphertext)` |
| **and process** | 记录「谁用什么数据、按什么方案、产出了什么」 | 条目模型对齐 W3C PROV（Entity / Activity / Agent），血缘是 DAG |
| **kept encrypted** | 服务方读不到内容；所有者决定披露粒度 | 端到端信封加密 + 项目密钥分纪元 + 成员公钥封装 |
| **backed by proof** | 第三方离线可验；不信任服务器 | 盐化承诺 + 包含证明 + 一致性证明 + 时间锚 + 独立 verifier |
| **GitHub/HF 类比** | 本地优先、像 git 一样用；hub 负责托管、协作、发现 | CLI + 本地仓 `.provena/` + Hub 服务 + Web |

### 1.1 Provena 证明什么、不证明什么（对外口径必须一致）

**证明**：①完整性（内容未被改）②作者（哪个密钥签的）③时间上界（不晚于某时刻存在，由日志排序时间 + 外部锚定给出）④顺序（预注册先于结果）⑤血缘（哪些数据经哪个步骤产出）⑥完整性的「完整」——某项目在某时刻的全部条目集合（无法事后悄悄删掉不利结果）。

**不证明**：数据真实反映了物理世界。Provena 证明的是「记录的诚实性」，不是「实验的真实性」。仪器签名（instrument key / TEE 证明）可以把门槛抬高，列为 Phase 3，设计稿见 [`docs/design/attested-capture.md`](design/attested-capture.md)。

### 1.2 非目标（v0.x）

发币 / 自建链；完整 ELN（电子实验记录本）界面；对密文计算；计算正确性的 ZK 证明（预留扩展点，不实现）。

## 2. 威胁模型

| 对手 | 想做什么 | 如何防/测 |
|---|---|---|
| 不诚实或被攻破的 Hub 运营方 | 读内容 | E2E 加密，服务端无明文、无密钥 |
| 同上 | 改写/分叉历史、给不同人看不同历史 | 签名树头（STH）+ 一致性证明；客户端缓存最新 STH；见证人联署；全局根周期性锚定到外部时间源 |
| 同上 | 拒绝服务 / 扣留条目 | 无法防止，**可检测**：提交即返回签名回执（SET），扣留即违约证据 |
| 不诚实的研究者 | 倒签（backdating） | 时间以日志排序时间（integrated time）为准，客户端时间只作自报字段 |
| 同上 | 删掉不利结果 | 条目只能追加；`redact` 只能销毁内容密钥（crypto-shredding），条目存在本身永远可见 |
| 同上 | 事后改假设（HARKing / p-hacking） | `plan` 条目先承诺方案，结果条目引用它；验证器检查先后顺序 |
| 密钥被盗 | 冒名签名 | owner `provena member rm` 移除该 agent（原子轮换项目密钥，此后其签名不再被接受）；计划内换钥用 Python API `provena.core.builders.succeed`；时间锚定区分移除前后 |

**信任假设**：密码原语安全；至少一个诚实见证人或一个外部锚（RFC 3161 TSA / OpenTimestamps）；作者妥善保管私钥。

## 3. 核心概念与数据模型

### 3.1 身份（Agent）

- 每个 Agent 一对密钥：**Ed25519**（签名）+ **X25519**（接收密钥封装）。
- Agent ID：`pv1a` + base32(H_tag("provena/agent-id/v1", ed25519_pub))[:32]（域分隔哈希）。可读名是自报元数据；机构归属由组织 Agent 签发的**链下身份凭证**背书（`provena identity issue|attach`，随证明包的 `credentials` 字段携带，读者自行决定信任哪些组织）。
- Agent 类型：`person` / `instrument` / `software`（含 AI agent）/ `org`。**AI agent 是一等公民**——AI 跑出来的分析步骤同样签名入账，这是 AI4S 场景的刚需。

### 3.2 项目账本（Ledger）

- 一个项目 = 一条独立 Merkle 日志（类比 repo）。项目 ID = 创世条目哈希。
- Hub 是 **sequencer**：给条目分配索引、写入时间，周期性签发 STH `{project, size, root, time}`。
- 跨项目：Hub 把所有项目的最新 STH 再做一棵「根之根」Merkle 树，周期性锚定到外部时间源。

### 3.3 条目（Entry）——账本的唯一写入单位

```
Entry {
  v: 1
  project: <project id>          # 创世条目此字段为空
  kind:    genesis | entity | activity | plan | reveal | attest | member | key | redact | grant | meta
  author:  <agent id>
  prev:    <hash of author's previous entry in this project | null>   # 作者链，防作者自身条目被裁剪
  refs:    [<entry hash>...]      # 血缘 / 引用
  body:    { 公开字段 }            # 例：commitment、cid、size、media_type、used/generated
  sealed:  <AEAD(project epoch key, 私有字段)> | null   # 例：文件名、参数、备注
  ts:      <client unix ms, 自报>
}
sig        = Ed25519(author_sk, tag("provena/entry/v1") || JCS(Entry 去掉 sig))
entry_hash = H_tag("provena/entry-hash/v1", JCS(Entry 含 sig))   # 条目 ID，hex
leaf_hash  = sha256(0x00 || entry_hash)                          # RFC 9162 叶子
# tag(x) = len(x) || x；H_tag(t, m) = sha256(tag(t) || m)，见 core/hashing.py
```

条目类型与 PROV 映射：

| kind | PROV | 用途 |
|---|---|---|
| `genesis` | — | 建项目：策略（公开/私有；`witnesses`：达到 witnessed 至少需要的受信见证人数）、初始成员 |
| `entity` | Entity | 登记一份数据（原始仪器输出、处理后数据、图、模型权重） |
| `activity` | Activity | 一个过程步骤：`used`（输入实体）、`generated`（输出实体）、`plan`（引用的方案）、执行 agent |
| `plan` | Plan | 预注册：方案/假设/分析计划的**承诺**，内容可暂不公开 |
| `reveal` | — | 打开先前承诺（公开 salt + 明文哈希，必要时附明文 cid），把内容转为可公开验证 |
| `attest` | — | 另一 Agent 对某条目的背书：review / replicate / calibration / endorse / dispute / capture / operator |
| `member` | — | 成员加入/移除、角色变更 |
| `key` | — | 项目纪元密钥轮换（封装给各成员）；Agent 密钥轮换/撤销 |
| `redact` | — | 声明某实体内容被销毁（crypto-shredding）；存在性保留 |
| `meta` | — | 项目名片（标题、描述、许可、标签），公开项目用于 Hub 发现与引用 |
| `grant` | — | 把单个实体的 DEK + 承诺开口封装给非成员（审稿人/期刊）；授权本身上账＝可审计的访问日志 |

### 3.4 数据（Blob）与承诺（Commitment）

- 文件按 1 MiB 分块，**流式 AEAD**（AES-256-GCM，nonce = 前缀 ‖ 块计数 ‖ 末块标志，防截断/重排）。
- 每个文件随机 256-bit **DEK**；DEK 用项目纪元密钥封装后放在 `entity.sealed` 里。
- `cid = sha256(ciphertext)`：存储层寻址与完整性。
- **承诺** `commitment = sha256("provena/commit/v1" ‖ salt32 ‖ sha256(plaintext))`：
  - 加盐使承诺**隐藏**（小文件/低熵数据无法被字典反推）
  - 公开时只需给出 `salt` + 明文（或明文哈希），任何人可验
  - 承诺与密文解耦：换密钥重加密不改变承诺，证明长期有效

## 4. 密码学选型

| 用途 | 选型 | 理由 |
|---|---|---|
| 哈希 | SHA-256，全部带域分隔前缀 | RFC 9162 / Sigstore 生态兼容；浏览器 WebCrypto 原生 |
| 签名 | Ed25519 | 确定性、短、WebCrypto 已支持 |
| 对称加密 | AES-256-GCM（分块 STREAM 构造） | `cryptography` 与 WebCrypto 都原生 |
| 密钥封装 | X25519 + HKDF-SHA256 + AES-256-GCM（HPKE base mode 等价构造） | 给成员/审稿人封装项目密钥 |
| 规范化 | RFC 8785 JCS 子集：**签名结构中禁止浮点数**（数值一律整数或字符串） | 规避跨语言浮点规范化坑 |
| 本地私钥保护 | scrypt 派生 + AES-GCM 加密的 keyfile（0600） | 不依赖系统钥匙串，可选接 Keychain |

所有原语都有**测试向量（golden files）**，第二语言实现（JS verifier）必须过同一套向量。

## 5. 账本与证明

### 5.1 日志算法
RFC 9162（Certificate Transparency v2）的 Merkle Tree Hash、包含证明、一致性证明。直接实现（<200 行），不引第三方库，因为这是信任根，必须可审计。

### 5.2 回执与树头
- **SET（Signed Entry Timestamp）**：提交即返回 `{project, index, entry_hash, integrated_time}` 的 Hub 签名——Hub 对「已收录」的承诺。
- **STH（Signed Tree Head）**：`{project, size, root, time}` Hub 签名。
- **Cosignature**：见证人校验新旧 STH 一致性后联署；同一见证人可跨主 Hub 与镜像比对。项目策略 `witnesses = k` 时，验证器要求至少 k 个不同的受信见证人覆盖全部目标才判 witnessed。

### 5.3 外部锚定（Anchor）
Hub 周期性（`--anchor-interval`，默认 600s；也可 `POST /v1/anchors/run`，30s 节流）把**所有项目最新 STH** 排序后建「根之根」Merkle 树，交给外部时间源签时间。一个锚覆盖全部项目，成本与项目数无关；时间源只看到 32 字节摘要。
- `rfc3161`（已实现）：标准 TSA；token 在 core 里用自带的最小 DER 解析器离线验证（CMS 签名、messageDigest、imprint、EKU timeStamping、证书有效期），已用 freetsa.org 真实 token 做交叉测试向量（ADR 0006）
- `self`：Hub 自签，仅开发用，验证器明确提示「不增加独立证据」
- `opentimestamps`：未实现（Phase 2）

证明包里的锚定可以覆盖**比包头更旧的项目头**：用一致性证明把锚定头接到包头，锚定头之前的条目都得到「不晚于 TSA 时间」的结论。

### 5.4 证明包（`.pvb`）
可携带、可离线验证的单个 JSON 文件，格式规范见 [`docs/spec/bundle-v1.md`](spec/bundle-v1.md)。两种模式：

- **selective**：只含目标条目 + 血缘闭包 + 引入各作者密钥的条目 + 相关 attest/reveal/redact，每条带包含证明。最小披露。
- **full**：含树头之前的全部条目，验证器重放状态机，额外证明「写入时作者仍是有权限的成员」。

验证器（`provena verify bundle.pvb`）**只依赖 `provena.core`**，不联网也能跑；输出它独立确认的事实清单 + 时间陈述的信任等级（unverified / self-sequenced / log-sequenced / witnessed / anchored，见 ADR 0007）。JS 版（M9）跑在浏览器里，审稿人拖入文件即可验。

## 6. 系统组件

```
                ┌────────────── 客户端（明文只存在这里）──────────────────────┐
  researcher →  │ provena CLI · Python SDK · Jupyter %%provena · capture 守护进程 │
  instrument →  │ provena ui（本地只读浏览器视图，127.0.0.1 + token）            │
  AI agent   →  │   core: 规范化·哈希·签名·加密·Merkle·状态机·证明·验证（信任根）│
                │   store: 本地仓 .provena/（日志、密文块、树头、证据、追踪路径）│
                │   ~/.provena: 加密 keyfile、agent card、trust.json（信任集合） │
                └──────────────────────┬───────────────────────────────────────┘
                                       │ HTTPS；写入免会话（条目自签名），私有读签名请求
                ┌──────────────────────▼───────────────────────────────────────┐
                │ Provena Hub（不受信：只见密文、哈希、签名）                    │
                │  API v1 (FastAPI) ─ sequencer ─ SET/STH 签名 ─ 限流            │
                │  SQLite(WAL) / PostgreSQL · BlobStore（文件系统 / S3）流式校验 │
                │  按需加载项目（LRU，冷加载出锁、单飞、限并发）                  │
                │  根之根锚定（RFC 3161）· 联署收集 · 公开浏览/搜索/引用页        │
                │  浏览器验证器 verifier.js（与 Python 同规则，含全量状态重放）    │
                └──────────────────────┬───────────────────────────────────────┘
                     ┌─────────────────┴──────────────────┐
                 独立见证人（联署前校验一致性）      RFC 3161 TSA（只见 32 字节摘要）
                     │
                 镜像 Hub（`provena mirror`：同样的条目、同样的顺序 → 同样的根；
                 见证人用同一状态文件跨 Hub 比对，任一方向不一致即判分叉）
```

挑战赛的评分程序是组织方的代码，评审方在本机以 `--yes` 运行：有 bubblewrap（Linux）或 `sandbox-exec`（macOS）时在沙箱里（断网、读不到 Provena 密钥与评审方仓库、只能写工作目录），任何平台都有 CPU 时间与文件大小上限（`cli/sandbox.py`）。

### 6.1 代码分层（单仓，单 Python 包，分子包）

| 子包 | 职责 | 允许依赖 |
|---|---|---|
| `provena.core` | 纯函数：canonical / hashing / keys / crypto / merkle / entries / proofs / bundle / verify | 只有 `cryptography` |
| `provena.store` | 本地仓：日志、密文块、树头/证据；`home`（keyfile、信任集合）；`paths`（账本路径净化）；`content`（校验后解密落盘） | core |
| `provena.client` | Hub HTTP 客户端 + 请求签名 | core |
| `provena.sdk` | 高层 Python API（`Project.add/plan/run/prove`，AI agent 溯源）、Hub 同步、capture 守护进程、Jupyter magic、RO-Crate / PROV 导出 | core, store, client |
| `provena.cli` | 命令行：`common`（共享辅助）、`ledger`（账本读写）、`proofs`（证明/验证/信任/分享）、`hubcmds`（Hub 交互与 `hub serve`）、`ui`（本地视图）、`challenge`（挑战赛）、`sandbox`（不受信程序隔离）；`main` 只含解析器 | core, store, client, sdk, server |
| `provena.server` | Hub：API、sequencer、SET/STH、BlobStore、锚定、联署、限流、网页与浏览器验证器 | core |

分层用测试强制（`tests/test_layering.py` 扫 import），**core 永远不准 import 其他子包**——verifier 的可审计性靠它。

### 6.2 Hub API（v1，REST/JSON）

完整列表见 [`docs/API.md`](API.md)。要点：`POST /v1/projects`（创世）、`POST …/entries`（返回 SET + 新 STH）、`GET …/entries`（私有项目需签名请求，分页）、`GET …/sth`、`…/proofs/inclusion|consistency`、`PUT/GET …/blobs/{cid}`（流式、按账本大小与哈希校验）、`…/cosignatures`、`…/anchors`、网页 `/`、`/p/{pid}`、`/p/{pid}/e/{entry}`（引用页）。

**认证**（ADR 0005）：写路径**不需要会话认证**——条目自带作者签名并由状态机判权，任何人都可以转交一个合法条目（与 CT 相同）；blob 由 cid 自证，且只接受已被本项目 entity/plan 条目引用、大小与账本一致的密文。只有**读私有项目**的条目与 blob 需要签名请求：请求头携带 `agent id + 时间戳 + sha256(body)` 的 Ed25519 签名（±5 分钟窗口），Hub 按账本状态机判断是否为成员。STH 与证明对所有人公开（只泄露日志长度）；`reveal --with-key` 过的 blob 对所有人公开。`redact` 条目被收录时 Hub 删除对应密文。

客户端首次 `provena remote` 时**钉住 Hub 日志公钥**（TOFU），之后每次同步：校验每条 SET、校验新 STH 签名、本地重算根、并用一致性证明连接上一次见过的 STH——Hub 分叉/改写历史会被立即发现。

### 6.3 状态机：账本即权限真源
项目当前成员、角色、纪元密钥、销毁（redact）与揭示记录 = **从创世条目起重放全部条目得到的状态**。Hub 和客户端用同一份 `core.state.replay()`，判权结果可复现、可审计；浏览器验证器有逐条对齐的 JS 实现（`replayState`），用规则违例语料与 Python 交叉测试。被拒条目不留任何痕迹（事务化）。每种 kind 的 body 字段白名单固定，不能夹带任意数据。

关键规则（摘）：写数据需 contributor 以上；只有实体作者或管理员能声明「谁产出了它」；产出必须登记在所引用方案之后（防 HARKing）；同一 cid 在项目内只能有一个所有者；移除成员原子轮换项目密钥；至少保留一个 owner。

### 6.4 信任模型（ADR 0007）
`VALID` 只表示密码学成立；**信任等级只由验证方的信任集合决定**（日志公钥、见证人公钥、TSA 证书指纹，`provena trust`；`provena remote` 钉住即信任该 Hub）：`unverified` < `self-sequenced` < `log-sequenced` < `witnessed` < `anchored`。不受信者签的证据只作 note；顺序类陈述（位置、预注册成立）仅在受信日志下作为事实。

## 7. 关键流程

1. **建项目**：`provena init` → 生成创世条目（策略 + 自己为 owner）+ 纪元 0 项目密钥（封装给自己）。
2. **登记数据**：`provena add raw/plate1.csv` → 分块加密 → 承诺 → `entity` 条目签名 → 本地入账；`provena push` → blob 上传 + 条目提交 → SET。
3. **记录过程**：`provena run --used E1 --plan P1 -- python analyze.py` → 执行命令、自动登记输出文件、写 `activity` 条目（命令行、环境哈希、输入输出）。
4. **预注册**：`provena plan protocol.md` → 只上链承诺；结果出来后 `provena reveal P1` 公开。
5. **分享给审稿人**：`provena share E3 --to reviewer.card.json` → `grant` 条目上账（只把 E3 的 DEK 封装给审稿人，不暴露项目密钥）+ 生成 `.pvb`；审稿人 `provena open x.pvb --hub URL` 验证→取密文→解密→核对承诺。
6. **公开发表**：`provena publish E3` → `reveal`（含 DEK）+ push；任何人凭证明包从 Hub 下载密文、解密、核对承诺。
7. **出证明**：`provena prove E3 -o e3.pvb [--full] [--open E3]`；引用：`provena cite E3`。
8. **验证**：`provena verify e3.pvb --require anchored`（或拖进任一 Hub 首页）。
9. **复现**：`provena rerun A --yes --attest` 在干净工作区重放并比对输出，结果以 `replicate` 证明入账；他人也可手工 `attest --type replicate`。
10. **交付**：`provena export rocrate -o crate/`（文件 + schema.org 描述 + 证明包）或 `export prov`。
11. **预注册盲测挑战赛（实验性）**：`provena challenge init|submit|close|score|audit`。预注册方案的公开条款块是唯一权威（真值、题目、评分程序条目与哈希、截止时间、`AGENT:PROJECT` 报名名单）；提交引用方案、只授权给评审方；真值只能在截止后由受信 Hub 排序的条目披露；评审与任何第三方共用同一套检查（`_check_inputs`），`audit` 无需密钥即可重推每一行。信任链与剩余限制见 [`design/challenge-mode.md`](design/challenge-mode.md) §3b，威胁 T22–T25。

## 8. 开发路线（每个里程碑 = 一个 PR，squash 合入 main）

| # | 里程碑 | 交付 | 验收 |
|---|---|---|---|
| M0 | 架构 + 工程骨架 | 本文档、ADR、pyproject、CI、CHANGELOG、`_version.py` | `pytest` 绿、ruff 绿 |
| M1 | core 密码原语 | canonical(JCS) / hashing / keys / AEAD 分块 / 封装 / 承诺 + 测试向量 | 向量全过 |
| M2 | Merkle 日志 + 条目 | RFC 9162 树、包含/一致性证明、Entry 签名与校验 | RFC 风格向量 + 性质测试 |
| M3 | 账本状态机 | `replay()`：成员/角色/纪元/撤销/作者链校验 | 非法序列全部被拒 |
| M4 | 本地仓 + CLI | init / keygen / add / plan / run / log / show / verify-local | 端到端脚本 |
| M5 | 证明包 + 离线验证器 | `.pvb` 格式、prove、verify、选择性披露、血缘 | 篡改任一字节必失败 |
| M6 | Hub 服务 | FastAPI、sequencer、SET/STH、blob、请求签名、权限 | 客户端 push/pull 往返 |
| M7 | 共享与发表 | share（按实体封装 DEK）/ publish / reveal / redact | 审稿人流程 e2e |
| M8 | 见证 + 锚定 | witness cosign、根之根、`Anchor` 接口（self / rfc3161；OpenTimestamps 未实现） | 锚定回执进证明包 |
| M9 | Web 浏览器 + JS verifier | 公开项目浏览、拖入 `.pvb` 验证 | 与 Python 共用向量 |
| M10–M13 | SDK/PROV、Hub 硬化、文档、浏览器 RFC 3161 | 见 CHANGELOG | — |

**状态（2026-10-31）**：M0–M13 全部完成；追加完成：流式大文件、S3 BlobStore、限流、引用页与 `cite`、项目名片与搜索、`rerun`、Jupyter magic、RO-Crate、本地 UI、浏览器全量状态重放；Phase 3 的 P3-1（capture）、P3-4 初版（AI agent 溯源）、设施证明类型。十二轮独立对抗性审查的确认问题全部修复并有回归测试（CHANGELOG Security 节）；PostgreSQL 元数据与按需加载项目（LRU）；实验性 `challenge` 命令（C3）与第三方审计。

**未做（Phase 2/3）**：组织/SSO 映射、TPM/设备证明（P3-3）、OpenTimestamps、ZK 选择性披露（数值范围证明）、Hub 联邦目录（单项目镜像已有）、DOI 对接。

## 9. 工程规范

- **仓库**：`https://github.com/jimmyag2026-prog/provena`（目录名 = repo 名，https remote）。
- **分支/合并**：trunk-based；`feat/` `fix/` `docs/` `refactor/` 分支 → PR → squash merge → 立删本地分支。main 不直推（仓库初始化除外）。
- **提交**：Conventional Commits；一个 PR 一个里程碑；CHANGELOG（Keep a Changelog）随 PR 更新 `Unreleased`。
- **版本**：SemVer，单一真源 `src/provena/_version.py`，pyproject dynamic version；tag 是发布动作，需用户确认。
- **测试**：pytest；密码学与 Merkle 必须有固定测试向量；不做无信息量的重复验证。
- **安全**：私钥永不入库、不进日志、不进命令行参数（口令走环境变量或交互输入）；新增文件提交前跑密钥 grep。
- **决策留痕**：重要取舍写 ADR（`docs/adr/NNNN-*.md`）；开发过程写 `docs/devlog/`。

## 10. 已拍板（2026-10-31）

1. **开源与许可**：以 Provena License 公开（仿 Kimi K3 许可证结构：默认 MIT 式宽松；对外经营 Hub 托管且 12 个月收入超过 100 万美元需另签协议；大规模商用须署名；科研/教学机构、内部使用、客户端与验证器不受限）。验证器始终可自由运行与再分发。
2. **锚定与信任默认值**：默认 RFC 3161；发行版内置试验区 Hub 日志公钥与 freetsa 指纹（ADR 0007 修订）。
3. **首个场景**：预注册 + 结果证明 + 挑战赛收据；内部赛试点已在试验区跑通。
4. **托管形态**：先自营试验区 Hub（DO），机构自建 Hub 同样支持。
5. **发布**：v0.2.0 已打 tag。
6. **Phase 3 范围**：按 `docs/design/next-dev-plan.md` 执行完毕。
