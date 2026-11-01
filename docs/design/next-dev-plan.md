# 下一阶段开发设计方案（v2 收窄 × agent 实测）

**Status: plan for decision** · 2026-10-31 · 合并两份输入：
- v2 产品与架构分析（内部文档，未公开）：收窄为「AI 驱动科研的证据层」、三个楔子、协议 P0
- `docs/design/agent-ux-review.md`（6 个 agent 实测：P0 假成功清单、agent 接口契约）

代码事实已对照 main @ d4e0e4b 核实。v2 报告 §6.1 提到的 `perf/batch-blob-check` 未提交 WIP 已作为 PR #4 合并，不再阻塞。

## 进度（2026-10-31，/goal 完成）

决定（用户）：名字保持 Provena；许可证已定为 Provena License（见 §5 第 3 项）；试验区 Hub 部署在 DO 服务器；其余按本方案默认；争取这一版接入 Spark Research（已接入并自动记账）；试点先办内部赛（已跑通）；见证人已上线；外部组织方试点留待以后。

| 阶段 | 状态 | PR |
|---|---|---|
| Phase 0 止血 | **完成**：输入/口令文件/无 traceback、同步如实报告、挑战赛只能提交一次、chunk 封顶、裸装可验证、agent_flows 进 CI；独立审查 9 条全修 | #10–#13、#15 |
| Phase 1 改名/许可 | 名字不改；许可证已定为 Provena License（根目录 `LICENSE`，2026-10-31 公开时加入） | — |
| Phase 2 agent 契约 | **完成**：`--json` 信封、退出码 0–7、口令文件、幂等、`#N`/前缀/路径引用、结构化 verify、`--json-lines`；两次 agent 复测后打磨 | #14、#16、#18 |
| Phase 3 协议 v2 | **完成**：ADR 0009 rules 2（rewrap/`--history`、可证明的步骤、补发密钥）、`rules.json` 单源、同一路径冲突 + `resolve` | #17、#26 |
| Phase 4 agent 入口 | **完成**：`provena mcp`、SDK `record`/`verify`、in-toto/DSSE、`--badge`、GitHub Action；**Spark Research 已真实接入**（spark-research #130 修三处外部 MCP 缺口 + V74 测试隔离泄漏；#131 每个任务与工具调用自动记账、每轮推送一次） | #19、#20 |
| Phase 5 挑战赛服务 | **完成**：`challenge status`/`join`、榜单排序；**DO 试验区** `https://jimmyresearch.com/provena` 上线（RFC 3161 锚定），PILOT 合成数据彩排跑通；挑战规则下沉 `provena.core.challenge` + Hub 榜单逐行核对（#34）；Hub 组织/配额/API key + schema 迁移（ADR 0012，#36）；外部见证人 GitHub Actions 每小时联署试验区全部公开项目（#39/#45，2026-10-31 已上线）；PILOT 默认决定 + 组织方手册（#41）；**内部赛试点跑通**（iris 真实数据、3 队、外部审计 OK，#43）。外部组织方试点由用户日后选定 | #21–#23、#34、#36、#39、#41、#43 |
| Phase 6 阅读面 | **完成**：Proof Reader、内置默认信任、时间锁 `seal`/`unseal`、锚定监控指标、`doctor --verifier`、恢复手册；C2SP checkpoint（#30，见证人可直接读取）；Hub 日志密钥轮换（ADR 0010，#32）；验证快照（#33/#35）；页面 JSON 孪生（#37）；**SPA 成为 Hub 前端**，浏览器内核对整本账与单条目，服务端渲染页退到 `/classic`（#38/#40/#42）。公共见证人：checkpoint 格式已就绪，由自建 trial witness 代替（已运行）；加入外部见证网络需对方运营者配合 | #24、#25、#30、#32、#33、#35、#37、#38、#40、#42 |

偏差：`provena.ops` 服务层没有单独抽出——SDK 的 `Project` 已承担这一角色（CLI、MCP 都调用它），等 Hub 侧需要时再拆。

---

## 0. 一句话与三个判断

> **把产品做成 agent 先用的证据层：agent 通过 MCP / SDK / 带机器契约的 CLI 写入，任何人在浏览器里读证据。**

1. **两份输入指向同一个方向。** v2 的楔子 ②（Agent Attestations）和楔子 ①（挑战赛收据）的参与方本身就是 agent，而实测证明现在的接口是给人用的。所以"agent 契约"不是 UX 打磨，而是三个楔子共同的前置条件。
2. **顺序必须是"先止血、再定契约、再改协议、最后做入口"。** 理由：
   - 假成功会让 agent 删掉数据；
   - MCP、SDK、挑战赛 JSON 都复用同一个服务层和返回结构，契约必须先定；
   - 任何新规则都要先有规则版本门（rules_version），否则每次改动都是全网协议升级。
3. **核心不重写。** `merkle`、`canonical`、`hashing`、`verify` 的事实与信任模型、ADR 0005/0007、证明包顶层结构都不动。需要新增的有三件：服务层 `provena.ops`、协议版本门、适配器层 `provena.adapters`。

---

## 1. 目标架构

```
 写入面（agent / 人）                                      阅读面（任何人）
 ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      ┌───────────────────────┐
 │ MCP 服务  │ │ Python   │ │ CLI      │ │ GitHub   │      │ Proof Reader（浏览器） │
 │ (adapters│ │ SDK      │ │ 文本/JSON │ │ Action   │      │ verifier.js + 挑战页   │
 │  .mcp)   │ │ record() │ │ 渲染      │ │ 徽章      │      │ 一键 audit + 徽章      │
 └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘      └──────────┬────────────┘
      └────────────┴─────┬──────┴────────────┘                       │
                         ▼                                           │
        ┌─────────────────────────────────────┐                      │
        │ provena.ops（新增服务层）             │   provena.challenge  │
        │ 每个操作 = 纯函数，返回类型化结果       │   （下沉的纯规则模块） │
        │ + ProvenaError(code, message, hint)  │◄─────────────────────┤
        └───────────────┬─────────────────────┘                      │
                        ▼                                            │
   store（Repo + 写锁 #6） · client（HubClient） · secrets（口令解析）  │
                        ▼                                            ▼
   core（不变的信任根 + rules_version 分派） ═══ 规则单源 spec/rules-v1.json ═══ verifier.js
```

关键改动：

| 层 | 现状 | 目标 |
|---|---|---|
| **服务层 `provena.ops`** | 业务逻辑写在 `cli/*.py` 里，边算边 `print` | 每个命令拆成 `ops.<name>(ctx, **args) -> Result`（dataclass）。CLI 只负责渲染文本或 JSON；SDK 和 MCP 直接调用 ops。这是 `--json` 全覆盖、MCP、托管 Hub 的共同前提 |
| **错误** | 各处抛 `CliError`、`ValueError`、`KeyError`，无 TTY 时直接崩出 traceback | 统一用 `ProvenaError(code, message, hint)`；`main()` 顶层兜住 `OSError`、`JSONDecodeError`、`EOFError`、`KeyboardInterrupt`，映射到 §2.1 的退出码 |
| **口令 `store/secrets.py`** | 只有环境变量和 getpass | 按 §2.2 的顺序解析；MCP 或守护进程持有已解锁的密钥 |
| **协议** | 状态机规则没有版本 | ADR 0009：genesis 里写 `policy.rules`，`core/state.py` 和 `verifier.js` 按版本分派；v1 冻结；Python 与 JS 共读 `spec/rules-v1.json` |
| **适配器 `provena.adapters`** | 无 | `mcp`（优先）、`jupyter`、`github_action`；分层测试加一条 `adapters → sdk/ops` |
| **挑战赛 `provena.challenge`** | 561 行规则写在 `cli/challenge.py` | 下沉为纯函数，CLI、Hub 挑战页和浏览器 audit 共用 |

---

## 2. Agent 契约（规范先行：`docs/spec/cli-contract-v1.md`）

### 2.1 输出与退出码

- 全局参数 `--json`：stdout **只**输出一个 JSON 对象，人读的提示全部走 stderr。`run` 的子进程输出与 Provena 自己的输出分开：子进程照常写 stdout，Provena 的结果写 stderr；`--json` 时写到 `--result-file`。
- 信封格式：`{"schema":"provena-cli/1","command":"add","ok":true,"data":{...},"warnings":[{code,message}],"error":null}`。`data` 里一律给完整哈希，同时给 `index`、`path`、`kind`。
- 退出码：

| 码 | 含义 | 例子 |
|---|---|---|
| 0 | 成功（含幂等的"已存在，未改动"） | `add` 遇到内容未变的文件 |
| 1 | 验证失败或要求未达到 | `verify --require` 未达到要求的等级 |
| 2 | 用法错误或输入非法 | 参数错、路径越界、引用不唯一 |
| 3 | 网络或 Hub 不可达 | 连接被拒，429 重试耗尽 |
| 4 | 认证或权限 | 口令错、无口令、403、已失效的成员 |
| 5 | 冲突或需要处理的状态 | 有搁置条目、同一路径冲突、与另一写入方竞争 |
| 6 | 完整性告警 | Hub 回滚或分叉、Hub 公钥变了、本地文件损坏 |
| 7 | 挑战赛判定 | `LATE`、`void`、榜单漏队 |
| 其他 | `run`、`rerun` 透传子进程的退出码 | 另在 JSON 的 `data.exit_code` 里给出 |

### 2.2 口令（无 TTY 时不再出现 traceback）

解析顺序如下，后几步只在前面都没有时才走：
1. `--passphrase-fd N`
2. `PROVENA_PASSPHRASE_FILE`（要求文件权限为 600）
3. `PROVENA_PASSPHRASE`
4. macOS Keychain 或 libsecret（可选）
5. TTY 交互输入
6. 以上都没有：报 `E_NO_PASSPHRASE`（退出码 4），提示可用的方法

规则：
- 每个 agent 名可以有自己的口令文件 `PROVENA_PASSPHRASE_FILE_<NAME>`。
- `--sandbox require` 改为接受 fd 或文件方式（评分程序读不到）。PILOT.md 里评审方的流程同步改掉，不再需要 pty。
- `hub serve` 同理。

### 2.3 幂等与可重试

- `add`、`plan`：内容未变（按 tracked 里的 sha256 判断）时跳过并返回 0；`--force` 才新增条目。
- `reveal`、`publish`：已揭示时返回成功；已 reveal、未带密钥时，允许用 `publish` 补发密钥（这是新动作，放进 rules v2）。
- `open`、`close`、`checkout`：内容相同时返回成功；`close` 可以重复输出 `truth.pvb`。
- 批量 `add`：先校验全部文件再提交，不允许出现"报错但前半已提交"。每提交一条就把 JSON 行刷出去（`--json-lines`），被杀之后的重试才不会重复。

### 2.4 少传 id

- `init`、`clone`、`keygen` 的 JSON 返回完整 id。
- `clone`、`witness` 接受唯一前缀或项目名。
- 新增 `trust add log --from-url URL`：打印 id 供带外核对，加 `--yes` 才写入。
- Hub 启动横幅及时刷新到日志，并打印日志公钥。
- 路径引用从账本解析，不只看本地 `tracked.json`，这样 clone 里也能用 plan 路径。
- `#N` 表示日志序号；4 位以下的十六进制前缀直接拒绝。
- 新增 `provena config agent NAME`，用来切换这个仓库用哪把密钥签名。

---

## 3. 各阶段设计

### Phase 0：止血（不依赖任何拍板，可以立即开工，约 2–3 天）

全部不改协议。每项都要有回归测试和阴性对照，收尾前单独审一轮。

| # | 问题 | 设计 |
|---|---|---|
| 0.1 | push 中断或 429 后谎报同步（实测 P0-3） | Hub 只接受账本已引用的 cid（ADR 0005），所以条目仍然先推。改动：①遇到 429 按 `Retry-After` 自动重试，有上限，可续传；②push 结束时用 `blobs/missing` 复核，仍有缺失就返回 5 并列出；③`status`、`doctor` 把"条目已同步"和"密文在 Hub 上 x/y"分开显示，有缺失时 doctor 失败 |
| 0.2 | 条目被搁置却返回 0（P0-4） | 有搁置条目时 push 和 pull 返回 5；`status`、`doctor` 显示搁置数；新增 `provena stranded list` 和 `provena stranded redo`：用当前纪元重新加密原文件，在最新状态上重建条目，并在 refs 里指向原条目哈希 |
| 0.3 | 从镜像 clone 后写入导致分叉（P0-5） | 镜像在 `GET /v1/projects/{pid}` 里返回 `primary`（`mirror` 时登记的主 Hub 公钥卡片）；从镜像 clone 时，把主 Hub 固定为 remote，镜像记为只读回退源；向非主 Hub 的 push 一律拒绝；新增 `remote --rehome URL` 迁移 |
| 0.4 | 先写后验 Hub 公钥（P0-6） | 任何 POST 之前先 `GET /v1/hub` 对比已固定的公钥，不一致报 6，并写清"什么都没有推送" |
| 0.5 | `add` 越界路径（P0-7）、`keygen` 路径穿越（P0-8） | 拒绝仓库外路径、`.provena/` 内路径和目录（`-r` 才递归）；agent 名只允许 `[A-Za-z0-9._-]`，且不能以点开头 |
| 0.6 | run 先执行再校验（P0-9），没有文件读写的步骤（P0-10 后半） | 所有校验都提前到执行之前；run 总是把子进程的 stdout/stderr 记录成一个密封的 transcript 输出实体。这样即使没有声明产物，也满足 "use or generate" 规则，不用改协议。SDK 的 `run` 同理（trace 即产物） |
| 0.7 | params 含浮点数时整步丢失并吞掉原异常（P0-10） | 进入工具之前就把 params 规范化：浮点数转成十进制字符串，`Path` 转字符串，无法表示的值报错。规范化放在 `yield` 之前；`finally` 里出错时保留工具的原异常；产物和 activity 要么一起写入，要么都不写 |
| 0.8 | 挑战赛用旧证明包绕过"只能提交一次"（P0-11，即 v2 附录 C #13） | score 和 audit 要求每队的全量包头带受信时间，且不早于截止；`submit` 拒绝第二次提交；`audit --submission` 比对榜单记分条目是否等于该包里的提交条目；`LATE` 返回 7 |
| 0.9 | 回滚检测与 doctor 误报（P0-12） | `_check_head` 在比较尺寸之前先做回滚判断，报 6 并写出 "hub rolled back from N to M"；doctor 比对线上 head 与 `synced`，自锚定不算"已锚定"；Hub 对数据目录加 flock，不允许两个进程同时用 |
| 0.10 | v2 列出的、不改协议的 P0 | `aead.decrypt_stream` 的 chunk_size 封顶（≤16 MiB，且不超过账本里记录的大小）；`challenge init` 拒绝过去的截止时间和同项目重复 init；顶层 httpx 改成惰性导入（裸装 `pip install` 也能 verify） |
| 0.11 | 两个崩溃 | `reveal`/`prove --open` 对 activity 报清楚的错误（activity 没有承诺值，要等 Phase 3）；无 TTY 时不再崩，先按 §2.2 实现第 2、3、6 步 |

**验收**：把 6 个 lane 的复现步骤固化成 `tests/agent_flows/*.sh`，在 CI 的 package 任务里跑；P0 清单全部从"待修"变成"已修"。

### Phase 1：拍板事项落地（阻塞对外，约 1 天，等 §5 的决定）

- 改名：包名、CLI 名、文档、Web 一次改完；`pv1a` 前缀保留，避免测试向量失效。
- 补 LICENSE；`pyproject` 的 license 字段与之对应（现在写了 Apache-2.0，却没有 LICENSE 文件）。
- 打 v0.2.0 tag：此时 Phase 0 已完成，tag 需要你确认。

### Phase 2：Agent 契约（约 1.5 周）

1. 先合并 `docs/spec/cli-contract-v1.md`（§2 的全部内容）。
2. 引入 `provena.ops` 与统一错误。逐个迁移命令，迁一个命令就补它的 JSON 快照测试，顺序：`init/keygen/add/plan/run/status/log/prove/verify` → `push/pull/clone/member/share` → `challenge *` → 其他。
3. 实现 `secrets` 解析（§2.2）、幂等（§2.3）、少传 id（§2.4）。
4. `verify --json` 结构化，同时保持向后兼容：保留 `facts` 文本，新增 `entries[]`（hash、kind、author、index、sequenced_time、time_bound、opened、attestations）、`require{required, reached, reasons}`、`evidence{witnesses_counted, anchors[{provider, independent}]}`、`preregistration[{plan, result, holds, basis}]`；JS 验证器输出同样的结构，并有一致性测试。

**验收**：6 个 lane 用 LLM agent 重新跑一遍，只看 `--help` 和 JSON；"要解析英文句子才能继续"的次数为 0。

### Phase 3：协议 v2（约 2 周；先写 ADR 和规范，再写代码）

| 项 | 设计 | 解决的问题 |
|---|---|---|
| ADR 0009 `rules_version` | genesis 里写 `policy.rules: 1|2`，缺省为 1；状态机按版本分派；v1 规则冻结；规则表放在 `spec/rules-v{1,2}.json`，Python 与 JS 共读 | 后面所有协议改动的前提（v2 P0） |
| `member.rewrap` / `member add --history` | owner 或 maintainer 把自己能读的历史纪元密钥补发给某个成员；状态机检查只能补发作者本人能读的纪元，且目标必须是在任成员 | 恢复后读不到历史（实测 P1-13 / v2 P0） |
| 多设备模型 | 一人多把密钥，用组织凭证绑定到同一个人；不改 `prev` 链；`identity` 加 UX，GUIDE 补多设备一节 | v2 P0；需要你拍板 |
| activity v2 | 公开字段 `status: ok|failed`；执行细节（退出码、模型、harness、params）做加盐承诺 `details_commitment`；`reveal` 支持打开执行细节 | 失败运行在证明包里可证明（P1-15）；能验证"哪个模型跑的这一步" |
| `reveal` 补密钥 | 已 reveal 的条目可以再追加一条只带密钥的 publish | §2.3 |
| 同一路径冲突 | 不改协议：pull 发现同一路径有来自不同作者的并发版本（双方都不是对方的祖先）时，`status` 报冲突并返回 5；用 `provena resolve PATH --keep <hash>` 记一条 refs 指向两边的新条目 | P1-14 |

**验收**：老的测试向量和证明包全部仍能验证；随机历史在 rules v1 和 v2 之间交叉生成，Python 与 JS 结果一致；先单独审一轮再合并。

### Phase 4：楔子 ②，Agent Attestations（约 2.5 周）

- **MCP 服务** `provena mcp --project DIR`：作为每个项目的唯一写入方，口令按 §2.2 解锁一次，密钥永远不进模型上下文。工具：`record_tool_call`、`start_run` / `finish_run`、`seal_trace`、`add_file`、`seal`（承诺）、`reveal`、`prove`、`verify`、`status`。每个工具都返回 §2.1 的 `data` 结构。
- **SDK**：`proj.record(tool, args, result, *, used, outputs, error, model, trace)` 一次写入，也支持没有文件读写的步骤；`sdk.verify(bundle, trust=) -> dict`，与 `verify --json` 同构。
- **导出**：in-toto Statement + DSSE，predicate 为 `science.run/v1`、`science.preregistration/v1`、`science.redaction/v1`（ADR 0011）。
- **徽章**：`verify --badge` 加 GitHub Action。
- **dogfood**：Spark Research 选一个真实研究任务全程留痕，并在 Claude Code 里通过 MCP 跑通一次。

### Phase 5：楔子 ①，Challenge Receipts（约 3 周，可与 Phase 4 后半并行）

- 挑战赛规则下沉到 `provena.challenge`，Hub 挑战页做真正的校验，而不是只显示。
- 新增 `challenge join <url>`：一条命令完成身份、项目、remote 和报名。
- 新增 `challenge status --json`：截止时间对比 Hub 时间、是否已关闭或作废、各报名队有没有提交。
- 榜单页上迟交的队永远排在按时的队之后；榜单 JSON 带上挑战 id；`audit` 列出缺席的报名队，并提示同一挑战有没有更新的榜单。
- Hub 身份与策略层：组织、API key、配额、`schema_version` 迁移，在 PR #3 的 `--creators` 基础上扩展。
- 托管 Hub 部署：RFC 3161 锚定 + 一个外部见证人。
- 按 PILOT.md 用合成数据彩排一次，再接一家真实组织方。

### Phase 6：Proof Reader、默认信任、时间锁（约 3 周）

- Hub 只提供 JSON API，前端 SPA 复用 `verifier.js`。
- 发行版内置推荐的 TSA 指纹和托管 Hub 公钥，首次 `verify` 默认就能到 `log-sequenced`。
- 树头导出为 C2SP checkpoint 格式，接入至少一个公共见证人。
- 时间锁：`seal <dir> --reveal-after <date>`，用于新鲜数据包的承诺和优先权证明。
- 运维：分叉、回滚和锚定失败的监控指标；DEPLOY 补恢复手册；`doctor` 增加只核查模式（不需要密钥和仓库）。

---

## 4. 节奏、纪律与验收方法

| 阶段 | 日历 | 依赖 | 能否现在开始 |
|---|---|---|---|
| Phase 0 止血 | 2–3 天 | 无 | **能** |
| Phase 1 改名、许可、tag | 1 天 | §5 第 1–3 项 | 等拍板 |
| Phase 2 agent 契约 | 1.5 周 | Phase 0 | 规范可以先写 |
| Phase 3 协议 v2 | 2 周 | Phase 2；§5 第 5 项 | ADR 可以先写 |
| Phase 4 MCP / SDK | 2.5 周 | Phase 2；activity v2 依赖 Phase 3 | — |
| Phase 5 挑战赛服务 | **完成**：`challenge status`/`join`、榜单排序；**DO 试验区** `https://jimmyresearch.com/provena` 上线（RFC 3161 锚定），PILOT 合成数据彩排跑通；挑战规则下沉 `provena.core.challenge` + Hub 榜单逐行核对（#34）；Hub 组织/配额/API key + schema 迁移（ADR 0012，#36）；外部见证人 GitHub Actions 每小时联署试验区全部公开项目（#39/#45，2026-10-31 已上线）；PILOT 默认决定 + 组织方手册（#41）；**内部赛试点跑通**（iris 真实数据、3 队、外部审计 OK，#43）。外部组织方试点由用户日后选定 | #21–#23、#34、#36、#39、#41、#43 |
| Phase 6 Proof Reader | 3 周 | Phase 3、5 | — |

合计约 12–13 周，与 v2 报告的估算一致。差别在于 Phase 0 和 2 是新插入的，用来替代 v2 V0 里零散的 UX 修补。

纪律：
- 每项一个分支、一个 PR，squash 合并后立刻删本地分支。
- 收尾前单独审一轮。
- 协议改动先写 ADR 和规范；Python 与 JS 同时改，并有一致性测试。
- 测试按真实目录布局写，pytest 不接管道。
- 并行阶段按并行 lane 纪律走独立 worktree，最后统一收口。

**验收方法：把 agent 实测变成常设回归。**
- 脚本化部分：`tests/agent_flows/` 每个 lane 一个脚本，在 CI 里跑。
- 每个阶段结束时，用 LLM agent 重跑 6 个 lane。评分口径：卡住次数、需要解析英文句子的次数、假成功次数、完成任务需要的命令数。
- 目标：Phase 0 后假成功为 0；Phase 2 后需要解析英文句子的次数为 0；Phase 4 后集成方的胶水代码不超过 10 行。

---

## 5. 需要你拍板（只有 Phase 0 不受影响）

1. **方向**：是否接受"AI 科研证据层 + 三楔子"，并把 agent 作为第一用户（v2 §7.1）。
2. **新名字**：我可以跑一轮域名、GitHub、PyPI 和商标查重。
3. **许可**：已定为 Provena License（仿 Kimi K3 结构，见根目录 `LICENSE`）。
4. **首个试点组织方**，以及托管 Hub 放在哪里（v2 §7.4–7.5）。
5. **两个协议默认值**：
   - 新成员默认能读历史，还是需要显式 `--history`。我的建议是显式加，恢复流程默认带上。
   - 多设备是否采用"一人多钥 + 组织凭证绑定"。
6. **Spark Research 接入时点**：随 Phase 4 同步，还是 v2.0 之后。

**我的建议**：Phase 0 现在就开工；同时你拍第 1–3 项，我先把 `cli-contract-v1.md` 和 ADR 0009 的草稿写好，等 Phase 0 完成就能直接进入 Phase 2。
