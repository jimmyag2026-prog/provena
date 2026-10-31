# 面向 agent 的使用流程评审（2026-10-31）

**Status: findings + plan** · 6 个独立测试 agent 分别扮演不同类型的 AI agent 用户，只用安装好的 wheel（main @ 267735b）、各自独立目录与端口，只读源码仓库。下文「已复现」表示主会话独立复现或在源码中确认过；其余为单个 lane 报告（多个 lane 都报到的已注明）。

## 0. 结论

1. **核心流程都走得通**：单人记录、Hub 协作、共享给审稿 agent、见证、镜像、挑战赛全流程、离线核查。被篡改的证明包一律被识破。
2. **但当前接口是给人用的 CLI，不是给 agent 用的。** agent 卡在四件事上，6 个 lane 中至少 4 个都报到：
   - **无终端时没有口令输入方式**：要么设环境变量，要么直接崩出 traceback；macOS 上 `--sandbox require` 又禁止设这个环境变量。
   - **几乎没有机器可读输出**：只有 `log`、`verify` 支持 `--json`，而且内容基本是英文句子，命令只打印 12 位短哈希。
   - **退出码不可区分**：用法错误、403、口令错、分叉、回滚全是 2。
   - **重试不幂等**：`add`/`plan` 重跑会在只增账本上永久留下重复条目。
3. **测试找到两个最严重的问题，已修复**：
   - 多个写入方同时写会永久写坏账本（PR #6）。
   - `verify --content` 在证明包内嵌明文时不比对用户给的文件，却显示匹配（PR #7）。
4. **还有一批"静默的假成功"**，对 agent 用户最危险，因为 agent 会相信 exit 0 和 "all good"。见 §2 P0。
5. **名称冲突（已核实）**：CSIRO 已有同名、同领域的开源科研溯源系统 Provena（`github.com/provena/provena`，`provena.io`）。对外发布前必须改名。

## 1. 各类 agent 的实际流程与卡点

| Lane | 角色 | 走通的流程 | 主要卡点 |
|---|---|---|---|
| A | 单人科研 agent | keygen → init → plan → add → run（含失败的 run）→ prove → verify → reveal/publish → export → cite → ui | 无 TTY 崩溃；拿不到完整哈希；没有产物的失败 run 执行了但没有记录；`reveal`/`prove --open` 打开 activity 时 `KeyError: 'salt'` |
| B | 经 Hub 协作的多个 agent | 交换公钥卡片 → member add → clone → 并发提交合并 → share 给审稿 agent → 见证 → rm/rotate → succeed → `--creators` 准入 | 64 位 id 要手抄；按 GUIDE 恢复后新设备读不到历史；与 rotate 并发时条目被搁置，退出码却是 0；两人改同一路径静默分叉 |
| C | 挑战赛各角色（约 115 条命令，约 8 分钟） | init → 按时与迟交 → close → score → 外部 audit → 各队 `--submission`；查出 5 种作弊中的 3 种 | 评分方无法非交互运行；`LATE` 也返回 0；用旧证明包可以绕过"只能提交一次"；没有 `challenge status` |
| D | agent 框架集成方 | SDK 记录 7 次工具调用 + CLI 记录 2 次，再 push → prove → verify；每条记录约 1.6 ms | 多写入方写坏账本（已修）；参数里有浮点数整步丢失并吞掉原异常；没有文件读写的步骤（LLM 调用、搜索）不被记录；没有 SDK 层的 verify |
| E | 容易出错的 agent | 乱序调用、unicode 文件名、200 MB 文件、被杀后重试、文件损坏都试过 | push 中断或遇到 429 后 status/doctor 仍然报成功；`add /etc/hosts` 写进账本后所有人的 checkout 都会卡住；`keygen --name ../x` 路径穿越 |
| F | 运维 agent 与核查 agent | 主 Hub + 镜像 + 准入 + 见证 + 备份恢复；只拿到一个证明包的核查方用 `verify --require` 按等级判断 | 从镜像 clone 后能写入，导致分叉；Hub 回滚后 doctor 仍然 "all good"；分叉和回滚没有监控指标；同一数据目录能起两个 Hub |

## 2. 问题清单（按优先级）

### P0：数据完整性与假成功（agent 会信 exit 0）

| # | 问题 | 来源 | 状态 |
|---|---|---|---|
| 1 | 多写入方并发把作者链分叉 | D、E | **已修 PR #6**（已复现） |
| 2 | `--content` 被内嵌明文顶替；对未打开的条目给的内容被忽略 | F | **已修 PR #7**（源码确认，阴性对照） |
| 3 | push 先发条目、后传密文：中断或 429 后，status/doctor 仍报 "in sync / all good"，本地删掉数据就丢了 | E、B、F | 待修 |
| 4 | 条目被搁置到 `stranded.jsonl`（如与 rotate 并发）时 push 返回 0，status/doctor 不提 | B、F | 待修 |
| 5 | 从镜像 clone 后可以写入并推到镜像，与主 Hub 分叉；clone 之后也无法改回主 Hub | F | 待修 |
| 6 | 客户端在核对已固定的 Hub 公钥之前就先写入（创世条目已经进了新 Hub） | E | 待修 |
| 7 | `add` 接受仓库外的路径和 `.provena/` 内的路径，一旦写入账本，所有人的 checkout 都永久卡在这条 | E | 待修 |
| 8 | `keygen --name ../evil` 写到 agents 目录之外 | E | 待修 |
| 9 | `run` 先执行再校验：没有产物的失败 run 有副作用，却没有记录（与 GUIDE 的说法不符） | A | 待修 |
| 10 | SDK `run(params=)` 含浮点数时整步丢失，并吞掉工具的原异常；没有文件读写的步骤直接不记录 | D | 待修（源码确认浮点数被禁） |
| 11 | 挑战赛：用第一次提交的旧证明包能绕过"只能提交一次"；`audit --submission` 用别的包也会通过 | C | 待修 |
| 12 | Hub 用旧备份回滚后，客户端只看到尺寸不一致，doctor 仍报 all good；同一数据目录可以起两个 Hub | F | 待修 |

### P1：协议层（改规则，Python 与 JS 两个验证器必须同步）

| # | 问题 | 来源 |
|---|---|---|
| 13 | `member add` 只包装当前纪元的密钥：按 GUIDE 恢复后，新设备和恢复密钥都读不到历史（已在源码确认）。需要 `member add --history`，并改恢复流程与文档 | B |
| 14 | 两人并发 `add` 同一路径，各自得到不同版本，没有任何冲突提示 | B |
| 15 | activity 的 `exit_code`、model、params 被密封且无法打开，所以"失败的运行"在证明包里证明不了 | A、D |

### P2：agent 接口契约（6 个 lane 普遍报到）

1. **非交互密钥**：增加 `PROVENA_PASSPHRASE_FILE` 和 `--passphrase-fd`（评分沙箱下可用），按 agent 区分口令；无 TTY 时报一行清楚的错误。
2. **全局 `--json`**：所有命令都支持，输出完整哈希；`log --json` 带 hash、index、path；`verify --json` 的 facts 改成结构化，含 required 与实际达到的等级、按条目的时间、预注册是否成立；CLI 与 JS 用同一套字段。
3. **退出码约定**：0 成功；1 验证失败；2 用法错误；3 网络；另设认证/403、冲突/分叉/回滚、迟交/作废等码，并写进文档。
4. **幂等**：内容没变时 `add`/`plan` 跳过；`reveal`/`publish`/`open`/`close` 重复执行时返回成功；`run` 自身的输出与子进程的 stdout 分开。
5. **少传 id**：`init`/`clone` 提供 `--json`；`clone`/`witness` 接受 id 前缀；增加 `trust add log --from-url`（打印 id 供带外核对）；Hub 启动时及时刷新并打印日志公钥；clone 里能用路径引用 plan；增加 `provena config agent NAME`。
6. **挑战赛**：每个子命令支持 `--json`；`LATE` 返回非 0；增加 `challenge status`；`close` 可重复执行；向未截止挑战的真值 `share` 时警告。
7. **SDK**：提供 `proj.record(tool, args, result, ...)`，没有文件读写也能记录，不可存的参数自动转换或只记哈希；提供 `sdk.verify()`；统一的异常体系。
8. **长期**：`provena mcp` 或本地守护进程，作为每个项目的唯一写入方，并持有已解锁的密钥。agent 框架通过它接入，P0-1 一类问题从结构上消失。

### P3：运维与文档

- **监控**：分叉、回滚指标；锚定尝试和失败计数；空闲时锚定新鲜度不再误报；Hub 启动时提示正在用自锚定。
- **DEPLOY**：补恢复手册，包括备份比线上旧的情况，以及被见证人拒签项目的处理办法。
- **核查方**：`doctor` 增加只核查模式（不需要密钥和仓库）；`/p/{pid}/e/<短 id>` 现在返回 200 加 "No such entry"，应改成 404，或者支持短 id。
- **PILOT.md**：彩排阶段没有 TSA，过不了 anchored 检查；评分方的流程要改成"口令文件"方式。

## 3. 建议的推进顺序

1. **M-A，数据完整性（P0 #3–#12），约 1 天**：每项都要有回归测试和阴性对照，并加一轮独立审查。
2. **M-B，agent 契约（P2 第 1–5 条）**：先定 JSON 字段和退出码约定，写成 `docs/spec/cli-contract.md`，再逐个命令实现。
3. **M-C，协议改动（P1）**：`member add --history`、同一路径冲突检测、可打开的 activity 字段。三项都要 Python 与 JS 同步，并补一致性测试。
4. **M-D，MCP / 守护进程 + SDK `record`/`verify`**：这是面向 agent 产品的主入口。
5. **对外发布前**：改名，因为与 CSIRO Provena 冲突。
