# 首个试点运行手册：预注册盲测挑战赛

**Status: draft for decision** · 2026-10-31 · 依据 `docs/design/challenge-mode.md` §3b 的信任链与已实现的 `provena challenge` 命令（实验性）

本手册把「用 Provena 跑一场可验证的挑战赛」落到角色、时间线、逐条命令与预案。建议路线：**先用合成数据完整彩排一次（1 天），再接真实挑战赛**。试点的价值不在命令本身，而在于让一个**组织方以外的人**在截止后独立复核榜单，并且复核成功。

## 1. 试点要证明的四件事

| 对外声明 | 由什么证明 | 谁能复核 |
|---|---|---|
| 真值、题目、评分程序在截止前就已固定，且截止前没有泄露 | 方案条款块 + 真值承诺的 Hub 回执 / RFC 3161 时间；组织方全量日志里截止前只公开方案、题目、评分程序 | 任何人（`challenge audit`） |
| 每队恰好一份提交，且在截止前 | 各队全量日志：恰好一个引用方案的步骤、恰好一次授权给评审方，二者的受信 Hub 回执早于截止 | 任何人 |
| 榜单没有漏掉按时提交 | `audit --submission 队伍包`：参赛队自己核对 | 每个参赛队 |
| 分数 = 预注册评分程序(真值, 预测) | 评分步骤引用评分程序条目（内容哈希写在方案里）；评分程序在沙箱里运行 | 评审方；第三方需评审方授权预测后 `rerun` |

最后一行是边界：预测只授权给评审方，所以**分数本身仍是评审方的声明**。试点要么接受这一点，要么在 §7 决定赛后公开预测。

## 2. 角色与基础设施

| 角色 | 需要什么 | 建议 |
|---|---|---|
| 组织方 | `org` 身份 + 一个**专用**公开项目 | 机构身份凭证（`identity issue`）给组织方成员 |
| 评审方 | 独立于组织方的身份 + 自己的公开项目 | 与组织方不同机构；**不得参赛**（命令会拒绝） |
| 参赛队 | 每队一个身份 + 一个**只用于本次挑战**的项目 | 报名名单写 `AGENT_ID:PROJECT_ID`，不要开放报名 |
| Hub | 一个主 Hub（`provena hub serve`，见 `docs/DEPLOY.md`） | 开启 RFC 3161 锚定（`--tsa`）与定期重新锚定 |
| 镜像 | 另一方运行的第二个 Hub | 组织方每晚 `provena mirror`；主 Hub 宕机时可从镜像 clone |
| 见证人 | 独立于 Hub 运营方的一方 | 同一个状态文件同时观察主 Hub 与镜像（跨 Hub 分叉检查） |

**对外公布的信任设置**（写进挑战公告，读者据此 `provena trust add`）：主 Hub 日志公钥、见证人 id、TSA 证书指纹、组织方与评审方的 agent id。

## 3. 时间线

| 时间 | 事项 | 负责 |
|---|---|---|
| T−14 天 | 部署主 Hub + 镜像 + 见证人 cron；生成所有身份；签发机构凭证 | 组织方 / 运维 |
| T−10 天 | 参赛队报名：每队提交 `agent id` 与**已建好的**专用项目 id | 参赛队 |
| T−7 天 | **合成数据彩排**：全体按本手册跑一遍。`HUB=… examples/pilot_rehearsal.sh` 在真实 Hub 上自动跑完整一遍（agent 方式：只看 JSON 与退出码；2026-10-31 已在 DO 试验区 `https://jimmyresearch.com/provena` 跑通）；`examples/challenge_cli_demo.sh` 是单机版本 | 全体 |
| T0 | `challenge init`（名单写入方案）；公布 `challenge.pvb` 与信任设置 | 组织方 |
| T0 + 1 h | 确认锚定：`provena pull && provena prove challenge-protocol.md -o p.pvb && provena verify p.pvb --require anchored`（`challenge.pvb` 生成于锚定之前，本身不含锚定） | 组织方 |
| T0 … T1 | 参赛队 `challenge submit`；看到 `ON TIME` 再把包发给评审方 | 参赛队 |
| T1 截止 | 不做任何操作；等下一次锚定 | — |
| T1 之后 | `challenge close`（截止前会被拒绝） | 组织方 |
| T1 + 1 天 | `challenge score`，公开 `leaderboard.pvb`；Hub 项目页显示排行榜 | 评审方 |
| T1 + 3 天 | 外部复核：至少一位与组织方、评审方都无关的人跑 `challenge audit`；每队用 `--submission` 核对自己 | 外部 + 参赛队 |

## 4. 各角色命令

**全体（一次）**

```bash
provena keygen --display "<名字>"                 # 口令走 PROVENA_PASSPHRASE 或交互输入
provena card > me.card.json                       # 交给组织方 / 评审方
provena trust add log <主 Hub 日志公钥>             # 以公告为准
provena trust add witness <见证人 id>
provena trust add tsa <TSA 证书 64 位指纹>
```

**参赛队（T−10 天报名前）**

```bash
mkdir rna-team1 && cd rna-team1
provena init --name rna-team1                     # 记下打印的项目 id，连同 agent id 报名
provena remote https://hub.example.org
```

**组织方（T0）**

```bash
cd rna-challenge                                  # 专用公开项目：provena init --public
provena remote https://hub.example.org
provena challenge init --title "RNA binders 2026" --truth truth.csv --targets targets.csv \
    --score score.py --deadline 2026-12-01T00:00+08:00 \
    --team <队1 agent>:<队1 项目> --team <队2 agent>:<队2 项目> -o challenge.pvb
provena mirror https://mirror.example.org
```

`score.py` 的约定：以 `python score.py 预测文件...` 在含 `truth.csv` 的目录里运行，写出 `scores.json`（预测文件路径 → 数值）。它会在沙箱里跑：不能联网、读不到密钥、只能写工作目录。

**参赛队（截止前）**

```bash
provena challenge submit challenge.pvb --predictions pred.csv --evaluator evaluator.card.json \
    -o team1.pvb                                  # 必须看到 ON TIME
```

**组织方（截止后）**

```bash
provena challenge close -o truth.pvb
```

**评审方**

```bash
unset PROVENA_PASSPHRASE                          # 评分程序读不到口令文件，但能读环境变量
export PROVENA_PASSPHRASE_FILE=~/.provena/evaluator.pass   # chmod 600；agent 无需终端
provena challenge score challenge.pvb --truth truth.pvb --submission team1.pvb \
    --submission team2.pvb --hub https://hub.example.org --sandbox require --yes \
    -o leaderboard.pvb
```

**任何人 / 每个参赛队**

```bash
provena --json challenge status challenge.pvb --hub https://hub.example.org   # open / awaiting close / closed / void
provena challenge audit leaderboard.pvb --challenge challenge.pvb --hub https://hub.example.org \
    [--submission team1.pvb]
```

## 5. 预案

| 情况 | 现象 | 处理 |
|---|---|---|
| 组织方截止前在账本上公开或授权了任何方案/题目/评分程序以外的内容 | `score` / `audit` 报 `challenge void` | 挑战作废并公开说明；账本上的证据本身就是说明 |
| 组织方在账本外私下发送真值 | 账本无法发现 | 声明边界；组织方项目只做这一件事，减少接触真值的人 |
| 参赛队提交后看不到 `ON TIME` | 没有受信 Hub 回执（退出码 7 为迟交） | 检查 `provena remote` 与 `provena push`；截止前重试 |
| 参赛队提交后截止前又往项目写了东西 | `score` 报 `sequenced before the deadline` | 截止后让该队重新 `provena prove --full` 提交与授权两条，发给评审方 |
| 评审方漏掉某队 | `audit --submission` 报 `omits an on-time submission` | 评审方重新评分并发布；旧榜单留在账本上 |
| 主 Hub 宕机 | push / clone 失败 | 从镜像 clone 读取；写入等主 Hub 恢复（截止时间按 Hub 回执算，需提前预留缓冲） |
| 见证人报告分叉 | 见证人拒绝联署，状态文件记录两个 Hub 的树头 | 冻结挑战，公开两份已签名树头；这就是 Hub 作恶的证据 |
| 评分程序有 bug | 分数异常 | 方案里的评分程序哈希不能改；只能公告后另开一场，或在方案里预先写明复核规则 |

## 6. 成功标准

1. 全部参赛队的提交被 `audit` 判定为按时（或有可证明的迟交）。
2. 至少一位外部人士在不信任组织方与评审方的前提下 `audit` 通过。
3. 截止到可验证榜单发布 ≤ 24 小时。
4. 每队都用 `audit --submission` 核对过自己。
5. 参赛队的预测在评分前没有离开参赛队与评审方（授权记录可审计）。

## 7. 决定（2026-10-31，按用户"其余按默认"）

| # | 问题 | 决定 |
|---|---|---|
| 1 | 接哪一场真实挑战赛 | 用户选定**先办内部赛**：2026-10-31 在试验区跑通（`docs/pilots/2026-10-31-internal-race.md`）。外部组织方（RNA 结构挑战赛 / Poreva Open）待用户选定，步骤见 `docs/pilots/organizer-kit.md` |
| 2 | 赛后是否公开预测 | 默认**不公开**（预测只授权给评审方） |
| 3 | 报名方式 | **只接受报名名单**（`AGENT_ID:PROJECT_ID`），不开放报名 |
| 4 | 主 Hub / 镜像 / 见证人 | 主 Hub：DO 试验区 `https://jimmyresearch.com/provena`；见证人：GitHub Actions `trial-witness`（独立机器与密钥、同一运营方，见 `docs/integrations/trial-hub.md`）；镜像：试点前由组织方或第三方另起一个 Hub（`provena mirror`）。三者越独立越好：正式赛请一位无关方运行见证人 |
| 5 | TSA | 试点用 freetsa.org（已内置信任其证书指纹）；正式赛再考虑商业 TSA |
