# Provena 使用指南（中文）

**Status: draft** · v0.x · 与英文版 [`GUIDE.md`](GUIDE.md) 逐节同步；命令由 `examples/demo.sh`、`examples/challenge_cli_demo.sh` 与测试覆盖

Provena 为你的实验保存一本签名的、只增不改的账本：每份数据、每个方案、每个处理步骤。内容在你本机加密；你选定的任何人之后都可以离线验证——不需要信任 Provena——什么东西存在过、谁产生的、按什么顺序、不晚于什么时间。

## 1. 一张表看懂概念

| 概念 | 含义 | 类比 Git / HF |
|---|---|---|
| **agent（身份）** | Ed25519 签名密钥 + X25519 加密密钥；人、仪器、AI agent 都可以是 agent | SSH key |
| **project（项目）** | 一本只增不改的账本（Merkle 日志），以创世条目哈希为 ID | 仓库 |
| **entity（数据）** | 登记的数据文件：密文 + 加盐承诺 | 提交的文件 |
| **plan（方案）** | 预注册的方案/假设：现在只公开承诺，以后再揭示内容 | — |
| **activity（步骤）** | 一个处理步骤：用了哪些数据、产出了哪些数据、依据哪个方案 | 结构化的 commit 信息 |
| **hub** | 给条目排序、签发回执与树头、存放密文 | GitHub / HF Hub |
| **证明包（`.pvb`）** | 一个自包含文件，证明关于若干条目的具体事实 | — |

## 2. 准备

```bash
pip install "provena-ledger[client]"   # 运行 hub 再加 [server]
provena keygen --display "Ada Lovelace"
```

PyPI 上名为 `provena` 的包是另一个无关项目；请安装 `provena-ledger`（命令和 import 名仍是 `provena`）。

密钥存在 `~/.provena/agents/`（或 `$PROVENA_HOME/agents/`），用口令加密。没有终端时（agent、CI、服务），把口令放进只有你能读的文件，设 `PROVENA_PASSPHRASE_FILE`（或按密钥设 `PROVENA_PASSPHRASE_FILE_<名字>`）；`PROVENA_PASSPHRASE` 也可以，但你的其他进程看得到它。**不要**写在命令行参数里。设置了它们时新建的密钥也会用这个口令。`provena card > ada.card.json` 导出公开身份卡，交给合作者。一台机器上多个身份：`provena --agent 名字 …`（或 `keygen --name 名字`）。

程序和 AI agent：把 `--json` 放在最前面（`provena --json add data.csv`）。这时标准输出只有一个 JSON 对象，含完整条目哈希和退出码，所有文字提示走标准错误。字段和退出码见 `docs/spec/cli-contract-v1.md`。超时后重跑同一条命令是安全的：内容没变的文件不会被记录两次。

## 3. 记录一次实验

```bash
mkdir binding-assay && cd binding-assay          # 里面放 protocol.md、raw/*.csv、fit.py
provena init --name binding-assay                # 打印项目 id
provena plan protocol.md                         # 预注册：只公开承诺
provena add raw/plate1.csv raw/plate2.csv
provena run --plan protocol.md --used raw/ --out results/ -- python fit.py
provena log
```

`run` 会执行命令并记录步骤——**成功和失败都记录**，负结果留在账本上。账本规则 2 之后创建的项目里，每一步都会公开显示成功还是失败（`ok` / `failed`），并对密封的执行细节（命令、退出码、模型、参数）做承诺；`provena reveal <步骤>` 会公开这些细节，任何人都能对照承诺核验。`--used` 可以是文件、目录或条目；命令行里出现的仓库内文件（`fit.py`）也会自动记为输入，这样只凭账本就能复现该步骤（不想把命令行里的配置文件等记入账本时用 `--no-auto-inputs` 关闭）。`--out results/` 只记录命令在其中新建或改动的文件。既没有输入也没有产物的步骤（调一次模型、搜一次网页）同样会记录：它的标准输出和标准错误存成 `transcripts/` 下的密封运行记录。`add` 和 `plan` 只接受项目内的普通文件（符号链接保留它自己的名字）。仪器与分析代码可以直接用 Python：

```python
from provena import sdk
proj = sdk.open(".")
with proj.run("拟合结合曲线", plan="protocol.md", used=["raw/plate1.csv"]) as run:
    ...
    run.output("results/kd.json")
```

### 复现一个步骤

```bash
provena rerun <activity> --yes --attest      # 还原输入、重新执行、比对输出
```

`rerun` 会先打印记录的命令和作者，只有加 `--yes` 才执行：命令来自账本，相当于合作者写的代码。有随机性的步骤（随机种子、时间戳、GPU 非确定性）会显示为 `DIFFERS`。加 `--sandbox require` 可在沙箱里运行：断网、读不到你的密钥、主目录与仓库（Linux 用 bubblewrap，macOS 用 `sandbox-exec`；先取消 `PROVENA_PASSPHRASE`）。

### 在 Jupyter 里

```python
%load_ext provena.sdk.ipython
```
```python
%%provena "拟合结合曲线" --used raw/plate1.csv --out results/kd.json --plan protocol.md
kd = fit(load("raw/plate1.csv")); save(kd, "results/kd.json")
```

单元格照常运行；它的**确切源码**被加密保存为该步骤的产出，失败的单元格也会记录。

### 在浏览器里看

```bash
provena ui        # 打印 http://127.0.0.1:8741/?t=<token>；只读，在本机解密
```

## 4. 通过 Hub 协作

```bash
provena remote https://hub.example.org     # 钉住 Hub 的日志公钥（首次信任）
provena push                               # 条目 + 密文；每条回执都被校验
provena member add bob.card.json --role contributor    # Bob 用 `provena card` 导出的卡
provena member list
# Bob（项目 id：`provena init` 打印的那个，或向 Ada 要）：
provena clone https://hub.example.org <project-id> && cd <dir> && provena checkout
```

角色：`owner` > `maintainer` > `contributor`（可写数据）> `reviewer`（可出具证明）> `viewer`。移除成员会轮换项目密钥：他保留已能读的内容，新内容读不到。

### 第二个 Hub（镜像）

```bash
provena mirror https://mirror.example.org          # 已排序的条目 + 密文
provena mirror --check https://mirror.example.org  # 分叉检查：同样大小下根是否一致
```

条目由作者签名，任何 Hub 都能保存同一本账；同样的条目、同样的顺序得到同样的 Merkle 根。主 Hub 宕机时，任何人都可以从镜像 `provena clone`（这样的检出是只读的：它从镜像得知主 Hub，`provena remote --rehome` 之后才向主 Hub 写入），已有的检出可以用 `provena pull --from https://mirror.example.org` 跟上进度（先在主 Hub 正常时用 `provena mirror --check` 钉住镜像）。这样读来的条目是临时的：下次从主 Hub `pull` 只保留它确认的条目，你也不会把它们推送出去。镜像在同一大小下的树头与你的账本不同，就是其中一个 Hub 分叉的证据。让同一个见证人（同一个状态文件）同时观察两个 Hub，会持续做这项检查，发现分叉即拒绝联署。撤回（redact）之后请再运行一次 `provena mirror`：撤回条目到达镜像时，镜像才删除对应密文。

### 同步没能完成时

`push` 和 `pull` 不会在还有事没做完时报成功。退出码：3 是 Hub 不可达（遇到限流会自动等待重试）；5 是还有事要做：上次 push 被打断（`status` 会提示，再 push 一次），或者你有未推送的条目已经接不上 Hub 上的账本，例如队友在此期间轮换了项目密钥（这些条目被搁置，对应文件显示为未登记；先 `provena stranded list`，再用 `provena stranded redo` 重新记录）；6 是 Hub 与你手上的记录矛盾：它的日志公钥变了（此时什么都不会写入），或者它的条目比你持有回执的还少，即发生了回滚（保留你的检出，并告知运维）。两位成员同时记录同一路径属于冲突（退出码 5）：两个版本都留在账本上，用 `provena resolve 路径 --keep 哈希` 选定你的检出使用哪一个。

### 密钥找回

你的 agent 密钥是解密项目数据的唯一途径。请一次性设置找回：

```bash
provena --agent recovery keygen --display "Ada（找回用）"   # 长口令（先取消 PROVENA_PASSPHRASE）；
                                                          # keyfile 离线保存（U 盘/纸）
provena member add ~/.provena/agents/recovery.card.json --role owner --history
```

`--history` 会把你持有的所有更早纪元的密钥也交给找回密钥，它才能读到加入之前记录的数据（账本规则 2；之前加入时没带它的成员，可以事后用 `provena member history <id>` 补上）。设备丢失时：在新设备生成新密钥，用找回密钥把它连同历史一起加进来，并移除丢失的那把（移除会轮换项目密钥）：

```bash
provena --agent laptop2 keygen --display "Ada（笔记本 2）"
provena --agent recovery member add ~/.provena/agents/laptop2.card.json --role owner --history
provena member list                                  # 查 id；下面用唯一前缀即可
provena --agent recovery member rm <丢失的 agent id>
provena config agent laptop2                         # 这个检出今后用新密钥签名
```

**多台设备。** 每台设备一把密钥，各自是成员（加 `--history`）；如果有组织凭证，用它把这些密钥都绑定到你本人（`provena identity`）。不要在机器之间复制密钥：同一把密钥在两台机器上同时使用，会让它自己的条目链分叉。

有计划的换钥（旧钥仍在）用密钥继任，每个项目做一次；继任者保留角色和所有纪元密钥，旧钥在该项目里失效：

```bash
provena --agent laptop2 keygen --display "Ada (laptop 2)"
provena succeed laptop2          # 也可以给另一台机器上生成的公钥卡片文件
```

## 5. 出证明、做验证

```bash
provena prove results/kd.json --open results/kd.json -o kd.pvb     # 选择性（最小披露）
provena prove results/kd.json --full -o kd-full.pvb               # 全量：额外证明权限
provena verify kd.pvb --trust-log <hub 日志 id> --content <entry>=results/kd.json
```

验证器只打印它**自己重新推导出的事实**，再给一个**信任等级**。`VALID` 表示密码学成立；等级只取决于**你**信任谁（`provena trust list`）：

| 等级 | 含义 |
|---|---|
| `unverified` | 有效，但签名的日志你不信任：顺序与时间只是声明 |
| `self-sequenced` | 由项目成员自签；时间是作者自己的说法 |
| `log-sequenced` | 由你信任的 Hub 排序计时（`provena remote` 会信任你钉住的 Hub） |
| `witnessed` | 你信任的见证人确认该 Hub 没有分叉 |
| `anchored` | 你信任的时间戳机构为日志树头盖了时间 |

```bash
provena trust add witness pv1a...                 # 独立见证人的完整 id
provena trust add tsa <64 位十六进制指纹>          # TSA 证书指纹（verify 的提示里会给出）
provena verify kd.pvb --json                      # 机器可读的结论（退出码相同）
provena verify kd.pvb --require anchored          # 低于该等级则非零退出（适合 CI）
provena verify kd.pvb --before 2026-11-01T00:00+08:00   # 每个目标都可证明早于该时间
```

`--before` 只采信**受信**的时间证据：你信任的日志树头、Hub 排序时签发的回执、或你信任的 TSA 时间戳。用 `--json` 时，只有证明包有效**且** `--require` / `--before` 检查都通过，`accepted` 才为真。

见证人是任何独立的一方：先生成一次密钥（`provena --agent witness keygen`），再例如用 cron 运行 `provena --agent witness witness https://hub.example.org <项目 id>`；它只联署延续了它此前所见历史的树头。联署保存在 Hub 上：`prove` 之前先 `provena pull`（或 `push`），证明包才会带上联署、验证为 `witnessed`。

审稿人不装 Provena 也可以：把 `.pvb` 拖进任一 Hub 首页，在浏览器里验证。

### 密钥背后是谁

密钥是匿名的。机构可以用 `org` 身份为其成员背书：

```bash
provena --agent uni keygen --kind org --display "某某大学"
provena --agent uni identity issue ada.card.json --name "Ada Lovelace" \
    --affiliation "化学系" --orcid 0000-0002-1825-0097 -o ada.cred.json
provena identity attach ada.cred.json        # 在项目里：证明包会附带它
provena trust add org <大学的 agent id>       # 读者自己决定信谁
```

凭证只覆盖它有效期内（签发之后）签的条目；签发之前记录的条目会显示「not valid at the time in question」。

## 6. 分享、发表、撤回

| 目的 | 命令 | 公开的内容 |
|---|---|---|
| 给一位审稿人看一个文件 | `provena share F --to rev.card.json` | 一条 `grant` 记录（谁在何时获得了什么的访问权） |
| 证明方案在先 | `provena reveal protocol.md` | 承诺的开口（盐 + 哈希） |
| 发表数据 | `provena publish F` | 内容密钥与文件名：任何人可下载、可核对 |
| 撤回同意 | `provena redact F --reason consent-withdrawn` | 「已销毁」这一事实；本地与（立即推送后）Hub 上的密文被删除；工作区里的文件请自行删除 |
| 引用一个结果 | `provena cite F --format bibtex` | — |
| 交付一个包 | `provena export rocrate -o crate/` | RO-Crate + 证明包（含解密后的文件；`--metadata-only` 不含） |

配置了 Hub 时，`reveal`、`redact`、`share` 与成员变更会立即推送。

### 使用其他实验室的数据

```bash
provena open 对方数据集.pvb --hub https://hub.example.org   # 验证并解密对方分享的内容
provena run --external <对方项目>:<对方条目> --out results/ -- python analyze.py
provena push                                                    # 让新步骤获得 Hub 计时
provena prove results/x.csv --external 对方数据集.pvb -o x.pvb
```

`--external` 需要完整的 64 位项目 id 与条目哈希（`provena show` 会打印）。验证器用同样的信任设置检查对方的证明包，并报告「used entry … of project …（that project's evidence: log-sequenced）」。用这些原语搭的完整预注册盲测挑战赛见 `examples/challenge_demo.sh`。

### 举办挑战赛（实验性）

各方先在自己的项目里 `provena init`（组织方用 `init --public`）并 `provena remote URL`；没有 Hub 时下面的命令会拒绝运行，因为是否按时只看 Hub 回执。完整流程见 `examples/challenge_cli_demo.sh`。

```bash
# 组织方：真值只上承诺；方案、题目、评分程序公开
provena challenge init --title "RNA binders" --truth truth.csv --targets targets.csv \
    --score score.py --deadline 2026-12-01T00:00+08:00 --team <agent-id>:<project-id> -o challenge.pvb
# 各参赛队，在报名的项目里
provena challenge submit challenge.pvb --predictions pred.csv --evaluator eval.card.json -o team1.pvb
#   退出码 0 = 按时，7 = 迟交；第二次提交会被拒绝。截止前不要再往这个项目写入
#   （证明包必须覆盖截止前排序的全部条目）
# 组织方，截止之后
provena challenge close -o truth.pvb
# 评审方
provena challenge score challenge.pvb --truth truth.pvb --submission team1.pvb \
    --submission team2.pvb --hub URL --yes -o leaderboard.pvb
# 任何人（不需要密钥）；参赛队可加 --submission 自己的包，检查自己没被漏掉
provena challenge audit leaderboard.pvb --challenge challenge.pvb --hub URL
```

报名名单写成 `--team AGENT_ID:PROJECT_ID`（每队唯一的提交项目）；不写名单则任何人可参赛，同一人可用多把密钥参赛。请用只为本次挑战建的项目提交：榜单附带各队全量证明包，内容仍加密，但日志结构公开。`close` 只能在截止后执行；真值提前泄露会使挑战作废。评审方公开榜单；`audit` 不需要密钥，从附带的证明中重新推出输入、规则与每一行是否按时——只有分数本身仍是评审方的声明。

评分程序以 `python score.py 预测文件...` 的形式在含 `truth.csv` 的工作目录里运行，须写出 `scores.json`（每个预测文件路径对应一个数值）。有 bubblewrap（Linux）或 `sandbox-exec`（macOS）时它在沙箱里运行：断网、读不到你的 Provena 密钥、主目录与仓库、只能写工作目录（`--sandbox require|off`）。评分时请取消 `PROVENA_PASSPHRASE`、交互输入口令：在 macOS 上，你运行的任何程序都能读到其他进程的环境变量。

## 7. Provena 不证明什么

它不证明数据反映了真实世界。它证明的是**记录**的完整性、作者、顺序与时间。在仪器端签名（设备上的 `instrument` 身份，`provena capture`）能让签名更靠近测量本身，但不能让一个不诚实的实验室变诚实。
