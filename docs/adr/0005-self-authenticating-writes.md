# ADR 0005: Hub 写路径无会话认证，靠条目自认证

- Status: accepted · 2026-10-31

## Context
Hub 需要防止伪造写入与存储滥用。常规做法是账号 + token；但 Provena 的条目本身已由作者签名、由状态机判权。

## Decision
- `POST entries` / `POST projects` 不要求请求认证：条目签名 + `ProjectState.apply` 即授权。
- `PUT blob` 不要求请求认证：cid 必须被本项目的 entity/plan 引用、大小等于账本记录、sha256 = cid。
- 只有读取私有项目的条目/blob 需要签名请求（成员资格从账本状态机得出）。

## Consequences
- 无账号体系、无 token 泄露面；任何中继（镜像、离线 U 盘转交）都能代为提交。
- 存储上限天然受「成员写入的条目」约束；后来已加按客户端的令牌桶限流（写入、建项目）、`--max-projects` 总量上限、16 路并发上传、单条目 1 MiB / 单 blob 1 GiB 上限。
- FastAPI 依赖注入的坑：`from __future__ import annotations` 会让闭包上的 `Depends` 失效、退化为可选查询参数——app.py 禁用该 import，测试 `test_private_project_requires_membership` 守住。
