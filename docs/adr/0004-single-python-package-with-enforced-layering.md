# ADR 0004: 单仓单 Python 包，子包分层由测试强制

- Status: accepted · 2026-10-31

## Context
需要 core/verifier 可审计、零多余依赖，同时开发期不想维护多个发布单元。

## Decision
一个 `provena` 包，子包 core/store/client/sdk/cli/server；`tests/test_layering.py` 静态扫描 import，core 不得依赖任何其他子包，且只依赖 `cryptography`。服务端依赖放 optional extras。

## Consequences
- 后续拆分为 `provena-core` 独立发布零成本（边界已由测试守住）。
- JS verifier 只需对齐 core 的测试向量。
