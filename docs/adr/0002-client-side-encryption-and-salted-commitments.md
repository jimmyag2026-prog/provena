# ADR 0002: 客户端加密 + 盐化承诺，承诺与密文解耦

- Status: accepted · 2026-10-31

## Context
「kept encrypted」与「backed by proof」存在张力：证明需要公开可验的指纹，但指纹不能泄露内容（低熵数据可被字典反推）。

## Decision
- 内容在客户端分块 AES-256-GCM 加密，每文件独立 DEK；DEK 由项目纪元密钥封装。
- 账本中登记 `commitment = sha256("provena/commit/v1" ‖ salt32 ‖ sha256(plaintext))` 与 `cid = sha256(ciphertext)`。
- 披露 = 公开 salt + 明文（或明文哈希）。

## Consequences
- 服务端零明文；重加密/换钥不影响已有证明。
- 选择性披露粒度 = 单个实体；更细粒度（字段级、数值范围）留给 Phase 2 的 ZK 扩展。
- 销毁 DEK 即可实现 crypto-shredding（满足删除权），而条目存在性不受影响。
