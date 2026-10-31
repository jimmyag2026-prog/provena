# ADR 0003: 条目模型对齐 W3C PROV（Entity / Activity / Agent）

- Status: accepted · 2026-10-31

## Context
「and process」要求记录过程而不只是文件。自定义模型易用但难互通；PROV 是科研溯源的既有标准（RO-Crate、CWLProv 均基于它）。

## Decision
条目 kind 中 `entity` / `activity` / `plan` 对应 PROV Entity / Activity / Plan；签名者即 Agent，AI agent 与仪器同为 Agent。其余 kind（genesis/member/key/attest/reveal/redact）是账本治理扩展。

## Consequences
- 可无损导出 PROV-JSON / RO-Crate，对接现有工作流系统。
- 血缘 = 条目 `refs` + activity 的 used/generated 构成的 DAG，证明包可携带整条血缘。
