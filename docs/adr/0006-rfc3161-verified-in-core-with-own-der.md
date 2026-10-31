# ADR 0006: RFC 3161 作为首个外部锚；token 在 core 内用自带 DER 解析器验证

- Status: accepted · 2026-10-31

## Context
「backed by proof」的时间维度需要 Hub 之外的独立证据。候选：RFC 3161 TSA、OpenTimestamps（比特币）、公链合约。验证器必须离线、只依赖 core（ADR 0004）。

## Decision
- 首个外部锚 = RFC 3161：机构熟悉（电子签章/法务惯例）、免费 TSA 可用、机构可自建 TSA、秒级出 token。
- 不引 asn1crypto/rfc3161ng：自写 ~150 行最小 DER 读写器 + CMS SignedData 校验，用 `cryptography` 验签。
- 交叉验证：仓库内保存一个 freetsa.org 真实 token 作为测试向量；本地测试 TSA 覆盖负例（篡改 messageDigest、缺 EKU、genTime 超出证书有效期、签名损坏）。
- TSA 证书链到根 CA 的信任**只报告不裁决**（subject + 证书指纹），由验证方决定是否接受该 TSA。

## Consequences
- core 依赖面不变，JS verifier 需同样实现 DER 子集（M9 可复用测试向量）。
- 已实现 ESSCertID / ESSCertIDv2 签名证书绑定校验（2026-10-31 补）。
- 未实现：证书链到根 CA 的校验、OpenTimestamps——列入 Phase 2。
