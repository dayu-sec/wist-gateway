-- 审批公钥登记（**外部签发**模式）。
--
-- 为什么需要这张表：私钥从网关移到审批人手上的 `wist-approve`（或其衍生的签名服务）之后，
-- 网关需要在收到 attestation 时**验一遍再发**——不是为了授权（授权在执行侧 agentd 的锚），
-- 而是为了「别把垃圾签名的计划发到机器上」。
--
-- 两条语义：
--
--   1. **`key_id` 与 agentd 锚、attestation.key_id 三者同名**：换钥匙时靠它对齐；
--   2. **吊销不删行**：审计要能回答「这把钥匙什么时候被谁撤的」；已签发的计划不受影响
--      （它们在机器上用的是自己的锚与过期时间）。
--
-- 公钥是公开信息（SPKI PEM），指纹是 DER 的 sha256 前 16 位，用于页面与 CLI 人工核对。

CREATE TABLE IF NOT EXISTS approver_key (
  key_id      TEXT PRIMARY KEY,
  -- 属主：`user:<id>` / `role:approver` / `admin:<指纹>`（审计与展示）
  owner       TEXT NOT NULL,
  -- Ed25519 SPKI PEM，含首尾行
  public_key  TEXT NOT NULL,
  -- DER 的 sha256 前 16 位（hex，小写）
  fingerprint TEXT NOT NULL,
  added_by    TEXT NOT NULL,
  added_at    TEXT NOT NULL,
  -- NULL = 生效中
  revoked_at  TEXT
);
