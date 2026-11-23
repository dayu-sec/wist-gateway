//! `wist-approve` —— 审批终端（V1：CLI）。
//!
//! 审批与签名在**同一次操作**里完成（`approve --sign`），但系统上仍是两件事：
//! 投票是服务端记录的事实，签名是本机私钥干的活。设计见
//! `docs/design/plan-external-signing.md` §7。

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use wist_approve::render_summary;
use wist_approve::{ApproverKey, GatewayClient, SigningPayload};
use wist_contracts::action_plan::{
    ATTESTATION_ALGORITHM_ED25519, ActionPlan, ActionPlanApproval, ActionPlanAttestation,
    plan_digest,
};

#[derive(Parser)]
#[command(
    name = "wist-approve",
    // 版本与平台由 `build.rs` 编进来（`WIST_APPROVE_VERSION` 由发布流水线传 tag）。
    // 审批人报障时这一行是唯一能对上 Release 制品的线索。
    version = concat!(env!("WIST_APPROVE_VERSION"), " (", env!("WIST_APPROVE_TARGET"), ")"),
    about = "审批终端：审批 + 签名（私钥只在本机）",
    long_about = None
)]
struct Cli {
    /// 网关地址，例如 `https://127.0.0.1`。
    #[arg(long, global = true, env = "WIST_GATEWAY")]
    gateway: Option<String>,
    /// approver token 文件（默认 `~/.wist/approver.token`）。
    #[arg(long, global = true)]
    token_file: Option<PathBuf>,
    /// 私有 CA 证书（PEM）。网关用自签证书时必须给。
    #[arg(long, global = true)]
    ca_file: Option<PathBuf>,
    /// **不要**在生产用：跳过 TLS 校验（仅本机联调）。
    #[arg(long, global = true)]
    insecure: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 生成 / 查看审批钥匙。
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },
    /// 待批 / 已批 / 已签发。
    List {
        #[arg(long)]
        agent: Option<String>,
    },
    /// 渲染一条审批的计划摘要（不会签任何东西）。
    Show {
        approval_id: String,
        #[arg(long)]
        allow_unknown_fields: bool,
    },
    /// 投票；加 `--sign` 则一步完成「批准 + 签名 + 提交」。
    Approve {
        approval_id: String,
        #[arg(long)]
        comment: Option<String>,
        /// 投票后立即签名并提交（默认只投票）。
        #[arg(long)]
        sign: bool,
        #[arg(long)]
        key: Option<PathBuf>,
        /// 写进证明的签发者标识（审计用，例如 `user:zhangsan`）。
        #[arg(long, default_value = "role:approver")]
        issued_by: String,
        /// 证明有效期（秒；且不晚于计划自身到期）。
        #[arg(long, default_value_t = 3600)]
        ttl_seconds: i64,
        /// 不询问直接执行（脚本用）。
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        allow_unknown_fields: bool,
    },
    /// 驳回（投票 reject）。审批人的身份由 token 派生，CLI 不自填。
    Reject {
        approval_id: String,
        #[arg(long)]
        comment: Option<String>,
    },
    /// 给一条**已批准**的单签名并提交（不投票）。
    Sign {
        approval_id: String,
        #[arg(long)]
        key: PathBuf,
        #[arg(long, default_value = "role:approver")]
        issued_by: String,
        #[arg(long, default_value_t = 3600)]
        ttl_seconds: i64,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        allow_unknown_fields: bool,
    },
    /// air-gap：把别处签好的 attestation 提交上去。
    Submit {
        approval_id: String,
        #[arg(long)]
        attestation: PathBuf,
    },
    /// 查看一条审批的状态。
    Status { approval_id: String },
}

#[derive(Subcommand)]
enum KeyAction {
    /// 生成一把钥匙（私钥 0600，同时导出 `.pub.pem`）。
    Generate {
        #[arg(long)]
        out: PathBuf,
        /// 允许覆盖已存在的私钥（会让机器上的锚静默失效，谨慎）。
        #[arg(long)]
        force: bool,
        /// 公钥输出路径（默认 `<out>.pub.pem`）。
        #[arg(long)]
        pub_out: Option<PathBuf>,
    },
    /// 打印 key_id / 指纹 / 公钥 PEM（与页面核对用）。
    Show {
        #[arg(long)]
        key: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("wist-approve: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<(), String> {
    match &cli.command {
        Command::Key { action } => run_key(action),
        Command::List { agent } => {
            let client = build_client(cli)?;
            let approvals = client
                .list(agent.as_deref())
                .map_err(|err| err.to_string())?;
            if approvals.is_empty() {
                println!("（没有审批单）");
                return Ok(());
            }
            for approval in approvals {
                println!(
                    "{:<44} {:<8} {:<10} {:<20} {:<24} {}",
                    approval.approval_id,
                    approval.risk_level,
                    approval.status,
                    approval.agent_id,
                    approval.requested_at,
                    if approval.issued { "已签发" } else { "" }
                );
            }
            Ok(())
        }
        Command::Show {
            approval_id,
            allow_unknown_fields,
        } => {
            let client = build_client(cli)?;
            let payload = client
                .signing_payload(approval_id)
                .map_err(|err| err.to_string())?;
            let (plan, summary) = prepare_summary(&payload, *allow_unknown_fields)?;
            let _ = plan;
            println!(
                "{}",
                summary.render(&payload.approval_id, "<未选定钥匙>", "<见 key show>")
            );
            println!(
                "\n审批人：{}（需要 {} 人）",
                payload.approvers.join(", "),
                payload.required_approvers
            );
            Ok(())
        }
        Command::Approve {
            approval_id,
            comment,
            sign,
            key,
            issued_by,
            ttl_seconds,
            yes,
            allow_unknown_fields,
        } => {
            // 先校验参数再动手：`approve --sign` 忘了 `--key` 时不该先投一票再报错 ——
            // 那一票是**不可撤回**的（同一人再投是覆盖，但记录已经留下了）。
            if *sign && key.is_none() {
                return Err("--sign 需要 --key <path>（审批私钥）".to_string());
            }
            let client = build_client(cli)?;
            let body = client
                .vote(approval_id, "approve", comment.as_deref())
                .map_err(|err| err.to_string())?;
            let status = body
                .get("status")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            println!("已投票：approval={approval_id} status={status}");
            if !*sign {
                println!("（只投了票；按 `wist-approve sign {approval_id} --key <path>` 再签）");
                return Ok(());
            }
            let key_path = key
                .clone()
                .ok_or_else(|| "--sign 需要 --key <path>（审批私钥）".to_string())?;
            sign_and_issue(
                &client,
                approval_id,
                &key_path,
                issued_by,
                *ttl_seconds,
                *yes,
                *allow_unknown_fields,
                false,
            )
        }
        Command::Reject {
            approval_id,
            comment,
        } => {
            let client = build_client(cli)?;
            let body = client
                .vote(approval_id, "reject", comment.as_deref())
                .map_err(|err| err.to_string())?;
            let status = body
                .get("status")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            println!("已驳回：approval={approval_id} status={status}");
            Ok(())
        }
        Command::Sign {
            approval_id,
            key,
            issued_by,
            ttl_seconds,
            yes,
            allow_unknown_fields,
        } => {
            let client = build_client(cli)?;
            sign_and_issue(
                &client,
                approval_id,
                key,
                issued_by,
                *ttl_seconds,
                *yes,
                *allow_unknown_fields,
                true,
            )
        }
        Command::Submit {
            approval_id,
            attestation,
        } => {
            let client = build_client(cli)?;
            let text = fs::read_to_string(attestation)
                .map_err(|err| format!("failed to read {}: {err}", attestation.display()))?;
            let attestation: ActionPlanAttestation = serde_json::from_str(&text)
                .map_err(|err| format!("invalid attestation JSON: {err}"))?;
            let result = client
                .issue(approval_id, &attestation)
                .map_err(|err| err.to_string())?;
            println!(
                "已提交签名：approval={approval_id} command={}",
                result.dispatched_command_id.as_deref().unwrap_or("-")
            );
            Ok(())
        }
        Command::Status { approval_id } => {
            let client = build_client(cli)?;
            let value = client
                .approval(approval_id)
                .map_err(|err| err.to_string())?;
            for key in [
                "approval_id",
                "agent_id",
                "status",
                "risk_level",
                "approved_at",
                "issued",
            ] {
                if let Some(field) = value.get(key) {
                    println!("{key:<12} {field}");
                }
            }
            Ok(())
        }
    }
}

fn run_key(action: &KeyAction) -> Result<(), String> {
    match action {
        KeyAction::Generate {
            out,
            force,
            pub_out,
        } => {
            let key = ApproverKey::generate_to(out, *force)?;
            let pub_path = pub_out
                .clone()
                .unwrap_or_else(|| with_suffix(out, ".pub.pem"));
            fs::write(&pub_path, key.public_pem())
                .map_err(|err| format!("failed to write {}: {err}", pub_path.display()))?;
            println!("已生成私钥 {}", out.display());
            println!("公钥       {}", pub_path.display());
            println!("key_id     {}", key.key_id());
            println!("指纹       {}", key.fingerprint());
            println!(
                "\n下一步：\n  1) 把公钥登记到网关（页面「审批公钥」或 POST /api/v1/admin/approver-keys）\n  2) 把同一份 PEM 钉到 agentd 的 [attestation] trusted_keys（key_id 用上面这串）"
            );
            Ok(())
        }
        KeyAction::Show { key } => {
            let key = ApproverKey::load_from(key)?;
            println!("key_id  {}", key.key_id());
            println!("指纹    {}", key.fingerprint());
            println!("\n{}", key.public_pem());
            Ok(())
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn sign_and_issue(
    client: &GatewayClient,
    approval_id: &str,
    key_path: &std::path::Path,
    issued_by: &str,
    ttl_seconds: i64,
    yes: bool,
    allow_unknown_fields: bool,
    require_approved: bool,
) -> Result<(), String> {
    let payload = client
        .signing_payload(approval_id)
        .map_err(|err| err.to_string())?;
    let (_plan, summary) = prepare_summary(&payload, allow_unknown_fields)?;
    let key = ApproverKey::load_from(key_path)?;

    println!(
        "{}",
        summary.render(approval_id, key.key_id(), key.fingerprint())
    );
    println!("审批人   {}", payload.approvers.join(", "));
    if require_approved && payload.approvers.is_empty() {
        return Err("approval has no approver recorded".to_string());
    }

    if !yes && !confirm("确认签名并下发？[yes/N] ")? {
        println!("已取消（未签名、未下发）。");
        return Ok(());
    }

    let mut attestation = build_attestation(&payload, &key, issued_by, ttl_seconds)?;
    key.sign(&mut attestation);
    if !key.verify(&attestation) {
        return Err(
            "self-check failed: the signature does not verify with our own public key".to_string(),
        );
    }
    let result = client
        .issue(approval_id, &attestation)
        .map_err(|err| err.to_string())?;
    println!(
        "已签发并下发：command={}",
        result.dispatched_command_id.as_deref().unwrap_or("-")
    );
    Ok(())
}

fn prepare_summary(
    payload: &SigningPayload,
    allow_unknown_fields: bool,
) -> Result<(ActionPlan, wist_approve::PlanSummary), String> {
    let plan: ActionPlan = serde_json::from_value(payload.plan.clone())
        .map_err(|err| format!("gateway returned a plan this CLI cannot parse: {err}"))?;
    let recomputed = plan_digest(&plan);
    if recomputed != payload.plan_digest {
        return Err(format!(
            "plan digest mismatch: gateway says {}, CLI recomputed {recomputed} — refusing to sign",
            payload.plan_digest
        ));
    }
    let summary = render_summary(&plan, &recomputed, allow_unknown_fields)?;
    Ok((plan, summary))
}

fn build_attestation(
    payload: &SigningPayload,
    key: &ApproverKey,
    issued_by: &str,
    ttl_seconds: i64,
) -> Result<ActionPlanAttestation, String> {
    if ttl_seconds <= 0 {
        return Err("--ttl-seconds must be positive".to_string());
    }
    let now = chrono::Utc::now();
    let plan: ActionPlan = serde_json::from_value(payload.plan.clone())
        .map_err(|err| format!("gateway returned a plan this CLI cannot parse: {err}"))?;
    let plan_expires = chrono::DateTime::parse_from_rfc3339(&plan.meta.expires_at)
        .map_err(|err| format!("plan expires_at is not RFC3339: {err}"))?
        .with_timezone(&chrono::Utc);
    let expires = (now + chrono::Duration::seconds(ttl_seconds)).min(plan_expires);
    if expires <= now {
        return Err(format!(
            "plan already expired at {} — nothing to sign",
            plan.meta.expires_at
        ));
    }
    let approved_at = payload
        .approved_at
        .clone()
        .ok_or_else(|| "approval has no approved_at; is it still pending?".to_string())?;
    Ok(ActionPlanAttestation {
        api_version: wist_contracts::API_VERSION_V1.to_string(),
        plan_digest: payload.plan_digest.clone(),
        approval: ActionPlanApproval {
            approval_id: payload.approval_id.clone(),
            approvers: payload.approvers.clone(),
            required_approvers: payload.required_approvers,
            approved_at,
        },
        risk_level: plan.constraints.risk_level,
        issued_by: issued_by.to_string(),
        key_id: key.key_id().to_string(),
        algorithm: ATTESTATION_ALGORITHM_ED25519.to_string(),
        signed_at: now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        expires_at: expires.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        signature: String::new(),
    })
}

fn confirm(prompt: &str) -> Result<bool, String> {
    print!("{prompt}");
    std::io::stdout()
        .flush()
        .map_err(|err| format!("failed to flush stdout: {err}"))?;
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|err| format!("failed to read stdin: {err}"))?;
    Ok(matches!(line.trim(), "yes" | "y" | "Y"))
}

fn build_client(cli: &Cli) -> Result<GatewayClient, String> {
    let gateway = cli
        .gateway
        .clone()
        .ok_or_else(|| "--gateway <url> (or WIST_GATEWAY) is required".to_string())?;
    let token_path = cli
        .token_file
        .clone()
        .or_else(default_token_path)
        .ok_or_else(|| "--token-file <path> is required".to_string())?;
    let token = fs::read_to_string(&token_path)
        .map_err(|err| format!("failed to read token {}: {err}", token_path.display()))?
        .trim()
        .to_string();
    if token.is_empty() {
        return Err(format!("token file {} is empty", token_path.display()));
    }
    GatewayClient::new(&gateway, &token, cli.ca_file.as_deref(), cli.insecure)
        .map_err(|err| err.to_string())
}

fn default_token_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".wist/approver.token"))
}

fn with_suffix(path: &std::path::Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wist_approve::SigningPayload;

    fn plan_json(expires_at: &str) -> serde_json::Value {
        serde_json::json!({
            "api_version": "v1",
            "kind": "action_plan",
            "meta": {
                "action_id": "act-1", "request_id": "req-1", "template_id": null,
                "tenant_id": "tenant-default", "environment_id": "env-default",
                "plan_version": 1, "compiled_at": "2026-01-01T00:00:00Z",
                "expires_at": expires_at
            },
            "target": {
                "agent_id": "agent-1", "instance_id": null, "node_id": "node-1",
                "host_name": null, "platform": "linux", "arch": "x86_64", "selectors": {}
            },
            "constraints": {
                "risk_level": "R2", "approval_ref": "apv-1", "approval_mode": "required",
                "requested_by": "tester", "reason": null,
                "max_total_duration_ms": 60000, "step_timeout_default_ms": 30000,
                "execution_profile": "agent_exec_v1",
                "required_capabilities": ["disk.cleanup.apply"]
            },
            "program": {
                "entry": "s1",
                "steps": [
                    { "id": "s1", "kind": "invoke", "op": "disk.cleanup.apply",
                      "args": { "target": "tmp", "min_age_hours": 8760 } },
                    { "id": "s2", "kind": "output" }
                ]
            }
        })
    }

    fn payload(expires_at: &str) -> SigningPayload {
        let plan = plan_json(expires_at);
        let parsed: ActionPlan = serde_json::from_value(plan.clone()).expect("plan");
        SigningPayload {
            approval_id: "apv-1".to_string(),
            agent_id: "agent-1".to_string(),
            plan_digest: plan_digest(&parsed),
            risk_level: "R2".to_string(),
            approvers: vec!["admin:abc".to_string()],
            required_approvers: 1,
            approved_at: Some("2026-11-23T00:00:00Z".to_string()),
            plan,
            plan_expires_at: expires_at.to_string(),
        }
    }

    fn fresh_key() -> ApproverKey {
        let dir = std::env::temp_dir().join(format!(
            "wist-approve-main-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let path = dir.join("k.key");
        let key = ApproverKey::generate_to(&path, false).expect("generate");
        let _ = std::fs::remove_dir_all(&dir);
        key
    }

    #[test]
    fn version_string_carries_the_build_identity() {
        // `--version` 是审批人报障时唯一能对上 Release 制品的线索（见 build.rs 的模块注释）。
        // 这里钉住两件事：版本不是空的（build.rs 真的跑过），平台三元组里带上了本机架构
        //（不然交叉编译出来的制品会自报错的平台）。
        let version = env!("WIST_APPROVE_VERSION");
        let target = env!("WIST_APPROVE_TARGET");
        assert!(!version.trim().is_empty(), "版本不能为空");
        assert!(
            target.contains(std::env::consts::ARCH),
            "平台三元组 {target} 与编译架构 {} 不一致",
            std::env::consts::ARCH
        );
    }

    #[test]
    fn attestation_expiry_never_outlives_the_plan() {
        let key = fresh_key();
        // 计划 10 秒后到期，而 ttl 要 1 小时 → 取 min（计划到期）。
        let soon = (chrono::Utc::now() + chrono::Duration::seconds(10))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let attestation =
            build_attestation(&payload(&soon), &key, "role:approver", 3600).expect("build");
        assert_eq!(attestation.expires_at, soon);
    }

    #[test]
    fn refuses_to_sign_an_already_expired_plan() {
        let key = fresh_key();
        let err = build_attestation(&payload("2020-01-01T00:00:00Z"), &key, "role:approver", 60)
            .expect_err("must refuse");
        assert!(err.contains("already expired"), "{err}");
    }

    #[test]
    fn refuses_a_non_positive_ttl() {
        let key = fresh_key();
        let err = build_attestation(&payload("2031-01-01T00:00:00Z"), &key, "role:approver", 0)
            .expect_err("must refuse");
        assert!(err.contains("positive"), "{err}");
    }

    #[test]
    fn refuses_to_render_when_the_digest_does_not_match() {
        let mut signed = payload("2031-01-01T00:00:00Z");
        signed.plan_digest = format!("plan-v1:sha256:{}", "ab".repeat(32));
        let err = prepare_summary(&signed, false).expect_err("must refuse");
        assert!(err.contains("digest mismatch"), "{err}");
    }

    #[test]
    fn attestation_copies_the_approved_facts() {
        let key = fresh_key();
        let payload = payload("2031-01-01T00:00:00Z");
        let attestation = build_attestation(&payload, &key, "role:approver", 60).expect("build");
        assert_eq!(attestation.plan_digest, payload.plan_digest);
        assert_eq!(attestation.approval.approval_id, payload.approval_id);
        assert_eq!(attestation.approval.approvers, payload.approvers);
        assert_eq!(
            attestation.approval.required_approvers,
            payload.required_approvers
        );
        assert_eq!(
            attestation.approval.approved_at,
            payload.approved_at.clone().expect("approved_at")
        );
        assert_eq!(
            attestation.risk_level,
            wist_contracts::action_plan::RiskLevel::R2
        );
        assert_eq!(attestation.key_id, key.key_id());
        assert_eq!(attestation.issued_by, "role:approver");
        assert_eq!(
            attestation.algorithm,
            wist_contracts::action_plan::ATTESTATION_ALGORITHM_ED25519
        );
    }

    #[test]
    fn verify_rejects_a_malformed_signature_hex() {
        let key = fresh_key();
        let mut attestation =
            build_attestation(&payload("2031-01-01T00:00:00Z"), &key, "role:approver", 60)
                .expect("build");
        key.sign(&mut attestation);
        assert!(key.verify(&attestation));
        attestation.signature = "zz".to_string();
        assert!(!key.verify(&attestation), "非 hex 签名必须验不过");
        attestation.signature = "abc".to_string();
        assert!(!key.verify(&attestation), "奇数长度必须验不过");
    }

    #[test]
    fn signature_round_trips_and_verifies() {
        let key = fresh_key();
        let mut attestation = build_attestation(
            &payload("2031-01-01T00:00:00Z"),
            &key,
            "role:approver",
            3600,
        )
        .expect("build");
        key.sign(&mut attestation);
        assert!(key.verify(&attestation));
        // 改一个字节就验不过。
        attestation.issued_by.push('x');
        assert!(!key.verify(&attestation));
    }
}
