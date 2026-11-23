//! 计划渲染：把**将要被签的字节**翻译成人话。
//!
//! 两个刻意设计：
//!
//! 1. **从计划本身渲染**，不从网关给的文案渲染 —— 页面/网关能不能骗人不重要，
//!    审批人看的就是他即将签的那份内容；
//! 2. **遇到不认识的 op / 未知参数就拒绝**。宁可让人升级 CLI，也不要"大致显示一下"
//!    就让人签 —— 那等于把危险参数的可见性交给了"这一版刚好覆盖了"的运气。

use std::collections::BTreeSet;

use wist_contracts::action_plan::{ActionPlan, RiskLevel};

/// 已知 op 及其参数白名单。
///
/// 加新 op 必须两处一起改：这里 + agentd 的 opcode 注册表。前端/CLI 都靠它决定
/// 「这个动作能不能给人看懂」，看不懂就不该让人签。
const KNOWN_OPS: &[(&str, &[&str])] = &[
    (
        "disk.cleanup.preview",
        &["target", "min_age_hours", "max_files", "max_bytes"],
    ),
    (
        "disk.cleanup.apply",
        &["target", "min_age_hours", "max_files", "max_bytes"],
    ),
];

#[derive(Debug, Clone)]
pub struct PlanSummary {
    pub op: String,
    pub risk: String,
    pub target: String,
    pub args: Vec<(String, String)>,
    pub expires_at: String,
    pub digest: String,
}

impl PlanSummary {
    pub fn render(&self, approval_id: &str, key_id: &str, fingerprint: &str) -> String {
        let mut out = String::new();
        out.push_str(&format!("审批单   {approval_id}\n"));
        out.push_str(&format!("风险     {}\n", self.risk));
        out.push_str(&format!("动作     {}\n", self.op));
        let args = self
            .args
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join("  ");
        if !args.is_empty() {
            out.push_str(&format!("参数     {args}\n"));
        }
        out.push_str(&format!("目标机   {}\n", self.target));
        out.push_str(&format!("有效期   {}\n", self.expires_at));
        out.push_str(&format!("计划摘要 {}\n", self.digest));
        out.push_str(&format!("签名     {key_id}（指纹 {fingerprint}）\n"));
        out
    }
}

/// 解析并渲染一份计划。`allow_unknown` 只放宽「未知参数」，**不放宽未知 op**：
/// 一个连动作是什么都说不清的计划，不该被批。
pub fn render_summary(
    plan: &ActionPlan,
    plan_digest: &str,
    allow_unknown: bool,
) -> Result<PlanSummary, String> {
    let op = plan
        .program
        .steps
        .iter()
        .filter(|step| step.kind == wist_contracts::action_plan::STEP_KIND_INVOKE)
        .filter_map(|step| step.op.as_deref())
        .collect::<Vec<_>>();
    if op.len() != 1 {
        return Err(format!(
            "plan must contain exactly one invoke step to be reviewable, found {}",
            op.len()
        ));
    }
    let op = op[0];
    let Some((_, allowed)) = KNOWN_OPS.iter().find(|(known, _)| *known == op) else {
        return Err(format!(
            "this version of wist-approve does not understand op `{op}`; upgrade the CLI before signing"
        ));
    };
    let step = plan
        .program
        .steps
        .iter()
        .find(|step| step.op.as_deref() == Some(op))
        .expect("invoke step exists");
    let args = step.args.clone().unwrap_or(serde_json::Value::Null);
    let mut rendered: Vec<(String, String)> = Vec::new();
    match &args {
        serde_json::Value::Null => {}
        serde_json::Value::Object(map) => {
            let allowed: BTreeSet<&str> = allowed.iter().copied().collect();
            for (key, value) in map {
                if !allowed.contains(key.as_str()) && !allow_unknown {
                    return Err(format!(
                        "unknown argument `{key}` for op `{op}`; refusing to show a partial summary (use --allow-unknown-fields to override)"
                    ));
                }
                let value = match key.as_str() {
                    "max_bytes" => value
                        .as_u64()
                        .map(|bytes| format!("{} ({bytes} B)", human_bytes(bytes)))
                        .unwrap_or_else(|| value.to_string()),
                    _ => value.to_string(),
                };
                rendered.push((key.clone(), value));
            }
            rendered.sort_by(|a, b| a.0.cmp(&b.0));
        }
        _ => return Err("step args is not an object".to_string()),
    }
    Ok(PlanSummary {
        op: op.to_string(),
        risk: format_risk(plan.constraints.risk_level),
        target: match plan.target.instance_id.as_deref() {
            Some(instance) => format!("{}（{instance}）", plan.target.agent_id),
            None => plan.target.agent_id.clone(),
        },
        args: rendered,
        expires_at: plan.meta.expires_at.clone(),
        digest: plan_digest.to_string(),
    })
}

fn format_risk(risk: RiskLevel) -> String {
    match risk {
        RiskLevel::R0 => "R0（只读）".to_string(),
        RiskLevel::R1 => "R1（只读）".to_string(),
        RiskLevel::R2 => "R2（写）".to_string(),
        RiskLevel::R3 => "R3（破坏性）".to_string(),
    }
}

fn human_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    let value = bytes as f64;
    if value < KIB {
        format!("{bytes} B")
    } else if value < KIB * KIB {
        format!("{:.1} KiB", value / KIB)
    } else if value < KIB * KIB * KIB {
        format!("{:.1} MiB", value / (KIB * KIB))
    } else {
        format!("{:.2} GiB", value / (KIB * KIB * KIB))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 用 JSON 构造计划：字段增删时不会因为结构体字面量而编译不过（测试只关心渲染）。
    fn plan_with(op: &str, args: serde_json::Value) -> ActionPlan {
        serde_json::from_value(serde_json::json!({
            "api_version": "v1",
            "kind": "action_plan",
            "meta": {
                "action_id": "act-1",
                "request_id": "req-1",
                "template_id": null,
                "tenant_id": "tenant-default",
                "environment_id": "env-default",
                "plan_version": 1,
                "compiled_at": "2026-01-01T00:00:00Z",
                "expires_at": "2031-01-01T00:00:00Z"
            },
            "target": {
                "agent_id": "agent-1",
                "instance_id": null,
                "node_id": "node-1",
                "host_name": null,
                "platform": "linux",
                "arch": "x86_64",
                "selectors": {}
            },
            "constraints": {
                "risk_level": "R2",
                "approval_ref": "apv-1",
                "approval_mode": "required",
                "requested_by": "tester",
                "reason": null,
                "max_total_duration_ms": 60000,
                "step_timeout_default_ms": 30000,
                "execution_profile": "agent_exec_v1",
                "required_capabilities": [op]
            },
            "program": {
                "entry": "s1",
                "steps": [
                    { "id": "s1", "kind": "invoke", "op": op, "args": args },
                    { "id": "s2", "kind": "output" }
                ]
            }
        }))
        .expect("plan")
    }

    #[test]
    fn renders_a_known_op_with_its_arguments() {
        let plan = plan_with(
            "disk.cleanup.apply",
            serde_json::json!({ "target": "tmp", "min_age_hours": 24, "max_bytes": 1048576 }),
        );
        let summary = render_summary(&plan, "plan-v1:sha256:deadbeef", false).expect("render");
        let text = summary.render("apv-1", "ed25519-1", "0123456789abcdef");
        assert!(text.contains("disk.cleanup.apply"), "{text}");
        assert!(text.contains("target=\"tmp\""), "{text}");
        assert!(text.contains("1.0 MiB"), "{text}");
        assert!(text.contains("apv-1"), "{text}");
        assert!(text.contains("0123456789abcdef"), "{text}");
    }

    #[test]
    fn refuses_an_unknown_op() {
        let plan = plan_with("disk.wipe", serde_json::json!({}));
        let err = render_summary(&plan, "plan-v1:sha256:deadbeef", false).expect_err("must refuse");
        assert!(err.contains("does not understand op"), "{err}");
    }

    #[test]
    fn refuses_a_plan_without_exactly_one_invoke_step() {
        // 零个 invoke：说不清要干什么。
        let mut plan = plan_with("disk.cleanup.apply", serde_json::json!({}));
        plan.program.steps[0].kind = "output".to_string();
        plan.program.steps[0].op = None;
        let err = render_summary(&plan, "plan-v1:sha256:deadbeef", false).expect_err("must refuse");
        assert!(err.contains("exactly one invoke step"), "{err}");

        // 两个 invoke：一个摘要说不清两种动作，拒绝。
        let mut plan = plan_with("disk.cleanup.apply", serde_json::json!({}));
        let mut extra = plan.program.steps[0].clone();
        extra.id = "s3".to_string();
        plan.program.steps.push(extra);
        let err = render_summary(&plan, "plan-v1:sha256:deadbeef", false).expect_err("must refuse");
        assert!(err.contains("exactly one invoke step"), "{err}");
    }

    #[test]
    fn refuses_non_object_step_args() {
        let mut plan = plan_with("disk.cleanup.apply", serde_json::json!([1, 2]));
        plan.program.steps[0].args = Some(serde_json::json!([1, 2]));
        let err = render_summary(&plan, "plan-v1:sha256:deadbeef", false).expect_err("must refuse");
        assert!(err.contains("not an object"), "{err}");
    }

    #[test]
    fn refuses_unknown_arguments_unless_overridden() {
        let plan = plan_with(
            "disk.cleanup.apply",
            serde_json::json!({ "target": "tmp", "delete_everything": true }),
        );
        let err = render_summary(&plan, "plan-v1:sha256:deadbeef", false).expect_err("must refuse");
        assert!(err.contains("unknown argument"), "{err}");
        assert!(render_summary(&plan, "plan-v1:sha256:deadbeef", true).is_ok());
    }
}
