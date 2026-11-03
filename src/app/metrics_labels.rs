//! 选择类 label 的**生效值**。
//!
//! ## 三层来源，逐键合并
//!
//! ```text
//! 生效值 = 部署默认（网关配置 [agent.metrics_labels]）
//!        ∪ 自动推断（按事实入库后判定；本阶段为空）
//!        ∪ 每 agent 手工覆盖（管理面写入，落 agent_metrics_labels 表）
//! ```
//!
//! 优先级 **手工 > 推断 > 部署默认**；三层都没有的键**不发** —— 不猜、不补默认值。
//!
//! ## 为什么合并放在网关
//!
//! 部署单元（`cluster`）与环境（`env`）只有控制面知道：让 agent 拿机器名或路径猜一个，
//! 不同部署单元会静默合流，而指标序列一旦合流就再也拆不开（只能靠时间轴分段）。
//! `app` 的推断同样需要注册表（白名单来源 + 闭集），那份表在控制面。
//!
//! ## 为什么本阶段没有推断
//!
//! `app` 的高置信度来源（systemd unit / 容器镜像 / k8s label）目前不在事实摘要里；
//! 只有可执行名 / 端口这些**不得用于取值**的证据。按规范 §3.4 规则 3，判不出就留空 ——
//! 因此本模块刻意不提供「猜一个」的路径。

use std::collections::BTreeMap;

use wist_api::metrics_labels::rules::{LabelError, is_valid_value, validate_labels};

/// 逐键来源词表（与 `wist_api::metrics_labels::label_source` 同值）。
pub use wist_api::metrics_labels::label_source;

/// 合并结果。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectiveLabels {
    /// 生效值（键有序，便于稳定比较与稳定响应）。
    pub labels: BTreeMap<String, String>,
    /// 每个键的来源（`default` / `inferred` / `manual`）。
    pub sources: BTreeMap<String, String>,
}

impl EffectiveLabels {
    /// 是否一个键都没有（= 这台机器不带任何选择类 label）。
    pub fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }

    /// 渲染成一行（日志 / 排障用）：`app=kafka(manual) env=prod(default)`。
    pub fn describe(&self) -> String {
        if self.labels.is_empty() {
            return String::new();
        }
        self.labels
            .iter()
            .map(|(key, value)| {
                let source = self.sources.get(key).map(String::as_str).unwrap_or("");
                format!("{key}={value}({source})")
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// 逐键合并部署默认与手工覆盖。
///
/// `inferred` 预留给下一阶段（`app` 推断），当前调用方传空表；留着这个参数是为了让
/// 「优先级」只有一处实现 —— 等推断上线时不必再改一遍所有调用点。
pub fn merge(
    defaults: &BTreeMap<String, String>,
    inferred: &BTreeMap<String, String>,
    overrides: &BTreeMap<String, String>,
) -> EffectiveLabels {
    let mut effective = EffectiveLabels::default();
    for (key, value) in defaults {
        effective.labels.insert(key.clone(), value.clone());
        effective
            .sources
            .insert(key.clone(), label_source::DEFAULT.to_string());
    }
    for (key, value) in inferred {
        effective.labels.insert(key.clone(), value.clone());
        effective
            .sources
            .insert(key.clone(), label_source::INFERRED.to_string());
    }
    for (key, value) in overrides {
        effective.labels.insert(key.clone(), value.clone());
        effective
            .sources
            .insert(key.clone(), label_source::MANUAL.to_string());
    }
    effective
}

/// 把一层「逐键改动」应用到已有覆盖上。
///
/// `Some(value)` = 设置 / 覆盖；`None` = 删除该键的**手工**覆盖（回落到推断或部署默认）。
/// 未出现在表里的键保持原状。应用后整表再判一次准入：删掉 `app` 会让 `role` 变成孤儿键，
/// 此时应当**整次拒绝**而不是留下一个越界的表。
pub fn apply_overrides(
    current: &BTreeMap<String, String>,
    changes: &BTreeMap<String, Option<String>>,
) -> Result<BTreeMap<String, String>, LabelError> {
    let mut merged = current.clone();
    for (key, value) in changes {
        match value {
            Some(value) => {
                merged.insert(key.clone(), value.clone());
            }
            None => {
                merged.remove(key);
            }
        }
    }
    validate_labels(&merged)?;
    Ok(merged)
}

/// 校验部署默认（配置装载时用）；返回第一个不合法的键值对说明。
pub fn validate_defaults(defaults: &BTreeMap<String, String>) -> Result<(), LabelError> {
    validate_labels(defaults)?;
    // 部署默认里出现的值也要能单独成立：`role` 之类的孤儿键检查已经在
    // `validate_labels` 里做过，这里只补一条「值文法」的旁证，便于错误信息更具体。
    for (key, value) in defaults {
        if !is_valid_value(value) {
            return Err(LabelError::BadValue {
                key: key.clone(),
                value: value.clone(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect()
    }

    #[test]
    fn manual_overrides_default_per_key_and_defaults_survive_for_the_rest() {
        let effective = merge(
            &map(&[("env", "prod"), ("cluster", "kafka-prod")]),
            &BTreeMap::new(),
            &map(&[("cluster", "kafka-canary")]),
        );
        assert_eq!(
            effective.labels,
            map(&[("env", "prod"), ("cluster", "kafka-canary")])
        );
        assert_eq!(
            effective.sources.get("cluster").map(String::as_str),
            Some(label_source::MANUAL)
        );
        assert_eq!(
            effective.sources.get("env").map(String::as_str),
            Some(label_source::DEFAULT)
        );
    }

    #[test]
    fn inference_sits_between_manual_and_default() {
        let effective = merge(
            &map(&[("env", "prod"), ("app", "default-app")]),
            &map(&[("app", "kafka")]),
            &map(&[("app", "kafka-manual")]),
        );
        assert_eq!(
            effective.labels.get("app").map(String::as_str),
            Some("kafka-manual")
        );
        assert_eq!(
            effective.sources.get("app").map(String::as_str),
            Some(label_source::MANUAL)
        );
    }

    #[test]
    fn nothing_configured_means_no_labels_at_all() {
        let effective = merge(&BTreeMap::new(), &BTreeMap::new(), &BTreeMap::new());
        assert!(effective.is_empty());
        assert_eq!(effective.describe(), "");
    }

    #[test]
    fn setting_a_key_adds_it_and_null_removes_only_the_override() {
        let current = map(&[("env", "prod")]);
        let merged = apply_overrides(
            &current,
            &BTreeMap::from([
                ("app".to_string(), Some("kafka".to_string())),
                ("env".to_string(), None),
            ]),
        )
        .expect("valid");
        assert_eq!(merged, map(&[("app", "kafka")]));
    }

    #[test]
    fn removing_app_while_role_remains_is_rejected_as_a_whole() {
        let current = map(&[("app", "kafka"), ("role", "broker")]);
        let err = apply_overrides(&current, &BTreeMap::from([("app".to_string(), None)]))
            .expect_err("role 没有 app 时不可校验");
        assert_eq!(err.code(), "metric_label_requires_app");
        // 整次拒绝：原来的表一个键都没动。
        assert_eq!(apply_overrides(&current, &BTreeMap::new()), Ok(current));
    }

    #[test]
    fn invalid_values_are_rejected_before_writing() {
        let err = apply_overrides(
            &BTreeMap::new(),
            &BTreeMap::from([("env".to_string(), Some("Prod".to_string()))]),
        )
        .expect_err("大写不在值文法里");
        assert_eq!(err.code(), "invalid_metric_label_value");
    }
}
