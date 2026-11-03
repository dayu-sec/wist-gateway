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

use wist_api::metrics_labels::rules::{
    LabelError, is_valid_value, validate_labels, validate_shape,
};

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

/// 逐键合并三层来源（部署默认 ∪ 推断 ∪ 手工覆盖）。
///
/// 除了优先级，这里还要处理一条**组合规则**：推断出来的 `role` / `shard` / `tier`
/// 依附于**推断出来的** `app`（它们只在那个 app 的登记表里成立）。`app` 一旦被部署默认
/// 或手工覆盖压掉，那几个键就变成了「挂在别的 app 上的角色」——语义错的比没有更糟
/// （`{app="redis", role="broker"}` 会让人以为 redis 有 broker 角色）。
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
    prune_inferred_dependents(&mut effective);
    effective
}

/// 丢掉「依附于推断 app」但 app 已被别的层接管的那几个键。
fn prune_inferred_dependents(effective: &mut EffectiveLabels) {
    let app_is_inferred = effective
        .sources
        .get("app")
        .is_some_and(|source| source == label_source::INFERRED);
    if app_is_inferred {
        return;
    }
    for key in ["role", "shard", "tier"] {
        let inferred_key = effective
            .sources
            .get(key)
            .is_some_and(|source| source == label_source::INFERRED);
        if inferred_key {
            effective.labels.remove(key);
            effective.sources.remove(key);
        }
    }
}

/// 合并后**保证结果可下发**：永不把一份非法值集交给 agent。
///
/// 为什么需要这一步：agent 侧对选择类 label 是**整包拒收**的（一份坏响应会让它保留旧缓存，
/// 现场表现为「改了标签但指标没变」）。所以网关宁可在自己这边降级，也不能把非法组合发出去。
///
/// 降级顺序（每一级都记一条事件，便于追「为什么某个 label 没出现」）：
/// 1. 三层全量 → 合法就用它；
/// 2. 丢掉推断层（它是唯一「可缺」的一层：`env` / `cluster` 来自部署默认，手工覆盖是人写的）
///    → 合法就用它；
/// 3. 都不合法 → 下发空表（不带任何选择类 label），而不是发一份会被拒收的报文。
pub fn merge_validated(
    defaults: &BTreeMap<String, String>,
    inferred: &BTreeMap<String, String>,
    overrides: &BTreeMap<String, String>,
) -> EffectiveLabels {
    let full = merge(defaults, inferred, overrides);
    if validate_labels(&full.labels).is_ok() {
        return full;
    }
    // 超上限是最常见的形态：部署默认已经有 6 个键，推断又加了 app / role。
    log::warn!(
        "event=MetricsLabelsEffectiveInvalid scope=with_inferred labels=\"{}\" detail=\"{}（丢弃推断层）\"",
        full.describe(),
        validate_labels(&full.labels)
            .err()
            .map(|err| err.code().to_string())
            .unwrap_or_default()
    );
    let without_inferred = merge(defaults, &BTreeMap::new(), overrides);
    if validate_labels(&without_inferred.labels).is_ok() {
        return without_inferred;
    }
    log::error!(
        "event=MetricsLabelsEffectiveInvalid scope=without_inferred labels=\"{}\" detail=\"{}（整包留空）\"",
        without_inferred.describe(),
        validate_labels(&without_inferred.labels)
            .err()
            .map(|err| err.code().to_string())
            .unwrap_or_default()
    );
    EffectiveLabels::default()
}

/// 把一层「逐键改动」应用到已有覆盖上。
///
/// `Some(value)` = 设置 / 覆盖；`None` = 删除该键的**手工**覆盖（回落到推断或部署默认）。
/// 未出现在表里的键保持原状。
///
/// 这一层只判**单键合法性**（[`validate_shape`]）：一次 PUT 可能只删 `app`，而 `role`
/// 还留在覆盖里 —— 中间态不成立，但合并推断层后可能完全合法（推断能给出 `app`）。
/// 组合校验交给调用方在**合并后的生效值**上做。
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
    validate_shape(&merged)?;
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
    fn removing_app_leaves_a_mid_state_that_is_only_legal_after_merging() {
        // 逐键写入允许「role 还在、app 刚被删」这一中间态：它本身不成立，
        // 但合并推断层之后可能完全合法 —— 所以组合校验不能压在这一层。
        let current = map(&[("app", "kafka"), ("role", "broker")]);
        let merged = apply_overrides(&current, &BTreeMap::from([("app".to_string(), None)]))
            .expect("单键都合法");
        assert_eq!(merged, map(&[("role", "broker")]));

        // 没有任何一层能给出 `app` 时，组合校验在生效值上拒绝它。
        let effective = merge(&BTreeMap::new(), &BTreeMap::new(), &merged);
        assert!(validate_labels(&effective.labels).is_err());

        // 推断层能给出 `app` 时，同一组覆盖是合法的（这正是修复前被误判的那种情况）。
        let effective = merge(&BTreeMap::new(), &map(&[("app", "kafka")]), &merged);
        assert_eq!(validate_labels(&effective.labels), Ok(()));
        assert_eq!(
            effective.labels.get("role").map(String::as_str),
            Some("broker")
        );
    }

    #[test]
    fn an_inferred_role_never_hangs_off_an_overridden_app() {
        // 推断：app=kafka + role=broker；人把 app 改成 redis。
        // `role=broker` 只在 kafka 的登记表里成立 —— 留着它就是语义错误。
        let effective = merge(
            &BTreeMap::new(),
            &map(&[("app", "kafka"), ("role", "broker")]),
            &map(&[("app", "redis")]),
        );
        assert_eq!(
            effective.labels.get("app").map(String::as_str),
            Some("redis")
        );
        assert!(
            !effective.labels.contains_key("role"),
            "app 不再是推断值时，推断出的角色必须一起撤掉"
        );

        // 注意优先级：推断 > 部署默认。所以部署默认里的 `app` 会被推断覆盖
        // （这正是「一个部署一个默认 app」不该压住逐机器推断的原因）。
        let effective = merge(
            &map(&[("app", "static-app")]),
            &map(&[("app", "kafka"), ("role", "broker")]),
            &BTreeMap::new(),
        );
        assert_eq!(
            effective.labels.get("app").map(String::as_str),
            Some("kafka")
        );
        assert_eq!(
            effective.labels.get("role").map(String::as_str),
            Some("broker")
        );

        // `app` 本身来自推断时，角色照常保留。
        let effective = merge(
            &BTreeMap::new(),
            &map(&[("app", "kafka"), ("role", "broker")]),
            &BTreeMap::new(),
        );
        assert_eq!(
            effective.labels.get("role").map(String::as_str),
            Some("broker")
        );
    }

    #[test]
    fn merge_validated_drops_inference_instead_of_emitting_an_illegal_set() {
        // 每一层单独看都合法，合起来 7 个键 → 超上限。agent 会整包拒收，
        // 所以网关必须先降级：丢掉「可缺的那一层」（推断），保住人写的两层。
        //
        // 注：这一形态要等推断产出 `tier` 这类键才可能出现；这里用白盒构造，
        // 验的是**降级阶梯**本身不会把非法值集发出去。
        let defaults = map(&[
            ("env", "prod"),
            ("cluster", "kafka-prod"),
            ("region", "cn-north"),
            ("zone", "az1"),
        ]);
        let overrides = map(&[("app", "kafka"), ("role", "broker")]);
        let inferred = map(&[("app", "kafka"), ("role", "broker"), ("tier", "hot")]);

        let effective = merge_validated(&defaults, &inferred, &overrides);
        assert_eq!(
            effective.labels,
            map(&[
                ("env", "prod"),
                ("cluster", "kafka-prod"),
                ("region", "cn-north"),
                ("zone", "az1"),
                ("app", "kafka"),
                ("role", "broker"),
            ]),
            "超上限 → 丢弃推断层，保住默认与手工覆盖"
        );
        assert!(validate_labels(&effective.labels).is_ok());

        // 正常情况下推断照样生效（不是「一超限就永久不推断」）。
        let effective = merge_validated(&map(&[("env", "prod")]), &inferred, &BTreeMap::new());
        assert_eq!(
            effective.labels.get("app").map(String::as_str),
            Some("kafka")
        );
        assert_eq!(
            effective.labels.get("tier").map(String::as_str),
            Some("hot")
        );
    }

    #[test]
    fn merge_validated_sends_nothing_rather_than_an_illegal_default_layer() {
        // 部署默认本身超限（配置层已拦，这里模拟历史/外部构造的坏值）：
        // 宁可不带 label，也不发一份会被 agent 拒收的报文。
        let defaults = map(&[
            ("env", "prod"),
            ("cluster", "a"),
            ("region", "b"),
            ("zone", "c"),
            ("shard", "0"),
            ("tier", "hot"),
            ("app", "kafka"),
        ]);
        let effective = merge_validated(&defaults, &BTreeMap::new(), &BTreeMap::new());
        assert!(effective.labels.is_empty());
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
