//! `app` / `role` 的**推断**：按注册表把事实里的高置信度证据映射成选择类 label。
//!
//! ## 为什么需要注册表，而不是「认出来就写」
//!
//! 选择类 label 会**把指标序列分段**：写了 `app=kafka` 再改成 `app=apache-kafka`，同一台机器
//! 的历史就断成两段、按 app 查还查不回来。所以取值必须落在一个**闭集**里 ——
//! 那就是注册表：`app` 的每个取值、每个 `app` 允许的 `role`、允许携带的选择键，都登记在册。
//!
//! 注册表是**策展数据**（知识库仓 `wist-knowledge/metrics-app-registry.toml`），代码里不内嵌
//! 默认副本：内嵌就是两份真相，改一处必然漂移（与 `purpose` / `discovery_policy` 同一条理由）。
//! 未配置 = **不推断**（`app` 留空），这是合法状态：规范允许 `{app=""}`。
//!
//! ## 证据从哪来
//!
//! 只接受**高置信度证据**（规范 §3.4 规则 3）：服务管理器单元名、容器名。
//! 可执行名 / cmdline / 监听端口**不得**作为取值 —— 那些只能作发现证据：`java` 可能是 kafka、
//! 也可能是 zookeeper，猜错的代价是「用途静默标错，还查不出来」。
//!
//! ## 判不出就不写
//!
//! * 零个 app 命中 → 留空；
//! * 两个及以上 app 命中（同机混跑两个系统）→ 留空并记一条事件，等人补登记 /
//!   改用进程口径（规范 §3.4 规则 5：一机多用途主机口径不可用）。

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use orion_error::conversion::ToStructError;
use orion_error::prelude::*;
use serde::Deserialize;
use wist_api::metrics_labels::rules::{self, LabelError};
use wist_error::{ConfigReason, ConfigResult};

/// 注册表里 `app` 的条数上限。
///
/// 推断每次拉取都要扫一遍（一台 agent 每 5 分钟一次），条数不受控会让这条路径慢慢变贵。
const MAX_APPS: usize = 512;
/// 单条 `app` 的证据条数上限。
const MAX_EVIDENCE_PER_APP: usize = 64;

/// 一份注册表。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppRegistry {
    entries: Vec<AppEntry>,
}

/// 一个已登记的 `app`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppEntry {
    /// 已归一（小写）的 `app` 取值，同时也是 label 的值。
    pub app: String,
    /// 命中的服务管理器单元（已归一：无类型后缀、无 `@实例`）。
    pub units: BTreeSet<String>,
    /// 命中的容器名（小写）。
    pub containers: BTreeSet<String>,
    /// 该 `app` 允许的静态角色词（⊆ 规范 §3.4 的 `role` 词表）。
    pub roles: BTreeSet<String>,
}

/// 推断结果。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InferredLabels {
    /// 命中注册表的 `app`；判不出时 `None`。
    pub app: Option<String>,
    /// 从证据里的角色词推出的 `role`；判不出 / 有歧义时 `None`。
    pub role: Option<String>,
    /// 给人看的一句依据（日志 / 排障）：`app=kafka unit:kafka`。
    pub detail: String,
}

impl InferredLabels {
    pub fn as_map(&self) -> BTreeMap<String, String> {
        let mut labels = BTreeMap::new();
        if let Some(app) = &self.app {
            labels.insert("app".to_string(), app.clone());
        }
        if let Some(role) = &self.role {
            labels.insert("role".to_string(), role.clone());
        }
        labels
    }
}

impl AppRegistry {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 按事实里的证据推断 `app` / `role`。
    ///
    /// 证据是 agent 归一过的那两份清单；这里**再归一一次**（纵深防御：网关不能被一份
    /// 没归一的报文带偏，例如 `Kafka.Service` 与 `kafka` 必须是同一个东西）。
    pub fn infer(&self, service_units: &[String], container_names: &[String]) -> InferredLabels {
        if self.entries.is_empty() {
            return InferredLabels::default();
        }
        let units: BTreeSet<String> = service_units
            .iter()
            .filter_map(|value| normalize_unit(value))
            .collect();
        let containers: BTreeSet<String> = container_names
            .iter()
            .filter_map(|value| normalize_container(value))
            .collect();

        // 命中集合：同一台机器可能同时命中多个 app（混跑），那时不猜。
        // 每个命中的元素是一组证据（同一 app 可能有多条），`role` 要跨整组看。
        let mut hits: Vec<(&AppEntry, &'static str, Vec<String>)> = Vec::new();
        for entry in &self.entries {
            // 命中判定：**模板名相同**即可（注册表登 `kafka`，事实里可能是 `kafka@broker-1`）。
            // 报出去的是事实里的全名 —— `role` 要从实例名里取词；一台机器可能有多条同 app
            // 的证据（`kafka@broker-1` 与 `kafka@controller-1`），所以这里整组传下去。
            let matched_units: Vec<String> = units
                .iter()
                .filter(|unit| {
                    entry
                        .units
                        .iter()
                        .any(|registered| unit_template(registered) == unit_template(unit))
                })
                .cloned()
                .collect();
            if !matched_units.is_empty() {
                hits.push((entry, "unit", matched_units));
                continue;
            }
            let matched_containers: Vec<String> = containers
                .iter()
                .filter(|container| entry.containers.contains(*container))
                .cloned()
                .collect();
            if !matched_containers.is_empty() {
                hits.push((entry, "container", matched_containers));
            }
        }

        match hits.as_slice() {
            [] => InferredLabels::default(),
            [(entry, kind, values)] => InferredLabels {
                app: Some(entry.app.clone()),
                role: infer_role(entry, values),
                detail: format!("app={} {kind}:{}", entry.app, values.join(",")),
            },
            many => {
                // 多命中不是错误，是**这台机器的形态**（或注册表还欠一次登记）。
                // 静默留空会在查询侧表现为 `{app=""}`，可见且可补；猜一个则会静默标错。
                let apps: Vec<&str> = many
                    .iter()
                    .map(|(entry, _, _)| entry.app.as_str())
                    .collect();
                log::info!(
                    "event=MetricsLabelInferenceAmbiguous apps={} detail=\"多个 app 命中证据，按规范留空\"",
                    apps.join(",")
                );
                InferredLabels::default()
            }
        }
    }
}

/// 从命中的**整组证据**里认出**静态角色词**。
///
/// 只看该 `app` 自己登记的 `roles`（规范：扩展必须先登记）：`kafka-broker-1` 里的 `broker`
/// 命中 → `role=broker`；`orders-api` 里的 `api` 没登记 → 不写。
///
/// **跨整组看**：一台机器可能同时跑 `kafka@broker-1` 与 `kafka@controller-1`。
/// 只取字典序靠前的那条会随机挑一个角色写出去，而规范要求多角色节点只写**主**角色、
/// 其余用 one-hot 指标（§13 补充约定 2）—— 判不出谁是主的时候宁可不写。
fn infer_role(entry: &AppEntry, values: &[String]) -> Option<String> {
    let mut found: BTreeSet<String> = BTreeSet::new();
    for value in values {
        for token in value.split(['-', '_', '.', '@']) {
            if entry.roles.contains(token) {
                found.insert(token.to_string());
            }
        }
    }
    match found.len() {
        1 => found.into_iter().next(),
        _ => None,
    }
}

/// 归一服务管理器单元：小写、去类型后缀。**保留 `@实例`**（其中的角色词是 `role` 的输入）。
fn normalize_unit(value: &str) -> Option<String> {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty() {
        return None;
    }
    let base = value
        .trim_end_matches(".service")
        .trim_end_matches(".socket")
        .trim_end_matches(".timer");
    (!base.is_empty()).then(|| base.to_string())
}

/// 模板名：`kafka@broker-1` → `kafka`。
///
/// 比对用模板名，`role` 用全名：注册表只登一次 `kafka`，而实例名里的 `broker`
/// 仍然是这台机器独有的信息。
fn unit_template(value: &str) -> &str {
    value.split('@').next().unwrap_or(value)
}

fn normalize_container(value: &str) -> Option<String> {
    let value = value.trim().to_ascii_lowercase();
    (!value.is_empty()).then_some(value)
}

// ── 装载与缓存 ──────────────────────────────────────────────────────────────

/// 注册表的**文件来源**：按 mtime + 长度缓存，改了文件下一次推断就用新表。
///
/// 为什么不只在启动时读一次：补登记新 app 是**数据变更**（不是代码变更），
/// 让它等一次网关重启，现场就会用「重启一下」来绕过流程。
/// 为什么不每次推断都读文件：一个部署每 5 分钟 × N 台 agent 都读一次，
/// 而这些内容几乎从不变 —— 缓存让稳态开销归零，又不必重启。
#[derive(Debug, Default)]
pub struct RegistrySource {
    cache: RwLock<Option<CachedRegistry>>,
}

#[derive(Debug)]
struct CachedRegistry {
    file: PathBuf,
    stamp: Option<Stamp>,
    registry: Arc<AppRegistry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Stamp {
    modified: Option<SystemTime>,
    len: u64,
}

impl RegistrySource {
    /// 取当前生效的注册表。`None` / 读不到 → 空表（不推断），从不 panic。
    ///
    /// 读失败时**沿用上一份成功装载的表**：注册表被临时写坏（编辑器保存到一半）
    /// 不该让整批机器的 `app` 突然消失 —— 那会让指标序列凭空断一段。
    pub fn resolve(&self, file: Option<&Path>) -> Arc<AppRegistry> {
        let Some(file) = file else {
            return Arc::new(AppRegistry::default());
        };
        let stamp = stamp_of(file);
        {
            let guard = self.cache.read().unwrap_or_else(|err| err.into_inner());
            if let Some(cached) = guard.as_ref()
                && cached.file == file
                && cached.stamp == stamp
            {
                return Arc::clone(&cached.registry);
            }
        }
        let registry = match load(file) {
            Ok(registry) => Arc::new(registry),
            Err(err) => {
                log::warn!(
                    "event=MetricsRegistryUnusable file={} detail=\"{err}\"（沿用上一份）",
                    file.display()
                );
                let guard = self.cache.read().unwrap_or_else(|err| err.into_inner());
                return match guard.as_ref() {
                    Some(cached) if cached.file == file => Arc::clone(&cached.registry),
                    _ => Arc::new(AppRegistry::default()),
                };
            }
        };
        let mut guard = self.cache.write().unwrap_or_else(|err| err.into_inner());
        *guard = Some(CachedRegistry {
            file: file.to_path_buf(),
            stamp,
            registry: Arc::clone(&registry),
        });
        registry
    }
}

fn stamp_of(file: &Path) -> Option<Stamp> {
    let metadata = std::fs::metadata(file).ok()?;
    Some(Stamp {
        modified: metadata.modified().ok(),
        len: metadata.len(),
    })
}

// ── 装载与校验 ──────────────────────────────────────────────────────────────

/// 注册表的 TOML 形状。
///
/// `deny_unknown_fields`：策展侧写了一个本版网关不认识的键要**当场报错** ——
/// 静默忽略的后果是「表看着生效了，行为却没变」（与 `purpose_rules` / 内容目录同一口径）。
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRegistry {
    /// 表版本（必填，>= 1）。改动登记内容就该 +1，便于回答「这台机器按哪版表推断的」。
    schema_version: String,
    #[serde(default)]
    apps: Vec<RawApp>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawApp {
    app: String,
    /// 服务管理器单元（可带类型后缀与 `@实例`，装载时归一）。
    #[serde(default)]
    units: Vec<String>,
    /// 容器名。
    #[serde(default)]
    containers: Vec<String>,
    /// 该 app 允许的静态角色（⊆ 规范词表）。
    #[serde(default)]
    roles: Vec<String>,
}

/// 装载并校验一份注册表。
pub fn load(path: &Path) -> ConfigResult<AppRegistry> {
    let text = std::fs::read_to_string(path).source_err(
        ConfigReason::Io,
        format!("read app registry {}", path.display()),
    )?;
    parse(&text).map_err(|err| {
        ConfigReason::Validation
            .to_err()
            .with_detail(format!("app registry {}: {err}", path.display()))
    })
}

fn parse(text: &str) -> Result<AppRegistry, String> {
    let raw: RawRegistry = toml::from_str(text).map_err(|err| err.to_string())?;
    if raw.schema_version.trim().is_empty() {
        return Err("schema_version 不能为空".to_string());
    }
    if raw.apps.len() > MAX_APPS {
        return Err(format!("条数 {} 超过上限 {MAX_APPS}", raw.apps.len()));
    }
    let mut entries: Vec<AppEntry> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for raw_app in raw.apps {
        let app = raw_app.app.trim().to_ascii_lowercase();
        // `app` 的值本身就是 label 值：同一套文法，否则写出去的序列查不回来。
        validate_value("app", &app)?;
        if !seen.insert(app.clone()) {
            return Err(format!("app {app:?} 重复登记"));
        }
        if raw_app.units.is_empty() && raw_app.containers.is_empty() {
            // 没有证据的条目永远不会命中 —— 那不是登记，是拼写错误的表现。
            return Err(format!("app {app:?} 既没有 units 也没有 containers"));
        }
        let mut units = BTreeSet::new();
        for unit in &raw_app.units {
            let normalized = normalize_unit(unit)
                .ok_or_else(|| format!("app {app:?} 的 unit {unit:?} 归一后为空"))?;
            units.insert(normalized);
        }
        if units.len() > MAX_EVIDENCE_PER_APP {
            return Err(format!(
                "app {app:?} 的 units 超过上限 {MAX_EVIDENCE_PER_APP}"
            ));
        }
        let mut containers = BTreeSet::new();
        for container in &raw_app.containers {
            let normalized = normalize_container(container)
                .ok_or_else(|| format!("app {app:?} 的 container {container:?} 为空"))?;
            containers.insert(normalized);
        }
        if containers.len() > MAX_EVIDENCE_PER_APP {
            return Err(format!(
                "app {app:?} 的 containers 超过上限 {MAX_EVIDENCE_PER_APP}"
            ));
        }
        let mut roles = BTreeSet::new();
        for role in &raw_app.roles {
            let role = role.trim().to_ascii_lowercase();
            if !rules::ROLES.contains(&role.as_str()) {
                return Err(format!("app {app:?} 的 role {role:?} 不在词表内"));
            }
            roles.insert(role);
        }
        entries.push(AppEntry {
            app,
            units,
            containers,
            roles,
        });
    }
    Ok(AppRegistry { entries })
}

fn validate_value(key: &str, value: &str) -> Result<(), String> {
    if !rules::is_valid_value(value) {
        return Err(format!(
            "{key} 的值 {value:?} 不合法（{}）",
            LabelError::BadValue {
                key: key.to_string(),
                value: value.to_string()
            }
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
schema_version = "v1"

[[apps]]
app = "kafka"
units = ["kafka.service", "kafka@broker-1.service"]
containers = ["kafka"]
roles = ["broker", "controller"]

[[apps]]
app = "redis"
containers = ["redis", "redis-sentinel"]
roles = ["sentinel"]

[[apps]]
app = "postgres"
units = ["postgresql.service"]
roles = ["primary", "replica"]
"#;

    fn registry() -> AppRegistry {
        parse(SAMPLE).expect("registry parses")
    }

    #[test]
    fn a_registry_normalises_units_and_matches_them() {
        let registry = registry();
        assert_eq!(registry.len(), 3);
        let inferred = registry.infer(&["kafka".to_string()], &[]);
        assert_eq!(inferred.app.as_deref(), Some("kafka"));
        assert_eq!(inferred.detail, "app=kafka unit:kafka");
        // 模板实例按模板名命中，但报出去的是**实例名**（role 要从里面取词）。
        let instance = registry.infer(&["kafka@broker-1".to_string()], &[]);
        assert_eq!(instance.app.as_deref(), Some("kafka"));
        assert_eq!(instance.role.as_deref(), Some("broker"));
        assert!(instance.detail.contains("kafka@broker-1"));
        // 带类型后缀上报也能命中（纵深防御：两侧归一实现一致，但不指望对端守规矩）。
        assert_eq!(
            registry
                .infer(&["Kafka.Service".to_string()], &[])
                .app
                .as_deref(),
            Some("kafka")
        );
    }

    #[test]
    fn multiple_instances_of_one_app_do_not_pick_an_arbitrary_role() {
        // 同机跑 broker 与 controller 两个实例：规范要求只写主角色、其余用 one-hot 指标；
        // 我们判不出谁是主 → 不写（而不是「字典序靠前那个」）。
        let registry = parse(
            r#"
schema_version = "v1"

[[apps]]
app = "kafka"
units = ["kafka"]
roles = ["broker", "controller"]
"#,
        )
        .expect("parses");

        let both = registry.infer(
            &[
                "kafka@broker-1".to_string(),
                "kafka@controller-1".to_string(),
            ],
            &[],
        );
        assert_eq!(both.app.as_deref(), Some("kafka"), "app 仍然判得出");
        assert!(both.role.is_none(), "两个不同角色词 → 有歧义，不写");

        // 两个实例都是同一个角色 → 可以写（没有歧义）。
        let same = registry.infer(
            &["kafka@broker-1".to_string(), "kafka@broker-2".to_string()],
            &[],
        );
        assert_eq!(same.role.as_deref(), Some("broker"));
    }

    #[test]
    fn a_container_name_is_enough_evidence() {
        let inferred = registry().infer(&[], &["redis".to_string()]);
        assert_eq!(inferred.app.as_deref(), Some("redis"));
    }

    #[test]
    fn no_evidence_means_no_labels() {
        let inferred = registry().infer(&[], &[]);
        assert_eq!(inferred, InferredLabels::default());
        assert!(inferred.as_map().is_empty());
        // 未配置注册表（空表）同样留空，而不是猜。
        assert!(
            AppRegistry::default()
                .infer(&["kafka".to_string()], &[])
                .app
                .is_none()
        );
    }

    #[test]
    fn two_matching_apps_are_ambiguous_and_leave_the_label_empty() {
        // 一机混跑两个系统：主机口径的选择不可用（规范 §3.4 规则 5），留空可被 {app=""} 发现。
        let inferred = registry().infer(&["kafka".to_string(), "postgresql".to_string()], &[]);
        assert!(inferred.app.is_none());
        assert!(inferred.role.is_none());
    }

    #[test]
    fn a_registered_role_token_in_the_evidence_fills_the_role() {
        let registry = parse(
            r#"
schema_version = "v1"

[[apps]]
app = "kafka"
units = ["kafka-broker-1", "kafka-controller-1"]
roles = ["broker", "controller"]
"#,
        )
        .expect("parses");

        assert_eq!(
            registry
                .infer(&["kafka-broker-1".to_string()], &[])
                .role
                .as_deref(),
            Some("broker")
        );
        assert_eq!(
            registry
                .infer(&["kafka-controller-1".to_string()], &[])
                .role
                .as_deref(),
            Some("controller")
        );
        // 同一个名字里出现两个角色词 → 有歧义，不写。
        assert!(
            registry
                .infer(&["kafka-broker-controller".to_string()], &[])
                .role
                .is_none()
        );
        // 不在该 app 登记表里的角色词不写（`api` 没登记过）。
        assert_eq!(registry.infer(&["kafka".to_string()], &[]).role, None);
    }

    /// 真实策展数据（`wist-knowledge/metrics-app-registry.toml`）必须能装载，
    /// 且对最常见的两套系统给出预期判定。缺数据**就失败**，不静默跳过（同 `purpose` 的做法）。
    #[test]
    fn the_curated_registry_parses_and_matches_the_common_systems() {
        let path = crate::test_support::knowledge_file("metrics-app-registry.toml");
        let registry = load(&path).expect("curated registry loads");
        assert!(!registry.is_empty());

        // Kafka：模板实例按模板名命中，实例名里的 `broker` 定 role。
        let kafka = registry.infer(&["kafka@broker-1".to_string()], &[]);
        assert_eq!(kafka.app.as_deref(), Some("kafka"));
        assert_eq!(kafka.role.as_deref(), Some("broker"));

        // Redis：集群主从随时切换 → 不写 role（规范 §3.4 规则 4）。
        let redis = registry.infer(&["redis".to_string()], &[]);
        assert_eq!(redis.app.as_deref(), Some("redis"));
        assert!(redis.role.is_none());

        // 未登记的自研服务：留空，不猜。
        assert!(
            registry
                .infer(&["my-custom-app".to_string()], &[])
                .app
                .is_none()
        );
    }

    #[test]
    fn a_registry_missing_evidence_cannot_silently_never_match() {
        let err = parse(
            r#"
schema_version = "v1"

[[apps]]
app = "kafka"
roles = ["broker"]
"#,
        )
        .expect_err("must be rejected");
        assert!(err.contains("既没有 units 也没有 containers"), "{err}");
    }

    #[test]
    fn registry_values_and_roles_are_validated() {
        for (body, needle) in [
            (
                "schema_version = \"v1\"\n[[apps]]\napp = \"Kafka Service\"\nunits = [\"kafka\"]\n",
                "不合法",
            ),
            (
                "schema_version = \"v1\"\n[[apps]]\napp = \"a\"\nunits = [\"a\"]\n[[apps]]\napp = \"a\"\nunits = [\"b\"]\n",
                "重复登记",
            ),
            (
                "schema_version = \"v1\"\n[[apps]]\napp = \"a\"\nunits = [\"a\"]\nroles = [\"leader\"]\n",
                "不在词表内",
            ),
            ("[[apps]]\napp = \"a\"\nunits = [\"a\"]\n", "schema_version"),
            (
                "schema_version = \"v1\"\n[[apps]]\napp = \"a\"\nunits = [\"a\"]\nextra = 1\n",
                "unknown field",
            ),
        ] {
            let err = parse(body).expect_err("must be rejected");
            assert!(err.contains(needle), "{body}: {err}");
        }
    }
}
