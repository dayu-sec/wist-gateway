//! 知识库内容包的管理面：录入 / 历史 / 激活（回滚）/ 生效视图 / 锁在旧版的工作。
//!
//! 设计见 `docs/design/knowledge-content-management.md` §7。
//!
//! 与「Agent 安装包」那套的**关键差别**：录入与生效是两件事 —— 安装包"录入即生效"，
//! 这里 `POST …/packages` 只落盘与登记，**切指针要另外调** `POST …/{id}/activate`。
//! 这样才有"先录入、验过、再切"和"回滚"（设计 I2）。
//!
//! NOTE(hand-added): 本模块的端点不在 jumo 静态模型 `binding.mju` 里（与 content / host_metrics
//! / pipeline 同一模式）。重新生成控制面代码时需回补本模块与 `api/mod.rs` 里的路由。

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::app::knowledge::{
    KnowledgeRecordError, KnowledgeSource, PACKAGE_FILES, load_recorded_package, record_package,
};
use crate::infra::{KnowledgeActivation, StoredKnowledgePackage, bytes_sha256_hex};

use super::{ApiState, admin_auth::require_admin_bearer, rate_limit};

/// 激活留痕一次最多返这么多：管理面展示"最近换过什么"，不做分页。
const ACTIVATION_LOG_LIMIT: u64 = 20;
/// 没写 `requested_by` 时的缺省主体（与安装包录入同一口径）。
const DEFAULT_ACTOR: &str = "platform-maintenance-engineer";

// ── 请求体 ──────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RecordKnowledgeRequest {
    /// `https://…` 链接，或**容器内**绝对路径（宿主路径容器里看不见）。
    pub source: String,
    /// 可选的期望摘要（发布侧 `*.sha256` 里那串），与来源字节核对。
    #[serde(default)]
    pub sha256: Option<String>,
    /// 录入成功后是否立即激活。缺省 `false`：**录入 ≠ 生效**。
    #[serde(default)]
    pub activate: bool,
    #[serde(default)]
    pub requested_by: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ActivateKnowledgeRequest {
    /// `activate` | `rollback`；缺省 `activate`。回滚就是"把指针指回上一版"。
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub requested_by: Option<String>,
}

// ── 响应体 ──────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct KnowledgeView {
    /// `none`（空载）| `config-files`（过渡期：仍从配置文件装载）| `package`（管理面登记的包）。
    source: &'static str,
    configured: bool,
    package_id: Option<String>,
    /// 世代号：每次激活 +1。派生结果"算自哪一版"的表级锚。
    generation: i64,
    /// 五份数据各自声明的版本（取得到就报）。
    catalog_version: Option<i64>,
    template_version: Option<i64>,
    policy_version: Option<i64>,
    purpose_version: Option<i64>,
    /// 生效包的登记信息（谁、什么时候切的）；空载或过渡态为 null。
    active: Option<ActiveView>,
    /// 空载时给运维看的三句话（设计 §8.7）——"为什么没推系统类型/没派活"要在这里答得上。
    hint: Option<&'static str>,
    /// 最近几次切换（激活/回滚）。
    activations: Vec<ActivationView>,
}

#[derive(Debug, Serialize)]
struct ActiveView {
    package_id: String,
    activated_by: String,
    activated_at: String,
}

#[derive(Debug, Serialize)]
struct ActivationView {
    from_package: Option<String>,
    to_package: String,
    generation: i64,
    reason: String,
    requested_by: String,
    created_at: String,
}

#[derive(Debug, Serialize)]
struct KnowledgePackageView {
    package_id: String,
    /// 原始录入来源（只留痕）。
    source: String,
    package_sha256: String,
    version: String,
    catalog_version: Option<i64>,
    template_version: Option<i64>,
    policy_version: Option<i64>,
    purpose_version: Option<i64>,
    parser_abi: i64,
    signed_by: String,
    cached_path: String,
    created_by: String,
    created_at: String,
    /// 是不是当前生效的那一版。
    active: bool,
    /// 副本还在不在（被手工删过、或备份还原不完整时为 false）。
    available: bool,
    /// 副本里实际有哪些文件（逐条 sha256）。副本不在时为空。
    files: Vec<KnowledgeFileView>,
}

#[derive(Debug, Serialize)]
struct KnowledgeFileView {
    name: String,
    sha256: String,
    bytes: u64,
}

#[derive(Debug, Serialize)]
struct KnowledgeLocksView {
    /// 当前生效包声明的目录版本（切新版后，旧版工作仍锁在旧号上）。
    active_catalog_version: Option<i64>,
    /// 按 `catalog_version` 分组的**在跑**常驻工作数。
    locks: Vec<KnowledgeLockView>,
}

#[derive(Debug, Serialize)]
struct KnowledgeLockView {
    catalog_version: i64,
    works: u64,
}

#[derive(Debug, Serialize)]
struct KnowledgeErrorBody {
    code: &'static str,
    message: String,
}

fn knowledge_error(status: StatusCode, code: &'static str, message: String) -> Response {
    (status, Json(KnowledgeErrorBody { code, message })).into_response()
}

fn record_error_response(err: KnowledgeRecordError) -> Response {
    // 状态码按"谁能修"分：来源/摘要错是**填错了**（400）；内容/签名不合法是**包不对**（422）；
    // 来源拿不到是**环境问题**（502）；落库失败是服务端（500）。
    let status = match &err {
        KnowledgeRecordError::SourceInvalid(_) | KnowledgeRecordError::DigestMismatch(_) => {
            StatusCode::BAD_REQUEST
        }
        KnowledgeRecordError::ManifestInconsistent(_)
        | KnowledgeRecordError::ContentInvalid(_)
        | KnowledgeRecordError::SignatureInvalid(_) => StatusCode::UNPROCESSABLE_ENTITY,
        KnowledgeRecordError::SourceUnavailable(_) => StatusCode::BAD_GATEWAY,
        KnowledgeRecordError::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    knowledge_error(status, err.code(), err.to_string())
}

fn package_view(
    package: &StoredKnowledgePackage,
    active_package_id: Option<&str>,
) -> KnowledgePackageView {
    let dir = std::path::Path::new(&package.cached_path);
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            files.push(KnowledgeFileView {
                name: entry.file_name().to_string_lossy().to_string(),
                sha256: bytes_sha256_hex(&bytes),
                bytes: bytes.len() as u64,
            });
        }
    }
    files.sort_by(|left, right| left.name.cmp(&right.name));
    let available = PACKAGE_FILES.iter().all(|name| dir.join(name).is_file());
    KnowledgePackageView {
        package_id: package.package_id.clone(),
        source: package.source.clone(),
        package_sha256: package.package_sha256.clone(),
        version: package.version.clone(),
        catalog_version: package.catalog_version,
        template_version: package.template_version,
        policy_version: package.policy_version,
        purpose_version: package.purpose_version,
        parser_abi: package.parser_abi,
        signed_by: package.signed_by.clone(),
        cached_path: package.cached_path.clone(),
        created_by: package.created_by.clone(),
        created_at: package.created_at.clone(),
        active: active_package_id == Some(package.package_id.as_str()),
        available,
        files,
    }
}

// ── 处理器 ──────────────────────────────────────────────────────────────────

/// 当前**生效**的知识库内容（设计 §7 / §8.7）。
///
/// 未配置时**不是 503**：回 `configured: false` 加一句"怎么办" —— 空载是要看得见的
/// 事实，而不是一个只能靠日志猜的哑谜。
pub async fn view_knowledge(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    // 以**内存里那一份**为准（它才是真正在用的），库里的行只补"谁什么时候切的"。
    let loaded = state.knowledge();
    let active_row = state.store.knowledge_active().await.ok().flatten();
    let activations = state
        .store
        .list_knowledge_activations(ACTIVATION_LOG_LIMIT)
        .await
        .unwrap_or_default();

    let source = loaded.source.label();
    let package_id = match &loaded.source {
        KnowledgeSource::Package { package_id } => Some(package_id.clone()),
        // 出厂初始包（`[knowledge] source_dir`）：来源是本地目录，没有 package_id。
        _ => None,
    };
    let content = loaded.content.as_deref();
    let template_version = content.and_then(|set| {
        let mut versions = set.templates().map(|template| template.template_version);
        let first = versions.next()?;
        versions.all(|version| version == first).then_some(first)
    });
    let view = KnowledgeView {
        source,
        configured: loaded.source != KnowledgeSource::None,
        package_id,
        generation: loaded.generation,
        catalog_version: content.map(|set| set.catalog_version),
        template_version,
        policy_version: loaded
            .discovery_policies
            .as_deref()
            .map(|set| set.policy_version),
        purpose_version: loaded
            .purpose_rules
            .as_deref()
            .map(|table| i64::from(table.purpose_version)),
        active: active_row.map(|row| ActiveView {
            package_id: row.package_id,
            activated_by: row.activated_by,
            activated_at: row.activated_at,
        }),
        hint: (loaded.source == KnowledgeSource::None).then_some(
            "知识库未配置：不产「系统类型」建议与用途建议；发现策略用 agentd 内建默认值。\
             录入一个包并激活即可 —— 包来自 wist-knowledge 的 Release 附件，\
             离线环境用 scripts/import-knowledge.sh 投放后再录。",
        ),
        activations: activations
            .into_iter()
            .map(|entry| ActivationView {
                from_package: entry.from_package,
                to_package: entry.to_package,
                generation: entry.generation,
                reason: entry.reason,
                requested_by: entry.requested_by,
                created_at: entry.created_at,
            })
            .collect(),
    };
    Json(view).into_response()
}

/// 录入一个知识库包（**不激活**，除非 body 里 `activate: true`）。
pub async fn record_knowledge_package(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    Json(input): Json<RecordKnowledgeRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let actor = input
        .requested_by
        .clone()
        .unwrap_or_else(|| DEFAULT_ACTOR.to_string());
    let recorded_at = chrono::Utc::now().to_rfc3339();
    let recorded = match record_package(
        &state.config,
        &state.store,
        &input.source,
        input.sha256.as_deref(),
        &actor,
        &recorded_at,
    )
    .await
    {
        Ok(recorded) => recorded,
        Err(err) => return record_error_response(err),
    };
    if input.activate
        && let Err(response) = activate_loaded(&state, recorded.loaded, "activate", &actor).await
    {
        return response;
    }
    let package = match state.store.knowledge_package(&recorded.package_id).await {
        Ok(Some(package)) => package,
        Ok(None) => {
            return knowledge_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "package_store_failed",
                "录入成功但读不回该包".to_string(),
            );
        }
        Err(err) => {
            return knowledge_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "package_store_failed",
                format!("读回该包失败：{err}"),
            );
        }
    };
    let active = state
        .store
        .knowledge_active()
        .await
        .ok()
        .flatten()
        .map(|row| row.package_id);
    Json(package_view(&package, active.as_deref())).into_response()
}

/// 录入过的包（最近优先）。
pub async fn list_knowledge_packages(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let active = state
        .store
        .knowledge_active()
        .await
        .ok()
        .flatten()
        .map(|row| row.package_id);
    match state.store.list_knowledge_packages().await {
        Ok(packages) => Json(
            packages
                .iter()
                .map(|package| package_view(package, active.as_deref()))
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(err) => knowledge_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "package_store_failed",
            format!("列出录入历史失败：{err}"),
        ),
    }
}

/// 单个包的明细（含副本里实际有哪些文件、是否还在）。
pub async fn view_knowledge_package(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    axum::extract::Path(package_id): axum::extract::Path<String>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let active = state
        .store
        .knowledge_active()
        .await
        .ok()
        .flatten()
        .map(|row| row.package_id);
    match state.store.knowledge_package(&package_id).await {
        Ok(Some(package)) => Json(package_view(&package, active.as_deref())).into_response(),
        Ok(None) => knowledge_error(
            StatusCode::NOT_FOUND,
            "package_not_found",
            format!("没有录入过这个包：{package_id}"),
        ),
        Err(err) => knowledge_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "package_store_failed",
            format!("读该包失败：{err}"),
        ),
    }
}

/// 切生效指针（激活 / 回滚到某一版）。
///
/// 顺序是**先验后切**：先把副本重新装载并校验，成功了才写指针、再换内存里那一份。
/// 任何一步失败都不动现状 —— 不能把网关推到"半可用"（设计 §8.6）。
pub async fn activate_knowledge_package(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
    axum::extract::Path(package_id): axum::extract::Path<String>,
    Json(input): Json<ActivateKnowledgeRequest>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let reason = input.reason.as_deref().unwrap_or("activate").to_string();
    if reason != "activate" && reason != "rollback" && reason != "repair" {
        return knowledge_error(
            StatusCode::BAD_REQUEST,
            "package_source_invalid",
            format!("reason 只能是 activate / rollback / repair（当前：{reason}）"),
        );
    }
    let actor = input
        .requested_by
        .clone()
        .unwrap_or_else(|| DEFAULT_ACTOR.to_string());
    // 副本不在（从未录入 / 被删）：明确回 not_found，而不是笼统的装载失败。
    match state.store.knowledge_package(&package_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return knowledge_error(
                StatusCode::NOT_FOUND,
                "package_not_found",
                format!("没有录入过这个包：{package_id}"),
            );
        }
        Err(err) => {
            return knowledge_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "package_store_failed",
                format!("读该包失败：{err}"),
            );
        }
    }
    let loaded = match load_recorded_package(&state.config, &package_id) {
        Ok(loaded) => loaded,
        Err(err) => return record_error_response(err),
    };
    if let Err(response) = activate_loaded(&state, loaded, &reason, &actor).await {
        return response;
    }
    let active = state
        .store
        .knowledge_active()
        .await
        .ok()
        .flatten()
        .map(|row| row.package_id);
    match state.store.knowledge_package(&package_id).await {
        Ok(Some(package)) => Json(package_view(&package, active.as_deref())).into_response(),
        Ok(None) => knowledge_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "package_store_failed",
            "切换成功但读不回该包".to_string(),
        ),
        Err(err) => knowledge_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "package_store_failed",
            format!("读回该包失败：{err}"),
        ),
    }
}

/// 写指针 + 换内存：**已装载成功**的那一份才会走到这里。
///
/// 返回 `Response` 当错误（而不是自定义错误类型）是为了让调用方直接转发给 axum；
/// `Response` 本身偏大，所以按仓里既有做法对这条 lint 明确豁免（同 `agent_ops` 的
/// `authenticate_agent`）。
#[allow(clippy::result_large_err)]
async fn activate_loaded(
    state: &ApiState,
    loaded: crate::app::knowledge::LoadedKnowledge,
    reason: &str,
    actor: &str,
) -> Result<(), Response> {
    let activated_at = chrono::Utc::now().to_rfc3339();
    let package_id = match &loaded.source {
        KnowledgeSource::Package { package_id } => package_id.clone(),
        // 只有登记过的包才允许切换（`load_recorded_package` 一定会填上它）。
        _ => {
            return Err(knowledge_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "package_store_failed",
                "内部错误：切的是未登记的包".to_string(),
            ));
        }
    };
    // ① 落库（世代 +1 + 审计，单事务）
    let active = match state
        .store
        .activate_knowledge(&KnowledgeActivation {
            package_id: &package_id,
            reason,
            requested_by: actor,
            created_at: &activated_at,
        })
        .await
    {
        Ok(active) => active,
        Err(err) => {
            return Err(knowledge_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "package_store_failed",
                format!("落库失败：{err}"),
            ));
        }
    };
    // ② 换内存里那一份（带上新的世代号）
    let mut loaded = loaded;
    loaded.generation = active.generation;
    state.replace_knowledge(std::sync::Arc::new(loaded));
    Ok(())
}

/// **谁还锁在旧版目录**（设计 §8.3）：换版不追改在跑的工作，所以要看得见。
pub async fn view_knowledge_locks(
    State(state): State<ApiState>,
    headers: HeaderMap,
    rate_limit::OptionalConnectInfo(client): rate_limit::OptionalConnectInfo,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }
    let active_catalog_version = state
        .knowledge()
        .content
        .as_deref()
        .map(|set| set.catalog_version);
    match state.store.standing_work_catalog_versions().await {
        Ok(entries) => Json(KnowledgeLocksView {
            active_catalog_version,
            locks: entries
                .into_iter()
                .map(|(catalog_version, works)| KnowledgeLockView {
                    catalog_version,
                    works,
                })
                .collect(),
        })
        .into_response(),
        Err(err) => knowledge_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "package_store_failed",
            format!("统计工作版本失败：{err}"),
        ),
    }
}
