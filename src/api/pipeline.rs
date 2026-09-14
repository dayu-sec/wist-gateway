//! 数据采集吞吐视图：把 wparse 的三层计数器（来源 / 解析 / 输出）从
//! VictoriaMetrics 拉出来，归一化成前端可直接渲染的分层拓扑。
//!
//! 手工扩展说明：本模块与其路由**不在** jumo 静态模型的
//! `jumo/model/static/control/binding.mju` 声明里 —— 与 `api/host_metrics.rs` 同一模式
//! （模型里也没有 host-metrics 路由）。若之后重新生成控制面代码，需要手动回补这两条路由，
//! 或先把对应 entry 补进模型再生成。
//!
//! 口径（以下都是在本机实测得到的结论，不是推测）：
//! - `wparse_*` 是**累计计数器**，必须走 `increase()`；直接返回累计值只会得到一条单调上升的斜线。
//! - 观测栈写入 VM 的粒度实测为 **60 秒**（计数器每整分钟跳一次）。因此默认 `step` 也是 60：
//!   采样更密只会重复同一个值；用 `rate([1m])` 去算一个 60s 阶跃的计数器，还会得到
//!   0 与尖峰交替的假象 —— wist-monitor 面板上那些孤立尖峰正是这么来的。
//! - 速率窗口取 **2 个导出周期（120s）**，兼顾新鲜度与抗阶梯抖动。
//! - 输出层存在**多出口扇出**（同一分组写多个 sink，例如 metrics 组同时写 json 与 vm_metrics，
//!   两侧速率相同）。分组速率用 `sum by (sink_group)` 取得，即**组内各出口写入速率之和**：
//!   同一批记录写 N 个目标会重复计入 N 次（与 wist-monitor 面板口径一致）。
//!   因此「落存储速率」不恒等于入流速率，分组数 > 1 时天然偏高。

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;

use axum::{
    extract::{connect_info::ConnectInfo, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use super::{admin_auth::require_admin_bearer, rate_limit, ApiState};
use crate::infra::victoria_metrics::query_json;

/// 默认统计窗口 30 分钟；步长固定 60s（= VM 导出粒度）。
const DEFAULT_WINDOW_SECONDS: i64 = 1800;
const DEFAULT_STEP_SECONDS: i64 = 60;
const RATE_WINDOW_SECONDS: i64 = 120;
const MIN_WINDOW_SECONDS: i64 = 300;
const MAX_WINDOW_SECONDS: i64 = 24 * 3600;

/// 命中这些输出分组说明数据没进目标存储。
const LOSS_SINK_GROUPS: [&str; 3] = ["miss", "residue", "error"];

const SOURCE_METRIC: &str = "wparse_receive_data";
const PARSE_METRIC: &str = "wparse_parse_all";
const SINK_METRIC: &str = "wparse_send_to_sink";

/// 每组标签：`(即时值查询用的标签, 展示形态)`
const SOURCE_LABELS: [&str; 2] = ["source_type", "source_name"];
const PARSE_LABELS: [&str; 2] = ["package_name", "rule_name"];
const SINK_LABELS: [&str; 2] = ["sink_group", "sink_name"];

#[derive(Debug, Deserialize)]
pub struct PipelineQuery {
    window: Option<i64>,
    step: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PipelineTopology {
    pub generated_at: i64,
    /// 所有序列中最新采样点的时间（unix 秒）。
    /// 用于区分「真的没有流量」和「指标通道断了」——通道断掉时窗口内
    /// 一条数据都没有，页面会全空，不看这个字段无法判断是哪种情况。
    /// `null` = 窗口内没有任何数据点。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_sample_at: Option<i64>,
    pub window_seconds: i64,
    pub step_seconds: i64,
    pub summary: PipelineSummary,
    pub sources: Vec<PipelineNode>,
    pub parses: Vec<PipelineGroup>,
    pub sinks: Vec<PipelineGroup>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PipelineSummary {
    /// 入流速率（各来源合计，e/s）
    pub ingress_rate: f64,
    /// 解析层输入速率合计（e/s）
    pub parse_rate: f64,
    /// 落存储速率（各输出口写入速率合计，含扇出重复计入，e/s）
    pub egress_rate: f64,
    /// 未落存储速率（miss + residue + error，e/s）
    pub loss_rate: f64,
    /// 进程启动至今累计接收
    pub total_received: f64,
    /// 入流合计曲线（各来源求和，`(unix 毫秒, e/s)`），供「接入与输出」节的汇总图
    pub ingress_series: Vec<(i64, f64)>,
    /// 落存储合计曲线（非 loss 输出口求和）
    pub egress_series: Vec<(i64, f64)>,
    /// 解析合计曲线（各包合计求和），供「解析规则」节的汇总图
    pub parse_series: Vec<(i64, f64)>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PipelineNode {
    pub id: String,
    pub label: String,
    pub rate: f64,
    pub total: f64,
    /// `(unix 毫秒, e/s)`
    pub series: Vec<(i64, f64)>,
    /// `(unix 毫秒, 累计量)`，供「数量」视图切换
    pub total_series: Vec<(i64, f64)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PipelineGroup {
    pub id: String,
    pub label: String,
    /// 分组输入速率（`sum by (parent)` 精确值，非子项求和）
    pub rate: f64,
    pub total: f64,
    pub series: Vec<(i64, f64)>,
    /// `(unix 毫秒, 累计量)`，供「数量」视图切换
    pub total_series: Vec<(i64, f64)>,
    pub children: Vec<PipelineNode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

/// 一个标签组合的采样结果。
struct LevelEntry {
    labels: Vec<String>,
    rate: f64,
    total: f64,
    series: Vec<(i64, f64)>,
    total_series: Vec<(i64, f64)>,
}

pub async fn get_pipeline_topology(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<PipelineQuery>,
    client: Option<ConnectInfo<SocketAddr>>,
) -> Response {
    let client_key = rate_limit::client_key(client);
    if let Err(response) = require_admin_bearer(&state, &headers, &client_key) {
        return response;
    }

    let window = query
        .window
        .unwrap_or(DEFAULT_WINDOW_SECONDS)
        .clamp(MIN_WINDOW_SECONDS, MAX_WINDOW_SECONDS);
    // 步长不允许小于导出粒度，否则图上只会是重复值。
    let step = query
        .step
        .unwrap_or(DEFAULT_STEP_SECONDS)
        .clamp(DEFAULT_STEP_SECONDS, 3600);

    match build_topology(&state.config.victoria_metrics_url, window, step).await {
        Ok(topology) => Json(topology).into_response(),
        Err(err) => (
            StatusCode::BAD_GATEWAY,
            format!("failed to query pipeline metrics: {err}"),
        )
            .into_response(),
    }
}

async fn build_topology(
    vm_url: &str,
    window: i64,
    step: i64,
) -> Result<PipelineTopology, String> {
    // 来源层：每个 `source_type:source_name` 一行
    let source_level = query_level(vm_url, SOURCE_METRIC, &SOURCE_LABELS, window, step).await?;
    let mut sources: Vec<PipelineNode> = source_level
        .into_iter()
        .map(|entry| PipelineNode {
            id: entry.labels.join(":"),
            label: entry.labels.join(":"),
            rate: entry.rate,
            total: entry.total,
            series: entry.series,
            total_series: entry.total_series,
            kind: None,
        })
        .collect();
    sources.sort_by(|left, right| right.rate.total_cmp(&left.rate));

    // 解析层 / 输出层：父标签聚合 + 子标签明细，两级都查（父级必须单独查，见模块注释）
    let parses = build_groups(vm_url, PARSE_METRIC, &PARSE_LABELS, window, step).await?;
    let sinks = build_groups(vm_url, SINK_METRIC, &SINK_LABELS, window, step).await?;

    let summary = summarize(&sources, &parses, &sinks);
    let latest_sample_at = latest_sample_seconds(&sources, &parses, &sinks);

    Ok(PipelineTopology {
        generated_at: chrono::Utc::now().timestamp(),
        latest_sample_at,
        window_seconds: window,
        step_seconds: step,
        summary,
        sources,
        parses,
        sinks,
    })
}

async fn build_groups(
    vm_url: &str,
    metric: &str,
    labels: &[&str; 2],
    window: i64,
    step: i64,
) -> Result<Vec<PipelineGroup>, String> {
    let child_level = query_level(vm_url, metric, labels, window, step).await?;
    // 父级只按第一个标签聚合
    let parent_only: [&str; 1] = [labels[0]];
    let parent_level = query_level(vm_url, metric, &parent_only, window, step).await?;

    let mut groups: Vec<PipelineGroup> = parent_level
        .into_iter()
        .map(|entry| PipelineGroup {
            kind: loss_kind(labels[0], &entry.labels[0]),
            id: entry.labels[0].clone(),
            label: display_group(&entry.labels[0]),
            rate: entry.rate,
            total: entry.total,
            series: entry.series,
            total_series: entry.total_series,
            children: Vec::new(),
        })
        .collect();

    for entry in child_level {
        let (parent, child) = (entry.labels[0].clone(), entry.labels[1].clone());
        let node = PipelineNode {
            id: format!("{parent}/{child}"),
            label: display_child(&child),
            rate: entry.rate,
            total: entry.total,
            series: entry.series,
            total_series: entry.total_series,
            kind: loss_kind(labels[0], &parent),
        };
        match groups.iter_mut().find(|group| group.id == parent) {
            Some(group) => group.children.push(node),
            None => groups.push(PipelineGroup {
                kind: loss_kind(labels[0], &parent),
                id: parent.clone(),
                label: display_group(&parent),
                rate: 0.0,
                total: 0.0,
                series: Vec::new(),
                total_series: Vec::new(),
                children: vec![node],
            }),
        }
    }

    for group in &mut groups {
        group
            .children
            .sort_by(|left, right| right.rate.total_cmp(&left.rate));
    }
    // 未落存储的分组排最前 —— 它们是唯一需要立刻处理的。
    groups.sort_by(|left, right| {
        let rank = |group: &PipelineGroup| i32::from(group.kind.as_deref() != Some("loss"));
        rank(left).cmp(&rank(right)).then(right.rate.total_cmp(&left.rate))
    });
    Ok(groups)
}

/// 查一层：`query_range` 拿速率与曲线，`query` 拿累计量。
/// `labels` 即该层的聚合维度；父级调用时传单元素切片即可。
async fn query_level(
    vm_url: &str,
    metric: &str,
    labels: &[&str],
    window: i64,
    step: i64,
) -> Result<Vec<LevelEntry>, String> {
    let by = labels.join(",");
    let rate_expr = format!(
        "sum by ({by}) (increase({metric}[{RATE_WINDOW_SECONDS}s])) / {RATE_WINDOW_SECONDS}"
    );
    let total_expr = format!("sum by ({by}) ({metric})");

    let mut rates = range_by_labels(vm_url, &rate_expr, labels, window, step).await?;
    // 累计曲线单独拉一份：计数器是单调上升的，供前端「数量」视图使用。
    let totals_series = range_by_labels(vm_url, &total_expr, labels, window, step).await?;
    let totals = instant_by_labels(vm_url, &total_expr, labels).await?;
    let mut totals_by_key: HashMap<String, Vec<(i64, f64)>> = totals_series
        .into_iter()
        .map(|(key, series)| (key.join("\u{1}"), series))
        .collect();

    let mut entries = Vec::new();
    for (key, series) in rates.drain(..) {
        let rate = series.last().map(|(_, value)| *value).unwrap_or(0.0);
        let joined = key.join("\u{1}");
        let total = totals.get(&joined).copied().unwrap_or(0.0);
        entries.push(LevelEntry {
            labels: key,
            rate,
            total,
            total_series: totals_by_key.remove(&joined).unwrap_or_default(),
            series,
        });
    }
    entries.sort_by(|left, right| right.rate.total_cmp(&left.rate));
    Ok(entries)
}

/// `query_range`：`(标签值拼接键, 曲线)`。标签按 `labels` 顺序取值。
async fn range_by_labels(
    vm_url: &str,
    expr: &str,
    labels: &[&str],
    window: i64,
    step: i64,
) -> Result<Vec<(Vec<String>, Vec<(i64, f64)>)>, String> {
    let now = chrono::Utc::now().timestamp();
    let start = (now - window).to_string();
    let end = now.to_string();
    let step_value = step.to_string();
    let payload = query_json(
        vm_url,
        "/api/v1/query_range",
        &[
            ("query", expr),
            ("start", start.as_str()),
            ("end", end.as_str()),
            ("step", step_value.as_str()),
        ],
    )
    .await?;

    Ok(collect_labeled(&payload, labels))
}

/// `query`（即时）：`标签值拼接键 → 累计值`。
async fn instant_by_labels(
    vm_url: &str,
    expr: &str,
    labels: &[&str],
) -> Result<HashMap<String, f64>, String> {
    let payload = query_json(vm_url, "/api/v1/query", &[("query", expr)]).await?;
    let mut map = HashMap::new();
    for item in payload["data"]["result"]
        .as_array()
        .cloned()
        .unwrap_or_default()
    {
        let key = label_key(&item["metric"], labels);
        let value = item["value"]
            .as_array()
            .and_then(|pair| pair.get(1))
            .and_then(|value| value.as_str())
            .and_then(|value| value.parse::<f64>().ok());
        if let Some(value) = value {
            map.insert(key, canon(value));
        }
    }
    Ok(map)
}

fn collect_labeled(
    payload: &serde_json::Value,
    labels: &[&str],
) -> Vec<(Vec<String>, Vec<(i64, f64)>)> {
    let mut result = Vec::new();
    for item in payload["data"]["result"]
        .as_array()
        .cloned()
        .unwrap_or_default()
    {
        let values = label_values(&item["metric"], labels);
        if values.len() != labels.len() {
            continue;
        }
        let points = values_to_points(&item);
        if points.is_empty() {
            continue;
        }
        result.push((values, points));
    }
    result
}

fn label_key(metric: &serde_json::Value, labels: &[&str]) -> String {
    label_values(metric, labels).join("\u{1}")
}

fn label_values(metric: &serde_json::Value, labels: &[&str]) -> Vec<String> {
    labels
        .iter()
        .map(|name| metric[*name].as_str().unwrap_or("").to_string())
        .collect()
}

fn values_to_points(item: &serde_json::Value) -> Vec<(i64, f64)> {
    item["values"]
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(|pair| {
                    let pair = pair.as_array()?;
                    let timestamp_ms = (pair.first()?.as_f64()? * 1000.0) as i64;
                    let raw = pair.get(1)?;
                    let value = raw
                        .as_str()
                        .and_then(|value| value.parse::<f64>().ok())
                        .or_else(|| raw.as_f64())?;
                    Some((timestamp_ms, canon(value)))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `sink_group` 的取值决定是否属于「未落存储」。
fn loss_kind(label_name: &str, value: &str) -> Option<String> {
    if label_name == "sink_group" && LOSS_SINK_GROUPS.contains(&value) {
        return Some("loss".to_string());
    }
    None
}

fn display_child(value: &str) -> String {
    if value == "[0]" {
        "默认出口".to_string()
    } else {
        value.to_string()
    }
}

fn display_group(value: &str) -> String {
    if value.is_empty() {
        "（未命名分组）".to_string()
    } else {
        value.to_string()
    }
}

/// 规范化浮点输出：`-0.0` 在 JSON 里会序列化成 `-0.0`，界面上看着像出错；
/// NaN / 无穷也不是有效指标，统一归零。
fn canon(value: f64) -> f64 {
    if !value.is_finite() || value == 0.0 {
        0.0
    } else {
        value
    }
}

/// 所有序列里最新的采样点（unix 秒）。系列为空时返回 `None`。
fn latest_sample_seconds(
    sources: &[PipelineNode],
    parses: &[PipelineGroup],
    sinks: &[PipelineGroup],
) -> Option<i64> {
    // 节点与分组都有 `series`，取各自最后一个点的时间戳。
    let mut latest: Option<i64> = None;
    let mut observe = |series: &[(i64, f64)]| {
        if let Some((timestamp_ms, _)) = series.last() {
            latest = Some(latest.map_or(*timestamp_ms, |current| current.max(*timestamp_ms)));
        }
    };

    for node in sources {
        observe(&node.series);
    }
    for group in parses.iter().chain(sinks.iter()) {
        observe(&group.series);
        for node in &group.children {
            observe(&node.series);
        }
    }

    latest.map(|timestamp_ms| timestamp_ms / 1000)
}

/// 把一层的多条序列按时间戳逐点求和，得到该层的合计曲线。
///
/// 同一层的序列来自同一次 `query_range`，时间戳天然对齐；这里仍以时间戳为键累加，
/// 不依赖下标对齐。这样做的好处是**不需要额外查询** —— 各分组之和本来就等于总量。
fn sum_series<'a, I>(series: I) -> Vec<(i64, f64)>
where
    I: IntoIterator<Item = &'a [(i64, f64)]>,
{
    let mut totals: BTreeMap<i64, f64> = BTreeMap::new();
    for points in series {
        for (timestamp_ms, value) in points {
            *totals.entry(*timestamp_ms).or_insert(0.0) += value;
        }
    }
    totals
        .into_iter()
        .map(|(timestamp_ms, value)| (timestamp_ms, canon(value)))
        .collect()
}

fn summarize(
    sources: &[PipelineNode],
    parses: &[PipelineGroup],
    sinks: &[PipelineGroup],
) -> PipelineSummary {
    let is_loss = |group: &PipelineGroup| group.kind.as_deref() == Some("loss");
    PipelineSummary {
        ingress_rate: canon(sources.iter().map(|node| node.rate).sum()),
        parse_rate: canon(parses.iter().map(|group| group.rate).sum()),
        egress_rate: canon(sinks.iter().filter(|g| !is_loss(g)).map(|g| g.rate).sum()),
        loss_rate: canon(sinks.iter().filter(|g| is_loss(g)).map(|g| g.rate).sum()),
        total_received: canon(sources.iter().map(|node| node.total).sum()),
        ingress_series: sum_series(sources.iter().map(|node| node.series.as_slice())),
        egress_series: sum_series(
            sinks
                .iter()
                .filter(|group| !is_loss(group))
                .map(|group| group.series.as_slice()),
        ),
        parse_series: sum_series(parses.iter().map(|group| group.series.as_slice())),
    }
}
