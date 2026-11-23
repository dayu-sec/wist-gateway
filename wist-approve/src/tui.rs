//! 无子命令时进入的**字符界面**（TUI）：审批人在终端里用方向键 / 回车完成
//! 「看单 → 批准 → 签名 → 看结果」，不需要背一串子命令。
//!
//! 三条刻意的取舍：
//!
//! 1. **子命令全部保留**。TUI 是给人用的默认路径；脚本、CI、air-gap（`submit` 带文件进出）
//!    仍走子命令——那些场景没有终端，也**不该**有。
//! 2. **可测逻辑下沉成纯函数**（[`Filter`] / [`can_perform`] / [`clamp_selection`]）。
//!    仓库没有终端模拟测试，把状态判断留在 `on_key` 里就只能靠人读。
//! 3. **网络调用是同步的**：审批面是内网管理接口，一次请求的延迟远小于它能避免的复杂度
//!    （多线程 + 消息通道）。期间界面不刷新，状态行会在下一次绘制时说明发生了什么。
//!
//! 信任边界没有被这里改变：**签名仍然发生在本地**，私钥不出本机；TUI 只是把
//! `signing-payload → 本地重算摘要 → 人读确认 → 签名 → submit` 这条路按得顺手一点。

use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, List, ListItem, ListState, Paragraph, Wrap};

use wist_approve::ApprovalSummary;
use wist_approve::{ApproverKey, GatewayClient};

/// 空闲多久自动重拉一次列表（别人可能刚提交、刚批过）。
const REFRESH: Duration = Duration::from_secs(15);
/// 审批人身份标签（写进签名覆盖的 `issued_by`）。可用环境变量覆盖。
const DEFAULT_ISSUED_BY: &str = "role:approver";
/// 证明有效期（秒）；`build_attestation` 会再与计划到期时间取 min。
const ATTESTATION_TTL_SECONDS: i64 = 3600;

/// 列表过滤档。与网页的「待审批 / 已批准 / 全部」同一口径。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Filter {
    Pending,
    Approved,
    All,
}

impl Filter {
    fn next(self) -> Self {
        match self {
            Self::Pending => Self::Approved,
            Self::Approved => Self::All,
            Self::All => Self::Pending,
        }
    }

    fn prev(self) -> Self {
        match self {
            Self::Pending => Self::All,
            Self::Approved => Self::Pending,
            Self::All => Self::Approved,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Pending => "待审批",
            Self::Approved => "已批准",
            Self::All => "全部",
        }
    }

    /// 这一档收不收这个状态。`all` 收全部（含驳回 / 过期：审计要看得到）。
    pub fn matches(self, status: &str) -> bool {
        match self {
            Self::All => true,
            Self::Pending => status == "pending",
            Self::Approved => status == "approved",
        }
    }
}

/// 一个可以对审批单做的动作。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Act {
    Approve,
    Reject,
    Sign,
    ApproveAndSign,
}

impl Act {
    fn label(self) -> &'static str {
        match self {
            Self::Approve => "批准",
            Self::Reject => "驳回",
            Self::Sign => "签发",
            Self::ApproveAndSign => "批准并签发",
        }
    }
}

/// 动作在当前状态下是否允许 —— **与网关状态机同一口径**。
///
/// 与网页侧 `allowedActions` 是两处实现（一个是 JS、一个是 Rust），所以两边各有测试：
/// 这里的直觉是「按钮出现了却点不动」比「没出现」更伤信任。
/// `has_key` 只影响签发类（没私钥就签不了，别让人点了才报错）。
pub fn can_perform(act: Act, status: &str, issued: bool, has_key: bool) -> bool {
    match act {
        Act::Approve | Act::Reject => status == "pending",
        Act::Sign => status == "approved" && !issued && has_key,
        Act::ApproveAndSign => status == "pending" && has_key,
    }
}

/// 选中位置夹到合法范围（列表可能被过滤、被刷新成更短）。
pub fn clamp_selection(selected: usize, len: usize) -> usize {
    if len == 0 { 0 } else { selected.min(len - 1) }
}

struct Detail {
    approval_id: String,
    summary: String,
    approvers: Vec<String>,
    required: u8,
    digest: String,
    risk: String,
    status: String,
    issued: bool,
    agent_id: String,
}

struct Confirm {
    act: Act,
    approval_id: String,
    preview: String,
}

pub struct App<'k> {
    filter: Filter,
    items: Vec<ApprovalSummary>,
    selected: usize,
    detail: Option<Result<Detail, String>>,
    status: String,
    key: Option<&'k ApproverKey>,
    key_label: String,
    gateway: String,
    confirm: Option<Confirm>,
    help: bool,
    quit: bool,
    last_refresh: Instant,
}

impl<'k> App<'k> {
    fn new(key: Option<&'k ApproverKey>, key_label: String, gateway: String) -> Self {
        Self {
            filter: Filter::Pending,
            items: Vec::new(),
            selected: 0,
            detail: None,
            status: format!("已连接 {gateway}"),
            key,
            key_label,
            gateway,
            confirm: None,
            help: false,
            quit: false,
            last_refresh: Instant::now(),
        }
    }

    fn has_key(&self) -> bool {
        self.key.is_some()
    }

    fn visible(&self) -> Vec<&ApprovalSummary> {
        self.items
            .iter()
            .filter(|item| self.filter.matches(&item.status))
            .collect()
    }

    fn selected_item(&self) -> Option<&ApprovalSummary> {
        self.visible().get(self.selected).copied()
    }

    fn refresh(&mut self, client: &GatewayClient) {
        match client.list(None) {
            Ok(items) => {
                self.items = items;
                self.selected = clamp_selection(self.selected, self.visible().len());
                self.load_detail(client);
            }
            Err(err) => self.status = format!("读取失败：{err}"),
        }
        self.last_refresh = Instant::now();
    }

    /// 取选中单的待签字节并渲染成人读摘要 —— 签名前先看的**就是这份**。
    fn load_detail(&mut self, client: &GatewayClient) {
        self.detail = None;
        let Some(item) = self.selected_item() else {
            return;
        };
        let approval_id = item.approval_id.clone();
        let result = (|| {
            let payload = client
                .signing_payload(&approval_id)
                .map_err(|err| err.to_string())?;
            let (_, summary) = crate::prepare_summary(&payload, false)?;
            let rendered = summary.render(
                &payload.approval_id,
                self.key_label.as_str(),
                self.key.map(ApproverKey::fingerprint).unwrap_or("-"),
            );
            Ok(Detail {
                approval_id: payload.approval_id,
                summary: rendered,
                approvers: payload.approvers,
                required: payload.required_approvers,
                digest: payload.plan_digest,
                risk: payload.risk_level,
                status: item.status.clone(),
                issued: item.issued,
                agent_id: payload.agent_id,
            })
        })();
        self.detail = Some(result);
    }

    fn move_by(&mut self, delta: isize, client: &GatewayClient) {
        let len = self.visible().len();
        if len == 0 {
            return;
        }
        let next = if delta < 0 {
            self.selected.saturating_sub(delta.unsigned_abs())
        } else {
            (self.selected + delta as usize).min(len - 1)
        };
        if next != self.selected {
            self.selected = next;
            self.load_detail(client);
        }
    }

    fn cycle_filter(&mut self, forward: bool, client: &GatewayClient) {
        self.filter = if forward {
            self.filter.next()
        } else {
            self.filter.prev()
        };
        self.selected = 0;
        self.load_detail(client);
    }

    fn ask(&mut self, act: Act) {
        let Some(item) = self.selected_item() else {
            self.status = "没有选中的审批单".to_string();
            return;
        };
        if !can_perform(act, &item.status, item.issued, self.has_key()) {
            self.status = match act {
                Act::Sign if !self.has_key() => {
                    "签发需要审批私钥：wist-approve key generate --out ~/.wist/approver.key"
                        .to_string()
                }
                Act::Sign | Act::ApproveAndSign => {
                    "这张单还没到「已批准」，或已经签发过了".to_string()
                }
                _ => format!("当前状态（{}）不能{}", item.status, act.label()),
            };
            return;
        }
        let preview = match &self.detail {
            Some(Ok(detail)) if detail.approval_id == item.approval_id => detail.summary.clone(),
            _ => item.plan_digest.clone(),
        };
        self.confirm = Some(Confirm {
            act,
            approval_id: item.approval_id.clone(),
            preview,
        });
    }

    fn execute(&mut self, confirm: Confirm, client: &GatewayClient) {
        let id = confirm.approval_id;
        let outcome = match confirm.act {
            Act::Approve => self
                .vote(client, &id, "approve")
                .map(|status| format!("已批准（{status}）")),
            Act::Reject => self
                .vote(client, &id, "reject")
                .map(|status| format!("已驳回（{status}）")),
            Act::Sign => self.sign(client, &id),
            Act::ApproveAndSign => self
                .vote(client, &id, "approve")
                .and_then(|_| self.sign(client, &id)),
        };
        self.status = match outcome {
            Ok(message) => message,
            Err(err) => format!("失败：{err}"),
        };
        self.refresh(client);
    }

    fn vote(
        &self,
        client: &GatewayClient,
        approval_id: &str,
        decision: &str,
    ) -> Result<String, String> {
        let body = client
            .vote(approval_id, decision, None)
            .map_err(|err| err.to_string())?;
        Ok(body
            .get("status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("?")
            .to_string())
    }

    fn sign(&self, client: &GatewayClient, approval_id: &str) -> Result<String, String> {
        let key = self.key.ok_or_else(|| "没有可用的审批私钥".to_string())?;
        let payload = client
            .signing_payload(approval_id)
            .map_err(|err| err.to_string())?;
        // 签名前**再**重算一次摘要：界面里显示的摘要和将要签的字节必须同源。
        crate::prepare_summary(&payload, false)?;
        let attestation =
            crate::build_attestation(&payload, key, &issued_by(), ATTESTATION_TTL_SECONDS)?;
        let result = client
            .issue(approval_id, &attestation)
            .map_err(|err| err.to_string())?;
        Ok(format!(
            "已签发并下发：command={}",
            result.dispatched_command_id.as_deref().unwrap_or("-")
        ))
    }

    fn on_key(&mut self, key: KeyEvent, client: &GatewayClient) {
        if key.kind != KeyEventKind::Press {
            return;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }
        // 确认框最优先：它挡着的操作是不可撤回的。
        if let Some(confirm) = self.confirm.take() {
            match key.code {
                KeyCode::Enter => self.execute(confirm, client),
                KeyCode::Esc | KeyCode::Char('n') => self.status = "已取消".to_string(),
                _ => self.confirm = Some(confirm),
            }
            return;
        }
        if self.help {
            self.help = false;
            return;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Up | KeyCode::Char('k') => self.move_by(-1, client),
            KeyCode::Down | KeyCode::Char('j') => self.move_by(1, client),
            KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => self.cycle_filter(true, client),
            KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => {
                self.cycle_filter(false, client)
            }
            KeyCode::Char('r') => self.refresh(client),
            KeyCode::Char('?') => self.help = true,
            KeyCode::Char('a') => self.ask(Act::Approve),
            KeyCode::Char('x') | KeyCode::Char('X') => self.ask(Act::Reject),
            KeyCode::Char('s') => self.ask(Act::Sign),
            KeyCode::Char('A') => self.ask(Act::ApproveAndSign),
            _ => {}
        }
    }

    fn render(&self, frame: &mut Frame) {
        let chunks = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(5),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(frame.area());

        self.render_header(frame, chunks[0]);
        let body = Layout::horizontal([Constraint::Percentage(42), Constraint::Percentage(58)])
            .split(chunks[1]);
        self.render_list(frame, body[0]);
        self.render_detail(frame, body[1]);
        frame.render_widget(Paragraph::new(self.footer()), chunks[2]);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                self.status.clone(),
                Style::default().fg(Color::Cyan),
            ))),
            chunks[3],
        );

        if let Some(confirm) = &self.confirm {
            self.render_confirm(frame, confirm);
        }
        if self.help {
            render_help(frame);
        }
    }

    fn render_header(&self, frame: &mut Frame, area: Rect) {
        let line = Line::from(vec![
            Span::styled(
                " wist-approve ",
                Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED),
            ),
            Span::raw(" 网关 "),
            Span::styled(self.gateway.clone(), Style::default().fg(Color::Cyan)),
            Span::raw(" · 钥匙 "),
            Span::styled(
                self.key_label.clone(),
                Style::default().fg(if self.has_key() {
                    Color::Green
                } else {
                    Color::Red
                }),
            ),
            Span::raw(" · 过滤 "),
            Span::styled(
                format!("[{}]", self.filter.label()),
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ]);
        frame.render_widget(Paragraph::new(line), area);
    }

    fn render_list(&self, frame: &mut Frame, area: Rect) {
        let visible = self.visible();
        let items: Vec<ListItem> = visible
            .iter()
            .map(|item| {
                ListItem::new(Line::from(vec![
                    Span::styled(
                        format!("{:<3}", item.risk_level),
                        Style::default().fg(Color::Magenta),
                    ),
                    Span::styled(
                        format!("{:<8}", status_label(&item.status)),
                        Style::default().fg(status_color(&item.status)),
                    ),
                    Span::raw(item.agent_id.clone()),
                    if item.issued {
                        Span::styled("  已签发", Style::default().fg(Color::DarkGray))
                    } else {
                        Span::raw("")
                    },
                ]))
            })
            .collect();

        let title = format!("审批单 · {} {}（{}）", self.filter.label(), "", items.len());
        let list = List::new(items)
            .block(Block::bordered().title(title))
            .highlight_style(
                Style::default()
                    .add_modifier(Modifier::REVERSED)
                    .add_modifier(Modifier::BOLD),
            );
        let mut state = ListState::default().with_selected(if visible.is_empty() {
            None
        } else {
            Some(self.selected)
        });
        frame.render_stateful_widget(list, area, &mut state);
    }

    fn render_detail(&self, frame: &mut Frame, area: Rect) {
        let block = Block::bordered().title("审阅（签名前请核对这份）");
        let text = match &self.detail {
            None => "（上下键选择一张审批单）".to_string(),
            Some(Err(err)) => format!("取不到待签字节：{err}"),
            Some(Ok(detail)) => {
                let mut text = detail.summary.clone();
                text.push_str(&format!(
                    "\n\n审批人：{}（需要 {} 人）\n机器：{}\n状态：{} · 风险 {}\n摘要：{}",
                    if detail.approvers.is_empty() {
                        "—".to_string()
                    } else {
                        detail.approvers.join(", ")
                    },
                    detail.required,
                    detail.agent_id,
                    status_label(&detail.status),
                    detail.risk,
                    detail.digest
                ));
                if detail.issued {
                    text.push_str("\n\n已签发：这张单不能再签。");
                }
                text
            }
        };
        frame.render_widget(
            Paragraph::new(text).block(block).wrap(Wrap { trim: false }),
            area,
        );
    }

    fn footer(&self) -> Line<'static> {
        Line::from(Span::styled(
            " ↑↓/jk 选择  tab/←→ 过滤  a 批准  s 签发  A 批准+签发  x 驳回  r 刷新  ? 帮助  q 退出 ",
            Style::default().fg(Color::DarkGray),
        ))
    }

    fn render_confirm(&self, frame: &mut Frame, confirm: &Confirm) {
        let area = centered(frame.area(), 70, 60);
        frame.render_widget(Clear, area);
        let text = format!(
            "确认{} {}？\n\n{}\n\n[Enter 执行 · Esc 取消]",
            confirm.act.label(),
            confirm.approval_id,
            confirm.preview
        );
        frame.render_widget(
            Paragraph::new(text)
                .block(Block::bordered().title(" 确认 "))
                .wrap(Wrap { trim: false }),
            area,
        );
    }
}

fn render_help(frame: &mut Frame) {
    let area = centered(frame.area(), 70, 60);
    frame.render_widget(Clear, area);
    let text = [
        "按键",
        "  ↑ ↓ / k j     选择审批单",
        "  tab / ← →     切换过滤（待审批 / 已批准 / 全部）",
        "  a             批准（投票）",
        "  s             签发并下发（需要审批私钥）",
        "  A             批准 + 签发（一步）",
        "  x             驳回",
        "  r             刷新    ? 帮助    q 退出",
        "",
        "为什么不能用鼠标点：审批是不可撤回的，键盘确认（Enter）比一次误点击安全。",
        "",
        "脚本 / 无终端场景请用子命令：wist-approve list | show | approve | sign | submit",
    ]
    .join("\n");
    frame.render_widget(
        Paragraph::new(text)
            .block(Block::bordered().title(" 帮助 "))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn centered(area: Rect, percent_x: u16, percent_y: u16) -> Rect {
    let vertical = Layout::vertical([
        Constraint::Percentage((100 - percent_y) / 2),
        Constraint::Percentage(percent_y),
        Constraint::Percentage((100 - percent_y) / 2),
    ])
    .split(area);
    Layout::horizontal([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ])
    .split(vertical[1])[1]
}

fn status_label(status: &str) -> &str {
    match status {
        "pending" => "待审批",
        "approved" => "已批准",
        "rejected" => "已驳回",
        "expired" => "已过期",
        other => other,
    }
}

fn status_color(status: &str) -> Color {
    match status {
        "pending" => Color::Yellow,
        "approved" => Color::Green,
        "rejected" => Color::Red,
        other => {
            let _ = other;
            Color::DarkGray
        }
    }
}

fn issued_by() -> String {
    std::env::var("WIST_ISSUED_BY").unwrap_or_else(|_| DEFAULT_ISSUED_BY.to_string())
}

fn load_key(path: Option<std::path::PathBuf>) -> (Option<ApproverKey>, String) {
    let path = match path {
        Some(path) => Some(path),
        None => std::env::var_os("HOME")
            .map(|home| std::path::PathBuf::from(home).join(".wist/approver.key")),
    };
    let Some(path) = path else {
        return (None, "未配置".to_string());
    };
    if !path.exists() {
        return (None, format!("未找到 {}", path.display()));
    }
    match ApproverKey::load_from(&path) {
        Ok(key) => {
            let label = key.key_id().to_string();
            (Some(key), label)
        }
        Err(err) => (None, format!("读取失败：{err}")),
    }
}

/// 入口：无子命令时调用。非终端环境直接拒绝（脚本该走子命令）。
pub fn run(cli: &crate::Cli) -> Result<(), String> {
    use std::io::IsTerminal;
    if !std::io::stdout().is_terminal() || !std::io::stdin().is_terminal() {
        return Err(
            "交互界面需要真正的终端；脚本里请用子命令（`wist-approve --help` 看清单）".to_string(),
        );
    }
    let client = crate::build_client(cli)?;
    let gateway = crate::resolved_gateway(cli)?;
    let (key, key_label) = load_key(cli.approver_key.clone());
    let mut app = App::new(key.as_ref(), key_label, gateway);
    app.refresh(&client);

    let mut terminal = ratatui::init();
    let outcome = event_loop(&mut terminal, &mut app, &client);
    ratatui::restore();
    outcome
}

fn event_loop(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App<'_>,
    client: &GatewayClient,
) -> Result<(), String> {
    while !app.quit {
        terminal
            .draw(|frame| app.render(frame))
            .map_err(|err| format!("绘制失败：{err}"))?;
        if event::poll(Duration::from_millis(250)).map_err(|err| err.to_string())? {
            match event::read().map_err(|err| err.to_string())? {
                Event::Key(key) => app.on_key(key, client),
                _ => {}
            }
        } else if app.last_refresh.elapsed() >= REFRESH {
            app.refresh(client);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(id: &str, status: &str, risk: &str, agent: &str) -> ApprovalSummary {
        ApprovalSummary {
            approval_id: id.to_string(),
            agent_id: agent.to_string(),
            plan_digest: format!("plan-v1:sha256:{}", "ab".repeat(32)),
            risk_level: risk.to_string(),
            requested_by: "user:alice".to_string(),
            requested_at: "2026-11-23T00:00:00Z".to_string(),
            expires_at: "2026-11-24T00:00:00Z".to_string(),
            required_approvers: 1,
            status: status.to_string(),
            approved_at: None,
            issued: false,
        }
    }

    fn rendered(app: &App<'_>, width: u16, height: u16) -> String {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("terminal");
        terminal.draw(|frame| app.render(frame)).expect("draw");
        let buffer = terminal.backend().buffer();
        buffer
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>()
    }

    /// 去空白后再比：中文是**双宽**字符，缓冲区里每个字后面跟一个空白 cell，
    /// 直接 `contains("未找到")` 会变成「未 找 到」而永远失败。
    fn flat(text: &str) -> String {
        text.split_whitespace().collect()
    }

    #[test]
    fn filter_cycles_both_ways() {
        assert_eq!(Filter::Pending.next(), Filter::Approved);
        assert_eq!(Filter::Approved.next(), Filter::All);
        assert_eq!(Filter::All.next(), Filter::Pending);
        assert_eq!(Filter::Pending.prev(), Filter::All);
        assert_eq!(Filter::All.prev(), Filter::Approved);
    }

    #[test]
    fn filters_pick_the_right_statuses() {
        for status in ["pending", "approved", "rejected", "expired", "weird"] {
            assert!(Filter::All.matches(status), "all 必须收 {status}");
            assert_eq!(
                Filter::Pending.matches(status),
                status == "pending",
                "pending 只收 pending（{status}）"
            );
            assert_eq!(
                Filter::Approved.matches(status),
                status == "approved",
                "approved 只收 approved（{status}）"
            );
        }
    }

    #[test]
    fn selection_is_clamped_to_the_list() {
        assert_eq!(clamp_selection(3, 0), 0, "空列表不能给出越界索引");
        assert_eq!(clamp_selection(3, 2), 1);
        assert_eq!(clamp_selection(1, 5), 1);
    }

    /// 与网关状态机同口径：批准/驳回只在 pending；签发只在「已批准且未签发」；
    /// 没有私钥时签发类一律不可用（不让人点了才报错）。
    #[test]
    fn actions_follow_the_state_machine() {
        assert!(can_perform(Act::Approve, "pending", false, true));
        assert!(!can_perform(Act::Approve, "approved", false, true));
        assert!(can_perform(Act::Reject, "pending", false, true));
        assert!(!can_perform(Act::Reject, "rejected", false, true));

        assert!(can_perform(Act::Sign, "approved", false, true));
        assert!(
            !can_perform(Act::Sign, "approved", true, true),
            "已签发不能再签"
        );
        assert!(
            !can_perform(Act::Sign, "pending", false, true),
            "没批够不能签"
        );
        assert!(
            !can_perform(Act::Sign, "approved", false, false),
            "没私钥不能签"
        );

        assert!(can_perform(Act::ApproveAndSign, "pending", false, true));
        assert!(!can_perform(Act::ApproveAndSign, "pending", false, false));
        assert!(!can_perform(Act::ApproveAndSign, "approved", false, true));
    }

    #[test]
    fn status_labels_cover_the_gateway_vocabulary() {
        for (status, label) in [
            ("pending", "待审批"),
            ("approved", "已批准"),
            ("rejected", "已驳回"),
            ("expired", "已过期"),
        ] {
            assert_eq!(status_label(status), label);
        }
        // 未知状态原样显示（宁可显示出来，也不要藏起来）。
        assert_eq!(status_label("weird"), "weird");
    }

    /// 真实渲染一遍（`TestBackend`，不需要 pty）：头部/列表/页脚都要在后。
    /// 这是桌面终端里的实际布局，纯逻辑测试盖不到“忘了把东西画出来”。
    #[test]
    fn renders_header_list_and_footer() {
        let mut app = App::new(
            None,
            "未找到 ~/.wist/approver.key".to_string(),
            "https://gw.example".to_string(),
        );
        app.items = vec![
            summary("apv_1", "pending", "R2", "agent-alpha"),
            summary("apv_2", "approved", "R1", "agent-beta"),
        ];
        let text = rendered(&app, 120, 24);
        let squashed = flat(&text);
        assert!(
            squashed.contains("https://gw.example"),
            "头部要显示网关：\n{text}"
        );
        assert!(
            squashed.contains(&flat("未找到 ~/.wist/approver.key")),
            "头部要显示钥匙状态：\n{text}"
        );
        assert!(squashed.contains("待审批"), "默认过滤档要显示");
        // 默认在「待审批」档：pending 的在，approved 的不在。
        assert!(
            squashed.contains("agent-alpha"),
            "当前档的行要显示：\n{text}"
        );
        assert!(
            !squashed.contains("agent-beta"),
            "非当前过滤档的行不应出现：\n{text}"
        );
        assert!(squashed.contains(&flat("q 退出")), "页脚要有键盘提示");
    }

    /// 切到「全部」可以看到已批准的单；确认框要把摘要摆在人眼前。
    #[test]
    fn all_filter_shows_approved_and_confirm_shows_the_summary() {
        let mut app = App::new(None, "—".to_string(), "https://gw.example".to_string());
        app.items = vec![
            summary("apv_1", "pending", "R2", "agent-alpha"),
            summary("apv_2", "approved", "R1", "agent-beta"),
        ];
        app.filter = Filter::All;
        let text = rendered(&app, 120, 24);
        let squashed = flat(&text);
        assert!(squashed.contains("agent-alpha") && squashed.contains("agent-beta"));

        app.confirm = Some(Confirm {
            act: Act::ApproveAndSign,
            approval_id: "apv_1".to_string(),
            preview: "动作 disk.cleanup.apply".to_string(),
        });
        let text = rendered(&app, 120, 24);
        let squashed = flat(&text);
        assert!(
            squashed.contains(&flat("确认批准并签发 apv_1")),
            "确认框要写清动作与单号：\n{text}"
        );
        assert!(
            squashed.contains(&flat("动作 disk.cleanup.apply")),
            "确认框要把摘要摆出来"
        );
        assert!(squashed.contains(&flat("Enter 执行")), "要说明怎么确认");
    }
}
