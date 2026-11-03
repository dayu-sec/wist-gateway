// NOTE(hand-added): 环回面（self-state / link-request / linkd-status / agent-package / agents）的
// **「本机对端」判据**。不在 jumo 静态模型里（它是准入策略不是接口）；重新生成控制面代码时需回补本模块。
//
// 为什么不是单纯的 `is_loopback()`：**发布态网关跑在容器里**。宿主侧常驻 `wist-gwlinkd` 连到宿主上
// 那个 published 端口时，经 docker 转发进容器，**对端是 docker 网络网关**（= 宿主在该网络上的地址），
// 不是 `127.0.0.1` —— 于是被 `is_loopback` 判成「外来」，环回面**全线 403**：
//   self-state（自述面）/ link-request（接入中心）/ linkd-status（心跳）/ agent-package（发布②）
// dev 态之所以没暴露：`dev/forward-443.py` 把对端变成了 `127.0.0.1`
// （见 `wist-design/doc/design/edge/gateway-status-report.md` §4）。
//
// 所以「本机」= **环回** ∪ **容器默认路由的下一跳**（仅确认在容器里时才认）∪ `[server] self_face_allow`。
//
// **为什么这条放宽不会放进外人**：published 端口上的外部客户端带的是**真实源 IP**
// （否则限流分桶会塌成一个；`api/rate_limit.rs` 也正是因此明确忽略 XFF），只有宿主经 docker
// 转发那一跳才显示成网络网关 —— 放行网络网关 = 放行宿主自己。见测试 `external_peers_stay_rejected`。

use std::net::IpAddr;

use super::AdminConfig;

/// 一个网段（IP + 前缀长度）；不带 `/n` 时按**单地址**（`/32` 或 `/128`）处理。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    /// 解析 `1.2.3.4` / `1.2.3.4/24` / `::1` / `::1/128`。
    pub fn parse(value: &str) -> Result<Self, String> {
        let value = value.trim();
        if value.is_empty() {
            return Err("空值".to_string());
        }
        let (addr, prefix) = match value.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (value, None),
        };
        let addr: IpAddr = addr
            .trim()
            .parse()
            .map_err(|_| format!("不是合法 IP：{addr}"))?;
        let max = if addr.is_ipv4() { 32u8 } else { 128u8 };
        let prefix = match prefix {
            Some(prefix) => prefix
                .trim()
                .parse::<u8>()
                .map_err(|_| format!("前缀长度不是数字：/{prefix}"))?,
            None => max,
        };
        if prefix > max {
            return Err(format!("前缀长度越界：/{prefix}（{addr} 最大 /{max}）"));
        }
        Ok(Self { addr, prefix })
    }

    /// `ip` 是否落在本网段内（IP 版本不同 = 不在）。
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = v4_mask(self.prefix);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = v6_mask(self.prefix);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }

    /// 是否覆盖**所有**地址（`/0`）。
    ///
    /// 环回面的放行名单里出现它，等于把这些**无鉴权**的面直接暴露给全世界 —— 配置层据此**拒启**
    /// （手滑写 `0.0.0.0/0` 是最容易犯的那种错）。
    pub fn is_unbounded(&self) -> bool {
        self.prefix == 0
    }
}

impl std::fmt::Display for IpNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// `/0` 要特判：`u32::MAX << 32` 在 debug 下会 panic（移位越界）。
fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

fn v6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    }
}

/// 环回面的「本机」判据（启动时解析一次，进程内不变 —— 装进 `ApiState`）。
#[derive(Debug, Clone, Default)]
pub struct LocalPeers {
    /// 容器默认路由的下一跳（= 宿主在容器网络上的地址）；`None` = 非容器 / 探测不到。
    container_gateway: Option<IpAddr>,
    /// `[server] self_face_allow` 追加放行的网段。
    extra: Vec<IpNet>,
}

impl LocalPeers {
    /// 直接构造（显式装配 / 测试）。
    pub fn new(container_gateway: Option<IpAddr>, extra: Vec<IpNet>) -> Self {
        Self {
            container_gateway,
            extra,
        }
    }

    /// 按配置解析 + 探测（启动时一次）。
    pub fn resolve(config: &AdminConfig) -> Self {
        Self {
            container_gateway: container_default_gateway(),
            extra: config.self_face_allow.clone(),
        }
    }

    /// 对端是不是**本机**：环回 ∪ 容器默认网关 ∪ 配置放行。
    pub fn is_local(&self, ip: IpAddr) -> bool {
        ip.is_loopback()
            || self.container_gateway == Some(ip)
            || self.extra.iter().any(|net| net.contains(ip))
    }

    /// 观测用：解析出的「本机」集合（启动日志 / 排查）。
    pub fn describe(&self) -> String {
        let gateway = self
            .container_gateway
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "none".to_string());
        let extra: Vec<String> = self.extra.iter().map(ToString::to_string).collect();
        format!(
            "loopback + container_gateway={gateway} + allow=[{}]",
            extra.join(", ")
        )
    }
}

/// 容器内才探测默认网关：宿主直接跑时 gwlinkd 走环回就够，无需放宽。
fn container_default_gateway() -> Option<IpAddr> {
    if !running_in_container() {
        return None;
    }
    default_gateway()
}

/// 是否跑在容器里（docker / podman / k8s）。判据是容器运行时留下的几个**标记**，
/// 宿主进程上都不成立。
fn running_in_container() -> bool {
    std::path::Path::new("/.dockerenv").exists()
        || std::path::Path::new("/run/.containerenv").exists()
        || std::fs::read_to_string("/proc/1/cgroup")
            .map(|text| {
                ["docker", "kubepods", "containerd", "lxc"]
                    .iter()
                    .any(|marker| text.contains(marker))
            })
            .unwrap_or(false)
}

/// 默认路由的下一跳：读 `/proc/net/route`（Linux 专有；其它平台读不到 ⇒ `None`，等价于「认不出」）。
///
/// 只在 [`container_default_gateway`] 里、且确认在容器中才调到它。
fn default_gateway() -> Option<IpAddr> {
    parse_default_gateway(&std::fs::read_to_string("/proc/net/route").ok()?)
}

/// 从 `/proc/net/route` 的**文本**里取默认路由的下一跳。
///
/// 抽成纯函数是为了**能在任何平台上单测** —— 这段格式解析（尤其网关那串小端十六进制）
/// 是最容易写错的一环，不能只靠「在 Linux 上跑对了」来背书。
///
/// 格式（表头之后每行）：`Iface Destination Gateway Flags RefCnt Use Metric Mask ...`
/// - `Destination == 00000000` ⇒ 默认路由；
/// - `Gateway` 是**小端**写的十六进制（x86 内存序）⇒ 要 `swap_bytes` 回来才是点分十进制。
fn parse_default_gateway(table: &str) -> Option<IpAddr> {
    use std::net::Ipv4Addr;

    for line in table.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 || fields[1] != "00000000" {
            continue;
        }
        let Ok(raw) = u32::from_str_radix(fields[2], 16) else {
            continue;
        };
        if raw == 0 {
            // 无网关（`onlink` 之类）：不是「本机」，继续找。
            continue;
        }
        let ip = Ipv4Addr::from(raw.swap_bytes());
        if !ip.is_unspecified() {
            return Some(IpAddr::V4(ip));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_net_parses_addresses_and_cidrs() {
        let single = IpNet::parse("10.0.0.7").expect("ip");
        assert!(single.contains("10.0.0.7".parse().expect("ip")));
        assert!(!single.contains("10.0.0.8".parse().expect("ip")));

        let net = IpNet::parse("172.28.0.0/16").expect("cidr");
        assert!(net.contains("172.28.3.9".parse().expect("ip")));
        assert!(!net.contains("172.29.0.1".parse().expect("ip")));

        // `/0` 不能因移位越界而 panic。
        assert!(
            IpNet::parse("0.0.0.0/0")
                .expect("all")
                .contains("203.0.113.1".parse().expect("ip"))
        );

        let v6 = IpNet::parse("::1/128").expect("v6");
        assert!(v6.contains("::1".parse().expect("ip")));
        assert!(!v6.contains("::2".parse().expect("ip")));
        // 版本不同 = 不在。
        assert!(!v6.contains("10.0.0.1".parse().expect("ip")));
    }

    #[test]
    fn ip_net_rejects_bad_values() {
        for bad in ["", "  ", "nope", "10.0.0.1/33", "10.0.0.1/x", "::1/129"] {
            assert!(IpNet::parse(bad).is_err(), "{bad:?} 应被拒");
        }
    }

    /// `/0`（覆盖一切）要能被**认出来** —— 配置层据此拒启（无鉴权面不能放给所有人）。
    #[test]
    fn unbounded_net_is_flagged() {
        let all = IpNet::parse("0.0.0.0/0").expect("all");
        assert!(all.is_unbounded());
        assert!(all.contains("203.0.113.1".parse().expect("ip")));
        assert!(IpNet::parse("::/0").expect("all v6").is_unbounded());
        assert!(!IpNet::parse("10.0.0.0/8").expect("cidr").is_unbounded());
        assert!(!IpNet::parse("10.0.0.7").expect("ip").is_unbounded());
    }

    #[test]
    fn loopback_is_always_local() {
        let peers = LocalPeers::new(None, Vec::new());
        assert!(peers.is_local("127.0.0.1".parse().expect("ip")));
        assert!(peers.is_local("::1".parse().expect("ip")));
    }

    /// **关键安全口径**：外面来的地址必须仍被拒 —— 「本机」只多认容器默认网关与显式放行。
    #[test]
    fn external_peers_stay_rejected() {
        let peers = LocalPeers::new(Some("172.28.0.1".parse().expect("ip")), Vec::new());
        assert!(
            peers.is_local("172.28.0.1".parse().expect("ip")),
            "容器默认网关 = 宿主"
        );
        assert!(
            !peers.is_local("172.28.0.9".parse().expect("ip")),
            "同网段的**别的**容器不是本机"
        );
        assert!(
            !peers.is_local("203.0.113.9".parse().expect("ip")),
            "外部地址不是本机"
        );
        assert!(
            !LocalPeers::new(None, Vec::new()).is_local("172.28.0.1".parse().expect("ip")),
            "非容器：默认网关不参与"
        );
    }

    #[test]
    fn configured_allow_extends_local_peers() {
        let peers = LocalPeers::new(None, vec![IpNet::parse("172.28.0.0/16").expect("cidr")]);
        assert!(peers.is_local("172.28.5.6".parse().expect("ip")));
        assert!(!peers.is_local("172.29.5.6".parse().expect("ip")));
    }

    /// 放行里的**网段**不能把版本不同 / 相邻网段带进来。
    #[test]
    fn allow_net_does_not_widen_across_families_or_neighbours() {
        let peers = LocalPeers::new(
            None,
            vec![
                IpNet::parse("10.0.0.0/8").expect("v4"),
                IpNet::parse("fd00::/8").expect("v6"),
            ],
        );
        assert!(peers.is_local("10.255.255.255".parse().expect("ip")));
        assert!(!peers.is_local("11.0.0.1".parse().expect("ip")));
        assert!(peers.is_local("fd00::1".parse().expect("ip")));
        assert!(!peers.is_local("fe00::1".parse().expect("ip")));
        // v4 网段不得匹配 v6 地址（反之亦然）。
        assert!(!peers.is_local("::ffff:10.0.0.1".parse().expect("ip")));
    }

    /// 默认网关**只**匹配那一个地址（不是它所在的网段）。
    #[test]
    fn container_gateway_matches_exactly() {
        let peers = LocalPeers::new(Some("172.17.0.1".parse().expect("ip")), Vec::new());
        assert!(peers.is_local("172.17.0.1".parse().expect("ip")));
        assert!(!peers.is_local("172.17.0.2".parse().expect("ip")));
    }

    /// `/proc/net/route` 解析（恒可在任何平台上跑）：默认路由行、小端网关、跳过非默认行。
    #[test]
    fn parses_the_default_gateway_from_proc_net_route() {
        // 典型 docker 默认桥：网关 172.17.0.1 → 小端十六进制 `010011AC`。
        let table = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n\
                     eth0\t0000A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n\
                     eth0\t00000000\t010011AC\t0003\t0\t0\t0\t00000000\n";
        assert_eq!(
            parse_default_gateway(table),
            Some("172.17.0.1".parse().expect("ip"))
        );

        // k8s 风味：网关 10.42.0.1 → `01002A0A`。
        let k8s = "Iface\tDestination\tGateway \tFlags\n\
                   eth0\t00000000\t01002A0A\t0003\n";
        assert_eq!(
            parse_default_gateway(k8s),
            Some("10.42.0.1".parse().expect("ip"))
        );
    }

    /// 解析要**婉拒绝畸形输入**：没有默认路由 / 网关全 0 / 行太短 / 网关不是十六进制 → `None`。
    #[test]
    fn proc_net_route_parsing_is_defensive() {
        // 只有表头（无默认路由）。
        assert_eq!(parse_default_gateway("Iface\tDestination\tGateway\n"), None);
        // `onlink` 之类的全 0 网关：不是「本机」。
        assert_eq!(
            parse_default_gateway("hdr\neth0\t00000000\t00000000\t0003\n"),
            None
        );
        // 行太短（拿不到 Gateway 列）。
        assert_eq!(parse_default_gateway("hdr\neth0\t00000000\n"), None);
        // Gateway 不是十六进制。
        assert_eq!(
            parse_default_gateway("hdr\neth0\t00000000\tZZZZZZZZ\t0003\n"),
            None
        );
        // 空文本。
        assert_eq!(parse_default_gateway(""), None);
    }

    /// 非容器平台上**不**认默认网关（宿主直接跑的部署行为不变）。
    #[test]
    fn gateway_is_only_detected_inside_a_container() {
        if !running_in_container() {
            assert_eq!(container_default_gateway(), None);
        }
    }

    /// 没探到网关时，`describe` 要**说出来**（启动日志里一眼能看出没生效）。
    #[test]
    fn describe_shows_none_without_a_gateway() {
        assert!(
            LocalPeers::default()
                .describe()
                .contains("container_gateway=none")
        );
    }

    #[test]
    fn describe_lists_the_resolved_set() {
        let peers = LocalPeers::new(
            Some("172.28.0.1".parse().expect("ip")),
            vec![IpNet::parse("10.0.0.0/8").expect("cidr")],
        );
        let text = peers.describe();
        assert!(text.contains("172.28.0.1"), "{text}");
        assert!(text.contains("10.0.0.0/8"), "{text}");
    }
}
