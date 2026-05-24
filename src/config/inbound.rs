use serde::{Deserialize, Serialize};

/// 所有入站类型的枚举，用 `type` 字段做 tag。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum InboundConfig {
    /// Linux TProxy，需要外部 iptables/nftables 配合（TCP + UDP）
    TProxy(TProxyInboundConfig),
    /// Linux Redirect（iptables -j REDIRECT / nftables redirect to），仅 TCP
    Redir(RedirInboundConfig),
    /// SOCKS5 + HTTP CONNECT 混合入站
    Mixed(MixedInboundConfig),
    /// DNS 服务器入站（将查询交由内部 DNS 模块处理后返回）
    Dns(DnsInboundConfig),
    /// TUN 虚拟网卡入站（L3 透明代理，TCP + UDP）
    Tun(TunInboundConfig),
}

impl InboundConfig {
    pub fn tag(&self) -> &str {
        match self {
            Self::TProxy(c) => &c.tag,
            Self::Redir(c) => &c.tag,
            Self::Mixed(c) => &c.tag,
            Self::Dns(c) => &c.tag,
            Self::Tun(c) => &c.tag,
        }
    }

    pub fn listen_addr(&self) -> (&str, u16) {
        match self {
            Self::TProxy(c) => (&c.listen, c.listen_port),
            Self::Redir(c) => (&c.listen, c.listen_port),
            Self::Mixed(c) => (&c.listen, c.listen_port),
            Self::Dns(c) => (&c.listen, c.listen_port),
            // TUN 入站无 listen 地址；port=0 在校验中豁免
            Self::Tun(_) => ("", 0),
        }
    }
}

// ── TProxy ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TProxyInboundConfig {
    pub tag: String,

    /// 监听地址，默认 0.0.0.0
    #[serde(default = "default_listen")]
    pub listen: String,

    pub listen_port: u16,

    /// 支持的网络协议
    #[serde(default)]
    pub network: Network,
}

// ── Redirect (NAT) ────────────────────────────────────────────────────────────

/// Linux Redirect 入站配置。
///
/// 对应 `iptables -t nat -j REDIRECT` 或 `nftables redirect to` 规则。
/// 仅支持 TCP；UDP 无法通过 REDIRECT 还原原始目标地址。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedirInboundConfig {
    pub tag: String,

    /// 监听地址，默认 0.0.0.0（接收所有被 redirect 过来的连接）
    #[serde(default = "default_listen")]
    pub listen: String,

    /// 监听端口，需与 nftables/iptables 规则中的 redirect 目标端口一致
    pub listen_port: u16,
}

// ── Mixed（SOCKS5 + HTTP CONNECT）────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MixedInboundConfig {
    pub tag: String,

    #[serde(default = "default_listen_local")]
    pub listen: String,

    pub listen_port: u16,

    #[serde(default)]
    pub network: Network,

    /// SOCKS5 用户名（可选，不填则不鉴权）
    #[serde(default)]
    pub username: Option<String>,

    /// SOCKS5 密码
    #[serde(default)]
    pub password: Option<String>,
}

// ── DNS-in ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsInboundConfig {
    pub tag: String,

    #[serde(default = "default_listen_local")]
    pub listen: String,

    /// 默认 53
    #[serde(default = "default_dns_port")]
    pub listen_port: u16,

    #[serde(default)]
    pub network: Network,
}

// ── 公共辅助类型 ──────────────────────────────────────────────────────────────

/// 网络协议选择
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    /// 仅 TCP
    Tcp,
    /// 仅 UDP
    Udp,
    /// TCP + UDP（默认）
    #[default]
    #[serde(alias = "tcp+udp")]
    TcpUdp,
}

impl Network {
    pub fn tcp(&self) -> bool {
        matches!(self, Self::Tcp | Self::TcpUdp)
    }
    pub fn udp(&self) -> bool {
        matches!(self, Self::Udp | Self::TcpUdp)
    }
}

fn default_listen() -> String {
    "0.0.0.0".into()
}
fn default_listen_local() -> String {
    "127.0.0.1".into()
}
fn default_dns_port() -> u16 {
    53
}

// ── TUN ───────────────────────────────────────────────────────────────────────

/// TUN 虚拟网卡入站配置。
///
/// 创建一个 TUN 设备，从 L3 层截获所有经过该网卡的 IP 流量（TCP + UDP），
/// 解析出目标地址后交给路由层，无需 iptables/nftables 配合。
///
/// ## 平台支持矩阵
///
/// | 字段                  | Linux | macOS | Windows |
/// |-----------------------|-------|-------|---------|
/// | auto_route            | ✓     | ✓     | ✓       |
/// | iproute2_table_index  | ✓     | —     | —       |
/// | iproute2_rule_index   | ✓     | —     | —       |
/// | strict_route          | ✓     | —     | ✓ (WFP) |
/// | include_interface     | ✓     | —     | —       |
/// | exclude_interface     | ✓     | —     | —       |
/// | include_uid           | ✓     | —     | —       |
/// | exclude_uid           | ✓     | —     | —       |
/// | udp_timeout           | ✓     | ✓     | ✓       |
///
/// ## 典型用法
/// ```json
/// {
///   "type": "tun",
///   "tag": "tun-in",
///   "interface_name": "tun0",
///   "address": ["198.18.0.1/16", "fd00::1/126"],
///   "mtu": 9000,
///   "auto_route": true,
///   "strict_route": true,
///   "stack": "system"
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunInboundConfig {
    /// 入站标识，用于路由规则匹配
    pub tag: String,

    /// TUN 设备名，留空则由系统自动分配
    /// Linux: `tun0`，macOS: `utun<N>`，Windows: 由 WinTun 分配
    #[serde(default)]
    pub interface_name: Option<String>,

    /// TUN 设备 MTU，默认 9000
    #[serde(default = "default_tun_mtu")]
    pub mtu: u32,

    /// TUN 设备绑定的 IPv4/IPv6 地址前缀列表
    /// 例如 `["198.18.0.1/16", "fd00::1/126"]`，至少需要一个 IPv4 前缀。
    /// 网关地址由第一个前缀自动推导（Linux/Windows 取下一个 IP，macOS 取自身）。
    pub address: Vec<String>,

    /// 是否自动配置系统路由，将默认流量导入 TUN 设备。
    ///
    /// - **Linux**：在独立路由表（`iproute2_table_index`，默认 2022）中添加路由，
    ///   通过策略规则（`iproute2_rule_index`，默认优先级 9000）引导流量；
    ///   自身出站流量通过 fwmark / `iif lo` 规则绕过，避免环回。
    /// - **macOS**：通过 `AF_ROUTE` socket（`RTM_ADD`）添加路由条目。
    /// - **Windows**：通过 `CreateIpForwardEntry2` WinAPI 添加路由。
    #[serde(default)]
    pub auto_route: bool,

    /// Linux 专用：`auto_route` 使用的 iproute2 路由表编号，默认 2022。
    /// 不同实例需使用不同的表编号以避免冲突。
    #[serde(default = "default_iproute2_table_index")]
    pub iproute2_table_index: u32,

    /// Linux 专用：`auto_route` 策略规则起始优先级，默认 9000。
    /// 规则集实际占用的槽位数量取决于配置（UID 规则数、接口规则数、地址数等），
    /// 建议预留至少 200 个优先级槽位（即不要在 `[priority, priority+200)` 内放其他规则）。
    /// nop 锚点固定在 `priority + 100`，teardown 时根据 setup 记录的状态精确清理。
    #[serde(default = "default_iproute2_rule_index")]
    pub iproute2_rule_index: u32,

    /// 严格路由模式，需配合 `auto_route`。
    ///
    /// - **Linux**：为缺失地址族（无 IPv4 或无 IPv6 地址时）添加
    ///   `FR_ACT_UNREACHABLE` 规则，阻止不支持的协议流量绕过 TUN。
    /// - **Windows**：通过 WFP（Windows Filtering Platform）阻止非 TUN
    ///   接口的 DNS（53 端口）流量，防止多宿主 DNS 泄漏。
    ///   （需要 Windows 10 及以上；更低版本会打印警告并跳过）
    /// - **macOS**：无效果，macOS 无对应内核机制。
    #[serde(default)]
    pub strict_route: bool,

    /// 网络栈实现：
    /// - `"system"`（默认）：依赖内核网络栈进行 L3→L4 转换，性能最佳
    /// - `"gvisor"`：用户态 gVisor 协议栈，兼容性更强
    /// - `"mixed"`：TCP 用 system，UDP 用 gVisor
    #[serde(default = "default_tun_stack")]
    pub stack: String,

    /// **Linux 专用**（需要 `auto_route`）：
    /// 仅拦截来自这些网络接口的流量，留空表示全部接口。
    /// 通过 `ip rule add iif <iface> goto <table_rule>` 实现白名单。
    /// 与 `exclude_interface` 互斥。
    #[serde(default)]
    pub include_interface: Vec<String>,

    /// **Linux 专用**（需要 `auto_route`）：
    /// 排除来自这些网络接口的流量。
    /// 通过 `ip rule add iif <iface> goto <nop>` 跳过 TUN 路由实现。
    /// 与 `include_interface` 互斥。
    #[serde(default)]
    pub exclude_interface: Vec<String>,

    /// **Linux 专用**（需要 `auto_route`）：
    /// 仅拦截属于这些 UID 的流量，留空表示全部用户。
    /// 实现方式：先为指定 UID 建立包含规则，再将其余所有 UID 范围
    /// 通过 `ip rule add uidrange ... goto <nop>` 排除。
    #[serde(default)]
    pub include_uid: Vec<u32>,

    /// **Linux 专用**（需要 `auto_route`）：
    /// 排除属于这些 UID 的流量。
    /// 通过 `ip rule add uidrange <uid>-<uid> goto <nop>` 实现。
    #[serde(default)]
    pub exclude_uid: Vec<u32>,

    /// UDP NAT 会话超时（秒），0 表示使用默认值 300 秒。
    #[serde(default)]
    pub udp_timeout: u64,
}

fn default_tun_mtu() -> u32 {
    9000
}

fn default_tun_stack() -> String {
    "system".to_string()
}

fn default_iproute2_table_index() -> u32 {
    2022
}

fn default_iproute2_rule_index() -> u32 {
    9000
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_redir() {
        let v = json!({
            "type": "redir",
            "tag": "redir-in",
            "listen": "0.0.0.0",
            "listen_port": 7892
        });
        let ib: InboundConfig = serde_json::from_value(v).unwrap();
        assert_eq!(ib.tag(), "redir-in");
        assert!(matches!(ib, InboundConfig::Redir(_)));
        let (listen, port) = ib.listen_addr();
        assert_eq!(listen, "0.0.0.0");
        assert_eq!(port, 7892);
    }

    #[test]
    fn parse_redir_defaults() {
        let v = json!({
            "type": "redir",
            "tag": "redir-in",
            "listen_port": 7892
        });
        let ib: InboundConfig = serde_json::from_value(v).unwrap();
        let (listen, _) = ib.listen_addr();
        assert_eq!(listen, "0.0.0.0");
    }

    #[test]
    fn parse_tproxy() {
        let v = json!({
            "type": "tproxy",
            "tag": "tp-in",
            "listen": "0.0.0.0",
            "listen_port": 7893,
            "network": "tcp+udp",
        });
        let ib: InboundConfig = serde_json::from_value(v).unwrap();
        assert_eq!(ib.tag(), "tp-in");
        assert!(matches!(ib, InboundConfig::TProxy(_)));
    }

    #[test]
    fn parse_mixed_defaults() {
        let v = json!({
            "type": "mixed",
            "tag": "mixed-in",
            "listen_port": 7890
        });
        let ib: InboundConfig = serde_json::from_value(v).unwrap();
        let (listen, port) = ib.listen_addr();
        assert_eq!(listen, "127.0.0.1");
        assert_eq!(port, 7890);
        if let InboundConfig::Mixed(c) = &ib {
            assert!(c.network.udp());
        }
    }

    #[test]
    fn parse_dns_in() {
        let v = json!({
            "type": "dns",
            "tag": "dns-in",
            "listen": "0.0.0.0",
            "listen_port": 5353,
            "network": "udp"
        });
        let ib: InboundConfig = serde_json::from_value(v).unwrap();
        assert!(matches!(ib, InboundConfig::Dns(_)));
        if let InboundConfig::Dns(c) = ib {
            assert!(c.network.udp());
            assert!(!c.network.tcp());
        }
    }

    #[test]
    fn network_both() {
        let n: Network = serde_json::from_str("\"tcp+udp\"").unwrap();
        assert!(n.tcp() && n.udp());
    }

    #[test]
    fn parse_tun_minimal() {
        let v = json!({
            "type": "tun",
            "tag": "tun-in",
            "address": ["198.18.0.1/16"]
        });
        let ib: InboundConfig = serde_json::from_value(v).unwrap();
        assert_eq!(ib.tag(), "tun-in");
        assert!(matches!(ib, InboundConfig::Tun(_)));
        if let InboundConfig::Tun(c) = &ib {
            assert_eq!(c.mtu, 9000);
            assert_eq!(c.stack, "system");
            assert!(!c.auto_route);
            assert!(!c.strict_route);
            assert!(c.interface_name.is_none());
        }
    }

    #[test]
    fn parse_tun_full() {
        let v = json!({
            "type": "tun",
            "tag": "tun-in",
            "interface_name": "utun0",
            "mtu": 65535,
            "address": ["198.18.0.1/16", "fd00::1/126"],
            "auto_route": true,
            "strict_route": true,
            "stack": "gvisor",
            "include_interface": ["eth0"],
            "exclude_uid": [0],
            "udp_timeout": 120
        });
        let ib: InboundConfig = serde_json::from_value(v).unwrap();
        if let InboundConfig::Tun(c) = &ib {
            assert_eq!(c.interface_name.as_deref(), Some("utun0"));
            assert_eq!(c.mtu, 65535);
            assert_eq!(c.address.len(), 2);
            assert!(c.auto_route);
            assert!(c.strict_route);
            assert_eq!(c.stack, "gvisor");
            assert_eq!(c.include_interface, vec!["eth0"]);
            assert_eq!(c.exclude_uid, vec![0u32]);
            assert_eq!(c.udp_timeout, 120);
        } else {
            panic!("expected Tun");
        }
    }
}
