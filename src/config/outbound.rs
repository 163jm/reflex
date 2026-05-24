use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// 所有出站类型，用 `type` 字段做 tag。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum OutboundConfig {
    Vless(VlessOutboundConfig),
    Vmess(VmessOutboundConfig),
    Shadowsocks(ShadowsocksOutboundConfig),
    Hysteria2(Hysteria2OutboundConfig),
    Tuic(TuicOutboundConfig),
    Trojan(TrojanOutboundConfig),
    Direct(DirectOutboundConfig),
    Block(BlockOutboundConfig),
    Socks(SocksOutboundConfig),
    Selector(SelectorOutboundConfig),
    UrlTest(UrlTestOutboundConfig),
}

impl OutboundConfig {
    pub fn tag(&self) -> &str {
        match self {
            Self::Vless(c) => &c.tag,
            Self::Vmess(c) => &c.tag,
            Self::Shadowsocks(c) => &c.tag,
            Self::Hysteria2(c) => &c.tag,
            Self::Tuic(c) => &c.tag,
            Self::Trojan(c) => &c.tag,
            Self::Direct(c) => &c.tag,
            Self::Block(c) => &c.tag,
            Self::Socks(c) => &c.tag,
            Self::Selector(c) => &c.tag,
            Self::UrlTest(c) => &c.tag,
        }
    }

    pub fn child_outbounds(&self) -> &[String] {
        match self {
            Self::Selector(c) => &c.outbounds,
            Self::UrlTest(c) => &c.outbounds,
            _ => &[],
        }
    }

    pub fn group_providers(&self) -> Option<&crate::config::provider::ProviderRef> {
        match self {
            Self::Selector(c) => c.providers.as_ref(),
            Self::UrlTest(c) => c.providers.as_ref(),
            _ => None,
        }
    }

    pub fn group_default(&self) -> Option<&str> {
        match self {
            Self::Selector(c) => c.r#default.as_deref(),
            _ => None,
        }
    }

    pub fn is_group(&self) -> bool {
        matches!(self, Self::Selector(_) | Self::UrlTest(_))
    }
}

// ── Shadowsocks ───────────────────────────────────────────────────────────────

/// Shadowsocks 出站配置。
///
/// 支持的加密方法（与 sing-box 对齐）：
/// - AEAD：`aes-128-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305`
/// - AEAD-2022：`2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm`、
///   `2022-blake3-chacha20-poly1305`
/// - 明文（仅测试）：`none`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowsocksOutboundConfig {
    pub tag: String,

    /// 服务器域名或 IP
    pub server: String,

    pub server_port: u16,

    /// 加密方法，如 `"aes-128-gcm"`、`"chacha20-ietf-poly1305"`、
    /// `"2022-blake3-aes-128-gcm"` 等。
    pub method: String,

    /// 密码（AEAD 模式）或 PSK（AEAD-2022，base64 编码）
    pub password: String,

    /// SIP003 插件名称，如 `"obfs-local"`（可选）
    #[serde(default)]
    pub plugin: Option<String>,

    /// SIP003 插件参数，如 `"obfs=http;obfs-host=www.example.com"`（可选）
    #[serde(default)]
    pub plugin_opts: Option<String>,

    /// 传输层配置（可选）；支持 xhttp 传输。
    /// 使用 xhttp 时，SS 加密后的数据将通过 HTTP 流传输，而非裸 TCP。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<ShadowsocksTransportConfig>,

    /// TLS 配置（xhttp 传输时可配合使用；裸 TCP 模式通常不需要）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,

    /// 出站本身走哪个 outbound（链式代理，预留）
    #[serde(default)]
    pub detour: Option<String>,
}

/// Shadowsocks 传输层配置
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ShadowsocksTransportConfig {
    /// WebSocket 传输
    Ws(WsTransportConfig),
    /// XHTTP (SplitHTTP) 传输
    Xhttp(XhttpTransportConfig),
}

// ── VLESS ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VlessOutboundConfig {
    pub tag: String,

    /// 服务器域名或 IP
    pub server: String,

    pub server_port: u16,

    /// UUID（标准格式，如 "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"）
    pub uuid: String,

    /// 传输层配置：ws 或 tcp。可选，缺省时视为裸 TCP。
    /// 与 sing-box 一致：`{ "type": "ws", "path": "...", "headers": {} }`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<VlessTransportConfig>,

    /// TLS 配置（与 sing-box 对齐）：
    /// - 普通 TLS：`{ "enabled": true, "server_name": "..." }`
    /// - REALITY：在 tls 对象内嵌套 `"reality": { "public_key": "...", "short_id": "..." }`
    /// - 无 TLS：省略此字段或 `{ "enabled": false }`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<VlessTlsConfig>,

    /// 出站本身走哪个 outbound（用于链式代理，暂未实现，预留字段）
    #[serde(default)]
    pub detour: Option<String>,
}

/// VLESS 传输层配置（与 sing-box V2RayTransportOptions 对齐）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum VlessTransportConfig {
    Ws(WsTransportConfig),
    /// 裸 TCP 传输
    Tcp(TcpTransportConfig),
    /// XHTTP (SplitHTTP) 传输
    Xhttp(XhttpTransportConfig),
}

/// TCP 传输配置（VLESS over TCP）
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct TcpTransportConfig {
    /// 是否启用 HTTP/1.1 伪装（预留）
    #[serde(default)]
    pub http_upgrade: bool,
}

/// VLESS TLS 配置（与 sing-box OutboundTLSOptions 对齐）
///
/// 普通 TLS 示例：
/// ```json
/// { "enabled": true, "server_name": "example.com", "insecure": false }
/// ```
/// REALITY 示例（reality 嵌套在 tls 内）：
/// ```json
/// {
///   "enabled": true,
///   "server_name": "www.apple.com",
///   "reality": { "enabled": true, "public_key": "...", "short_id": "..." }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct VlessTlsConfig {
    /// 是否启用 TLS，默认 false
    #[serde(default)]
    pub enabled: bool,

    /// SNI，默认等于 server 字段
    #[serde(default)]
    pub server_name: Option<String>,

    /// 跳过证书验证（不安全，仅调试用）
    #[serde(default)]
    pub insecure: bool,

    /// 自定义 CA 证书路径（PEM）
    #[serde(default)]
    pub ca_path: Option<String>,

    /// ALPN 列表
    #[serde(default)]
    pub alpn: Vec<String>,

    /// REALITY 配置（存在时启用 REALITY，忽略普通 TLS 验证）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality: Option<RealityConfig>,
}

/// REALITY 客户端配置（嵌套在 tls 对象内，与 sing-box OutboundRealityOptions 对齐）
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RealityConfig {
    /// 启用标志（sing-box 兼容）
    #[serde(default)]
    pub enabled: bool,

    /// 服务端 x25519 公钥（base64url 编码）
    #[serde(default)]
    pub public_key: String,

    /// shortId（hex，0~16字符，偶数位）
    #[serde(default)]
    pub short_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WsTransportConfig {
    /// WebSocket 握手路径，默认 "/"
    #[serde(default = "default_ws_path")]
    pub path: String,

    /// 额外请求头（常用于设置 Host）
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// 早期数据（0-RTT），字节数，0 表示禁用
    #[serde(default)]
    pub early_data_header_name: Option<String>,

    #[serde(default)]
    pub max_early_data: u32,
}

/// XHTTP (SplitHTTP) 传输配置
///
/// 字段名与 sing-box / Xray xhttp transport 完全对齐，示例：
/// ```json
/// {
///   "type": "xhttp",
///   "host": "example.com",
///   "path": "/xhttp/",
///   "mode": "packet-up",
///   "headers": { "X-Custom": "value" },
///   "scMaxEachPostBytes": 1000000,
///   "scMinPostsIntervalMs": 30,
///   "scMaxBufferedPosts": 512,
///   "noGRPCHeader": false,
///   "noSSEHeader": false,
///   "uplinkHTTPMethod": "POST",
///   "xmux": {
///     "maxConcurrency": 8,
///     "maxConnections": 4,
///     "cMaxReuseTimes": 64,
///     "hMaxRequestTimes": 128,
///     "hMaxReusableSecs": 300
///   }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct XhttpTransportConfig {
    /// HTTP Host 头（可选，缺省使用 server 字段或 TLS SNI）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,

    /// URL 路径，默认 "/"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// 传输模式：`stream-one` | `stream-up` | `packet-up`（默认）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,

    /// 额外自定义请求头
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, String>,

    /// packet-up 模式每个 POST 的最大字节数
    /// sing-box / Xray 字段名：`scMaxEachPostBytes`
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "scMaxEachPostBytes"
    )]
    pub sc_max_each_post_bytes: Option<u64>,

    /// 相邻两次 POST 的最小间隔毫秒数
    /// sing-box / Xray 字段名：`scMinPostsIntervalMs`
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "scMinPostsIntervalMs"
    )]
    pub sc_min_posts_interval_ms: Option<u64>,

    /// 允许缓冲的最大 POST 数
    /// sing-box / Xray 字段名：`scMaxBufferedPosts`
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "scMaxBufferedPosts"
    )]
    pub sc_max_buffered_posts: Option<u64>,

    /// 禁用 gRPC 兼容头（`content-type: application/grpc`）
    /// sing-box / Xray 字段名：`noGRPCHeader`
    #[serde(default, rename = "noGRPCHeader")]
    pub no_grpc_header: bool,

    /// 禁用 SSE 响应头（`content-type: text/event-stream`）
    /// sing-box / Xray 字段名：`noSSEHeader`
    #[serde(default, rename = "noSSEHeader")]
    pub no_sse_header: bool,

    /// 上行 HTTP 方法，默认 `"POST"`
    /// sing-box / Xray 字段名：`uplinkHTTPMethod`
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "uplinkHTTPMethod"
    )]
    pub uplink_http_method: Option<String>,

    /// Xmux 连接复用配置
    /// sing-box / Xray 字段名：`xmux`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xmux: Option<XmuxConfig>,
}

/// Xmux 连接复用配置（与 sing-box / Xray `xmux` 字段对齐）
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct XmuxConfig {
    /// 单连接最大并发流数
    /// sing-box / Xray 字段名：`maxConcurrency`
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "maxConcurrency"
    )]
    pub max_concurrency: Option<u32>,

    /// 最大连接数
    /// sing-box / Xray 字段名：`maxConnections`
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "maxConnections"
    )]
    pub max_connections: Option<u32>,

    /// 客户端连接最大复用次数
    /// sing-box / Xray 字段名：`cMaxReuseTimes`
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "cMaxReuseTimes"
    )]
    pub c_max_reuse_times: Option<u32>,

    /// 每条 h2 连接最大请求次数
    /// sing-box / Xray 字段名：`hMaxRequestTimes`
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "hMaxRequestTimes"
    )]
    pub h_max_request_times: Option<u32>,

    /// h2 连接最长复用秒数
    /// sing-box / Xray 字段名：`hMaxReusableSecs`
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "hMaxReusableSecs"
    )]
    pub h_max_reusable_secs: Option<u32>,

    /// h2 keepalive 间隔秒数
    /// sing-box / Xray 字段名：`hKeepAlivePeriod`
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "hKeepAlivePeriod"
    )]
    pub h_keep_alive_period: Option<u64>,
}

// ── VMess ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmessOutboundConfig {
    pub tag: String,

    /// 服务器域名或 IP
    pub server: String,

    pub server_port: u16,

    /// VMess 用户 UUID
    pub uuid: String,

    /// VMess security 字段，如 "auto"、"none"、"aes-128-gcm"、"chacha20-poly1305"。
    #[serde(default = "default_vmess_security")]
    pub security: String,

    /// 传输层配置：tcp 或 ws。
    #[serde(default)]
    pub transport: VmessTransportConfig,

    /// TLS 配置；默认关闭，配置 { "enabled": true } 时启用。
    #[serde(default = "default_disabled_tls")]
    pub tls: TlsConfig,

    #[serde(default)]
    pub detour: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum VmessTransportConfig {
    #[default]
    Tcp,
    Ws(WsTransportConfig),
    /// XHTTP (SplitHTTP) 传输
    Xhttp(XhttpTransportConfig),
}

// ── Hysteria2 ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hysteria2OutboundConfig {
    pub tag: String,

    pub server: String,
    pub server_port: u16,

    pub password: String,

    #[serde(default)]
    pub tls: TlsConfig,

    /// 上行带宽 Mbps（与 sing-box up_mbps 对齐），0 表示不限速
    #[serde(default)]
    pub up_mbps: u64,

    /// 下行带宽 Mbps（与 sing-box down_mbps 对齐），0 表示不限速
    #[serde(default)]
    pub down_mbps: u64,

    #[serde(default)]
    pub detour: Option<String>,
}

/// Mbps → bytes/s 转换（供出站内部使用）
pub fn mbps_to_bps(mbps: u64) -> u64 {
    mbps * 1_000_000 / 8
}

// ── TUIC ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TuicOutboundConfig {
    pub tag: String,

    pub server: String,
    pub server_port: u16,

    /// TUIC UUID
    pub uuid: String,

    /// TUIC password
    pub password: String,

    /// 拥塞控制算法，如 "cubic"、"new_reno"、"bbr"。
    #[serde(default = "default_tuic_congestion_control")]
    pub congestion_control: String,

    /// UDP relay mode，如 "native"。
    #[serde(default = "default_tuic_udp_relay_mode")]
    pub udp_relay_mode: String,

    /// TUIC 基于 QUIC/TLS，默认启用 TLS。
    #[serde(default)]
    pub tls: TlsConfig,

    #[serde(default)]
    pub heartbeat: Option<String>,

    /// 与 sing-box 对齐：zero_rtt_handshake
    #[serde(default)]
    pub zero_rtt_handshake: bool,

    #[serde(default)]
    pub detour: Option<String>,
}

// ── Trojan ────────────────────────────────────────────────────────────────────

/// Trojan 出站配置。
///
/// 支持传输层：
/// - `{ "type": "tcp" }` 裸 TCP（通常配合 TLS）
/// - `{ "type": "ws", "path": "/", "headers": {} }` WebSocket
///
/// TLS 配置通过 `tls` 字段控制（默认启用）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrojanOutboundConfig {
    pub tag: String,

    /// 服务器域名或 IP
    pub server: String,

    pub server_port: u16,

    /// Trojan 密码（明文，握手时 SHA-224 后 hex 编码）
    pub password: String,

    /// 传输层配置。可选，缺省时为裸 TCP（与 sing-box 一致）。
    /// WS 示例：`{ "type": "ws", "path": "/ws", "headers": { "Host": "..." } }`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<TrojanTransportConfig>,

    /// TLS 配置（Trojan 通常必须启用 TLS）
    #[serde(default)]
    pub tls: TlsConfig,

    /// 出站链式代理（预留）
    #[serde(default)]
    pub detour: Option<String>,
}

/// Trojan 传输层配置
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum TrojanTransportConfig {
    /// 裸 TCP 传输（默认）
    Tcp(TrojanTcpConfig),
    /// WebSocket 传输
    Ws(WsTransportConfig),
    /// XHTTP (SplitHTTP) 传输
    Xhttp(XhttpTransportConfig),
}

impl Default for TrojanTransportConfig {
    fn default() -> Self {
        Self::Tcp(TrojanTcpConfig::default())
    }
}

/// Trojan over TCP 配置（暂无额外字段，保留扩展空间）
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct TrojanTcpConfig {}

// ── Direct / Block ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectOutboundConfig {
    pub tag: String,

    /// 绑定本地出口 IP（可选）
    #[serde(default)]
    pub bind_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockOutboundConfig {
    pub tag: String,
}

// ── SOCKS ─────────────────────────────────────────────────────────────────────

/// SOCKS5/SOCKS4/SOCKS4a 出站配置（与 sing-box SOCKSOutboundOptions 对齐）。
///
/// 配置示例（SOCKS5 带认证）：
/// ```json
/// {
///   "type": "socks",
///   "tag": "socks-out",
///   "server": "127.0.0.1",
///   "server_port": 1080,
///   "version": "5",
///   "username": "user",
///   "password": "pass"
/// }
/// ```
///
/// SOCKS4 示例（不支持域名，客户端需预先解析）：
/// ```json
/// {
///   "type": "socks",
///   "tag": "socks4-out",
///   "server": "127.0.0.1",
///   "server_port": 1080,
///   "version": "4"
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocksOutboundConfig {
    pub tag: String,

    /// 代理服务器地址（域名或 IP）
    pub server: String,

    /// 代理服务器端口
    pub server_port: u16,

    /// 协议版本："5"（默认）、"4a"、"4"
    /// 与 sing-box `version` 字段对齐；缺省为 SOCKS5
    #[serde(default)]
    pub version: Option<String>,

    /// 用户名（SOCKS5 USER/PASS 认证，可选）
    #[serde(default)]
    pub username: Option<String>,

    /// 密码（SOCKS5 USER/PASS 认证，可选）
    #[serde(default)]
    pub password: Option<String>,
}

impl SocksOutboundConfig {
    /// 解析 version 字符串，返回规范化值。
    /// 合法值："5" | "4a" | "4"，其余视为错误。
    pub fn parsed_version(&self) -> anyhow::Result<SocksVersion> {
        match self.version.as_deref().unwrap_or("5") {
            "5" | "" => Ok(SocksVersion::V5),
            "4a" => Ok(SocksVersion::V4a),
            "4" => Ok(SocksVersion::V4),
            other => anyhow::bail!("unsupported socks version: '{other}', expected 5 / 4a / 4"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocksVersion {
    V5,
    V4a,
    V4,
}

// ── Selector / URL-Test ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectorOutboundConfig {
    pub tag: String,

    /// 静态 outbound tag 列表（在 providers 展开节点之前，排在最前面）。
    #[serde(default)]
    pub outbounds: Vec<String>,

    /// 引用的 provider 及过滤配置（展开节点追加在 outbounds 之后）。
    #[serde(default)]
    pub providers: Option<crate::config::provider::ProviderRef>,

    /// 默认选中的 outbound tag；为空时使用 outbounds[0]。
    #[serde(default)]
    pub r#default: Option<String>,

    /// 切换节点时是否强制中断经由本组的现有连接（默认 false）。
    #[serde(default)]
    pub interrupt_existing_connections: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UrlTestOutboundConfig {
    pub tag: String,

    /// 参与测速和自动选择的静态 outbound tag 列表。
    #[serde(default)]
    pub outbounds: Vec<String>,

    /// 引用的 provider 及过滤配置。
    #[serde(default)]
    pub providers: Option<crate::config::provider::ProviderRef>,

    /// 测速 URL。
    #[serde(default = "default_url_test_url")]
    pub url: String,

    /// 测速间隔，如 "3m"、"30s"、"1h"。
    #[serde(default = "default_url_test_interval")]
    pub interval: String,

    /// 单次测速最大等待时间。
    #[serde(default = "default_url_test_idle_timeout")]
    pub idle_timeout: String,

    /// 延迟容差（毫秒）：当前节点延迟在最低延迟 + tolerance 内时不切换。
    #[serde(default)]
    pub tolerance: u64,
}

impl UrlTestOutboundConfig {
    pub fn interval_duration(&self) -> anyhow::Result<std::time::Duration> {
        parse_duration(&self.interval)
    }

    pub fn idle_timeout_duration(&self) -> anyhow::Result<std::time::Duration> {
        parse_duration(&self.idle_timeout)
    }
}

// ── 公共 TLS 配置 ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// SNI，默认等于 server 字段
    #[serde(default)]
    pub server_name: Option<String>,

    /// 跳过证书验证（不安全，仅调试用）
    #[serde(default)]
    pub insecure: bool,

    /// 自定义 CA 证书路径（PEM）
    #[serde(default)]
    pub ca_path: Option<String>,

    /// ALPN 列表，默认由协议层决定
    #[serde(default)]
    pub alpn: Vec<String>,

    /// 最低 TLS 版本
    #[serde(default)]
    pub min_version: Option<TlsVersion>,

    /// 最高 TLS 版本
    #[serde(default)]
    pub max_version: Option<TlsVersion>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            server_name: None,
            insecure: false,
            ca_path: None,
            alpn: vec![],
            min_version: None,
            max_version: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsVersion {
    #[serde(rename = "1.2")]
    Tls12,
    #[serde(rename = "1.3")]
    Tls13,
}

fn default_ws_path() -> String {
    "/".into()
}
fn default_vmess_security() -> String {
    "auto".into()
}
fn default_tuic_congestion_control() -> String {
    "cubic".into()
}
fn default_tuic_udp_relay_mode() -> String {
    "native".into()
}
fn default_true() -> bool {
    true
}
fn default_disabled_tls() -> TlsConfig {
    TlsConfig {
        enabled: false,
        ..Default::default()
    }
}
fn default_url_test_url() -> String {
    "https://www.gstatic.com/generate_204".into()
}
fn default_url_test_interval() -> String {
    "3m".into()
}
fn default_url_test_idle_timeout() -> String {
    "30m".into()
}

/// 内部使用的 REALITY 拨号配置，由 VlessTlsConfig + RealityConfig 组合而来，
/// 传递给 `reality::reality_connect()`。不对应任何 JSON 字段。
#[derive(Debug, Clone)]
pub struct RealityDialConfig {
    pub public_key: String,
    pub short_id: String,
    pub server_name: Option<String>,
    pub server: String,
    pub alpn: Vec<String>,
    pub fingerprint: String,
}

pub fn parse_duration(s: &str) -> anyhow::Result<std::time::Duration> {
    let s = s.trim();
    anyhow::ensure!(!s.is_empty(), "duration cannot be empty");
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    anyhow::ensure!(!num.is_empty(), "duration missing number: '{s}'");
    let value: u64 = num.parse()?;
    let seconds = match unit {
        "" | "s" => value,
        "m" => value * 60,
        "h" => value * 60 * 60,
        "d" => value * 24 * 60 * 60,
        _ => anyhow::bail!("unsupported duration unit in '{s}'"),
    };
    Ok(std::time::Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_vless() {
        // sing-box 格式：tls 字段 + transport 可选
        let v = json!({
            "type": "vless",
            "tag": "proxy",
            "server": "example.com",
            "server_port": 443,
            "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "transport": {
                "type": "ws",
                "path": "/ws",
                "headers": { "Host": "example.com" }
            },
            "tls": {
                "enabled": true,
                "server_name": "example.com",
                "insecure": false
            }
        });
        let ob: OutboundConfig = serde_json::from_value(v).unwrap();
        assert_eq!(ob.tag(), "proxy");
        if let OutboundConfig::Vless(c) = ob {
            assert_eq!(c.server, "example.com");
            let tls = c.tls.as_ref().expect("expected tls");
            assert!(tls.enabled);
            assert_eq!(tls.server_name.as_deref(), Some("example.com"));
            assert!(!tls.insecure);
            let Some(VlessTransportConfig::Ws(ref ws)) = c.transport else {
                panic!("expected ws transport");
            };
            assert_eq!(ws.path, "/ws");
            assert_eq!(ws.headers.get("Host").unwrap(), "example.com");
        }
    }

    #[test]
    fn parse_vless_reality() {
        // sing-box 格式：reality 嵌套在 tls 内，transport 可省略
        let v = json!({
            "type": "vless",
            "tag": "reality-proxy",
            "server": "1.2.3.4",
            "server_port": 443,
            "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "tls": {
                "enabled": true,
                "server_name": "www.example.com",
                "reality": {
                    "enabled": true,
                    "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "short_id": "0123456789abcdef"
                }
            }
        });
        let ob: OutboundConfig = serde_json::from_value(v).unwrap();
        assert_eq!(ob.tag(), "reality-proxy");
        if let OutboundConfig::Vless(c) = ob {
            // transport 缺省时为 None（裸 TCP）
            assert!(c.transport.is_none());
            let tls = c.tls.as_ref().expect("expected tls");
            let reality = tls.reality.as_ref().expect("expected reality");
            assert_eq!(reality.short_id, "0123456789abcdef");
            assert_eq!(tls.server_name.as_deref(), Some("www.example.com"));
        } else {
            panic!("expected vless outbound");
        }
    }

    #[test]
    fn parse_vmess_ws_tcp_tls_options() {
        let ws: OutboundConfig = serde_json::from_value(json!({
            "type": "vmess",
            "tag": "vmess-ws-tls",
            "server": "example.com",
            "server_port": 443,
            "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "security": "auto",
            "transport": {
                "type": "ws",
                "path": "/vmess",
                "headers": { "Host": "example.com" }
            },
            "tls": { "enabled": true, "server_name": "example.com" }
        }))
        .unwrap();
        if let OutboundConfig::Vmess(c) = ws {
            assert!(c.tls.enabled);
            assert!(matches!(c.transport, VmessTransportConfig::Ws(_)));
        } else {
            panic!("expected vmess config");
        }

        let tcp: OutboundConfig = serde_json::from_value(json!({
            "type": "vmess",
            "tag": "vmess-tcp",
            "server": "example.com",
            "server_port": 80,
            "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "transport": { "type": "tcp" },
            "tls": { "enabled": false }
        }))
        .unwrap();
        if let OutboundConfig::Vmess(c) = tcp {
            assert!(!c.tls.enabled);
            assert!(matches!(c.transport, VmessTransportConfig::Tcp));
        }
    }

    #[test]
    fn parse_tuic() {
        let ob: OutboundConfig = serde_json::from_value(json!({
            "type": "tuic",
            "tag": "tuic",
            "server": "example.com",
            "server_port": 443,
            "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "password": "secret",
            "congestion_control": "bbr",
            "udp_relay_mode": "native",
            "tls": { "enabled": true, "server_name": "example.com" }
        }))
        .unwrap();
        if let OutboundConfig::Tuic(c) = ob {
            assert_eq!(c.congestion_control, "bbr");
            assert!(c.tls.enabled);
        } else {
            panic!("expected tuic config");
        }
    }

    #[test]
    fn parse_hysteria2() {
        let v = json!({
            "type": "hysteria2",
            "tag": "hy2",
            "server": "example.com",
            "server_port": 443,
            "password": "secret",
            "up_mbps": 50,
            "down_mbps": 200
        });
        let ob: OutboundConfig = serde_json::from_value(v).unwrap();
        assert_eq!(ob.tag(), "hy2");
    }

    #[test]
    fn parse_direct_block() {
        let direct: OutboundConfig =
            serde_json::from_value(json!({ "type": "direct", "tag": "direct" })).unwrap();
        let block: OutboundConfig =
            serde_json::from_value(json!({ "type": "block", "tag": "block" })).unwrap();
        assert_eq!(direct.tag(), "direct");
        assert_eq!(block.tag(), "block");
    }

    #[test]
    fn parse_socks_defaults() {
        // 最简配置：仅必填字段，version 缺省 → SOCKS5，无认证
        let ob: OutboundConfig = serde_json::from_value(json!({
            "type": "socks",
            "tag": "socks-out",
            "server": "127.0.0.1",
            "server_port": 1080
        }))
        .unwrap();
        assert_eq!(ob.tag(), "socks-out");
        if let OutboundConfig::Socks(c) = ob {
            assert_eq!(c.server, "127.0.0.1");
            assert_eq!(c.server_port, 1080);
            assert!(c.version.is_none());
            assert!(c.username.is_none());
            assert!(c.password.is_none());
            assert_eq!(c.parsed_version().unwrap(), SocksVersion::V5);
        } else {
            panic!("expected socks config");
        }
    }

    #[test]
    fn parse_socks5_with_auth() {
        let ob: OutboundConfig = serde_json::from_value(json!({
            "type": "socks",
            "tag": "socks5-auth",
            "server": "proxy.example.com",
            "server_port": 1080,
            "version": "5",
            "username": "alice",
            "password": "s3cr3t"
        }))
        .unwrap();
        if let OutboundConfig::Socks(c) = ob {
            assert_eq!(c.parsed_version().unwrap(), SocksVersion::V5);
            assert_eq!(c.username.as_deref(), Some("alice"));
            assert_eq!(c.password.as_deref(), Some("s3cr3t"));
        } else {
            panic!("expected socks config");
        }
    }

    #[test]
    fn parse_socks4a() {
        let ob: OutboundConfig = serde_json::from_value(json!({
            "type": "socks",
            "tag": "socks4a-out",
            "server": "127.0.0.1",
            "server_port": 1080,
            "version": "4a"
        }))
        .unwrap();
        if let OutboundConfig::Socks(c) = ob {
            assert_eq!(c.parsed_version().unwrap(), SocksVersion::V4a);
        } else {
            panic!("expected socks config");
        }
    }

    #[test]
    fn parse_selector_and_url_test() {
        let selector: OutboundConfig = serde_json::from_value(json!({
            "type": "selector",
            "tag": "🚀 节点选择",
            "outbounds": ["自动选择", "香港节点 01", "direct"],
            "default": "自动选择"
        }))
        .unwrap();
        assert_eq!(selector.tag(), "🚀 节点选择");
        if let OutboundConfig::Selector(c) = selector {
            assert_eq!(c.outbounds.len(), 3);
            assert_eq!(c.r#default.as_deref(), Some("自动选择"));
        } else {
            panic!("expected selector config");
        }

        let url_test: OutboundConfig = serde_json::from_value(json!({
            "type": "url-test",
            "tag": "自动选择",
            "outbounds": ["香港节点 01", "台湾节点 01", "美国节点 01"],
            "url": "https://www.gstatic.com/generate_204",
            "interval": "3m",
            "idle_timeout": "30m",
            "tolerance": 50
        }))
        .unwrap();
        assert_eq!(url_test.tag(), "自动选择");
        if let OutboundConfig::UrlTest(c) = url_test {
            assert_eq!(c.interval_duration().unwrap().as_secs(), 180);
            assert_eq!(c.idle_timeout_duration().unwrap().as_secs(), 1800);
            assert_eq!(c.tolerance, 50);
        } else {
            panic!("expected url-test config");
        }
    }

    #[test]
    fn bandwidth_mbps_to_bps() {
        // 与 sing-box 对齐：整数 Mbps → bytes/s
        assert_eq!(mbps_to_bps(100), 12_500_000);
        assert_eq!(mbps_to_bps(0), 0);
        assert_eq!(mbps_to_bps(1000), 125_000_000);
    }

    #[test]
    fn tls_defaults() {
        let tls = TlsConfig::default();
        assert!(tls.enabled);
        assert!(!tls.insecure);
        assert!(tls.server_name.is_none());
    }
}
