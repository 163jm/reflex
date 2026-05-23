use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    /// 路由规则，顺序匹配，第一条命中生效
    #[serde(default)]
    pub rules: Vec<RouteRuleConfig>,

    /// 所有规则未命中时的默认出站 tag
    pub r#final: String,

    /// 规则集声明（local 或 remote）
    #[serde(default)]
    pub rule_set: Vec<RuleSetRef>,

    /// 是否对 DNS 响应中的 IP 也做路由（用于 fake-ip 或 IP 分流）
    #[serde(default)]
    pub resolve_dns: bool,
}

// ── Rule ─────────────────────────────────────────────────────────────────────

/// 一条路由规则，所有非空条件之间是 AND 语义，
/// 同一条件内多个值是 OR 语义。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRuleConfig {
    // ── 来源条件 ──────────────────────────────────────────────
    /// 来自指定入站 tag
    #[serde(default)]
    pub inbound: Vec<String>,

    /// 网络类型过滤
    #[serde(default)]
    pub network: Option<NetworkFilter>,

    // ── 目标条件 ──────────────────────────────────────────────
    /// 命中的 ruleset tag（OR），同时支持域名和 IP 规则集
    #[serde(default)]
    pub ruleset: Vec<String>,

    /// 内联精确域名（OR）
    #[serde(default)]
    pub domain: Vec<String>,

    /// 内联域名后缀（OR）
    #[serde(default)]
    pub domain_suffix: Vec<String>,

    /// 内联域名关键词（OR）
    #[serde(default)]
    pub domain_keyword: Vec<String>,

    /// 内联 IP CIDR（OR），支持 v4 和 v6
    #[serde(default)]
    pub ip_cidr: Vec<String>,

    /// 目标端口过滤（OR），支持单端口和范围，如 [80, 443, "8000-9000"]
    #[serde(default)]
    pub port: Vec<PortFilter>,

    /// 目标端口范围（备用写法，与 port 字段合并处理）
    #[serde(default)]
    pub port_range: Vec<String>,

    // ── 嗅探 ─────────────────────────────────────────────────
    /// 命中本规则时先对 TCP 流做协议嗅探，
    /// 用嗅探结果更新目标域名后重新路由。
    /// 通常配合「无条件 catch-all」规则置于规则链最前面使用。
    #[serde(default)]
    pub sniff: bool,

    /// 嗅探超时（毫秒），0 表示使用默认值（300 ms）
    #[serde(default)]
    pub sniff_timeout_ms: u64,

    /// 指定启用的嗅探协议列表，如 `["tls", "http", "quic", "ssh", "bittorrent"]`。
    /// 省略或为空时使用默认列表（tls/http/quic/ssh/bittorrent）。
    /// 支持的值：`"tls"`, `"http"`, `"quic"`, `"ssh"`, `"bittorrent"`（或 `"bt"`）。
    #[serde(default)]
    pub sniff_type: Vec<String>,

    /// 嗅探到域名后是否覆盖目标地址（默认 false）。
    /// 设为 true 时将连接目标地址替换为嗅探到的域名（适用于 FakeIP 模式）；
    /// 设为 false 时仅将嗅探结果用于路由规则匹配，目标地址保持不变。
    #[serde(default)]
    pub sniff_override_destination: bool,

    /// 嗅探到的应用层协议过滤（OR），如 `["dns"]`。
    /// 匹配由 DNS inbound 进入或嗅探识别出的协议名称。
    /// 目前支持的值：`"dns"`。
    #[serde(default)]
    pub protocol: Vec<String>,

    // ── DNS 解析（用于域名→IP 后继续匹配后续 IP 规则）────────────
    /// 将本规则的动作设为 resolve：遇到此规则时，若目标是域名，
    /// 先用内部 DNS 将其解析为 IP，然后继续向后匹配（跳过所有 resolve 规则）。
    ///
    /// 典型用法：放在域名规则集与 IP 规则集之间，使域名流量在未被前面域名
    /// 规则命中时先解析成 IP，再让后续 IP 规则集继续命中。
    ///
    /// ```json
    /// { "resolve": true }
    /// { "resolve": true, "server": "dns-domestic" }
    /// ```
    ///
    /// `server`：可选，指定用于解析的 DNS server tag（必须在 `dns.servers` 中声明）。
    /// 不填则使用默认 DNS 服务器。
    ///
    /// 设为 true 时 `outbound` 字段被忽略。
    #[serde(default)]
    pub resolve: bool,

    /// 解析时使用的 DNS server tag（选填，仅在 `resolve = true` 时生效）。
    #[serde(default, rename = "server")]
    pub resolve_server: Option<String>,

    // ── DNS 劫持 ──────────────────────────────────────────────
    /// 将本规则的动作设为 hijack-dns（等价于 sing-box 的 `"action": "hijack-dns"`）。
    ///
    /// **必须**配合至少一个匹配条件（`inbound`、`protocol`、`network`、端口等）
    /// 一起使用，否则配置加载时报错。
    ///
    /// 典型用法：
    /// - `{"hijack_dns": true, "protocol": ["dns"]}` —— 劫持所有嗅探为 DNS 协议的流量
    /// - `{"hijack_dns": true, "inbound": ["dns-in"]}` —— 劫持来自 dns-in 入站的流量
    ///
    /// 设为 true 时 `outbound` 字段被忽略，action 固定为交给 DNS 模块处理。
    #[serde(default)]
    pub hijack_dns: bool,

    // ── 动作 ─────────────────────────────────────────────────
    /// 目标 outbound tag，特殊值 "dns-out" 表示交给 DNS 模块。
    /// 当 `sniff = true` 或 `hijack_dns = true` 时该字段可留空。
    #[serde(default)]
    pub outbound: String,
}

impl RouteRuleConfig {
    /// 是否有任何匹配条件（全空的规则无意义）
    pub fn has_conditions(&self) -> bool {
        !self.inbound.is_empty()
            || self.network.is_some()
            || !self.protocol.is_empty()
            || !self.ruleset.is_empty()
            || !self.domain.is_empty()
            || !self.domain_suffix.is_empty()
            || !self.domain_keyword.is_empty()
            || !self.ip_cidr.is_empty()
            || !self.port.is_empty()
            || !self.port_range.is_empty()
    }
}

// ── RuleSet 引用 ──────────────────────────────────────────────────────────────

/// 规则集来源类型
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleSetType {
    /// 本地文件，必须配合 `path` 字段使用
    Local,
    /// 远程 URL，必须配合 `url` 字段使用；可选填 `path` 作为本地缓存路径
    Remote,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSetRef {
    /// 在 rules 中引用的名字
    pub tag: String,

    /// 来源类型：`"local"` 或 `"remote"`
    pub r#type: RuleSetType,

    /// 本地文件路径。
    /// - `type = "local"` 时**必填**，指定规则集文件位置。
    /// - `type = "remote"` 时**选填**，作为下载后的本地缓存路径；
    ///   不填则缓存到 cache_file（若未启用则仅驻留内存）。
    #[serde(default)]
    pub path: Option<String>,

    /// 远程规则集 URL（`type = "remote"` 时**必填**）。
    #[serde(default)]
    pub url: Option<String>,

    /// 用于下载远程规则集的出站 tag（选填）。
    /// 填写时通过该出站下载，无法下载则报错；不填则直连下载。
    #[serde(default)]
    pub download_detour: Option<String>,
}

// ── 辅助类型 ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkFilter {
    Tcp,
    Udp,
}

/// 端口过滤：可以是数字或 "start-end" 字符串，用自定义反序列化处理。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortFilter(pub u16, pub u16); // (start, end)，单端口则 start == end

impl PortFilter {
    pub fn contains(&self, port: u16) -> bool {
        port >= self.0 && port <= self.1
    }
}

impl<'de> Deserialize<'de> for PortFilter {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = PortFilter;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "a port number or a range string like \"8000-9000\"")
            }
            // JSON 数字
            fn visit_u64<E: Error>(self, v: u64) -> Result<Self::Value, E> {
                if v > 65535 {
                    return Err(E::custom(format!("port {v} out of range")));
                }
                Ok(PortFilter(v as u16, v as u16))
            }
            // JSON 字符串 "8000-9000"
            fn visit_str<E: Error>(self, v: &str) -> Result<Self::Value, E> {
                if let Some((s, e)) = v.split_once('-') {
                    let start: u16 = s.trim().parse().map_err(E::custom)?;
                    let end: u16 = e.trim().parse().map_err(E::custom)?;
                    if start > end {
                        return Err(E::custom(format!("invalid range: {v}")));
                    }
                    Ok(PortFilter(start, end))
                } else {
                    let p: u16 = v.trim().parse().map_err(E::custom)?;
                    Ok(PortFilter(p, p))
                }
            }
        }
        de.deserialize_any(Visitor)
    }
}

impl Serialize for PortFilter {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if self.0 == self.1 {
            s.serialize_u16(self.0)
        } else {
            s.serialize_str(&format!("{}-{}", self.0, self.1))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_route_config() {
        let v = json!({
            "rules": [
                {
                    "inbound": ["dns-in"],
                    "outbound": "dns-out"
                },
                {
                    "ruleset": ["geoip-cn", "geosite-cn"],
                    "outbound": "direct"
                },
                {
                    "network": "udp",
                    "port": [53],
                    "outbound": "dns-out"
                },
                {
                    "ip_cidr": ["192.168.0.0/16", "10.0.0.0/8"],
                    "outbound": "direct"
                },
                {
                    "domain_suffix": [".cn"],
                    "port": [80, 443, "8000-9000"],
                    "outbound": "direct"
                }
            ],
            "final": "proxy",
            "rule_set": [
                { "tag": "geosite-cn", "type": "local", "path": "/etc/proxy/rules/geosite-cn.rrs" },
                { "tag": "geoip-cn",   "type": "local", "path": "/etc/proxy/rules/geoip-cn.rrs"   }
            ]
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert_eq!(route.rules.len(), 5);
        assert_eq!(route.r#final, "proxy");
        assert_eq!(route.rule_set.len(), 2);
    }

    #[test]
    fn port_filter_number() {
        let pf: PortFilter = serde_json::from_value(json!(443)).unwrap();
        assert_eq!(pf, PortFilter(443, 443));
        assert!(pf.contains(443));
        assert!(!pf.contains(80));
    }

    #[test]
    fn port_filter_range_str() {
        let pf: PortFilter = serde_json::from_value(json!("8000-9000")).unwrap();
        assert_eq!(pf, PortFilter(8000, 9000));
        assert!(pf.contains(8000));
        assert!(pf.contains(8500));
        assert!(pf.contains(9000));
        assert!(!pf.contains(7999));
    }

    #[test]
    fn port_filter_invalid_range() {
        let r: Result<PortFilter, _> = serde_json::from_value(json!("9000-8000"));
        assert!(r.is_err());
    }

    #[test]
    fn rule_has_conditions() {
        let empty = RouteRuleConfig {
            inbound: vec![],
            network: None,
            protocol: vec![],
            ruleset: vec![],
            domain: vec![],
            domain_suffix: vec![],
            domain_keyword: vec![],
            ip_cidr: vec![],
            port: vec![],
            port_range: vec![],
            sniff: false,
            sniff_timeout_ms: 0,
            sniff_type: vec![],
            sniff_override_destination: false,
            resolve: false,
            resolve_server: None,
            hijack_dns: false,
            outbound: "direct".into(),
        };
        assert!(!empty.has_conditions());

        // hijack_dns 单独存在不算条件（会在 router 层报错）
        let hijack_only = RouteRuleConfig {
            hijack_dns: true,
            ..empty.clone()
        };
        assert!(!hijack_only.has_conditions());

        let with_ruleset = RouteRuleConfig {
            ruleset: vec!["geosite-cn".into()],
            ..empty.clone()
        };
        assert!(with_ruleset.has_conditions());

        let with_protocol = RouteRuleConfig {
            protocol: vec!["dns".into()],
            ..empty
        };
        assert!(with_protocol.has_conditions());
    }

    #[test]
    fn port_filter_serialize() {
        let single = PortFilter(443, 443);
        assert_eq!(serde_json::to_string(&single).unwrap(), "443");

        let range = PortFilter(8000, 9000);
        assert_eq!(serde_json::to_string(&range).unwrap(), "\"8000-9000\"");
    }
}
