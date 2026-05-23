//! 全局配置项

use serde::{Deserialize, Serialize};

/// 全局选项，与 dns / log / inbounds 等平级。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GlobalConfig {
    /// 是否允许 IPv6 流量流经核心。
    ///
    /// - `true`（默认）：IPv6 正常处理，DNS 解析行为由 `dns.strategy` 控制。
    /// - `false`：完全屏蔽 IPv6，DNS 仅发 A 记录查询，`dns.strategy` 此时无效。
    #[serde(default = "default_true")]
    pub ipv6: bool,

    /// 出站 socket 的 SO_MARK 值（Linux 专用），0 表示不设置。
    /// 常用于配合 ip rule fwmark 实现策略路由，避免代理流量回环。
    #[serde(default)]
    pub routing_mark: u32,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            ipv6: true,
            routing_mark: 0,
        }
    }
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_ipv6_true() {
        let g = GlobalConfig::default();
        assert!(g.ipv6);
        assert_eq!(g.routing_mark, 0);
    }

    #[test]
    fn parse_global_fields() {
        let v: GlobalConfig =
            serde_json::from_str(r#"{"ipv6": false, "routing_mark": 100}"#).unwrap();
        assert!(!v.ipv6);
        assert_eq!(v.routing_mark, 100);
    }

    #[test]
    fn parse_empty_global() {
        let v: GlobalConfig = serde_json::from_str(r#"{}"#).unwrap();
        assert!(v.ipv6);
        assert_eq!(v.routing_mark, 0);
    }
}
