//! Sing-box JSON 订阅格式解析器。
//!
//! 解析顶层 `outbounds` 数组，过滤出真实节点（排除 selector/urltest/direct/block/dns），
//! 直接复用 Reflex 自身的 `OutboundConfig` 反序列化。

use crate::config::outbound::OutboundConfig;

/// 解析 Sing-box JSON 文本，返回 (节点名, OutboundConfig) 列表。
pub fn parse_singbox_json(text: &str) -> anyhow::Result<Vec<(String, OutboundConfig)>> {
    // 只需要 outbounds 字段
    let doc: SingBoxDoc = serde_json::from_str(text)
        .map_err(|e| anyhow::anyhow!("sing-box json parse error: {e}"))?;

    let result = doc
        .outbounds
        .into_iter()
        .filter(is_real_node)
        .map(|ob| (ob.tag().to_string(), ob))
        .collect();

    Ok(result)
}

#[derive(serde::Deserialize)]
struct SingBoxDoc {
    #[serde(default)]
    outbounds: Vec<OutboundConfig>,
}

/// 判断是否为真实节点（排除 meta outbound 类型）。
fn is_real_node(ob: &OutboundConfig) -> bool {
    !matches!(
        ob,
        OutboundConfig::Direct(_)
            | OutboundConfig::Block(_)
            | OutboundConfig::Selector(_)
            | OutboundConfig::UrlTest(_)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_singbox_outbounds() {
        let json = r#"{
            "outbounds": [
                {
                    "type": "vless",
                    "tag": "JP VLESS",
                    "server": "jp.example.com",
                    "server_port": 443,
                    "uuid": "12345678-1234-1234-1234-123456789abc",
                    "tls": { "enabled": true }
                },
                {
                    "type": "selector",
                    "tag": "proxy",
                    "outbounds": ["JP VLESS"]
                },
                {
                    "type": "direct",
                    "tag": "direct"
                }
            ]
        }"#;
        let nodes = parse_singbox_json(json).unwrap();
        // 只保留 vless，selector 和 direct 被过滤
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].0, "JP VLESS");
        assert!(matches!(nodes[0].1, OutboundConfig::Vless(_)));
    }
}
