//! 订阅格式自动检测入口。
//!
//! 检测顺序：
//! 1. JSON → 有 `outbounds` 数组 → Sing-box JSON
//! 2. YAML → 有 `proxies` 字段 → Clash YAML
//! 3. Base64 解码后重复 1-2
//! 4. 全部失败 → 报错

pub mod clash;
pub mod singbox;

use crate::config::outbound::OutboundConfig;

/// 自动检测格式并解析，返回 (原始节点名, OutboundConfig) 列表。
pub fn parse_auto(bytes: &[u8]) -> anyhow::Result<Vec<(String, OutboundConfig)>> {
    // 尝试直接解析
    if let Ok(result) = try_parse(bytes) {
        return Ok(result);
    }

    // 尝试 Base64 解码后解析
    let decoded = decode_base64(bytes)?;
    try_parse(&decoded)
        .map_err(|_| anyhow::anyhow!("unable to detect provider format (tried json, yaml, base64)"))
}

fn try_parse(bytes: &[u8]) -> anyhow::Result<Vec<(String, OutboundConfig)>> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| anyhow::anyhow!("content is not valid UTF-8"))?;

    // 1. JSON + outbounds → Sing-box
    if let Ok(nodes) = singbox::parse_singbox_json(text) {
        if !nodes.is_empty() {
            tracing::debug!(
                "provider format detected: sing-box json ({} nodes)",
                nodes.len()
            );
            return Ok(nodes);
        }
    }

    // 2. YAML + proxies → Clash
    if looks_like_yaml(text) {
        let nodes = clash::parse_clash_yaml(text)?;
        tracing::debug!(
            "provider format detected: clash yaml ({} nodes)",
            nodes.len()
        );
        return Ok(nodes);
    }

    anyhow::bail!("unrecognized format")
}

fn looks_like_yaml(text: &str) -> bool {
    // 快速启发：包含 "proxies:" 行
    text.lines()
        .any(|line| line.trim_start().starts_with("proxies:"))
}

fn decode_base64(bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    use base64::{engine::general_purpose, Engine};
    // 去除首尾空白（订阅常带换行）
    let trimmed = bytes
        .iter()
        .copied()
        .filter(|&b| !b.is_ascii_whitespace())
        .collect::<Vec<_>>();
    general_purpose::STANDARD
        .decode(&trimmed)
        .or_else(|_| general_purpose::URL_SAFE.decode(&trimmed))
        .map_err(|e| anyhow::anyhow!("base64 decode failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_clash_yaml() {
        let yaml = b"proxies:\n  - name: JP\n    type: hy2\n    server: jp.example.com\n    port: 443\n    password: pass\n";
        let nodes = parse_auto(yaml).unwrap();
        assert_eq!(nodes[0].0, "JP");
    }
}
