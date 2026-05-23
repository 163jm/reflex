//! Provider 配置：从远端 URL 或本地文件订阅节点列表。

use serde::{Deserialize, Serialize};

/// 单个 provider 的顶层配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "type", rename_all = "lowercase")]
pub enum ProviderConfig {
    Remote(RemoteProviderConfig),
    Local(LocalProviderConfig),
}

impl ProviderConfig {
    pub fn tag(&self) -> &str {
        match self {
            Self::Remote(c) => &c.tag,
            Self::Local(c) => &c.tag,
        }
    }
}

/// 远端订阅 provider：从 URL 下载节点列表，定时更新，本地缓存。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteProviderConfig {
    /// Provider 唯一标识，在 outbound 里通过此 tag 引用。
    pub tag: String,

    /// 订阅链接 URL。
    pub url: String,

    /// 本地缓存文件路径（相对于配置文件目录或绝对路径）。
    /// 启动时优先从此文件加载，避免冷启动必须联网。
    /// 更新成功后自动写回此文件。
    #[serde(default)]
    pub path: Option<String>,

    /// HTTP 请求时使用的 User-Agent。
    /// 常见值：`clash.meta`、`sing-box`。
    #[serde(default = "default_user_agent")]
    pub user_agent: String,

    /// 定时更新间隔，如 `"12h"`、`"24h"`。默认 24 小时。
    #[serde(default = "default_update_interval")]
    pub update_interval: String,

    /// 健康检测配置（可选）。
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,
}

/// 本地文件 provider：从本地文件读取节点列表，不联网，不定时更新。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalProviderConfig {
    /// Provider 唯一标识。
    pub tag: String,

    /// 节点列表文件路径（Clash YAML 或 Sing-box JSON）。
    pub path: String,

    /// 健康检测配置（可选）。
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,
}

/// 健康检测配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheckConfig {
    /// 测速 URL，默认 `https://www.gstatic.com/generate_204`。
    #[serde(default = "default_health_check_url")]
    pub url: String,

    /// 检测间隔，如 `"10m"`、`"5m"`。默认 10 分钟。
    #[serde(default = "default_health_check_interval")]
    pub interval: String,

    /// 单次检测超时，如 `"5s"`、`"3s"`。默认 5 秒。
    #[serde(default = "default_health_check_timeout")]
    pub timeout: String,
}

/// outbound（selector / urltest）里对 provider 的引用及过滤配置。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ProviderRef {
    /// 引用的 provider tag 列表。
    #[serde(default)]
    pub tags: Vec<String>,

    /// 黑名单关键词（大小写不敏感包含匹配）：
    /// 节点名包含任意一个关键词 → 排除。先于 `filter` 执行。
    #[serde(default)]
    pub exclude_filter: Vec<String>,

    /// 白名单关键词（大小写不敏感包含匹配）：
    /// 节点名必须包含至少一个关键词才保留。为空时保留全部（黑名单过滤后）。
    #[serde(default)]
    pub filter: Vec<String>,
}

impl ProviderRef {
    /// 对节点名应用过滤规则，返回是否应保留该节点。
    pub fn matches(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();

        // 1. 黑名单：命中任意一个关键词则排除
        for kw in &self.exclude_filter {
            if name_lower.contains(&kw.to_lowercase()) {
                return false;
            }
        }

        // 2. 白名单：为空时保留全部，否则必须命中至少一个
        if self.filter.is_empty() {
            return true;
        }
        self.filter
            .iter()
            .any(|kw| name_lower.contains(&kw.to_lowercase()))
    }
}

// ── 默认值 ────────────────────────────────────────────────────────────────────

fn default_user_agent() -> String {
    "clash.meta".to_string()
}

fn default_update_interval() -> String {
    "24h".to_string()
}

fn default_health_check_url() -> String {
    "https://www.gstatic.com/generate_204".to_string()
}

fn default_health_check_interval() -> String {
    "10m".to_string()
}

fn default_health_check_timeout() -> String {
    "5s".to_string()
}

// ── 时间解析工具 ──────────────────────────────────────────────────────────────

pub fn parse_duration(s: &str) -> anyhow::Result<std::time::Duration> {
    let s = s.trim();
    if let Some(h) = s.strip_suffix('h') {
        let n: u64 = h.trim().parse()?;
        return Ok(std::time::Duration::from_secs(n * 3600));
    }
    if let Some(m) = s.strip_suffix('m') {
        let n: u64 = m.trim().parse()?;
        return Ok(std::time::Duration::from_secs(n * 60));
    }
    if let Some(sec) = s.strip_suffix('s') {
        let n: u64 = sec.trim().parse()?;
        return Ok(std::time::Duration::from_secs(n));
    }
    anyhow::bail!("invalid duration: '{s}' (expected format: 12h / 10m / 5s)")
}

impl RemoteProviderConfig {
    pub fn update_interval_duration(&self) -> anyhow::Result<std::time::Duration> {
        parse_duration(&self.update_interval)
    }
}

impl HealthCheckConfig {
    pub fn interval_duration(&self) -> anyhow::Result<std::time::Duration> {
        parse_duration(&self.interval)
    }

    pub fn timeout_duration(&self) -> anyhow::Result<std::time::Duration> {
        parse_duration(&self.timeout)
    }
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_remote_provider() {
        let json = r#"{
            "type": "remote",
            "tag": "my-sub",
            "url": "https://example.com/sub",
            "path": "cache/my-sub.yaml",
            "user_agent": "clash.meta",
            "update_interval": "12h",
            "health_check": {
                "url": "https://www.gstatic.com/generate_204",
                "interval": "10m",
                "timeout": "5s"
            }
        }"#;
        let p: ProviderConfig = serde_json::from_str(json).unwrap();
        assert_eq!(p.tag(), "my-sub");
        let ProviderConfig::Remote(r) = &p else {
            panic!()
        };
        assert_eq!(r.update_interval_duration().unwrap().as_secs(), 12 * 3600);
        let hc = r.health_check.as_ref().unwrap();
        assert_eq!(hc.interval_duration().unwrap().as_secs(), 600);
        assert_eq!(hc.timeout_duration().unwrap().as_secs(), 5);
    }

    #[test]
    fn parse_local_provider() {
        let json = r#"{"type": "local", "tag": "my-local", "path": "proxies.yaml"}"#;
        let p: ProviderConfig = serde_json::from_str(json).unwrap();
        assert_eq!(p.tag(), "my-local");
    }

    #[test]
    fn provider_ref_filter() {
        let r = ProviderRef {
            tags: vec!["my-sub".into()],
            exclude_filter: vec!["过期".into(), "剩余流量".into()],
            filter: vec!["日本".into(), "JP".into()],
        };
        // 命中黑名单 → 排除
        assert!(!r.matches("过期节点"));
        // 命中白名单 → 保留
        assert!(r.matches("日本 01"));
        assert!(r.matches("JP-Tokyo"));
        // 不在白名单 → 排除
        assert!(!r.matches("美国 01"));
        // 大小写不敏感
        assert!(r.matches("jp-01"));
    }

    #[test]
    fn provider_ref_no_filter() {
        let r = ProviderRef {
            tags: vec!["my-sub".into()],
            ..Default::default()
        };
        // 无过滤条件，保留全部
        assert!(r.matches("任意节点名"));
        assert!(r.matches("过期节点"));
    }

    #[test]
    fn provider_ref_exclude_only() {
        let r = ProviderRef {
            tags: vec!["my-sub".into()],
            exclude_filter: vec!["过期".into()],
            filter: vec![],
        };
        assert!(!r.matches("过期节点"));
        assert!(r.matches("日本 01"));
        assert!(r.matches("美国 01"));
    }
}
