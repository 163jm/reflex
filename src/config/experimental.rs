use serde::{Deserialize, Serialize};

/// 顶层 experimental 配置
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ExperimentalConfig {
    #[serde(default)]
    pub cache_file: Option<CacheFileConfig>,

    #[serde(default)]
    pub clash_api: Option<ClashApiConfig>,
}

/// cache_file 子配置
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheFileConfig {
    /// 是否启用缓存文件
    #[serde(default)]
    pub enabled: bool,

    /// redb 文件路径，默认 "cache.db"
    #[serde(default = "default_cache_path")]
    pub path: String,

    /// 是否持久化 fakeip ip↔domain 映射
    #[serde(default)]
    pub store_fakeip: bool,

    /// fakeip 记录过期天数，超过此天数未访问的记录在启动时清理，默认 7 天
    #[serde(default = "default_fakeip_ttl_days")]
    pub fakeip_ttl_days: u32,

    /// 是否持久化 DNS 缓存响应（跨重启保留）。
    /// false（默认）= 仅内存缓存；true = 内存 + redb 持久化双写。
    #[serde(default)]
    pub store_dns: bool,

    /// DNS 持久缓存后台清理间隔（秒），0 = 使用默认值 3600
    #[serde(default)]
    pub dns_cleanup_interval_secs: u64,
}

impl Default for CacheFileConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_cache_path(),
            store_fakeip: false,
            fakeip_ttl_days: default_fakeip_ttl_days(),
            store_dns: false,
            dns_cleanup_interval_secs: 0,
        }
    }
}

/// clash_api 子配置（兼容 Clash/Sing-Box 风格 external controller）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClashApiConfig {
    /// 是否启用 Clash API。配置了 clash_api 时默认启用。
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// 默认模式，兼容 Clash 的 rule / global / direct 命名。
    #[serde(default = "default_clash_mode")]
    pub default_mode: String,

    /// 模式列表，供 Dashboard 展示切换选项；默认包含 default_mode。
    #[serde(default)]
    pub mode_list: Vec<String>,

    /// HTTP API 监听地址，如 "127.0.0.1:9090" 或 "0.0.0.0:9090"。
    #[serde(default = "default_external_controller")]
    pub external_controller: String,

    /// API 认证密钥；为空则不验证。
    #[serde(default)]
    pub secret: String,

    /// 静态 Web UI 目录；为空则不提供 UI 文件。
    #[serde(default)]
    pub external_ui: Option<String>,
}

impl Default for ClashApiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_mode: default_clash_mode(),
            mode_list: vec![],
            external_controller: default_external_controller(),
            secret: String::new(),
            external_ui: None,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_clash_mode() -> String {
    "rule".to_string()
}

fn default_external_controller() -> String {
    "127.0.0.1:9090".to_string()
}

fn default_cache_path() -> String {
    "cache.db".to_string()
}

fn default_fakeip_ttl_days() -> u32 {
    7
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_full_experimental() {
        let v = json!({
            "cache_file": {
                "enabled": true,
                "path": "/var/lib/reflex/cache.db",
                "store_fakeip": true,
                "fakeip_ttl_days": 14
            },
            "clash_api": {
                "default_mode": "rule",
                "mode_list": ["rule", "global", "direct"],
                "external_controller": "0.0.0.0:9090",
                "secret": "test-secret",
                "external_ui": "ui"
            }
        });
        let cfg: ExperimentalConfig = serde_json::from_value(v).unwrap();
        let cf = cfg.cache_file.unwrap();
        assert!(cf.enabled);
        assert_eq!(cf.path, "/var/lib/reflex/cache.db");
        assert!(cf.store_fakeip);
        assert_eq!(cf.fakeip_ttl_days, 14);
        let clash_api = cfg.clash_api.unwrap();
        assert!(clash_api.enabled);
        assert_eq!(clash_api.default_mode, "rule");
        assert_eq!(clash_api.external_controller, "0.0.0.0:9090");
        assert_eq!(clash_api.external_ui.as_deref(), Some("ui"));
    }

    #[test]
    fn parse_minimal_cache_file() {
        let v = json!({ "cache_file": { "enabled": true } });
        let cfg: ExperimentalConfig = serde_json::from_value(v).unwrap();
        let cf = cfg.cache_file.unwrap();
        assert_eq!(cf.path, "cache.db");
        assert!(!cf.store_fakeip);
        assert_eq!(cf.fakeip_ttl_days, 7);
    }

    #[test]
    fn parse_minimal_clash_api() {
        let v = json!({ "clash_api": {} });
        let cfg: ExperimentalConfig = serde_json::from_value(v).unwrap();
        let clash_api = cfg.clash_api.unwrap();
        assert!(clash_api.enabled);
        assert_eq!(clash_api.default_mode, "rule");
        assert_eq!(clash_api.external_controller, "127.0.0.1:9090");
        assert!(clash_api.external_ui.is_none());
    }

    #[test]
    fn parse_empty_experimental() {
        let v = json!({});
        let cfg: ExperimentalConfig = serde_json::from_value(v).unwrap();
        assert!(cfg.cache_file.is_none());
        assert!(cfg.clash_api.is_none());
    }

    #[test]
    fn reject_unknown_fields() {
        let v = json!({ "unknown_key": true });
        assert!(serde_json::from_value::<ExperimentalConfig>(v).is_err());
    }
}
