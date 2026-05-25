//! 规则集注册表：供 Clash API 查询规则数量、更新时间，并触发 remote 规则集刷新。
//!
//! 与 `Router` 解耦：Router 持有只读的编译后规则集用于路由决策，
//! Registry 持有可读写的元数据，允许运行时通过 API 触发重新下载。
//! （注意：reload 后路由规则本身不会热更新，需要重启生效；
//!  此功能主要用于更新缓存文件，下次重启时加载最新规则集。）

use std::sync::Arc;

use tokio::sync::RwLock;

use crate::{
    config::route::{RouteConfig, RuleSetType},
    router::RuleSetMeta,
};

// ── 公开结构 ──────────────────────────────────────────────────────────────────

pub struct RuleSetRegistry {
    inner: RwLock<RegistryInner>,
    /// 原始配置，供 reload 时查找 url / path
    route_config: RouteConfig,
}

struct RegistryInner {
    /// tag → 元数据
    meta: std::collections::HashMap<String, RuleSetMeta>,
}

impl RuleSetRegistry {
    /// 从 Router 的 ruleset_meta 初始化
    pub fn from_router_meta(
        route_config: RouteConfig,
        meta: std::collections::HashMap<String, RuleSetMeta>,
    ) -> Arc<Self> {
        Arc::new(Self {
            inner: RwLock::new(RegistryInner { meta }),
            route_config,
        })
    }

    /// 返回所有规则集的元数据快照（克隆，开销低）
    pub async fn snapshot(&self) -> std::collections::HashMap<String, RuleSetMeta> {
        self.inner.read().await.meta.clone()
    }

    /// 触发指定 remote 规则集重新下载，更新本地缓存文件，并刷新元数据。
    /// 失败时返回错误描述。
    pub async fn reload_remote(&self, tag: &str) -> anyhow::Result<()> {
        let rs_ref = self
            .route_config
            .rule_set
            .iter()
            .find(|r| r.tag == tag)
            .ok_or_else(|| anyhow::anyhow!("rule_set '{tag}' not found"))?
            .clone();

        if rs_ref.r#type != RuleSetType::Remote {
            anyhow::bail!("rule_set '{tag}' is not remote, cannot update");
        }

        let url = rs_ref
            .url
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("rule_set '{tag}': missing url"))?
            .to_string();

        let tag_owned = tag.to_string();
        let path = rs_ref.path.clone();

        // 阻塞下载放到专用线程池，避免阻塞 tokio 工作线程
        let data = tokio::task::spawn_blocking(move || download_bytes(&url, &tag_owned))
            .await
            .map_err(|e| anyhow::anyhow!("spawn_blocking panicked: {e}"))??;

        // 覆盖磁盘缓存
        if let Some(ref p) = path {
            if let Some(parent) = std::path::Path::new(p).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Err(e) = std::fs::write(p, &data) {
                tracing::warn!(tag, path = p, err = %e, "rule_set: failed to write disk cache");
            } else {
                tracing::debug!(tag, path = p, "rule_set: disk cache updated");
            }
        }

        // 计算新的规则数量
        let loaded = crate::ruleset::LoadedRuleSet::from_bytes(&data)
            .map_err(|e| anyhow::anyhow!("rule_set '{tag}': parse error: {e}"))?;
        let rs = crate::ruleset::RuleSet::from_loaded(loaded)
            .map_err(|e| anyhow::anyhow!("rule_set '{tag}': compile error: {e}"))?;
        let rule_count = rs.rule_count();

        let updated_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        {
            let mut guard = self.inner.write().await;
            guard.meta.insert(
                tag.to_string(),
                RuleSetMeta {
                    rule_count,
                    updated_at_ms,
                },
            );
        }

        tracing::info!(tag, rule_count, "rule_set: remote reload done");
        Ok(())
    }
}

// ── 下载辅助（同步，供 spawn_blocking 使用）──────────────────────────────────

fn download_bytes(url: &str, tag: &str) -> anyhow::Result<Vec<u8>> {
    use std::io::Read;
    let resp = ureq::get(url)
        .call()
        .map_err(|e| anyhow::anyhow!("rule_set '{tag}': download failed from '{url}': {e}"))?;
    let mut buf = Vec::new();
    resp.into_reader()
        .read_to_end(&mut buf)
        .map_err(|e| anyhow::anyhow!("rule_set '{tag}': failed to read response body: {e}"))?;
    Ok(buf)
}
