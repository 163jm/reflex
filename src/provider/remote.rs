//! 远端订阅 Provider：下载、缓存、定时更新。

use std::{path::PathBuf, sync::Arc, time::Duration};

use tokio::time;
use tracing::{debug, info, warn};

use crate::config::provider::RemoteProviderConfig;

use super::ProviderManager;

/// 启动远端 provider：
/// 1. 优先从缓存文件加载
/// 2. 若无缓存则立即下载
/// 3. 后台定时更新
pub async fn start_remote_provider(
    config: RemoteProviderConfig,
    manager: Arc<ProviderManager>,
    config_dir: PathBuf,
) {
    let tag = config.tag.clone();
    let update_interval = config
        .update_interval_duration()
        .unwrap_or(Duration::from_secs(24 * 3600));
    let cache_path = config.path.as_ref().map(|p| resolve_path(&config_dir, p));

    // 1. 尝试从缓存加载
    let loaded_from_cache = if let Some(ref path) = cache_path {
        match std::fs::read(path) {
            Ok(bytes) => match super::parser::parse_auto(&bytes) {
                Ok(nodes) => {
                    info!(provider = %tag, path = ?path, nodes = nodes.len(), "loaded from cache");
                    manager.update_nodes(&tag, nodes);
                    true
                }
                Err(e) => {
                    warn!(provider = %tag, err = %e, "cache parse failed, will download");
                    false
                }
            },
            Err(_) => false,
        }
    } else {
        false
    };

    // 2. 若无缓存，立即下载一次
    if !loaded_from_cache {
        match fetch_and_update(&config, &manager, cache_path.as_deref()).await {
            Ok(_) => {}
            Err(e) => {
                warn!(provider = %tag, err = %e, "initial fetch failed");
            }
        }
    }

    // 3. 后台定时更新
    let config = Arc::new(config);
    tokio::spawn(async move {
        let mut ticker = time::interval(update_interval);
        ticker.tick().await; // 跳过立即触发的第一次
        loop {
            ticker.tick().await;
            debug!(provider = %config.tag, "scheduled update");
            match fetch_and_update(&config, &manager, cache_path.as_deref()).await {
                Ok(_) => {}
                Err(e) => {
                    warn!(provider = %config.tag, err = %e, "scheduled update failed");
                }
            }
        }
    });
}

async fn fetch_and_update(
    config: &RemoteProviderConfig,
    manager: &ProviderManager,
    cache_path: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    let bytes = download(&config.url, &config.user_agent).await?;

    // 写缓存
    if let Some(path) = cache_path {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Err(e) = std::fs::write(path, &bytes) {
            warn!(provider = %config.tag, err = %e, "failed to write cache");
        }
    }

    let nodes = super::parser::parse_auto(&bytes)?;
    info!(provider = %config.tag, nodes = nodes.len(), "fetched from remote");
    manager.update_nodes(&config.tag, nodes);
    Ok(())
}

async fn download(url: &str, user_agent: &str) -> anyhow::Result<Vec<u8>> {
    let client = reqwest::Client::builder()
        .user_agent(user_agent)
        .timeout(Duration::from_secs(30))
        .build()?;

    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("download failed: {e}"))?;

    if !resp.status().is_success() {
        anyhow::bail!("download HTTP {}", resp.status());
    }

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| anyhow::anyhow!("read body failed: {e}"))?;

    Ok(bytes.to_vec())
}

/// 启动本地 provider：只读一次文件，不更新。
pub fn start_local_provider(
    config: crate::config::provider::LocalProviderConfig,
    manager: Arc<ProviderManager>,
    config_dir: PathBuf,
) {
    let path = resolve_path(&config_dir, &config.path);
    match std::fs::read(&path) {
        Ok(bytes) => match super::parser::parse_auto(&bytes) {
            Ok(nodes) => {
                info!(provider = %config.tag, path = ?path, nodes = nodes.len(), "local provider loaded");
                manager.update_nodes(&config.tag, nodes);
            }
            Err(e) => {
                warn!(provider = %config.tag, path = ?path, err = %e, "local provider parse failed");
            }
        },
        Err(e) => {
            warn!(provider = %config.tag, path = ?path, err = %e, "local provider read failed");
        }
    }
}

fn resolve_path(config_dir: &std::path::Path, p: &str) -> PathBuf {
    let path = PathBuf::from(p);
    if path.is_absolute() {
        path
    } else {
        config_dir.join(path)
    }
}
