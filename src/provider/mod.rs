//! Proxy Provider 管理器：负责加载、更新、去重命名节点，并通知订阅者。

pub mod health;
pub mod parser;
pub mod remote;

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
};

use tokio::sync::watch;
use tracing::info;

use crate::config::{
    outbound::OutboundConfig,
    provider::{ProviderConfig, ProviderRef},
};

// ── 公共类型 ──────────────────────────────────────────────────────────────────

/// 一个 provider 当前持有的节点列表（去重命名后）。
/// `Vec<(唯一tag, OutboundConfig)>`
pub type ProviderNodes = Vec<(String, OutboundConfig)>;

/// 变更通知：当某 provider 节点列表更新时广播。
pub type UpdateSender = watch::Sender<()>;
pub type UpdateReceiver = watch::Receiver<()>;

// ── ProviderManager ───────────────────────────────────────────────────────────

/// 管理所有 provider 的运行时状态。
///
/// - 每个 provider 有自己的 `watch` 通道，节点更新时发送通知。
/// - 节点去重命名在全局 tag 表 `global_tags` 里维护，跨所有 provider 共享。
pub struct ProviderManager {
    /// provider tag → 当前节点列表（已去重命名）
    nodes: RwLock<HashMap<String, ProviderNodes>>,
    /// 全局已使用的节点 tag 集合（用于去重命名）
    global_tags: RwLock<HashSet<String>>,
    /// provider tag → 更新通知发送端
    senders: HashMap<String, Arc<UpdateSender>>,
    /// provider tag → 更新通知接收端（供 outbound group 订阅）
    receivers: HashMap<String, UpdateReceiver>,
}

impl ProviderManager {
    pub fn new(configs: &[ProviderConfig]) -> Self {
        let mut senders = HashMap::new();
        let mut receivers = HashMap::new();
        for cfg in configs {
            let (tx, rx) = watch::channel(());
            let tag = cfg.tag().to_string();
            senders.insert(tag.clone(), Arc::new(tx));
            receivers.insert(tag, rx);
        }
        Self {
            nodes: RwLock::new(HashMap::new()),
            global_tags: RwLock::new(HashSet::new()),
            senders,
            receivers,
        }
    }

    /// 获取某 provider 的更新通知接收端（outbound group 用来监听节点变化）。
    pub fn subscribe(&self, provider_tag: &str) -> Option<UpdateReceiver> {
        self.receivers.get(provider_tag).cloned()
    }

    /// 更新某 provider 的节点列表（由 remote/local provider 调用）。
    ///
    /// 内部执行去重命名，然后广播更新通知。
    pub fn update_nodes(&self, provider_tag: &str, raw_nodes: Vec<(String, OutboundConfig)>) {
        let named = self.dedup_name(provider_tag, raw_nodes);
        let count = named.len();

        {
            let mut nodes = self.nodes.write().unwrap();
            nodes.insert(provider_tag.to_string(), named);
        }

        info!(provider = %provider_tag, nodes = %count, "provider nodes updated");

        if let Some(tx) = self.senders.get(provider_tag) {
            let _ = tx.send(());
        }
    }

    /// 取出某 provider 当前节点列表的快照。
    pub fn nodes_snapshot(&self, provider_tag: &str) -> ProviderNodes {
        self.nodes
            .read()
            .unwrap()
            .get(provider_tag)
            .cloned()
            .unwrap_or_default()
    }

    /// 根据 `ProviderRef` 展开并过滤节点，返回过滤后的 (tag, OutboundConfig) 列表。
    pub fn expand(&self, pref: &ProviderRef) -> ProviderNodes {
        let nodes_map = self.nodes.read().unwrap();
        let mut result = Vec::new();
        for ptag in &pref.tags {
            let provider_nodes = nodes_map.get(ptag.as_str()).cloned().unwrap_or_default();
            for (tag, ob) in provider_nodes {
                if pref.matches(&tag) {
                    result.push((tag, ob));
                }
            }
        }
        result
    }

    // ── 去重命名 ─────────────────────────────────────────────────────────────
    //
    // 算法：
    // 1. 先把该 provider 旧节点的 tag 从全局表里释放
    // 2. 对新节点逐一分配唯一 tag：
    //    - 原名不冲突 → 直接使用
    //    - 冲突 → 加后缀 `_1`、`_2`…直到不冲突
    // 3. 把新 tag 全部注册到全局表

    fn dedup_name(&self, provider_tag: &str, raw: Vec<(String, OutboundConfig)>) -> ProviderNodes {
        let mut global = self.global_tags.write().unwrap();

        // 1. 释放该 provider 旧占用的 tag
        {
            let nodes = self.nodes.read().unwrap();
            if let Some(old) = nodes.get(provider_tag) {
                for (tag, _) in old {
                    global.remove(tag);
                }
            }
        }

        // 2. 为新节点分配唯一 tag
        let mut result = Vec::with_capacity(raw.len());
        for (name, mut ob) in raw {
            let unique_tag = alloc_unique_tag(&name, &mut global);
            // 用唯一 tag 替换 OutboundConfig 内部的 tag 字段
            set_outbound_tag(&mut ob, &unique_tag);
            result.push((unique_tag, ob));
        }

        result
    }
}

/// 在全局 tag 集合里分配一个唯一名称。
fn alloc_unique_tag(name: &str, global: &mut HashSet<String>) -> String {
    if !global.contains(name) {
        global.insert(name.to_string());
        return name.to_string();
    }
    let mut i = 1u32;
    loop {
        let candidate = format!("{name}_{i}");
        if !global.contains(&candidate) {
            global.insert(candidate.clone());
            return candidate;
        }
        i += 1;
    }
}

/// 将 OutboundConfig 内部的 tag 字段替换为指定值。
fn set_outbound_tag(ob: &mut OutboundConfig, tag: &str) {
    match ob {
        OutboundConfig::Vless(c) => c.tag = tag.to_string(),
        OutboundConfig::Vmess(c) => c.tag = tag.to_string(),
        OutboundConfig::Shadowsocks(c) => c.tag = tag.to_string(),
        OutboundConfig::Hysteria2(c) => c.tag = tag.to_string(),
        OutboundConfig::Tuic(c) => c.tag = tag.to_string(),
        OutboundConfig::Trojan(c) => c.tag = tag.to_string(),
        OutboundConfig::Direct(c) => c.tag = tag.to_string(),
        OutboundConfig::Block(c) => c.tag = tag.to_string(),
        OutboundConfig::Socks(c) => c.tag = tag.to_string(),
        OutboundConfig::Selector(c) => c.tag = tag.to_string(),
        OutboundConfig::UrlTest(c) => c.tag = tag.to_string(),
    }
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{outbound::DirectOutboundConfig, provider::ProviderConfig};

    fn make_direct(name: &str) -> (String, OutboundConfig) {
        (
            name.to_string(),
            OutboundConfig::Direct(DirectOutboundConfig {
                tag: name.to_string(),
                bind_address: None,
            }),
        )
    }

    fn make_manager(tags: &[&str]) -> ProviderManager {
        let configs: Vec<ProviderConfig> = tags
            .iter()
            .map(|t| {
                ProviderConfig::Local(crate::config::provider::LocalProviderConfig {
                    tag: t.to_string(),
                    path: String::new(),
                    health_check: None,
                })
            })
            .collect();
        ProviderManager::new(&configs)
    }

    #[test]
    fn dedup_same_name_across_providers() {
        let mgr = make_manager(&["sub1", "sub2"]);

        mgr.update_nodes("sub1", vec![make_direct("日本"), make_direct("美国")]);
        mgr.update_nodes("sub2", vec![make_direct("日本"), make_direct("新加坡")]);

        let sub1 = mgr.nodes_snapshot("sub1");
        let sub2 = mgr.nodes_snapshot("sub2");

        let tags: Vec<_> = sub1
            .iter()
            .chain(sub2.iter())
            .map(|(t, _)| t.as_str())
            .collect();
        // 「日本」只出现一次，另一个应为「日本_1」
        let jp_count = tags.iter().filter(|&&t| t == "日本").count();
        let jp1_count = tags.iter().filter(|&&t| t == "日本_1").count();
        assert_eq!(jp_count, 1, "exactly one '日本'");
        assert_eq!(jp1_count, 1, "exactly one '日本_1'");
        assert!(tags.contains(&"美国"));
        assert!(tags.contains(&"新加坡"));
    }

    #[test]
    fn dedup_existing_suffix() {
        // 订阅里本来就有「日本_1」，应该跳到「日本_2」
        let mgr = make_manager(&["sub1"]);
        mgr.update_nodes(
            "sub1",
            vec![
                make_direct("日本"),
                make_direct("日本_1"),
                make_direct("日本"),
            ],
        );
        let nodes = mgr.nodes_snapshot("sub1");
        let tags: Vec<_> = nodes.iter().map(|(t, _)| t.as_str()).collect();
        assert!(tags.contains(&"日本"), "original");
        assert!(tags.contains(&"日本_1"), "already exists");
        assert!(tags.contains(&"日本_2"), "allocated suffix");
    }

    #[test]
    fn expand_with_filter() {
        let mgr = make_manager(&["sub1"]);
        mgr.update_nodes(
            "sub1",
            vec![
                make_direct("日本 01"),
                make_direct("美国 01"),
                make_direct("过期节点"),
            ],
        );
        let pref = ProviderRef {
            tags: vec!["sub1".into()],
            exclude_filter: vec!["过期".into()],
            filter: vec!["日本".into()],
        };
        let nodes = mgr.expand(&pref);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].0, "日本 01");
    }
}
