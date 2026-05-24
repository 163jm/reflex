//! 出站注册表：按 tag 索引所有出站实例。

use std::{collections::HashMap, sync::Arc};

use crate::{
    config::outbound::OutboundConfig,
    dns::DnsResolver,
    experimental::{CacheFile, CacheFileReader},
    outbound::{
        direct::{BlockOutbound, DirectOutbound},
        group::{OutboundRegistry, SelectorOutbound, UrlTestOutbound},
        Outbound, OutboundStatus,
    },
    provider::ProviderManager,
};

pub struct OutboundManager {
    map: HashMap<String, Arc<dyn Outbound>>,
}

impl OutboundManager {
    pub fn from_config(configs: &[OutboundConfig]) -> anyhow::Result<Self> {
        Self::from_config_with_resolver(configs, None)
    }

    pub fn from_config_with_resolver(
        configs: &[OutboundConfig],
        resolver: Option<Arc<DnsResolver>>,
    ) -> anyhow::Result<Self> {
        Self::from_config_full(configs, resolver, None, None, None, 0)
    }

    /// 完整构造函数，支持 CacheFile 持久化和 ProviderManager。
    pub fn from_config_full(
        configs: &[OutboundConfig],
        resolver: Option<Arc<DnsResolver>>,
        cache_writer: Option<Arc<CacheFile>>,
        cache_reader: Option<Arc<CacheFileReader>>,
        provider_manager: Option<Arc<ProviderManager>>,
        routing_mark: u32,
    ) -> anyhow::Result<Self> {
        let registry: OutboundRegistry = Arc::new(std::sync::OnceLock::new());
        let mut map: HashMap<String, Arc<dyn Outbound>> = HashMap::new();

        for cfg in configs {
            let tag = cfg.tag().to_string();
            if map.contains_key(&tag) {
                anyhow::bail!("duplicate outbound tag: '{tag}'");
            }
            let ob: Arc<dyn Outbound> = match cfg {
                OutboundConfig::Direct(c) => {
                    if let Some(ref r) = resolver {
                        Arc::new(
                            DirectOutbound::with_resolver(c.clone(), r.clone())
                                .with_mark(routing_mark),
                        )
                    } else {
                        Arc::new(DirectOutbound::new(c.clone()).with_mark(routing_mark))
                    }
                }
                OutboundConfig::Block(c) => Arc::new(BlockOutbound::new(c.clone())),
                OutboundConfig::Socks(c) => Arc::new(
                    crate::outbound::socks::SocksOutbound::new(c.clone())?.with_mark(routing_mark),
                ),
                OutboundConfig::Selector(c) => Arc::new(SelectorOutbound::new(
                    c.clone(),
                    registry.clone(),
                    cache_writer.clone(),
                    cache_reader.clone(),
                    provider_manager.clone(),
                )?),
                OutboundConfig::UrlTest(c) => {
                    Arc::new(UrlTestOutbound::new(c.clone(), registry.clone())?)
                }

                #[cfg(feature = "outbound-net")]
                OutboundConfig::Shadowsocks(c) => Arc::new(
                    crate::outbound::shadowsocks::ShadowsocksOutbound::new(c.clone())?
                        .with_mark(routing_mark),
                ),
                #[cfg(not(feature = "outbound-net"))]
                OutboundConfig::Shadowsocks(c) => fallback_block(&c.tag, "Shadowsocks"),

                #[cfg(feature = "outbound-net")]
                OutboundConfig::Trojan(c) => Arc::new(
                    crate::outbound::trojan::TrojanOutbound::new(c.clone())?
                        .with_mark(routing_mark),
                ),
                #[cfg(not(feature = "outbound-net"))]
                OutboundConfig::Trojan(c) => fallback_block(&c.tag, "Trojan"),

                #[cfg(feature = "outbound-net")]
                OutboundConfig::Vless(c) => Arc::new(
                    crate::outbound::vless::VlessOutbound::new(c.clone())?.with_mark(routing_mark),
                ),
                #[cfg(not(feature = "outbound-net"))]
                OutboundConfig::Vless(c) => fallback_block(&c.tag, "VLESS"),

                #[cfg(feature = "outbound-net")]
                OutboundConfig::Vmess(c) => Arc::new(
                    crate::outbound::vmess::VmessOutbound::new(c.clone())?.with_mark(routing_mark),
                ),
                #[cfg(not(feature = "outbound-net"))]
                OutboundConfig::Vmess(c) => fallback_block(&c.tag, "VMess"),

                #[cfg(feature = "outbound-net")]
                OutboundConfig::Hysteria2(c) => Arc::new(
                    crate::outbound::hy2::Hy2Outbound::new(c.clone())?.with_mark(routing_mark),
                ),
                #[cfg(not(feature = "outbound-net"))]
                OutboundConfig::Hysteria2(c) => fallback_block(&c.tag, "Hysteria2"),

                #[cfg(feature = "outbound-net")]
                OutboundConfig::Tuic(c) => Arc::new(
                    crate::outbound::tuic::TuicOutbound::new(c.clone())?.with_mark(routing_mark),
                ),
                #[cfg(not(feature = "outbound-net"))]
                OutboundConfig::Tuic(c) => fallback_block(&c.tag, "TUIC"),
            };
            map.insert(tag, ob);
        }

        registry
            .set(map.clone())
            .map_err(|_| anyhow::anyhow!("outbound registry already initialized"))?;

        Ok(Self { map })
    }

    pub fn get(&self, tag: &str) -> Option<Arc<dyn Outbound>> {
        self.map.get(tag).cloned()
    }

    pub fn statuses(&self) -> Vec<OutboundStatus> {
        let mut statuses = self
            .map
            .values()
            .map(|outbound| outbound.status())
            .collect::<Vec<_>>();
        statuses.sort_by(|a, b| a.name.cmp(&b.name));
        statuses
    }

    pub fn status(&self, tag: &str) -> Option<OutboundStatus> {
        self.map.get(tag).map(|outbound| outbound.status())
    }

    pub fn select(&self, tag: &str, child: &str) -> anyhow::Result<()> {
        self.map
            .get(tag)
            .ok_or_else(|| anyhow::anyhow!("outbound '{tag}' not found"))?
            .select_child(child)
    }

    pub fn as_map(&self) -> &HashMap<String, Arc<dyn Outbound>> {
        &self.map
    }

    /// 返回 OutboundRegistry（Arc<OnceLock<...>>），供 health_check 使用。
    pub fn as_registry(&self) -> OutboundRegistry {
        // 重新构造一个 registry（map 已经 set 过了）
        let registry: OutboundRegistry = Arc::new(std::sync::OnceLock::new());
        let _ = registry.set(self.map.clone());
        registry
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(not(feature = "outbound-net"))]
fn fallback_block(tag: &str, protocol: &str) -> Arc<dyn Outbound> {
    tracing::warn!(
        tag = %tag,
        protocol = %protocol,
        "outbound requires feature 'outbound-net', falling back to block"
    );
    Arc::new(BlockOutbound::new(
        crate::config::outbound::BlockOutboundConfig {
            tag: tag.to_string(),
        },
    ))
}
