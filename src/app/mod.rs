//! 应用层：把所有组件串联起来。

pub mod clash_api;
pub mod dispatcher;
pub mod outbound_mgr;
pub mod ruleset_registry;
pub mod sniff;
pub mod stats;

use std::sync::Arc;

use tokio::{sync::mpsc, task::JoinSet};
use tracing::{error, info};

use crate::{
    config::{dns::ResolveStrategy, inbound::InboundConfig, Config},
    dns::DnsResolver,
    experimental::{open_cache_file, CacheFile, CacheFileReader},
    inbound::{
        dns::DnsInbound, mixed::MixedInbound, tun::TunInbound, InboundTcpStream, InboundUdpPacket,
    },
    router::Router,
};

use clash_api::ClashApi;
use dispatcher::Dispatcher;
use outbound_mgr::OutboundManager;
use ruleset_registry::RuleSetRegistry;
use stats::Stats;

#[cfg(target_os = "linux")]
use crate::inbound::{redir::RedirInbound, tproxy::TProxyInbound};

pub struct App {
    tasks: JoinSet<anyhow::Result<()>>,
    /// 对外暴露统计，供监控接口查询
    pub stats: Arc<Stats>,
}

impl App {
    pub async fn start(config_path: &str) -> anyhow::Result<Self> {
        Self::start_with_config_path(Config::from_file(config_path)?, Some(config_path)).await
    }

    pub async fn start_with_config(config: Config) -> anyhow::Result<Self> {
        Self::start_with_config_path(config, None).await
    }

    pub async fn start_with_config_path(
        config: Config,
        config_path: Option<&str>,
    ) -> anyhow::Result<Self> {
        let stats = Stats::new();

        // ── 0. 实验性功能：cache_file ────────────────────────────────────────
        let (cache_writer, cache_reader): (Option<Arc<CacheFile>>, Option<Arc<CacheFileReader>>) =
            if let Some(cf_cfg) = config.experimental.cache_file.as_ref() {
                if cf_cfg.enabled {
                    let (writer, reader) = open_cache_file(
                        &cf_cfg.path,
                        cf_cfg.store_fakeip,
                        cf_cfg.fakeip_ttl_days,
                        cf_cfg.store_dns,
                        cf_cfg.dns_cleanup_interval_secs,
                    )?;
                    info!(
                        path=%cf_cfg.path,
                        store_fakeip=%cf_cfg.store_fakeip,
                        store_dns=%cf_cfg.store_dns,
                        "cache file opened"
                    );
                    (Some(writer), Some(reader))
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            };

        // ── 1. 路由器（先建，因为 DNS resolver 需要共享规则集）────────────────
        let router = Arc::new(Router::from_config(
            &config.route,
            cache_reader.as_ref().map(|r| r.as_ref()),
            cache_writer.as_ref().map(|w| w.as_ref()),
        )?);
        info!("router: {} rules loaded", config.route.rules.len());

        // ── 2. DNS 解析器（先于 OutboundManager 构建，传入 outbound 前需要它）──
        // 注意：此时 outbounds 还未构建，detour 字段暂时无法解析；
        // 先用无 outbounds 的版本初始化，待 OutboundManager 建好后再注入。
        // 为了解决循环依赖（DNS需要outbound，outbound需要DNS），
        // 使用两阶段初始化：先用 Arc<OnceLock> 延迟注入。
        let (dns_tx, dns_rx) = mpsc::channel::<crate::inbound::dns::DnsQuery>(256);

        // 第一阶段：不带 outbounds 构建 DNS resolver（detour 暂时为直连）
        let dns_resolver = Arc::new({
            let mut r = DnsResolver::from_config_full(
                &config.dns,
                &router.rulesets,
                None, // outbounds 还未就绪
                cache_writer.clone(),
                cache_reader.clone(),
                config.global.routing_mark,
            )?;
            if !config.global.ipv6 {
                // global.ipv6=false 强制 Ipv4Only，覆盖 dns.strategy 的任何设置
                r.strategy = ResolveStrategy::Ipv4Only;
                // 同步更新所有 fakeip upstream 的 strategy
                r.set_fakeip_strategy(ResolveStrategy::Ipv4Only);
            }
            r
        });

        // ── 3. Provider Manager（先于 OutboundManager，节点需要在 outbound 构建前加载）
        let provider_manager = if config.providers.is_empty() {
            None
        } else {
            let config_dir = std::path::PathBuf::from(
                config_path
                    .as_ref()
                    .and_then(|p| std::path::Path::new(p).parent())
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|| ".".to_string()),
            );
            let mgr = Arc::new(crate::provider::ProviderManager::new(&config.providers));
            for provider_cfg in &config.providers {
                match provider_cfg {
                    crate::config::ProviderConfig::Remote(c) => {
                        crate::provider::remote::start_remote_provider(
                            c.clone(),
                            mgr.clone(),
                            config_dir.clone(),
                        )
                        .await;
                    }
                    crate::config::ProviderConfig::Local(c) => {
                        crate::provider::remote::start_local_provider(
                            c.clone(),
                            mgr.clone(),
                            config_dir.clone(),
                        );
                    }
                }
            }
            Some(mgr)
        };

        // ── 4. 出站注册表（注入 DNS resolver 和 ProviderManager）────────────
        let outbound_mgr = Arc::new(OutboundManager::from_config_full(
            &config.outbounds,
            Some(dns_resolver.clone()),
            cache_writer.clone(),
            cache_reader.clone(),
            provider_manager.clone(),
            config.global.routing_mark,
        )?);
        info!(
            "outbound manager: {} outbounds registered",
            outbound_mgr.len()
        );

        // ── provider 节点变更监听 + health_check ─────────────────────────────
        if let Some(ref pmgr) = provider_manager {
            // 为每个 selector/urltest outbound 启动 provider 变更监听
            for ob_cfg in &config.outbounds {
                let pref = match ob_cfg {
                    crate::config::OutboundConfig::Selector(c) => c.providers.clone(),
                    crate::config::OutboundConfig::UrlTest(c) => c.providers.clone(),
                    _ => None,
                };
                if let Some(pref) = pref {
                    if pref.tags.is_empty() {
                        continue;
                    }
                    let ob_tag = ob_cfg.tag().to_string();
                    let outbound_mgr_ref = outbound_mgr.clone();
                    let pmgr_ref = pmgr.clone();
                    let pref_clone = pref.clone();
                    // 对每个引用的 provider 订阅更新
                    for ptag in &pref.tags {
                        let mut rx = match pmgr.subscribe(ptag) {
                            Some(r) => r,
                            None => continue,
                        };
                        let ob_tag2 = ob_tag.clone();
                        let pmgr2 = pmgr_ref.clone();
                        let pref2 = pref_clone.clone();
                        let mgr2 = outbound_mgr_ref.clone();
                        tokio::spawn(async move {
                            loop {
                                if rx.changed().await.is_err() {
                                    break;
                                }
                                // 重新展开所有 provider 节点
                                let nodes = pmgr2.expand(&pref2);
                                let tags: Vec<String> = nodes.into_iter().map(|(t, _)| t).collect();
                                if let Some(ob) = mgr2.get(&ob_tag2) {
                                    if let Some(sel) = ob
                                        .as_any()
                                        .downcast_ref::<crate::outbound::group::SelectorOutbound>(
                                    ) {
                                        sel.refresh_provider_nodes(tags);
                                    } else if let Some(ut) = ob
                                        .as_any()
                                        .downcast_ref::<crate::outbound::group::UrlTestOutbound>(
                                    ) {
                                        ut.refresh_provider_nodes(tags);
                                    }
                                }
                            }
                        });
                    }
                    // 初始展开
                    let nodes = pmgr.expand(&pref);
                    let tags: Vec<String> = nodes.into_iter().map(|(t, _)| t).collect();
                    if let Some(ob) = outbound_mgr.get(&ob_tag) {
                        if let Some(sel) = ob
                            .as_any()
                            .downcast_ref::<crate::outbound::group::SelectorOutbound>()
                        {
                            sel.refresh_provider_nodes(tags);
                        } else if let Some(ut) = ob
                            .as_any()
                            .downcast_ref::<crate::outbound::group::UrlTestOutbound>()
                        {
                            ut.refresh_provider_nodes(tags);
                        }
                    }
                }
            }

            // health_check
            let hc_history = Arc::new(crate::app::clash_api::DelayHistory::default());
            let ob_registry = outbound_mgr.as_registry();
            for provider_cfg in &config.providers {
                let (ptag, hc) = match provider_cfg {
                    crate::config::ProviderConfig::Remote(c) => (&c.tag, c.health_check.as_ref()),
                    crate::config::ProviderConfig::Local(c) => (&c.tag, c.health_check.as_ref()),
                };
                if let Some(hc) = hc {
                    crate::provider::health::start_health_check(
                        ptag.clone(),
                        hc.clone(),
                        pmgr.clone(),
                        ob_registry.clone(),
                        hc_history.clone(),
                    );
                }
            }
        }

        // 第二阶段：用完整的 outbounds 重建 DNS resolver（解析 detour 字段）
        let dns_resolver = Arc::new({
            let mut r = DnsResolver::from_config_full(
                &config.dns,
                &router.rulesets,
                Some(outbound_mgr.as_map()),
                cache_writer,
                cache_reader,
                config.global.routing_mark,
            )?;
            if !config.global.ipv6 {
                // global.ipv6=false 强制 Ipv4Only，覆盖 dns.strategy 的任何设置
                r.strategy = ResolveStrategy::Ipv4Only;
                // 同步更新所有 fakeip upstream 的 strategy
                r.set_fakeip_strategy(ResolveStrategy::Ipv4Only);
            }
            r
        });
        info!(
            "dns resolver: {} servers, {} rules",
            config.dns.servers.len(),
            config.dns.rules.len()
        );

        // ── 4. 入站 → Dispatcher 通道 ────────────────────────────────────────
        let (tcp_tx, tcp_rx) = mpsc::channel::<InboundTcpStream>(1024);
        let (udp_tx, udp_rx) = mpsc::channel::<InboundUdpPacket>(1024);

        let mut tasks: JoinSet<anyhow::Result<()>> = JoinSet::new();

        // ── 5. 启动各 Inbound ────────────────────────────────────────────────
        for ib_config in &config.inbounds {
            match ib_config {
                InboundConfig::TProxy(c) => {
                    #[cfg(target_os = "linux")]
                    {
                        info!(tag=%c.tag, listen=%c.listen, port=%c.listen_port, "starting tproxy inbound");
                        let inbound = TProxyInbound::new(c.clone(), tcp_tx.clone(), udp_tx.clone());
                        tasks.spawn(async move { inbound.run().await });
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        anyhow::bail!("tproxy inbound '{}' is only supported on Linux", c.tag);
                    }
                }
                InboundConfig::Redir(c) => {
                    #[cfg(target_os = "linux")]
                    {
                        info!(tag=%c.tag, listen=%c.listen, port=%c.listen_port, "starting redir inbound");
                        let inbound = RedirInbound::new(c.clone(), tcp_tx.clone());
                        tasks.spawn(async move { inbound.run().await });
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        anyhow::bail!("redir inbound '{}' is only supported on Linux", c.tag);
                    }
                }
                InboundConfig::Mixed(c) => {
                    info!(tag=%c.tag, listen=%c.listen, port=%c.listen_port, "starting mixed inbound");
                    let inbound = MixedInbound::new(c.clone(), tcp_tx.clone(), udp_tx.clone());
                    tasks.spawn(async move { inbound.run().await });
                }
                InboundConfig::Dns(c) => {
                    info!(tag=%c.tag, listen=%c.listen, port=%c.listen_port, "starting dns inbound");
                    let inbound = DnsInbound::new(c.clone(), dns_tx.clone());
                    tasks.spawn(async move { inbound.run().await });
                }
                InboundConfig::Tun(c) => {
                    info!(
                        tag = %c.tag,
                        interface = ?c.interface_name,
                        mtu = c.mtu,
                        auto_route = c.auto_route,
                        stack = %c.stack,
                        "starting tun inbound"
                    );
                    let inbound = TunInbound::new(c.clone(), tcp_tx.clone(), udp_tx.clone());
                    tasks.spawn(async move { inbound.run().await });
                }
            }
        }

        // ── 6. DNS 处理循环 ──────────────────────────────────────────────────
        {
            let resolver = dns_resolver.clone();
            tasks.spawn(async move {
                resolver.run(dns_rx).await;
                Ok(())
            });
        }

        // ── 连接追踪器（Dispatcher 和 ClashApi 共享）────────────────────────
        let conn_tracker = crate::app::clash_api::ConnectionTracker::new();

        // ── 7. TCP Dispatcher ────────────────────────────────────────────────
        {
            let dispatcher = Dispatcher::new(
                router.clone(),
                outbound_mgr.clone(),
                dns_tx.clone(),
                dns_resolver.clone(),
                stats.clone(),
                conn_tracker.clone(),
            );
            tasks.spawn(async move {
                dispatcher.run_tcp(tcp_rx).await;
                Ok(())
            });
        }

        // ── 8. UDP Dispatcher ────────────────────────────────────────────────
        {
            let dispatcher = Dispatcher::new(
                router.clone(),
                outbound_mgr.clone(),
                dns_tx.clone(),
                dns_resolver.clone(),
                stats.clone(),
                conn_tracker.clone(),
            );
            tasks.spawn(async move {
                dispatcher.run_udp(udp_rx).await;
                Ok(())
            });
        }

        // ── 9. Clash API（可选）───────────────────────────────────────────────
        if let Some(clash_api_config) = config.experimental.clash_api.clone() {
            if clash_api_config.enabled {
                let route_cfg = Arc::new(config.route.clone());
                // 构建规则集注册表（从 router 的元数据初始化）
                let rs_registry = RuleSetRegistry::from_router_meta(
                    config.route.clone(),
                    router.ruleset_meta.clone(),
                );
                let clash_api = ClashApi::new(
                    clash_api_config,
                    outbound_mgr.clone(),
                    stats.clone(),
                    route_cfg,
                    config.inbounds.clone(),
                    config.log.level,
                    conn_tracker.clone(),
                    rs_registry,
                );
                tasks.spawn(async move { clash_api.run().await });
            }
        }

        Ok(Self { tasks, stats })
    }

    pub async fn wait(mut self) {
        while let Some(res) = self.tasks.join_next().await {
            match res {
                Ok(Ok(())) => {}
                Ok(Err(e)) => error!(err=%e, "task exited with error"),
                Err(e) => error!(err=%e, "task panicked"),
            }
        }
    }
}
