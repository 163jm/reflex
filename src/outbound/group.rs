//! 出站节点组：selector / url-test。
//!
//! 节点组本身也是 outbound，可被路由规则直接引用；命中后再按组策略委托给
//! 组内某个真实 outbound。

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, OnceLock, RwLock,
    },
    time::{Duration, Instant},
};

use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info, warn};

use crate::{
    config::outbound::{SelectorOutboundConfig, UrlTestOutboundConfig},
    experimental::{CacheFile, CacheFileReader},
    inbound::{InboundTcpStream, InboundUdpPacket},
    outbound::{AsyncReadWrite, Outbound, OutboundDelay, OutboundStatus},
};

pub type OutboundRegistry = Arc<OnceLock<HashMap<String, Arc<dyn Outbound>>>>;

// ── 连接中断组 ────────────────────────────────────────────────────────────────
//
// 维护本 Selector 上当前所有活跃连接的弱引用关闭句柄。
// 切换节点时调用 `interrupt()` 强制关闭所有（或仅内部）连接。

struct ConnItem {
    close_tx: tokio::sync::oneshot::Sender<()>,
    is_external: bool,
}

pub struct InterruptGroup {
    conns: Mutex<Vec<ConnItem>>,
}

impl InterruptGroup {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            conns: Mutex::new(Vec::new()),
        })
    }

    /// 注册一个新连接，返回中断信号接收端。连接结束时 Receiver drop 即自动注销。
    fn register(self: &Arc<Self>, is_external: bool) -> tokio::sync::oneshot::Receiver<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut conns = self.conns.lock().unwrap();
        // 顺便清理掉接收端已关闭（连接已结束）的残留条目，防止 Vec 无限增长
        conns.retain(|item| !item.close_tx.is_closed());
        conns.push(ConnItem {
            close_tx: tx,
            is_external,
        });
        rx
    }

    /// 中断组内连接。
    /// `interrupt_external = true`  → 中断所有连接（含外部来源）
    /// `interrupt_external = false` → 仅中断内部连接
    fn interrupt(&self, interrupt_external: bool) {
        // 一次性取走全部，再把需要保留的放回
        let all = std::mem::take(&mut *self.conns.lock().unwrap());
        let mut keep = Vec::new();
        for item in all {
            // 接收端已关闭（连接已自然结束）的条目直接丢弃，无需发信号
            if item.close_tx.is_closed() {
                continue;
            }
            if !item.is_external || interrupt_external {
                // 发送中断信号；接收端已关闭（连接已结束）时忽略错误
                let _ = item.close_tx.send(());
            } else {
                keep.push(item);
            }
        }
        *self.conns.lock().unwrap() = keep;
    }
}

// ── SelectorOutbound ──────────────────────────────────────────────────────────

pub struct SelectorOutbound {
    config: SelectorOutboundConfig,
    /// 完整节点列表（静态 outbounds + provider 展开，运行时动态维护）
    all_tags: RwLock<Vec<String>>,
    selected: RwLock<String>,
    registry: OutboundRegistry,
    cache_writer: Option<Arc<CacheFile>>,
    #[allow(dead_code)]
    cache_reader: Option<Arc<CacheFileReader>>,
    interrupt_group: Arc<InterruptGroup>,
    /// provider manager（有 providers 时非 None）
    #[allow(dead_code)]
    provider_manager: Option<Arc<crate::provider::ProviderManager>>,
}

impl SelectorOutbound {
    pub fn new(
        config: SelectorOutboundConfig,
        registry: OutboundRegistry,
        cache_writer: Option<Arc<CacheFile>>,
        cache_reader: Option<Arc<CacheFileReader>>,
        provider_manager: Option<Arc<crate::provider::ProviderManager>>,
    ) -> anyhow::Result<Self> {
        // 初始 all_tags = 静态 outbounds（provider 节点在首次展开后追加）
        let initial_tags = config.outbounds.clone();

        // 恢复上次选中
        let selected = cache_reader
            .as_ref()
            .and_then(|r| r.load_selected(&config.tag))
            .filter(|saved| initial_tags.contains(saved))
            .or_else(|| config.r#default.clone())
            .or_else(|| initial_tags.first().cloned())
            .unwrap_or_default();

        Ok(Self {
            config,
            all_tags: RwLock::new(initial_tags),
            selected: RwLock::new(selected),
            registry,
            cache_writer,
            cache_reader,
            interrupt_group: InterruptGroup::new(),
            provider_manager,
        })
    }

    /// 将 provider 展开的节点追加到 all_tags，去掉不再存在的旧 provider 节点。
    /// 由 `start_provider_watcher` 调用。
    pub fn refresh_provider_nodes(&self, provider_nodes: Vec<String>) {
        let mut all = self
            .all_tags
            .write()
            .expect("selector all_tags lock poisoned");
        // 静态部分保持不变，替换 provider 部分
        let static_part: Vec<String> = self
            .config
            .outbounds
            .iter()
            .filter(|t| all.contains(t))
            .cloned()
            .collect();
        let mut new_all = static_part;
        for tag in provider_nodes {
            if !new_all.contains(&tag) {
                new_all.push(tag);
            }
        }

        // 检查当前选中节点是否还在新列表里
        let current = self
            .selected
            .read()
            .expect("selector lock poisoned")
            .clone();
        if !current.is_empty() && !new_all.contains(&current) {
            // 当前节点已被删除，回退到第一个
            if let Some(first) = new_all.first().cloned() {
                *self.selected.write().expect("selector lock poisoned") = first.clone();
                info!(
                    group = %self.config.tag,
                    old = %current,
                    new = %first,
                    "selector: selected node removed, fallback to first"
                );
            }
        }

        *all = new_all;
    }

    fn current_tag(&self) -> String {
        let selected = self
            .selected
            .read()
            .expect("selector lock poisoned")
            .clone();
        let all = self
            .all_tags
            .read()
            .expect("selector all_tags lock poisoned");
        if all.contains(&selected) {
            selected
        } else {
            all.first().cloned().unwrap_or_default()
        }
    }

    fn all_tags_snapshot(&self) -> Vec<String> {
        self.all_tags
            .read()
            .expect("selector all_tags lock poisoned")
            .clone()
    }

    fn selected_outbound(&self) -> anyhow::Result<Arc<dyn Outbound>> {
        let tag = self.current_tag();
        lookup_outbound(&self.registry, &tag)
    }

    fn set_selected(&self, tag: &str) -> anyhow::Result<()> {
        let all = self
            .all_tags
            .read()
            .expect("selector all_tags lock poisoned");
        anyhow::ensure!(
            all.iter().any(|t| t == tag),
            "selector '{}' does not contain outbound '{tag}'",
            self.config.tag
        );
        drop(all);

        let changed = {
            let mut w = self.selected.write().expect("selector lock poisoned");
            if *w == tag {
                false
            } else {
                *w = tag.to_string();
                true
            }
        };

        if changed {
            if let Some(cache) = &self.cache_writer {
                cache.store_selected(&self.config.tag, tag);
            }
            self.interrupt_group
                .interrupt(self.config.interrupt_existing_connections);
            info!(
                group = %self.config.tag,
                selected = %tag,
                interrupt = %self.config.interrupt_existing_connections,
                "selector: switched outbound"
            );
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl Outbound for SelectorOutbound {
    fn tag(&self) -> &str {
        &self.config.tag
    }

    async fn handle_tcp(&self, conn: InboundTcpStream) -> anyhow::Result<(u64, u64)> {
        let tag = self.current_tag();
        let outbound = lookup_outbound(&self.registry, &tag)?;
        debug!(group=%self.config.tag, selected=%tag, target=%conn.target, "selector tcp");

        // 把连接注册进中断组，获取中断信号接收端
        // is_external = true 表示这是来自客户端的"外部"连接
        let interrupt_rx = self.interrupt_group.register(true);

        // 在子 outbound 上建立到远端的连接并双向转发。
        // 我们需要在中断信号到来时提前关闭，因此不能直接调用 outbound.handle_tcp(conn)
        // （那样的话 relay 在子 outbound 内部跑，我们没有取消句柄）。
        // 改为：先 connect_tcp 建隧道，再自己 relay，select! 监听中断。
        let target_host = conn.target.host();
        let target_port = conn.target.port();

        let remote = match tokio::time::timeout(
            Duration::from_secs(30),
            outbound.connect_tcp(&target_host, target_port),
        )
        .await
        {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => return Err(e),
            Err(_) => anyhow::bail!("selector connect_tcp timeout"),
        };

        // 双向转发，同时监听中断信号
        let (up, down) = relay_with_interrupt(conn.stream, remote, interrupt_rx).await;
        debug!(group=%self.config.tag, up=%up, down=%down, "selector tcp done");
        Ok((up, down))
    }

    async fn handle_tcp_live(
        &self,
        conn: crate::inbound::InboundTcpStream,
        live_up: std::sync::Arc<std::sync::atomic::AtomicI64>,
        live_down: std::sync::Arc<std::sync::atomic::AtomicI64>,
    ) -> anyhow::Result<(u64, u64)> {
        let tag = self.current_tag();
        let outbound = lookup_outbound(&self.registry, &tag)?;
        debug!(group=%self.config.tag, selected=%tag, target=%conn.target, "selector tcp (tracked)");

        let interrupt_rx = self.interrupt_group.register(true);
        let target_host = conn.target.host();
        let target_port = conn.target.port();

        let remote = match tokio::time::timeout(
            Duration::from_secs(30),
            outbound.connect_tcp(&target_host, target_port),
        )
        .await
        {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => return Err(e),
            Err(_) => anyhow::bail!("selector connect_tcp timeout"),
        };

        let (up, down) =
            relay_with_interrupt_tracked(conn.stream, remote, interrupt_rx, live_up, live_down)
                .await;
        debug!(group=%self.config.tag, up=%up, down=%down, "selector tcp done");
        Ok((up, down))
    }

    async fn handle_udp(&self, packet: InboundUdpPacket) -> anyhow::Result<()> {
        let tag = self.current_tag();
        let outbound = lookup_outbound(&self.registry, &tag)?;
        debug!(group=%self.config.tag, selected=%tag, target=%packet.target, "selector udp");
        // UDP 无连接，无法中断，直接代理
        outbound.handle_udp(packet).await
    }

    async fn connect_tcp(&self, host: &str, port: u16) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        self.selected_outbound()?.connect_tcp(host, port).await
    }

    fn status(&self) -> OutboundStatus {
        OutboundStatus {
            name: self.config.tag.clone(),
            type_name: "Selector".to_string(),
            now: Some(self.current_tag()),
            all: self.all_tags_snapshot(),
            history: vec![],
        }
    }

    fn select_child(&self, tag: &str) -> anyhow::Result<()> {
        self.set_selected(tag)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

pub struct UrlTestOutbound {
    config: UrlTestOutboundConfig,
    /// 完整节点列表（静态 outbounds + provider 展开）
    all_tags: RwLock<Vec<String>>,
    selected: Arc<RwLock<Option<String>>>,
    latencies: Arc<Mutex<HashMap<String, Option<u64>>>>,
    last_check: Arc<Mutex<Option<Instant>>>,
    /// 原子锁：防止多个并发连接同时触发探测
    is_checking: AtomicBool,
    /// Arc 包装的 is_checking，供后台 task 使用（AtomicBool 不能直接 clone）
    is_checking_arc: Arc<AtomicBool>,
    registry: OutboundRegistry,
}

impl UrlTestOutbound {
    pub fn new(config: UrlTestOutboundConfig, registry: OutboundRegistry) -> anyhow::Result<Self> {
        let has_providers = config
            .providers
            .as_ref()
            .is_some_and(|p| !p.tags.is_empty());
        if config.outbounds.is_empty() && !has_providers {
            anyhow::bail!("url-test outbound '{}': outbounds is empty", config.tag);
        }
        parse_probe_url(&config.url)?;
        config.interval_duration()?;
        config.idle_timeout_duration()?;
        let all_tags = config.outbounds.clone();
        let is_checking_inner = Arc::new(AtomicBool::new(false));
        Ok(Self {
            config,
            all_tags: RwLock::new(all_tags),
            selected: Arc::new(RwLock::new(None)),
            latencies: Arc::new(Mutex::new(HashMap::new())),
            last_check: Arc::new(Mutex::new(None)),
            is_checking: AtomicBool::new(false),
            is_checking_arc: is_checking_inner,
            registry,
        })
    }

    /// provider 节点更新时调用，刷新 all_tags。
    pub fn refresh_provider_nodes(&self, provider_nodes: Vec<String>) {
        let mut all = self
            .all_tags
            .write()
            .expect("urltest all_tags lock poisoned");
        let static_part: Vec<String> = self
            .config
            .outbounds
            .iter()
            .filter(|t| all.contains(t))
            .cloned()
            .collect();
        let mut new_all = static_part;
        for tag in provider_nodes {
            if !new_all.contains(&tag) {
                new_all.push(tag);
            }
        }

        // 若当前选中节点被删除，清空（下次 refresh() 重新选最优）
        let current = self
            .selected
            .read()
            .expect("urltest selected lock poisoned")
            .clone();
        if let Some(ref cur) = current {
            if !new_all.contains(cur) {
                *self
                    .selected
                    .write()
                    .expect("urltest selected lock poisoned") = None;
            }
        }
        *all = new_all;
        // 重置检测时间，触发立即重测
        *self.last_check.lock().expect("urltest check lock poisoned") = None;
    }

    fn all_tags_snapshot(&self) -> Vec<String> {
        self.all_tags
            .read()
            .expect("urltest all_tags lock poisoned")
            .clone()
    }

    async fn current_tag(&self) -> String {
        // 优化：健康检查完全后台化，不阻塞当前连接。
        // - 首次（selected=None）：立即返回第一个节点，同时在后台触发探测；
        //   探测完成后 selected 更新为最优节点，后续连接自动受益。
        // - 后续（到达 interval）：同样后台触发，不阻塞连接。
        // 参照 sing-box url-test 的 background refresh 设计。
        if self.should_check()
            && self
                .is_checking
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            // 将 refresh 所需的全部状态 clone 出来，在独立 task 中运行，
            // 不阻塞当前连接的建立。
            let config = self.config.clone();
            let all_tags = self.all_tags_snapshot();
            let registry = self.registry.clone();
            let selected = self.selected.clone();
            let latencies = self.latencies.clone();
            let last_check = self.last_check.clone();
            let is_checking = self.is_checking_arc.clone();
            tokio::spawn(async move {
                UrlTestOutbound::refresh_background(
                    config, all_tags, registry, selected, latencies, last_check,
                )
                .await;
                is_checking.store(false, Ordering::Release);
            });
        }

        self.selected
            .read()
            .expect("url-test selection lock poisoned")
            .clone()
            .unwrap_or_else(|| {
                // 首次尚未探测完成：返回第一个节点（后台探测后会更新）
                self.all_tags
                    .read()
                    .expect("urltest all_tags lock poisoned")
                    .first()
                    .cloned()
                    .unwrap_or_default()
            })
    }

    fn should_check(&self) -> bool {
        let interval = self
            .config
            .interval_duration()
            .unwrap_or(Duration::from_secs(180));
        let last_check = self
            .last_check
            .lock()
            .expect("url-test check lock poisoned");
        last_check.is_none_or(|last: std::time::Instant| last.elapsed() >= interval)
    }

    #[allow(dead_code)]
    async fn refresh(&self) {
        Self::refresh_background(
            self.config.clone(),
            self.all_tags_snapshot(),
            self.registry.clone(),
            self.selected.clone(),
            self.latencies.clone(),
            self.last_check.clone(),
        )
        .await
    }

    /// 后台探测函数：接受全部需要的状态 clone，在独立 tokio task 中运行，不依赖 &self。
    async fn refresh_background(
        config: UrlTestOutboundConfig,
        all_tags: Vec<String>,
        registry: OutboundRegistry,
        selected: Arc<RwLock<Option<String>>>,
        latencies: Arc<Mutex<HashMap<String, Option<u64>>>>,
        last_check: Arc<Mutex<Option<Instant>>>,
    ) {
        {
            let mut lc = last_check.lock().expect("url-test check lock poisoned");
            *lc = Some(Instant::now());
        }

        let probe_url = config.url.clone();
        let probe_timeout = Duration::from_secs(5);

        let (probe_host, probe_port) = match parse_probe_url(&probe_url) {
            Ok(parsed) => parsed,
            Err(e) => {
                warn!(group=%config.tag, err=%e, "url-test invalid probe url");
                return;
            }
        };
        let probe_path = parse_probe_path(&probe_url);

        // ── 并行探测所有出站 ─────────────────────────────────────────────
        let futs: Vec<_> = all_tags
            .iter()
            .map(|tag| {
                let tag = tag.clone();
                let outbound = match lookup_outbound(&registry, &tag) {
                    Ok(ob) => ob,
                    Err(e) => {
                        warn!(group=%config.tag, outbound=%tag, err=%e, "url-test outbound missing");
                        return futures_util::future::Either::Left(async move { (tag, None) });
                    }
                };
                let host = probe_host.clone();
                let path = probe_path.clone();
                let url = probe_url.clone();
                futures_util::future::Either::Right(async move {
                    let started = Instant::now();
                    let latency = tokio::time::timeout(
                        probe_timeout,
                        probe_via_outbound(outbound.as_ref(), &host, probe_port, &path, &url),
                    )
                    .await;
                    let latency = match latency {
                        Ok(Ok(())) => Some(started.elapsed().as_millis() as u64),
                        Ok(Err(e)) => { debug!(outbound=%tag, err=%e, "url-test probe failed"); None }
                        Err(_) => { debug!(outbound=%tag, "url-test probe timeout"); None }
                    };
                    (tag, latency)
                })
            })
            .collect();

        let results = futures_util::future::join_all(futs).await;
        let measured: HashMap<String, Option<u64>> = results.into_iter().collect();

        let best = measured
            .iter()
            .filter_map(|(tag, lat)| lat.map(|l| (tag.clone(), l)))
            .min_by_key(|(_, l)| *l);

        if let Some((best_tag, best_latency)) = best {
            let current = selected
                .read()
                .expect("url-test selection lock poisoned")
                .clone();
            let new_selected = if let Some(cur) = current {
                let cur_lat = measured.get(&cur).and_then(|l| *l);
                match cur_lat {
                    Some(l) if l <= best_latency + config.tolerance => cur,
                    _ => best_tag,
                }
            } else {
                best_tag
            };
            *selected.write().expect("url-test selection lock poisoned") = Some(new_selected);
        }

        *latencies.lock().expect("url-test latency lock poisoned") = measured;
    }

    async fn selected_outbound(&self) -> anyhow::Result<(String, Arc<dyn Outbound>)> {
        let tag = self.current_tag().await;
        let outbound = lookup_outbound(&self.registry, &tag)?;
        Ok((tag, outbound))
    }

    fn force_selected(&self, tag: &str) -> anyhow::Result<()> {
        let all = self
            .all_tags
            .read()
            .expect("urltest all_tags lock poisoned");
        anyhow::ensure!(
            all.iter().any(|t| t == tag),
            "url-test '{}' does not contain outbound '{tag}'",
            self.config.tag
        );
        drop(all);
        *self
            .selected
            .write()
            .expect("url-test selection lock poisoned") = Some(tag.to_string());
        Ok(())
    }

    fn status_snapshot(&self) -> OutboundStatus {
        let all = self.all_tags_snapshot();
        let now = self
            .selected
            .read()
            .expect("url-test selection lock poisoned")
            .clone()
            .or_else(|| all.first().cloned());
        let history = self
            .latencies
            .lock()
            .expect("url-test latency lock poisoned")
            .iter()
            .filter_map(|(tag, latency)| {
                latency.map(|delay| OutboundDelay {
                    name: tag.clone(),
                    delay,
                })
            })
            .collect();
        OutboundStatus {
            name: self.config.tag.clone(),
            type_name: "URLTest".to_string(),
            now,
            all,
            history,
        }
    }
}

#[async_trait::async_trait]
impl Outbound for UrlTestOutbound {
    fn tag(&self) -> &str {
        &self.config.tag
    }

    async fn handle_tcp(&self, conn: InboundTcpStream) -> anyhow::Result<(u64, u64)> {
        let (tag, outbound) = self.selected_outbound().await?;
        debug!(group=%self.config.tag, selected=%tag, target=%conn.target, "url-test tcp");
        outbound.handle_tcp(conn).await
    }

    async fn handle_udp(&self, packet: InboundUdpPacket) -> anyhow::Result<()> {
        let (tag, outbound) = self.selected_outbound().await?;
        debug!(group=%self.config.tag, selected=%tag, target=%packet.target, "url-test udp");
        outbound.handle_udp(packet).await
    }

    async fn connect_tcp(&self, host: &str, port: u16) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        let (_tag, outbound) = self.selected_outbound().await?;
        outbound.connect_tcp(host, port).await
    }

    fn status(&self) -> OutboundStatus {
        self.status_snapshot()
    }

    fn select_child(&self, tag: &str) -> anyhow::Result<()> {
        self.force_selected(tag)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

// ── relay_with_interrupt ──────────────────────────────────────────────────────
//
// 双向转发，同时监听中断信号。
// 当 interrupt_rx 收到信号（节点切换）时，立即停止转发并返回当前字节计数。

async fn relay_with_interrupt<A, R>(
    local: A,
    remote: R,
    interrupt_rx: tokio::sync::oneshot::Receiver<()>,
) -> (u64, u64)
where
    A: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    let (mut local_r, mut local_w) = tokio::io::split(local);
    let (mut remote_r, mut remote_w) = tokio::io::split(remote);

    // 用 pin! 让两个 copy future 可以在 select! 里同时轮询
    let upload = tokio::io::copy(&mut local_r, &mut remote_w);
    let download = tokio::io::copy(&mut remote_r, &mut local_w);
    let mut interrupt = interrupt_rx;

    tokio::pin!(upload, download);

    let mut up_bytes: u64 = 0;
    let mut dn_bytes: u64 = 0;

    // 简化：relay 完整完成（任意方向关闭），或收到中断信号
    tokio::select! {
        res = &mut upload => {
            up_bytes = res.unwrap_or(0);
            // 继续等 download 方向，但不必要；直接返回
        }
        res = &mut download => {
            dn_bytes = res.unwrap_or(0);
        }
        _ = &mut interrupt => {
            // 中断：两端的 split 保有者在 drop 时自动关闭
        }
    }

    (up_bytes, dn_bytes)
}

// relay_with_interrupt 的计数版本：同时更新 live_up / live_down 原子计数器
async fn relay_with_interrupt_tracked<A, R>(
    local: A,
    remote: R,
    interrupt_rx: tokio::sync::oneshot::Receiver<()>,
    live_up: std::sync::Arc<std::sync::atomic::AtomicI64>,
    live_down: std::sync::Arc<std::sync::atomic::AtomicI64>,
) -> (u64, u64)
where
    A: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    use crate::outbound::CountedStream;
    let counted_local = CountedStream::new(local, live_up, live_down);
    relay_with_interrupt(counted_local, remote, interrupt_rx).await
}

fn lookup_outbound(registry: &OutboundRegistry, tag: &str) -> anyhow::Result<Arc<dyn Outbound>> {
    registry
        .get()
        .and_then(|map| map.get(tag))
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("outbound '{tag}' not found"))
}

fn parse_probe_url(url: &str) -> anyhow::Result<(String, u16)> {
    let (default_port, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (443, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (80, rest)
    } else {
        anyhow::bail!("url-test url must start with http:// or https://: '{url}'");
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    anyhow::ensure!(!authority.is_empty(), "url-test url missing host: '{url}'");
    let (host, port) = if let Some((host, port)) = authority.rsplit_once(':') {
        (host.to_string(), port.parse()?)
    } else {
        (authority.to_string(), default_port)
    };
    anyhow::ensure!(!host.is_empty(), "url-test url missing host: '{url}'");
    Ok((host, port))
}

/// 解析 probe URL 的路径部分（含 query）。
/// "https://www.gstatic.com/generate_204" → "/generate_204"
fn parse_probe_path(url: &str) -> String {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let path_start = rest.find('/').unwrap_or(rest.len());
    let path = &rest[path_start..];
    if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    }
}

/// Bug 1 修复：真正通过 outbound 代理发送 HTTP HEAD 请求，
/// 测量完整的端到端延迟（代理出口 → 目标服务器），而非仅测到代理服务器的 TCP 延迟。
async fn probe_via_outbound(
    outbound: &dyn crate::outbound::Outbound,
    host: &str,
    port: u16,
    path: &str,
    url: &str,
) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // 1. 通过 outbound 建立到目标服务器的代理 TCP 连接
    let mut stream = outbound.connect_tcp(host, port).await?;

    // 2. 发送最简 HTTP/1.1 HEAD 请求
    let request = format!(
        "HEAD {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: reflex/1.0\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    // 3. 读取响应首行，确认收到 HTTP 响应即视为成功
    //    （不检查状态码：204、200、301 均视为节点可用）
    let mut buf = vec![0u8; 256];
    let n = stream.read(&mut buf).await?;
    anyhow::ensure!(n > 0, "probe: empty response from {url}");
    anyhow::ensure!(
        buf[..n].starts_with(b"HTTP/"),
        "probe: non-HTTP response from {url}"
    );
    Ok(())
}
