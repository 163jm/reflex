//! Dispatcher：从入站通道接收连接/包，查询路由器，转发给对应出站，记录统计。

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};
use tracing::debug;

use crate::{
    dns::DnsResolver,
    inbound::{
        dns::{DnsQuery, DnsQueryTx},
        InboundTcpStream, InboundUdpPacket, Target,
    },
    router::{RouteAction, Router},
};

use super::{
    clash_api::{ConnInfo, ConnectionTracker, RuleInfo},
    outbound_mgr::OutboundManager,
    sniff::{is_dns_wire, sniff},
    stats::{Stats, TcpGuard, UdpGuard},
};

// ── UDP 会话超时（参照 sing-box constant/timeout.go）─────────────────────────

/// 默认 UDP 会话空闲超时：5 分钟
const UDP_TIMEOUT: Duration = Duration::from_secs(300);

/// 协议专属短超时，端口 → 超时时长
fn udp_timeout_for_port(port: u16) -> Duration {
    match port {
        53 => Duration::from_secs(10),   // DNS
        123 => Duration::from_secs(10),  // NTP
        3478 => Duration::from_secs(10), // STUN
        443 => Duration::from_secs(30),  // QUIC
        _ => UDP_TIMEOUT,
    }
}

// ── UDP 会话表 ────────────────────────────────────────────────────────────────

/// 会话 key：(入站源地址, 目标地址, 出站 tag)
/// 同一 (src, dst) 走不同出站时各自独立（规则切换场景）
type UdpSessionKey = (SocketAddr, String, String); // (src, target_str, outbound_tag)

/// 向已存在会话的入站方向投递数据
struct UdpSessionHandle {
    /// 向会话 task 投递新包载荷
    data_tx: mpsc::Sender<bytes::Bytes>,
    last_seen: Instant,
}

/// Dispatcher 持有的 UDP 会话表（每个 run_udp 实例独占，无需 Arc<Mutex>）
struct UdpSessionTable {
    sessions: HashMap<UdpSessionKey, UdpSessionHandle>,
}

impl UdpSessionTable {
    fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// 检查会话是否存活（Sender 未关闭）
    fn get_live(&mut self, key: &UdpSessionKey) -> Option<&mut UdpSessionHandle> {
        let alive = self
            .sessions
            .get(key)
            .is_some_and(|h| !h.data_tx.is_closed());
        if alive {
            return self.sessions.get_mut(key);
        }
        // Sender 已关闭说明会话 task 已退出，移除
        self.sessions.remove(key);
        None
    }

    fn insert(&mut self, key: UdpSessionKey, handle: UdpSessionHandle) {
        self.sessions.insert(key, handle);
    }

    /// 定期清理已关闭的会话（Sender closed 或超时），避免 HashMap 无限增长
    fn gc(&mut self) {
        self.sessions
            .retain(|_, h| !h.data_tx.is_closed() && h.last_seen.elapsed() < UDP_TIMEOUT * 2);
    }
}

// ── Dispatcher ────────────────────────────────────────────────────────────────

pub struct Dispatcher {
    router: Arc<Router>,
    outbound_mgr: Arc<OutboundManager>,
    dns_tx: DnsQueryTx,
    dns_resolver: Arc<DnsResolver>,
    stats: Arc<Stats>,
    conn_tracker: Arc<ConnectionTracker>,
}

impl Dispatcher {
    pub fn new(
        router: Arc<Router>,
        outbound_mgr: Arc<OutboundManager>,
        dns_tx: DnsQueryTx,
        dns_resolver: Arc<DnsResolver>,
        stats: Arc<Stats>,
        conn_tracker: Arc<ConnectionTracker>,
    ) -> Self {
        Self {
            router,
            outbound_mgr,
            dns_tx,
            dns_resolver,
            stats,
            conn_tracker,
        }
    }

    pub async fn run_tcp(self, mut rx: mpsc::Receiver<InboundTcpStream>) {
        while let Some(mut conn) = rx.recv().await {
            // ── FakeIP 反向查找（参照 sing-box route.go routeConnection）──────────
            // 若目标 IP 落在 FakeIP 段内，立即还原为域名目标，再进入路由匹配。
            if let Target::Socket(addr) = &conn.target {
                let ip = addr.ip();
                let port = addr.port();
                if let Some(domain) = self.dns_resolver.lookup_fakeip(ip) {
                    debug!(
                        fakeip = %ip,
                        domain = %domain,
                        "fakeip reverse lookup: restoring domain target"
                    );
                    conn.target = Target::Domain(domain, port);
                }
            }

            // 先做第一次路由，检查是否需要嗅探
            let (action_ref, rule_type, rule_payload) = self.router.route_tcp(&conn);
            let action = action_ref.clone();
            let mut rule_info = RuleInfo {
                rule_type: rule_type.to_string(),
                rule_payload: rule_payload.to_string(),
            };
            let action = if let RouteAction::Sniff {
                timeout_ms,
                override_destination,
                sniff_types,
            } = action
            {
                // 嗅探：非破坏性读取头部，识别域名后按配置决定是否覆盖目标地址
                let sniff_result = sniff(&mut conn.stream, timeout_ms, &sniff_types).await;
                if let Some(result) = sniff_result {
                    let port = conn.target.port();
                    // 将协议写入 sniffed_protocol，供路由规则匹配
                    if conn.sniffed_protocol.is_none() {
                        conn.sniffed_protocol = Some(result.protocol.to_string());
                    }
                    if let Some(domain) = result.domain {
                        if override_destination {
                            debug!(
                                original = %conn.target,
                                sniffed = %domain,
                                protocol = result.protocol,
                                "sniff updated target domain"
                            );
                            conn.target = crate::inbound::Target::Domain(domain, port);
                        } else {
                            debug!(
                                original = %conn.target,
                                sniffed = %domain,
                                protocol = result.protocol,
                                "sniff identified domain (override_destination=false, target unchanged)"
                            );
                            conn.sniffed_domain = Some(domain);
                        }
                    } else {
                        debug!(
                            original = %conn.target,
                            protocol = result.protocol,
                            "sniff identified protocol (no domain)"
                        );
                    }
                }
                // 检测 TCP DNS（port 53 上的 DNS over TCP，长度前缀后接 DNS 报文）
                if conn.target.port() == 53
                    && conn.sniffed_protocol.is_none()
                    && conn.stream.prefix.len() >= 14
                {
                    let dns_buf = &conn.stream.prefix[2..];
                    if is_dns_wire(dns_buf) {
                        conn.sniffed_protocol = Some("dns".to_string());
                    }
                }
                // 重新路由（跳过所有 Sniff 规则，避免死循环）
                {
                    let (a, rt, rp) = self.router.route_tcp_after_sniff(&conn, &conn.target);
                    rule_info = RuleInfo {
                        rule_type: rt.to_string(),
                        rule_payload: rp.to_string(),
                    };
                    a.clone()
                }
            } else {
                action
            };

            // 处理 Resolve 动作：将域名解析为 IP，再继续路由（跳过 Sniff/Resolve）
            let action = if let RouteAction::Resolve { server } = &action {
                if let Target::Domain(host, port) = &conn.target {
                    let host = host.clone();
                    let port = *port;
                    let resolve_result = match server {
                        Some(tag) => self.dns_resolver.resolve_domain_via(&host, tag).await,
                        None => self.dns_resolver.resolve_domain(&host).await,
                    };
                    match resolve_result {
                        Ok(ip) => {
                            let resolved_target =
                                Target::Socket(std::net::SocketAddr::new(ip, port));
                            debug!(
                                domain = %host,
                                ip = %ip,
                                "resolve: domain resolved, re-routing with IP target"
                            );
                            {
                                let (a, rt, rp) =
                                    self.router.route_tcp_after_resolve(&conn, &resolved_target);
                                rule_info = RuleInfo {
                                    rule_type: rt.to_string(),
                                    rule_payload: rp.to_string(),
                                };
                                a.clone()
                            }
                        }
                        Err(e) => {
                            debug!(domain = %host, err = %e, "resolve: DNS lookup failed, falling through");
                            // 解析失败时跳过 resolve 规则继续后续匹配
                            {
                                let (a, rt, rp) =
                                    self.router.route_tcp_after_resolve(&conn, &conn.target);
                                rule_info = RuleInfo {
                                    rule_type: rt.to_string(),
                                    rule_payload: rp.to_string(),
                                };
                                a.clone()
                            }
                        }
                    }
                } else {
                    // 目标已经是 IP，无需解析，直接跳过 resolve 继续
                    let (a, rt, rp) = self.router.route_tcp_after_resolve(&conn, &conn.target);
                    rule_info = RuleInfo {
                        rule_type: rt.to_string(),
                        rule_payload: rp.to_string(),
                    };
                    a.clone()
                }
            } else {
                action
            };

            let mgr = self.outbound_mgr.clone();
            let dns_tx = self.dns_tx.clone();
            let stats = self.stats.clone();
            let conn_tracker = self.conn_tracker.clone();

            tokio::spawn(async move {
                if let Err(e) =
                    dispatch_tcp(conn, action, rule_info, mgr, dns_tx, stats, conn_tracker).await
                {
                    debug!(err=%e, "tcp dispatch error");
                    debug!("tcp dispatch error chain: {:#}", e);
                }
            });
        }
    }

    pub async fn run_udp(self, mut rx: mpsc::Receiver<InboundUdpPacket>) {
        let mut session_table = UdpSessionTable::new();
        // GC 定时器：每 30 秒清理一次死会话
        let mut gc_ticker = tokio::time::interval(Duration::from_secs(30));
        gc_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                maybe_packet = rx.recv() => {
                    let Some(mut packet) = maybe_packet else { break };

                    // ── FakeIP 反向查找 ──────────────────────────────────────
                    if let Target::Socket(addr) = &packet.target {
                        let ip = addr.ip();
                        let port = addr.port();
                        if let Some(domain) = self.dns_resolver.lookup_fakeip(ip) {
                            debug!(
                                fakeip = %ip,
                                domain = %domain,
                                "fakeip reverse lookup (udp): restoring domain target"
                            );
                            packet.target = Target::Domain(domain, port);
                        }
                    }

                    // UDP DNS 协议检测
                    if packet.sniffed_protocol.is_none() && is_dns_wire(&packet.data) {
                        packet.sniffed_protocol = Some("dns".to_string());
                    }

                    let (action_ref, rule_type, rule_payload) = self.router.route_udp(&packet);
                    let action = action_ref.clone();
                    let mut rule_info = RuleInfo {
                        rule_type: rule_type.to_string(),
                        rule_payload: rule_payload.to_string(),
                    };

                    // UDP 不支持嗅探，Sniff action 降级为默认路由
                    let action = if matches!(action, RouteAction::Sniff { .. }) {
                        self.router.default_action().clone()
                    } else {
                        action
                    };

                    // 处理 Resolve 动作
                    let action = if let RouteAction::Resolve { server } = &action {
                        if let Target::Domain(host, port) = &packet.target {
                            let host = host.clone();
                            let port = *port;
                            let resolve_result = match server {
                                Some(tag) => self.dns_resolver.resolve_domain_via(&host, tag).await,
                                None => self.dns_resolver.resolve_domain(&host).await,
                            };
                            match resolve_result {
                                Ok(ip) => {
                                    let resolved = Target::Socket(std::net::SocketAddr::new(ip, port));
                                    let (a, rt, rp) = self.router.route_udp_after_resolve(&packet, &resolved);
                                    rule_info = RuleInfo { rule_type: rt.to_string(), rule_payload: rp.to_string() };
                                    a.clone()
                                }
                                Err(e) => {
                                    debug!(domain = %host, err = %e, "resolve(udp): DNS lookup failed, falling through");
                                    let (a, rt, rp) = self.router.route_udp_after_resolve(&packet, &packet.target);
                                    rule_info = RuleInfo { rule_type: rt.to_string(), rule_payload: rp.to_string() };
                                    a.clone()
                                }
                            }
                        } else {
                            let (a, rt, rp) = self.router.route_udp_after_resolve(&packet, &packet.target);
                            rule_info = RuleInfo { rule_type: rt.to_string(), rule_payload: rp.to_string() };
                            a.clone()
                        }
                    } else {
                        action
                    };

                    // DNS 直接走原有逻辑，不需要会话复用
                    if matches!(action, RouteAction::DnsOut) {
                        let mgr = self.outbound_mgr.clone();
                        let dns_tx = self.dns_tx.clone();
                        let stats = self.stats.clone();
                        let conn_tracker = self.conn_tracker.clone();
                        tokio::spawn(async move {
                            if let Err(e) = dispatch_udp(packet, action, rule_info, mgr, dns_tx, stats, conn_tracker).await {
                                debug!(err=%e, "udp dns dispatch error");
                            }
                        });
                        continue;
                    }

                    // 对于真正的出站，使用会话复用
                    let outbound_tag = match &action {
                        RouteAction::Outbound(tag) => tag.clone(),
                        _ => {
                            // Block / 其他 action，直接 dispatch
                            let mgr = self.outbound_mgr.clone();
                            let dns_tx = self.dns_tx.clone();
                            let stats = self.stats.clone();
                            let conn_tracker = self.conn_tracker.clone();
                            tokio::spawn(async move {
                                if let Err(e) = dispatch_udp(packet, action, rule_info, mgr, dns_tx, stats, conn_tracker).await {
                                    debug!(err=%e, "udp dispatch error");
                                }
                            });
                            continue;
                        }
                    };

                    let target_str = packet.target.to_string();
                    let session_key: UdpSessionKey = (packet.src, target_str, outbound_tag.clone());
                    let timeout = udp_timeout_for_port(packet.target.port());

                    if let Some(handle) = session_table.get_live(&session_key) {
                        // 会话存活，直接投递数据
                        let _ = handle.data_tx.try_send(packet.data);
                        handle.last_seen = Instant::now();
                        debug!(src=%packet.src, dst=%packet.target, "udp: reuse session");
                    } else {
                        // 新会话：启动一个长期 task 持有出站连接
                        debug!(src=%packet.src, dst=%packet.target, outbound=%outbound_tag, "udp: new session");
                        // 投递通道：inbound → session task，容量 64
                        let (data_tx, data_rx) = mpsc::channel::<bytes::Bytes>(64);

                        // 先把第一个包发进去再启动 task
                        let _ = data_tx.try_send(packet.data.clone());

                        let mgr = self.outbound_mgr.clone();
                        let stats = self.stats.clone();
                        let conn_tracker = self.conn_tracker.clone();
                        let dns_tx = self.dns_tx.clone();
                        let reply_tx = packet.session.reply_tx.clone();
                        let src = packet.src;
                        let target = packet.target.clone();
                        let inbound_tag = packet.inbound_tag.clone();
                        let rule_info_clone = rule_info.clone();
                        let ob_tag = outbound_tag.clone();

                        tokio::spawn(async move {
                            run_udp_session(
                                src,
                                target,
                                inbound_tag,
                                ob_tag,
                                data_rx,
                                reply_tx,
                                rule_info_clone,
                                mgr,
                                dns_tx,
                                stats,
                                conn_tracker,
                                timeout,
                            )
                            .await;
                        });

                        session_table.insert(
                            session_key,
                            UdpSessionHandle {
                                data_tx,
                                last_seen: Instant::now(),
                            },
                        );
                    }
                }
                _ = gc_ticker.tick() => {
                    session_table.gc();
                }
            }
        }
    }
}

// ── UDP 会话 task ─────────────────────────────────────────────────────────────
//
// 每个 (src, dst, outbound) 三元组对应一个此 task。
// task 持有与出站的连接，循环收包→转发，并在空闲超时后自动退出。
// task 退出后 data_tx 端的 Sender 关闭，session_table.get_live 检测到后自动清理。

#[allow(clippy::too_many_arguments)]
async fn run_udp_session(
    src: SocketAddr,
    target: Target,
    inbound_tag: String,
    outbound_tag: String,
    mut data_rx: mpsc::Receiver<bytes::Bytes>,
    reply_tx: mpsc::Sender<(bytes::Bytes, SocketAddr)>,
    rule_info: RuleInfo,
    mgr: Arc<OutboundManager>,
    _dns_tx: DnsQueryTx,
    stats: Arc<Stats>,
    conn_tracker: Arc<ConnectionTracker>,
    timeout: Duration,
) {
    use crate::inbound::UdpSession;

    let ob = match mgr.get(&outbound_tag) {
        Some(o) => o,
        None => {
            debug!(tag=%outbound_tag, "udp session: outbound not found");
            return;
        }
    };

    let _guard = UdpGuard::new(stats.tag(&outbound_tag));
    let host = target.to_string();
    let dest_port = target.port();
    let conn_guard = conn_tracker.register(
        ConnInfo {
            network: "udp",
            host: &host,
            source: src,
            dest_port,
            inbound: &inbound_tag,
            outbound: &outbound_tag,
        },
        &rule_info,
    );

    // 从 data_rx 持续收包，每包构造一个 InboundUdpPacket 交给出站
    // 出站的回包通过 reply_tx 发回入站
    loop {
        let data = tokio::time::timeout(timeout, data_rx.recv()).await;
        match data {
            Ok(Some(payload)) => {
                let packet = InboundUdpPacket {
                    data: payload,
                    src,
                    target: target.clone(),
                    inbound_tag: inbound_tag.clone(),
                    session: UdpSession {
                        reply_tx: reply_tx.clone(),
                    },
                    sniffed_protocol: None,
                    sniffed_domain: None,
                };
                if let Err(e) = ob.handle_udp(packet).await {
                    debug!(err=%e, outbound=%outbound_tag, "udp session: handle_udp error");
                    // 出站报错不立即退出，继续等待下一个包（避免因单包错误中断整个会话）
                }
            }
            Ok(None) => {
                // data_rx 已关闭（Dispatcher 退出），结束会话
                debug!(src=%src, dst=%target, "udp session: data_rx closed");
                break;
            }
            Err(_) => {
                // 超时，会话空闲太久，主动关闭
                debug!(src=%src, dst=%target, outbound=%outbound_tag, timeout=?timeout, "udp session: idle timeout");
                break;
            }
        }
    }

    drop(conn_guard);
    // DNS 出站路径不走此函数，此处直接 drop _guard
}

// ── TCP 分发 ──────────────────────────────────────────────────────────────────

async fn dispatch_tcp(
    conn: InboundTcpStream,
    action: RouteAction,
    rule_info: RuleInfo,
    mgr: Arc<OutboundManager>,
    dns_tx: DnsQueryTx,
    stats: Arc<Stats>,
    conn_tracker: Arc<ConnectionTracker>,
) -> anyhow::Result<()> {
    match action {
        RouteAction::DnsOut => {
            let guard = TcpGuard::new(stats.tag("dns-out"));
            let res = handle_dns_tcp(conn, dns_tx).await;
            if res.is_err() {
                guard.record_error();
            }
            res
        }
        RouteAction::Outbound(tag) => {
            let ob = mgr
                .get(&tag)
                .ok_or_else(|| anyhow::anyhow!("outbound '{tag}' not found"))?;
            debug!(tag=%tag, target=%conn.target, "tcp → outbound");
            let guard = TcpGuard::new(stats.tag(&tag));
            // 注册到连接追踪器，conn_guard drop 时自动移除
            let host = conn.target.to_string();
            let dest_port = conn.target.port();
            let source = conn
                .stream
                .peer_addr()
                .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
            let conn_guard = conn_tracker.register(
                ConnInfo {
                    network: "tcp",
                    host: &host,
                    source,
                    dest_port,
                    inbound: &conn.inbound_tag,
                    outbound: &tag,
                },
                &rule_info,
            );
            match ob.handle_tcp(conn).await {
                Ok((up, down)) => {
                    conn_guard.add_bytes(up as i64, down as i64);
                    guard.add_bytes(up, down);
                    Ok(())
                }
                Err(e) => {
                    guard.record_error();
                    Err(e)
                }
            }
        }
        RouteAction::Sniff { .. } => {
            // 不可达：Sniff 在 run_tcp 中已处理并重路由，不会传入此函数
            unreachable!("Sniff action must not reach dispatch_tcp")
        }
        RouteAction::Resolve { .. } => {
            // 不可达：Resolve 在 run_tcp 中已处理并重路由，不会传入此函数
            unreachable!("Resolve action must not reach dispatch_tcp")
        }
    }
}

// ── UDP 分发（仅用于 DNS-out 和非 Outbound action）───────────────────────────

async fn dispatch_udp(
    packet: InboundUdpPacket,
    action: RouteAction,
    rule_info: RuleInfo,
    mgr: Arc<OutboundManager>,
    dns_tx: DnsQueryTx,
    stats: Arc<Stats>,
    conn_tracker: Arc<ConnectionTracker>,
) -> anyhow::Result<()> {
    match action {
        RouteAction::DnsOut => {
            let _guard = UdpGuard::new(stats.tag("dns-out"));
            handle_dns_udp(packet, dns_tx).await
        }
        RouteAction::Outbound(tag) => {
            // 仅在无法走会话复用时（如 Block 降级）走这里，正常 Outbound 由 run_udp 的会话 task 处理
            let ob = mgr
                .get(&tag)
                .ok_or_else(|| anyhow::anyhow!("outbound '{tag}' not found"))?;
            debug!(tag=%tag, target=%packet.target, "udp → outbound (direct)");
            let _guard = UdpGuard::new(stats.tag(&tag));
            let host = packet.target.to_string();
            let dest_port = packet.target.port();
            let conn_guard = conn_tracker.register(
                ConnInfo {
                    network: "udp",
                    host: &host,
                    source: packet.src,
                    dest_port,
                    inbound: &packet.inbound_tag,
                    outbound: &tag,
                },
                &rule_info,
            );
            let result = ob.handle_udp(packet).await;
            drop(conn_guard);
            result
        }
        RouteAction::Sniff { .. } => {
            debug!("Sniff action reached dispatch_udp unexpectedly, dropping packet");
            Ok(())
        }
        RouteAction::Resolve { .. } => {
            debug!("Resolve action reached dispatch_udp unexpectedly, dropping packet");
            Ok(())
        }
    }
}

// ── DNS over TCP（来自 tproxy/mixed 路由到 dns-out）──────────────────────────

async fn handle_dns_tcp(mut conn: InboundTcpStream, dns_tx: DnsQueryTx) -> anyhow::Result<()> {
    use bytes::Bytes;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        sync::oneshot,
    };

    loop {
        let len = match conn.stream.read_u16().await {
            Ok(v) => v as usize,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        };
        anyhow::ensure!(len <= 4096, "DNS TCP message too large: {len}");

        let mut buf = vec![0u8; len];
        conn.stream.read_exact(&mut buf).await?;

        let (reply_tx, reply_rx) = oneshot::channel::<Bytes>();
        dns_tx
            .send(DnsQuery {
                message: Bytes::from(buf),
                from: conn
                    .stream
                    .peer_addr()
                    .unwrap_or("0.0.0.0:0".parse().unwrap()),
                inbound_tag: conn.inbound_tag.clone(),
                reply_tx,
            })
            .await
            .map_err(|_| anyhow::anyhow!("dns resolver closed"))?;

        let resp = reply_rx
            .await
            .map_err(|_| anyhow::anyhow!("dns reply dropped"))?;

        conn.stream
            .write_all(&(resp.len() as u16).to_be_bytes())
            .await?;
        conn.stream.write_all(&resp).await?;
    }
    Ok(())
}

// ── DNS over UDP（来自 tproxy/mixed 路由到 dns-out）──────────────────────────

async fn handle_dns_udp(packet: InboundUdpPacket, dns_tx: DnsQueryTx) -> anyhow::Result<()> {
    use tokio::sync::oneshot;

    let (reply_tx, reply_rx) = oneshot::channel();
    dns_tx
        .send(DnsQuery {
            message: packet.data,
            from: packet.src,
            inbound_tag: packet.inbound_tag,
            reply_tx,
        })
        .await
        .map_err(|_| anyhow::anyhow!("dns resolver closed"))?;

    let resp = reply_rx
        .await
        .map_err(|_| anyhow::anyhow!("dns reply dropped"))?;

    let _ = packet.session.reply_tx.send((resp, packet.src)).await;
    Ok(())
}
