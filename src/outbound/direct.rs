//! Direct（直连）和 Block（丢弃）出站。
//!
//! 修复说明：
//! - [BUG] UDP 并发竞争：原来复用单个全局 socket，多个并发包共享 recv_from 会互相"偷包"。
//!   修复：每个 UDP 请求使用独立 socket，send/recv 在该 socket 上完成后立即关闭。
//!   bind_address 模式本已独立绑定，行为不变。
//! - [BUG] TCP bind_address 时使用 socket2 同步 connect：改用 tokio::net::TcpSocket
//!   的异步 connect，消除阻塞风险，代码也更简洁。
//! - [BUG] UDP 超时静默丢弃：改为 debug 日志，方便排查。
//! - [优化] 提取 tcp_connect_addr 辅助方法，消除 handle_tcp / connect_tcp 重复代码。
//! - connect_tcp 设置 TCP_NODELAY，降低小包延迟。

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpStream;
use tracing::debug;

use crate::{
    config::outbound::{BlockOutboundConfig, DirectOutboundConfig},
    dns::DnsResolver,
    inbound::{InboundTcpStream, InboundUdpPacket},
    outbound::{
        apply_mark_to_tcp, apply_mark_to_udp, relay, resolve_target_with_dns, set_tcp_opts,
        Outbound, OutboundStatus,
    },
};

// ── Direct ────────────────────────────────────────────────────────────────────

pub struct DirectOutbound {
    config: DirectOutboundConfig,
    /// 内部 DNS 解析器，用于域名解析（替代系统 getaddrinfo）
    resolver: Option<Arc<DnsResolver>>,
    /// 全局 SO_MARK（来自 global.routing_mark），0 表示不设置
    routing_mark: u32,
}

impl DirectOutbound {
    pub fn new(config: DirectOutboundConfig) -> Self {
        Self {
            config,
            resolver: None,
            routing_mark: 0,
        }
    }

    pub fn with_resolver(config: DirectOutboundConfig, resolver: Arc<DnsResolver>) -> Self {
        Self {
            config,
            resolver: Some(resolver),
            routing_mark: 0,
        }
    }

    pub fn with_mark(mut self, mark: u32) -> Self {
        self.routing_mark = mark;
        self
    }

    /// 向已解析的目标地址建立 TCP 连接，尊重 `bind_address` 配置。
    ///
    /// 原来用 `socket2::Socket::connect`（同步）再转 tokio，改为用
    /// `tokio::net::TcpSocket` 的异步 `connect`，彻底避免在 async 上下文中
    /// 执行阻塞调用。
    async fn tcp_connect_addr(&self, addr: SocketAddr) -> anyhow::Result<TcpStream> {
        let stream = if let Some(bind_ip) = &self.config.bind_address {
            let bind_addr: SocketAddr = format!("{bind_ip}:0").parse()?;
            let socket = if bind_addr.is_ipv6() {
                tokio::net::TcpSocket::new_v6()?
            } else {
                tokio::net::TcpSocket::new_v4()?
            };
            socket.set_reuseaddr(true)?;
            socket.bind(bind_addr)?;
            socket.connect(addr).await?
        } else {
            TcpStream::connect(addr).await?
        };
        set_tcp_opts(&stream)?;
        apply_mark_to_tcp(&stream, self.routing_mark)?;
        Ok(stream)
    }

    /// 为单次 UDP 发送创建一个独立 socket。
    ///
    /// 原实现复用全局 socket，多个并发 `handle_udp` 共享同一个 socket 的
    /// `recv_from`，导致并发时相互"偷包"（包被错误的 future 收走后，正确的
    /// future 超时）。改为每次创建独立 socket，收完一个响应后随任务销毁，
    /// 从根本上消除竞争。
    ///
    /// 对于 DNS、QUIC 探测等高频场景，socket 创建开销远小于偷包带来的重试/
    /// 超时代价；如需进一步优化可引入 per-session socket pool。
    async fn new_udp_socket(&self, dst: SocketAddr) -> anyhow::Result<tokio::net::UdpSocket> {
        let sock = if let Some(bind_ip) = &self.config.bind_address {
            let bind_addr: SocketAddr = format!("{bind_ip}:0").parse()?;
            tokio::net::UdpSocket::bind(bind_addr).await?
        } else if dst.is_ipv6() {
            tokio::net::UdpSocket::bind("[::]:0").await?
        } else {
            tokio::net::UdpSocket::bind("0.0.0.0:0").await?
        };
        apply_mark_to_udp(&sock, self.routing_mark)?;
        Ok(sock)
    }
}

#[async_trait::async_trait]
impl Outbound for DirectOutbound {
    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn status(&self) -> OutboundStatus {
        OutboundStatus {
            name: self.config.tag.clone(),
            type_name: "Direct".to_string(),
            now: None,
            all: vec![],
            history: vec![],
        }
    }

    /// 建立经由 direct 出站的 TCP 连接，供 DNS upstream detour 使用。
    async fn connect_tcp(
        &self,
        host: &str,
        port: u16,
    ) -> anyhow::Result<Box<dyn crate::outbound::AsyncReadWrite>> {
        let target = crate::inbound::Target::Domain(host.to_string(), port);
        let addr = resolve_target_with_dns(&target, self.resolver.as_ref()).await?;
        let stream = self.tcp_connect_addr(addr).await?;
        Ok(Box::new(stream))
    }

    async fn handle_tcp(&self, conn: InboundTcpStream) -> anyhow::Result<(u64, u64)> {
        let addr = resolve_target_with_dns(&conn.target, self.resolver.as_ref()).await?;
        debug!(tag=%self.config.tag, target=%conn.target, addr=%addr, "direct tcp");

        let remote = self.tcp_connect_addr(addr).await?;

        let (up, down) = relay(conn.stream, remote).await;
        debug!(tag=%self.config.tag, up=%up, down=%down, "direct tcp done");
        Ok((up, down))
    }

    async fn handle_tcp_live(
        &self,
        mut conn: crate::inbound::InboundTcpStream,
        live_up: std::sync::Arc<std::sync::atomic::AtomicI64>,
        live_down: std::sync::Arc<std::sync::atomic::AtomicI64>,
    ) -> anyhow::Result<(u64, u64)> {
        conn.stream.set_live_counters(live_up, live_down);
        self.handle_tcp(conn).await
    }

    async fn handle_udp(&self, mut packet: InboundUdpPacket) -> anyhow::Result<()> {
        let dst = resolve_target_with_dns(&packet.target, self.resolver.as_ref()).await?;
        debug!(tag=%self.config.tag, target=%packet.target, dst=%dst, "direct udp");

        // 每次会话创建一个独立 socket，整个会话期间复用（固定源端口）。
        // 游戏服务器依赖源端口识别客户端，若每包换新 socket（新源端口）则无法通信。
        let sock = std::sync::Arc::new(self.new_udp_socket(dst).await?);
        // 发送第一个上行包
        sock.send_to(&packet.data, dst).await?;

        let reply_tx = packet.session.reply_tx.clone();
        let client_src = packet.src;
        let tag = self.config.tag.clone();

        // 取出后续上行包通道（由 run_udp_session 注入）
        // Task 1：持续从 upstream_rx 接收后续上行包，用同一个 socket 发出
        // 这保证整个游戏会话共用一个本地源端口
        if let Some(mut rx) = packet.upstream_rx.take() {
            let sock_send = sock.clone();
            tokio::spawn(async move {
                while let Some(data) = rx.recv().await {
                    if let Err(e) = sock_send.send_to(&data, dst).await {
                        debug!(dst=%dst, err=%e, "direct udp: upstream send error");
                        break;
                    }
                }
            });
        }

        // Task 2：持续从游戏服务器接收回包，转发给客户端（tproxy writeback）
        // 5 秒无包后退出，此时 socket 销毁，会话结束
        // lifetime_guards 持有 ConnGuard / UdpGuard，确保连接在 clash API 中保持可见
        let sock_recv = sock;
        let guards = packet.lifetime_guards;
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                if reply_tx.is_closed() {
                    break;
                }
                match tokio::time::timeout(
                    tokio::time::Duration::from_secs(30),
                    sock_recv.recv_from(&mut buf),
                )
                .await
                {
                    Ok(Ok((n, _from))) => {
                        let data = bytes::Bytes::copy_from_slice(&buf[..n]);
                        let spoofed_src = dst; // 伪造源地址 = 游戏服务器 IP:port
                        if reply_tx.send((data, client_src, spoofed_src)).await.is_err() {
                            break;
                        }
                    }
                    Ok(Err(e)) => {
                        debug!(tag=%tag, dst=%dst, err=%e, "direct udp: recv error");
                        break;
                    }
                    Err(_) => {
                        // 30 秒内无回包，退出收包循环（会话空闲超时）
                        debug!(tag=%tag, dst=%dst, "direct udp: idle timeout (30s), closing recv loop");
                        break;
                    }
                }
            }
            drop(guards); // 这里 drop guards，连接从 clash API 中消失
        });

        Ok(())
    }
}

// ── Block ─────────────────────────────────────────────────────────────────────

pub struct BlockOutbound {
    config: BlockOutboundConfig,
}

impl BlockOutbound {
    pub fn new(config: BlockOutboundConfig) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
impl Outbound for BlockOutbound {
    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn status(&self) -> OutboundStatus {
        OutboundStatus {
            name: self.config.tag.clone(),
            type_name: "Reject".to_string(),
            now: None,
            all: vec![],
            history: vec![],
        }
    }

    async fn handle_tcp(&self, conn: InboundTcpStream) -> anyhow::Result<(u64, u64)> {
        debug!(tag=%self.config.tag, target=%conn.target, "block tcp");
        drop(conn.stream); // RST/FIN
        Ok((0, 0))
    }

    async fn handle_udp(&self, packet: InboundUdpPacket) -> anyhow::Result<()> {
        debug!(tag=%self.config.tag, target=%packet.target, "block udp");
        Ok(())
    }
}
