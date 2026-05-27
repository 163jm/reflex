//! 入站层：负责接收本机流量，识别目标地址，交给路由层处理。
//!
//! 四种入站类型：
//! - [`tproxy`]：Linux TProxy，透明代理，TCP + UDP
//! - [`redir`]：Linux Redirect（NAT），透明代理，仅 TCP
//! - [`mixed`]：SOCKS5 + HTTP CONNECT，TCP + UDP ASSOCIATE
//! - [`dns`]：DNS 服务器入站
//! - [`tun`]：TUN 虚拟网卡，L3 透明代理，TCP + UDP

pub mod dns;
pub mod mixed;
#[cfg(target_os = "linux")]
pub mod redir;
#[cfg(target_os = "linux")]
pub mod tproxy;
pub mod tun;

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};

// ── 共享抽象 ──────────────────────────────────────────────────────────────────

/// 一条已建立的入站 TCP 连接，携带原始目标地址。
/// 路由层拿到它后决定走哪个出站。
pub struct InboundTcpStream {
    /// TCP 流（可能携带嗅探时 peek 出的前缀字节）
    pub stream: SniffedStream,
    /// 连接的真实目标（域名或 IP:Port）
    pub target: Target,
    /// 来自哪个入站 tag
    pub inbound_tag: String,
    /// 嗅探识别出的应用层协议（如 `"dns"`），未嗅探时为 None
    pub sniffed_protocol: Option<String>,
    /// 嗅探识别出的域名（override_destination=false 时不覆盖 target，但保存在此）
    pub sniffed_domain: Option<String>,
}

// ── SniffedStream ─────────────────────────────────────────────────────────────

/// 对 [`TcpStream`] 的薄包装，允许在嗅探时将 peek 出的字节归还回去，
/// 使后续的出站读取对这些字节无感知。
///
/// 读取顺序：先消耗 `prefix`，再透传 `inner`。
/// 写入、关闭等操作直接委托给 `inner`。
pub struct SniffedStream {
    /// 嗅探阶段 peek 出的字节（未嗅探时为空）
    pub prefix: Bytes,
    pub inner: TcpStream,
    /// 实时流量计数器（可选）：由 `handle_tcp_live` 注入，在 poll_read/poll_write 里更新
    pub live_down: Option<std::sync::Arc<std::sync::atomic::AtomicI64>>,
    pub live_up: Option<std::sync::Arc<std::sync::atomic::AtomicI64>>,
}

impl SniffedStream {
    /// 直接从裸 [`TcpStream`] 创建，prefix 为空（未嗅探）。
    pub fn new(stream: TcpStream) -> Self {
        Self {
            prefix: Bytes::new(),
            inner: stream,
            live_down: None,
            live_up: None,
        }
    }

    /// 注入实时计数器，后续每次 read/write 都会更新对应原子值。
    pub fn set_live_counters(
        &mut self,
        live_up: std::sync::Arc<std::sync::atomic::AtomicI64>,
        live_down: std::sync::Arc<std::sync::atomic::AtomicI64>,
    ) {
        self.live_up = Some(live_up);
        self.live_down = Some(live_down);
    }

    /// 嗅探完成后，将 peek 出的字节作为 prefix 归还。
    pub fn prepend(&mut self, data: Bytes) {
        if data.is_empty() {
            return;
        }
        if self.prefix.is_empty() {
            self.prefix = data;
        } else {
            // 极少见：多次 prepend，直接拼接
            let mut buf = bytes::BytesMut::with_capacity(self.prefix.len() + data.len());
            buf.extend_from_slice(&self.prefix);
            buf.extend_from_slice(&data);
            self.prefix = buf.freeze();
        }
    }
    /// 委托给内层 TcpStream 的 `peer_addr()`。
    pub fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.inner.peer_addr()
    }
}

impl AsyncRead for SniffedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let amt = self.prefix.len().min(buf.remaining());
            buf.put_slice(&self.prefix[..amt]);
            self.prefix.advance(amt);
            if let Some(c) = &self.live_down {
                c.fetch_add(amt as i64, std::sync::atomic::Ordering::Relaxed);
            }
            return Poll::Ready(Ok(()));
        }
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let n = buf.filled().len() - before;
            if n > 0 {
                if let Some(c) = &self.live_down {
                    c.fetch_add(n as i64, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
        result
    }
}

impl AsyncWrite for SniffedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = &result {
            if let Some(c) = &self.live_up {
                c.fetch_add(*n as i64, std::sync::atomic::Ordering::Relaxed);
            }
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// 一个入站 UDP 数据包（或 UDP 会话的第一个包），携带原始目标地址。
pub struct InboundUdpPacket {
    /// 数据载荷
    pub data: bytes::Bytes,
    /// 发送方地址（用于回包）
    pub src: SocketAddr,
    /// 真实目标地址
    pub target: Target,
    /// 来自哪个入站 tag
    pub inbound_tag: String,
    /// 嗅探识别出的应用层协议（如 `"dns"`），未嗅探时为 None
    pub sniffed_protocol: Option<String>,
    /// 嗅探识别出的域名（override_destination=false 时不覆盖 target，但保存在此）
    pub sniffed_domain: Option<String>,
    /// UDP 会话句柄（用于后续回包）
    pub session: UdpSession,
    /// 后续上行包通道（仅在 dispatcher run_udp_session 里非 None）。
    /// 出站实现收到后应持续从此通道读取并发往服务端，直到通道关闭或超时。
    /// 这保证整个会话共用同一个出站 socket（固定源端口），游戏协议要求此行为。
    pub upstream_rx: Option<tokio::sync::mpsc::Receiver<bytes::Bytes>>,
    /// 需要与会话生命周期绑定的守卫对象（ConnGuard / UdpGuard 等）。
    /// 出站实现应将此字段 move 进持久 task，确保连接在 clash API 中保持可见。
    pub lifetime_guards: Vec<Box<dyn std::any::Any + Send>>,
}

/// 连接目标：域名或 IP
#[derive(Debug, Clone)]
pub enum Target {
    /// 域名 + 端口（来自 SOCKS5/HTTP CONNECT 握手，或 DNS 嗅探）
    Domain(String, u16),
    /// IP + 端口（来自 TProxy 或已解析）
    Socket(SocketAddr),
}

impl Target {
    pub fn port(&self) -> u16 {
        match self {
            Self::Domain(_, p) => *p,
            Self::Socket(a) => a.port(),
        }
    }

    pub fn host(&self) -> String {
        match self {
            Self::Domain(d, _) => d.clone(),
            Self::Socket(a) => a.ip().to_string(),
        }
    }

    /// 将 Target 转为 SocketAddr，Domain 类型使用 0.0.0.0 占位（仅用于回包伪造源地址场景）
    pub fn to_socket_addr_lossy(&self) -> SocketAddr {
        match self {
            Self::Socket(a) => *a,
            Self::Domain(_, p) => SocketAddr::from(([0, 0, 0, 0], *p)),
        }
    }
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Domain(d, p) => write!(f, "{d}:{p}"),
            Self::Socket(a) => write!(f, "{a}"),
        }
    }
}

/// UDP 会话句柄，入站层持有，用于将出站的回包写回给客户端。
#[derive(Debug, Clone)]
pub struct UdpSession {
    /// 用于回包：(数据, 客户端地址, 伪造源地址=原始目标IP)
    pub reply_tx: tokio::sync::mpsc::Sender<(bytes::Bytes, SocketAddr, SocketAddr)>,
}
