pub mod direct;
pub mod group;
pub mod proto;
pub mod socks;

#[cfg(feature = "outbound-net")]
pub mod hy2;
#[cfg(feature = "outbound-net")]
pub mod shadowsocks;
#[cfg(feature = "outbound-net")]
pub mod tls;
#[cfg(feature = "outbound-net")]
pub mod trojan;
#[cfg(feature = "outbound-net")]
pub mod tuic;
#[cfg(feature = "outbound-net")]
pub mod vless;
#[cfg(feature = "outbound-net")]
pub mod vmess;
#[cfg(feature = "outbound-net")]
#[cfg(feature = "outbound-net")]
pub mod xhttp;

use crate::dns::DnsResolver;
use crate::inbound::{InboundTcpStream, InboundUdpPacket, Target};
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

// ── SO_MARK 工具 ──────────────────────────────────────────────────────────────

/// 对已创建的 TCP socket（tokio::net::TcpStream）设置 SO_MARK。
/// 仅 Linux 生效；其他平台为空操作（编译通过，无运行时开销）。
#[allow(unused_variables)]
pub fn apply_mark_to_tcp(stream: &TcpStream, mark: u32) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        if mark != 0 {
            use std::os::unix::io::AsRawFd;
            let fd = stream.as_raw_fd();
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    &mark as *const u32 as *const libc::c_void,
                    std::mem::size_of::<u32>() as libc::socklen_t,
                )
            };
            if ret != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

/// 对已创建的 UDP socket（tokio::net::UdpSocket）设置 SO_MARK。
/// 仅 Linux 生效；其他平台为空操作。
#[allow(unused_variables)]
pub fn apply_mark_to_udp(sock: &tokio::net::UdpSocket, mark: u32) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        if mark != 0 {
            use std::os::unix::io::AsRawFd;
            let fd = sock.as_raw_fd();
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    &mark as *const u32 as *const libc::c_void,
                    std::mem::size_of::<u32>() as libc::socklen_t,
                )
            };
            if ret != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

/// 创建一个绑定到 `bind` 地址、并在 Linux 上设置了 SO_MARK 的 quinn Endpoint。
///
/// quinn 的 Endpoint 不暴露底层 fd，必须在 bind 之前通过 socket2 设置 mark，
/// 再将 socket 传给 `quinn::Endpoint::new()`。
#[cfg(feature = "outbound-net")]
#[allow(unused_variables)]
pub fn new_marked_quic_endpoint(
    bind: std::net::SocketAddr,
    mark: u32,
) -> anyhow::Result<quinn::Endpoint> {
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = if bind.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;

    #[cfg(target_os = "linux")]
    if mark != 0 {
        use std::os::unix::io::AsRawFd;
        let fd = sock.as_raw_fd();
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &mark as *const u32 as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }

    sock.bind(&bind.into())?;
    let std_udp: std::net::UdpSocket = sock.into();
    std_udp.set_nonblocking(true)?;
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        std_udp,
        std::sync::Arc::new(quinn::TokioRuntime),
    )
    .map_err(|e| anyhow::anyhow!("quinn endpoint create failed: {e}"))?;
    Ok(endpoint)
}

// ── TCP 连接辅助 ──────────────────────────────────────────────────────────────

/// 参照 sing-box constant/timeout.go：
/// TCPKeepAliveInitial = 5 min，TCPKeepAliveInterval = 75 s
const TCP_KEEPALIVE_IDLE: std::time::Duration = std::time::Duration::from_secs(300);
const TCP_KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(75);

/// 对 TcpStream 统一设置 nodelay + keepalive。
/// keepalive 能及时检测并清理死连接（网络中断、NAT 超时等），
/// 避免连接长期占用资源。
pub fn set_tcp_opts(stream: &TcpStream) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    let sock = socket2::SockRef::from(stream);
    let ka = socket2::TcpKeepalive::new()
        .with_time(TCP_KEEPALIVE_IDLE)
        .with_interval(TCP_KEEPALIVE_INTERVAL);
    sock.set_tcp_keepalive(&ka)?;
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct OutboundStatus {
    pub name: String,
    #[serde(rename = "type")]
    pub type_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub now: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub all: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<OutboundDelay>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OutboundDelay {
    /// 出站节点的 tag 名
    pub name: String,
    /// 延迟（毫秒）
    pub delay: u64,
}

// ── Outbound trait ────────────────────────────────────────────────────────────

/// 所有出站实现共享的接口。
/// 返回 `(bytes_up, bytes_down)` 供统计层记录。
#[async_trait::async_trait]
pub trait Outbound: Send + Sync + 'static {
    /// 处理一条 TCP 连接，返回 (上行字节数, 下行字节数)
    async fn handle_tcp(&self, conn: InboundTcpStream) -> anyhow::Result<(u64, u64)>;

    /// 处理一条 TCP 连接，并实时更新 `live_up` / `live_down` 原子计数器。
    /// 默认实现将计数器注入 `conn.stream`（SniffedStream），
    /// 后续所有出站对该流的 read/write 都会实时更新计数器，无需各出站单独覆盖。
    async fn handle_tcp_live(
        &self,
        mut conn: crate::inbound::InboundTcpStream,
        live_up: std::sync::Arc<std::sync::atomic::AtomicI64>,
        live_down: std::sync::Arc<std::sync::atomic::AtomicI64>,
    ) -> anyhow::Result<(u64, u64)> {
        conn.stream.set_live_counters(live_up, live_down);
        self.handle_tcp(conn).await
    }
    /// 处理一个 UDP 包
    async fn handle_udp(&self, packet: InboundUdpPacket) -> anyhow::Result<()>;
    fn tag(&self) -> &str;

    /// 向下转型支持（用于 provider watcher 识别 SelectorOutbound / UrlTestOutbound）
    fn as_any(&self) -> &dyn std::any::Any {
        // 默认实现返回 unit，具体类型需覆盖此方法
        &()
    }

    fn status(&self) -> OutboundStatus {
        OutboundStatus {
            name: self.tag().to_string(),
            type_name: "Proxy".to_string(),
            now: None,
            all: vec![],
            history: vec![],
        }
    }

    fn select_child(&self, _tag: &str) -> anyhow::Result<()> {
        anyhow::bail!("outbound '{}' is not selectable", self.tag())
    }

    /// 建立一条经由该出站的 TCP 隧道连接，供 DNS upstream 的 detour 使用。
    ///
    /// 默认实现直接连接目标地址（等同于 direct），出站实现可覆盖以走代理隧道。
    async fn connect_tcp(&self, host: &str, port: u16) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        let addr = tokio::net::lookup_host(format!("{host}:{port}"))
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("DNS lookup failed for {host}:{port}"))?;
        let stream = tokio::net::TcpStream::connect(addr).await?;
        set_tcp_opts(&stream)?;
        Ok(Box::new(stream))
    }
}

/// 供 `connect_tcp` 返回值使用的类型别名：可读写的异步流。
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Unpin + 'static {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> AsyncReadWrite for T {}

// ── 双向转发 ──────────────────────────────────────────────────────────────────

// 在两个异步读写流之间双向透明转发，支持 TCP half-close。
//
// 参照 sing-box `connectionCopy`：某方向读到 EOF 后调用对端的 `shutdown()`
// 发送 TCP FIN，让对端能干净地感知到写端关闭，而不是悬挂等待超时。
//
// 使用 64 KiB buffer（sing-box 批量 size），相比默认 8 KiB 对大流量吞吐
// 提升明显（减少系统调用次数）。
//
// 返回 `(a→b 字节数, b→a 字节数)`。

// ── CountedStream：包装任意 AsyncRead+AsyncWrite，实时更新计数器 ───────────────

/// 透明包装一个双向流，在每次 read（下载）和 write（上传）时
/// 实时更新 `live_up` / `live_down` 原子计数器。
/// 用于在不修改各出站实现的情况下，为所有代理出站提供实时流量统计。
pub struct CountedStream<S> {
    inner: S,
    live_up: std::sync::Arc<std::sync::atomic::AtomicI64>,
    live_down: std::sync::Arc<std::sync::atomic::AtomicI64>,
}

impl<S> CountedStream<S> {
    pub fn new(
        inner: S,
        live_up: std::sync::Arc<std::sync::atomic::AtomicI64>,
        live_down: std::sync::Arc<std::sync::atomic::AtomicI64>,
    ) -> Self {
        Self {
            inner,
            live_up,
            live_down,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountedStream<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::sync::atomic::Ordering;
        let before = buf.filled().len();
        let result = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        let after = buf.filled().len();
        if after > before {
            self.live_down
                .fetch_add((after - before) as i64, Ordering::Relaxed);
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountedStream<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::sync::atomic::Ordering;
        let result = std::pin::Pin::new(&mut self.inner).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(n)) = &result {
            self.live_up.fetch_add(*n as i64, Ordering::Relaxed);
        }
        result
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// 与 `relay` 相同，但每次转发时实时更新 `live_up` / `live_down` 原子计数器。
/// 供连接追踪器实时上报上传/下载字节数使用。
pub async fn relay_tracked<A, B>(
    a: A,
    b: B,
    live_up: std::sync::Arc<std::sync::atomic::AtomicI64>,
    live_down: std::sync::Arc<std::sync::atomic::AtomicI64>,
) -> (u64, u64)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);

    const BUF_SIZE: usize = 65536;

    let (r1, r2) = tokio::join!(
        copy_half_tracked(&mut ar, &mut bw, BUF_SIZE, live_up),
        copy_half_tracked(&mut br, &mut aw, BUF_SIZE, live_down),
    );
    (r1, r2)
}

async fn copy_half_tracked<R, W>(
    reader: &mut R,
    writer: &mut W,
    buf_size: usize,
    counter: std::sync::Arc<std::sync::atomic::AtomicI64>,
) -> u64
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use std::sync::atomic::Ordering;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; buf_size];
    let mut total = 0u64;
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if writer.write_all(&buf[..n]).await.is_err() {
            break;
        }
        total += n as u64;
        counter.fetch_add(n as i64, Ordering::Relaxed);
    }
    let _ = writer.shutdown().await;
    total
}

pub async fn relay<A, B>(a: A, b: B) -> (u64, u64)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);

    const BUF_SIZE: usize = 65536;

    let (r1, r2) = tokio::join!(
        copy_half(&mut ar, &mut bw, BUF_SIZE),
        copy_half(&mut br, &mut aw, BUF_SIZE),
    );
    (r1, r2)
}

/// 单方向 copy：读到 EOF 后向写端发 shutdown（TCP half-close FIN）。
async fn copy_half<R, W>(reader: &mut R, writer: &mut W, buf_size: usize) -> u64
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; buf_size];
    let mut total = 0u64;
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if writer.write_all(&buf[..n]).await.is_err() {
            break;
        }
        total += n as u64;
    }
    // 发送 FIN，通知对端写完了；忽略错误（连接可能已被对端关闭）
    let _ = writer.shutdown().await;
    total
}

// ── 目标地址解析 ──────────────────────────────────────────────────────────────

pub async fn resolve_target(target: &Target) -> anyhow::Result<SocketAddr> {
    match target {
        Target::Socket(addr) => Ok(*addr),
        Target::Domain(host, port) => {
            let addr = tokio::net::lookup_host((host.as_str(), *port))
                .await?
                .next()
                .ok_or_else(|| anyhow::anyhow!("DNS lookup failed for {host}"))?;
            Ok(addr)
        }
    }
}

/// 优先用内部 DNS 解析器解析域名，避免走系统 getaddrinfo。
/// 若 resolver 为 None 则退回系统解析（向后兼容）。
pub async fn resolve_target_with_dns(
    target: &Target,
    resolver: Option<&Arc<DnsResolver>>,
) -> anyhow::Result<SocketAddr> {
    match target {
        Target::Socket(addr) => Ok(*addr),
        Target::Domain(host, port) => {
            if let Some(r) = resolver {
                let ip = r.resolve_domain(host).await?;
                Ok(SocketAddr::new(ip, *port))
            } else {
                let addr = tokio::net::lookup_host((host.as_str(), *port))
                    .await?
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("DNS lookup failed for {host}"))?;
                Ok(addr)
            }
        }
    }
}
#[cfg(feature = "outbound-net")]
pub mod reality;
