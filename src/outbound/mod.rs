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
pub mod xhttp;

use crate::dns::DnsResolver;
use crate::inbound::{InboundTcpStream, InboundUdpPacket, Target};
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

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

/// 在两个异步读写流之间双向透明转发，支持 TCP half-close。
///
/// 参照 sing-box `connectionCopy`：某方向读到 EOF 后调用对端的 `shutdown()`
/// 发送 TCP FIN，让对端能干净地感知到写端关闭，而不是悬挂等待超时。
///
/// 使用 64 KiB buffer（sing-box 批量 size），相比默认 8 KiB 对大流量吞吐
/// 提升明显（减少系统调用次数）。
///
/// 返回 `(a→b 字节数, b→a 字节数)`。
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
