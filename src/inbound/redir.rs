//! Linux Redirect 入站（`iptables -j REDIRECT` / `nftables redirect to`）。
//!
//! ## 原理
//! Redirect 是比 TProxy 更简单的透明代理方案：内核把匹配流量的目标地址改写为
//! 本机监听地址，但原始目标仍可通过 `SO_ORIGINAL_DST` / `IP6T_SO_ORIGINAL_DST`
//! getsockopt 取回。仅支持 **TCP**（UDP 无法用 REDIRECT target 还原原始目标）。
//!
//! ## 与 TProxy 的区别
//! | 特性 | Redirect | TProxy |
//! |------|----------|--------|
//! | 协议 | TCP only | TCP + UDP |
//! | 配置难度 | 简单 | 需要额外 ip rule/ip route |
//! | 需要 IP_TRANSPARENT | 否 | 是 |
//! | 适用场景 | 本机出站拦截 | 网关转发 + 本机 |
//!
//! ## nftables 示例
//! ```nft
//! table inet reflex_redir {
//!     chain prerouting {
//!         type nat hook prerouting priority dstnat; policy accept;
//!         # 跳过私有地址
//!         ip daddr { 10.0.0.0/8, 127.0.0.0/8, 172.16.0.0/12,
//!                    192.168.0.0/16, 224.0.0.0/3 } return
//!         # TCP 全部 redirect 到本机 7892
//!         meta l4proto tcp redirect to :7892
//!     }
//!     chain output {
//!         type nat hook output priority dstnat; policy accept;
//!         ip daddr { 10.0.0.0/8, 127.0.0.0/8, 172.16.0.0/12,
//!                    192.168.0.0/16, 224.0.0.0/3 } return
//!         # 排除代理自身（按 GID 或 mark）
//!         skgid 1000 return
//!         meta l4proto tcp redirect to :7892
//!     }
//! }
//! ```
//!
//! ## iptables 示例
//! ```bash
//! iptables -t nat -A PREROUTING -p tcp \
//!   ! -d 10.0.0.0/8 ! -d 127.0.0.0/8 ! -d 172.16.0.0/12 \
//!   ! -d 192.168.0.0/16 -j REDIRECT --to-ports 7892
//! ```

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    time::Duration,
};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::{net::TcpListener, sync::mpsc};
use tracing::{debug, error, info, warn};

use crate::{
    config::inbound::RedirInboundConfig,
    inbound::{InboundTcpStream, SniffedStream, Target},
};

// ── SO_ORIGINAL_DST 常量 ──────────────────────────────────────────────────────
// IPPROTO_IP  level, SO_ORIGINAL_DST = 80
// IPPROTO_IPV6 level, IP6T_SO_ORIGINAL_DST = 80（同值，不同 level）

const SO_ORIGINAL_DST: libc::c_int = 80;

// ── 公开结构 ──────────────────────────────────────────────────────────────────

pub struct RedirInbound {
    config: RedirInboundConfig,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
}

impl RedirInbound {
    pub fn new(config: RedirInboundConfig, tcp_tx: mpsc::Sender<InboundTcpStream>) -> Self {
        Self { config, tcp_tx }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let bind: SocketAddr =
            format!("{}:{}", self.config.listen, self.config.listen_port).parse()?;
        let tag = self.config.tag.clone();

        info!(tag=%tag, addr=%bind, "redir inbound starting");

        let listener = create_redir_tcp_listener(bind)?;
        run_tcp(listener, self.tcp_tx, tag).await
    }
}

// ── Socket 创建 ───────────────────────────────────────────────────────────────

/// 创建用于接收 REDIRECT 流量的 TCP listener。
///
/// Redirect 不需要 `IP_TRANSPARENT`；内核已将连接目标改写为本机地址，
/// listener 只需普通绑定即可。`SO_REUSEADDR` 保证进程重启时不等待 TIME_WAIT。
fn create_redir_tcp_listener(addr: SocketAddr) -> anyhow::Result<TcpListener> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_reuse_address(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    // backlog 4096：与 tproxy 保持一致，应对突发连接
    sock.listen(4096)?;
    Ok(TcpListener::from_std(std::net::TcpListener::from(sock))?)
}

// ── TCP accept 循环 ───────────────────────────────────────────────────────────

async fn run_tcp(
    listener: TcpListener,
    tx: mpsc::Sender<InboundTcpStream>,
    tag: String,
) -> anyhow::Result<()> {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                let raw = e.raw_os_error();
                // EMFILE(24)/ENFILE(23)：FD 耗尽，退避后重试（与 tproxy 保持一致）
                if raw == Some(libc::EMFILE) || raw == Some(libc::ENFILE) {
                    error!(err=%e, "redir tcp accept error (fd exhausted, backing off 200ms)");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                } else {
                    error!(err=%e, "redir tcp accept error");
                }
                continue;
            }
        };

        // 从连接 fd 上读取原始目标地址（SO_ORIGINAL_DST）
        let target = match get_original_dst(&stream) {
            Ok(dst) => Target::Socket(dst),
            Err(e) => {
                warn!(peer=%peer, err=%e, "redir: failed to get original dst, dropping");
                continue;
            }
        };

        debug!(peer=%peer, target=%target, "redir tcp accepted");

        if tx
            .send(InboundTcpStream {
                stream: SniffedStream::new(stream),
                target,
                inbound_tag: tag.clone(),
                sniffed_protocol: None,
                sniffed_domain: None,
            })
            .await
            .is_err()
        {
            // Dispatcher 已关闭，退出
            break;
        }
    }
    Ok(())
}

// ── 获取原始目标地址 ──────────────────────────────────────────────────────────

/// 通过 `SO_ORIGINAL_DST` / `IP6T_SO_ORIGINAL_DST` getsockopt 取回
/// 被 REDIRECT 改写前的真实目标地址。
///
/// 参考 sing-box `redir/redir_linux.go` 的 `GetOriginalDestination` 实现：
/// - IPv4：`getsockopt(IPPROTO_IP, SO_ORIGINAL_DST)` → `sockaddr_in`
/// - IPv6：`getsockopt(IPPROTO_IPV6, IP6T_SO_ORIGINAL_DST=80)` → `sockaddr_in6`
fn get_original_dst(stream: &tokio::net::TcpStream) -> anyhow::Result<SocketAddr> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();

    unsafe {
        // ── IPv4 ──────────────────────────────────────────────────────────────
        let mut addr4: libc::sockaddr_in = std::mem::zeroed();
        let mut len4 = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        if libc::getsockopt(
            fd,
            libc::IPPROTO_IP,
            SO_ORIGINAL_DST,
            &mut addr4 as *mut _ as *mut libc::c_void,
            &mut len4,
        ) == 0
        {
            let ip = Ipv4Addr::from(u32::from_be(addr4.sin_addr.s_addr));
            return Ok(SocketAddr::V4(SocketAddrV4::new(
                ip,
                u16::from_be(addr4.sin_port),
            )));
        }

        // ── IPv6 (IP6T_SO_ORIGINAL_DST = 80，level = IPPROTO_IPV6) ───────────
        let mut addr6: libc::sockaddr_in6 = std::mem::zeroed();
        let mut len6 = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        if libc::getsockopt(
            fd,
            libc::IPPROTO_IPV6,
            SO_ORIGINAL_DST, // IP6T_SO_ORIGINAL_DST = 80
            &mut addr6 as *mut _ as *mut libc::c_void,
            &mut len6,
        ) == 0
        {
            let ip = Ipv6Addr::from(addr6.sin6_addr.s6_addr);
            return Ok(SocketAddr::V6(SocketAddrV6::new(
                ip,
                u16::from_be(addr6.sin6_port),
                0,
                0,
            )));
        }
    }

    anyhow::bail!(
        "SO_ORIGINAL_DST failed: {}",
        std::io::Error::last_os_error()
    )
}
