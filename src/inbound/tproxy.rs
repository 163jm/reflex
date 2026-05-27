//! Linux TProxy 入站。
//!
//! ## 使用前提
//! 外部已配置好 iptables/nftables 规则，例如：
//!
//! ```bash
//! # TCP
//! iptables -t mangle -A PREROUTING -p tcp -j TPROXY \
//!   --tproxy-mark 0x1 --on-ip 0.0.0.0 --on-port 7893
//!
//! # UDP
//! iptables -t mangle -A PREROUTING -p udp -j TPROXY \
//!   --tproxy-mark 0x1 --on-ip 0.0.0.0 --on-port 7893
//!
//! # 本机流量路由（避免环路）
//! ip rule add fwmark 0x1 table 100
//! ip route add local 0.0.0.0/0 dev lo table 100
//! ```

use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::unix::io::{AsRawFd, RawFd},
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    io::unix::AsyncFd,
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tracing::{debug, error, info, warn};

use crate::{
    config::inbound::TProxyInboundConfig,
    inbound::{InboundTcpStream, InboundUdpPacket, SniffedStream, Target, UdpSession},
};

pub struct TProxyInbound {
    config: TProxyInboundConfig,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
}

impl TProxyInbound {
    pub fn new(
        config: TProxyInboundConfig,
        tcp_tx: mpsc::Sender<InboundTcpStream>,
        udp_tx: mpsc::Sender<InboundUdpPacket>,
    ) -> Self {
        Self {
            config,
            tcp_tx,
            udp_tx,
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let bind: SocketAddr =
            format!("{}:{}", self.config.listen, self.config.listen_port).parse()?;
        let tag = self.config.tag.clone();
        let net = self.config.network;
        let routing_mark = self.config.routing_mark;

        info!(tag=%tag, addr=%bind, "tproxy inbound starting");

        let mut handles = vec![];

        if net.tcp() {
            let listener = create_tproxy_tcp_listener(bind)?;
            let tx = self.tcp_tx.clone();
            let tag = tag.clone();
            handles.push(tokio::spawn(
                async move { run_tcp(listener, tx, tag).await },
            ));
        }

        if net.udp() {
            let socket = create_tproxy_udp_socket(bind)?;
            let tx = self.udp_tx.clone();
            let tag = tag.clone();
            handles.push(tokio::spawn(async move { run_udp(socket, tx, tag, routing_mark).await }));
        }

        for h in handles {
            h.await??;
        }
        Ok(())
    }
}

// ── TCP ───────────────────────────────────────────────────────────────────────

fn create_tproxy_tcp_listener(addr: SocketAddr) -> anyhow::Result<TcpListener> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_reuse_address(true)?;
    sock.set_ip_transparent(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    sock.listen(4096)?;
    Ok(TcpListener::from_std(std::net::TcpListener::from(sock))?)
}

async fn run_tcp(
    listener: TcpListener,
    tx: mpsc::Sender<InboundTcpStream>,
    tag: String,
) -> anyhow::Result<()> {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                // EMFILE (24) / ENFILE (23)：FD 耗尽，短暂退避后继续。
                // 立即重试只会产生无意义的错误风暴并消耗 CPU。
                // 参考 sing-box loopTCPIn 的 Temporary() 处理逻辑。
                let raw = e.raw_os_error();
                if raw == Some(libc::EMFILE) || raw == Some(libc::ENFILE) {
                    error!(err=%e, "tproxy tcp accept error (fd exhausted, backing off 200ms)");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                } else {
                    error!(err=%e, "tproxy tcp accept error");
                }
                continue;
            }
        };

        let target = match get_original_dst_tcp(&stream) {
            Ok(dst) => Target::Socket(dst),
            Err(e) => {
                warn!(peer=%peer, err=%e, "failed to get original dst");
                continue;
            }
        };

        debug!(peer=%peer, target=%target, "tproxy tcp accepted");

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
            break;
        }
    }
    Ok(())
}

fn get_original_dst_tcp(stream: &TcpStream) -> anyhow::Result<SocketAddr> {
    let fd = stream.as_raw_fd();
    unsafe {
        // IPv4
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        if libc::getsockopt(
            fd,
            libc::SOL_IP,
            libc::SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        ) == 0
        {
            let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            return Ok(SocketAddr::V4(SocketAddrV4::new(
                ip,
                u16::from_be(addr.sin_port),
            )));
        }
        // IPv6 (IP6T_SO_ORIGINAL_DST = 80)
        let mut addr6: libc::sockaddr_in6 = std::mem::zeroed();
        let mut len6 = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        if libc::getsockopt(
            fd,
            libc::IPPROTO_IPV6,
            80,
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

// ── UDP ───────────────────────────────────────────────────────────────────────

/// UDP 会话：(src, dst) → 回包 sender，带最后活跃时间
struct UdpSessionEntry {
    /// (数据, 客户端地址, 伪造源地址) — 伪造源地址 = 原始目标（游戏服务器IP:port）
    reply_tx: mpsc::Sender<(Bytes, SocketAddr, SocketAddr)>,
    last_seen: Instant,
    /// 该会话的空闲超时时长（按目标端口决定）
    timeout: Duration,
}

fn create_tproxy_udp_socket(addr: SocketAddr) -> anyhow::Result<std::net::UdpSocket> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.set_ip_transparent(true)?;
    sock.set_nonblocking(true)?;

    unsafe {
        let one: libc::c_int = 1;
        if addr.is_ipv4() {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_RECVORIGDSTADDR,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        } else {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVORIGDSTADDR,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
    sock.bind(&addr.into())?;
    Ok(sock.into())
}

/// tproxy UDP 会话空闲超时（参照 sing-box：默认 5 分钟，DNS/NTP/STUN 用 10 s）
const TPROXY_UDP_SESSION_TIMEOUT: Duration = Duration::from_secs(300);

fn tproxy_udp_timeout_for_port(port: u16) -> Duration {
    match port {
        53 | 123 | 3478 => Duration::from_secs(10),
        443 => Duration::from_secs(30),
        _ => TPROXY_UDP_SESSION_TIMEOUT,
    }
}

async fn run_udp(
    socket: std::net::UdpSocket,
    tx: mpsc::Sender<InboundUdpPacket>,
    tag: String,
    routing_mark: u32,
) -> anyhow::Result<()> {
    let local_addr = socket.local_addr()?;
    info!(tag=%tag, addr=%local_addr, routing_mark=%routing_mark, "tproxy udp listener started");
    let async_fd = Arc::new(AsyncFd::new(socket)?);
    // (数据, 客户端地址, 伪造源地址=游戏服务器IP:port)
    let (global_reply_tx, mut global_reply_rx) = mpsc::channel::<(Bytes, SocketAddr, SocketAddr)>(256);

    // 回包发送循环：照抄 sing-box tproxyPacketWriter 的做法
    // 新建一个 IP_TRANSPARENT socket，bind 到游戏服务器的 IP:port，
    // 然后直接 send_to 客户端——客户端收到的源地址天然就是游戏服务器地址。
    // 同时必须设置 SO_MARK = routing_mark，否则新 socket 发出的包会被
    // nftables 的 proxy_out 链再次拦截，导致回包永远发不出去。
    tokio::spawn(async move {
        while let Some((data, client_addr, server_addr)) = global_reply_rx.recv().await {
            match tproxy_udp_writeback(&data, client_addr, server_addr, routing_mark) {
                Ok(_) => {}
                Err(e) => warn!(err=%e, client=%client_addr, server=%server_addr, "tproxy udp writeback error"),
            }
        }
    });

    let mut sessions: HashMap<(SocketAddr, SocketAddr), UdpSessionEntry> = HashMap::new();
    let mut buf = vec![0u8; 65535];
    let fd = async_fd.get_ref().as_raw_fd();

    // GC 定时器：每 30 秒清理过期会话，不依赖包计数
    // 参照 sing-box canceler 的 context + timer 设计，以时间为基准而非流量
    let mut gc_ticker = tokio::time::interval(Duration::from_secs(30));
    gc_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased; // 优先处理数据包，GC 是低优先级

            readable = async_fd.readable() => {
                let mut guard = readable?;

                // edge-trigger 模式：必须循环读到 EAGAIN，否则缓冲区里剩余的包
                // 不会再触发 epoll 事件，导致这些包被永久丢弃。
                loop {
                    let (n, src, dst) = match recvmsg_with_dst(fd, &mut buf) {
                        Ok(v) => v,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            // 缓冲区已清空，清除 ready 标记，等待下次 epoll 事件
                            guard.clear_ready();
                            break;
                        }
                        Err(e) => {
                            error!(err=%e, "tproxy udp recvmsg error");
                            guard.clear_ready();
                            break;
                        }
                    };

                    let data = Bytes::copy_from_slice(&buf[..n]);
                    let timeout = tproxy_udp_timeout_for_port(dst.port());

                    let key = (src, dst);
                    let entry = sessions.entry(key).or_insert_with(|| {
                        debug!(src=%src, dst=%dst, "tproxy udp new session");
                        UdpSessionEntry {
                            reply_tx: global_reply_tx.clone(),
                            last_seen: Instant::now(),
                            timeout,
                        }
                    });
                    entry.last_seen = Instant::now();

                    let session = UdpSession {
                        reply_tx: entry.reply_tx.clone(),
                    };
                    let packet = InboundUdpPacket {
                        data,
                        src,
                        target: Target::Socket(dst),
                        inbound_tag: tag.clone(),
                        session,
                        sniffed_protocol: None,
                        sniffed_domain: None,
                        upstream_rx: None,
                        lifetime_guards: vec![],
                    };

                    if tx.send(packet).await.is_err() {
                        return Ok(());
                    }
                }
            }

            _ = gc_ticker.tick() => {
                // 按每个会话自身的超时清理，而不是全局固定 60 s
                sessions.retain(|_, v| v.last_seen.elapsed() < v.timeout);
                debug!(sessions=%sessions.len(), "tproxy udp gc done");
            }
        }
    }
}

// ── recvmsg（同步，在 readable 回调里调用）────────────────────────────────────

fn recvmsg_with_dst(fd: RawFd, buf: &mut [u8]) -> Result<(usize, SocketAddr, SocketAddr), std::io::Error> {
    const CMSG_SPACE: usize = 128;
    let mut cmsg_buf = [0u8; CMSG_SPACE];
    let mut src_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };

    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut src_storage as *mut _ as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = CMSG_SPACE as _;

    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let src = sockaddr_storage_to_socketaddr(&src_storage)
        .map_err(std::io::Error::other)?;
    let dst = extract_original_dst_from_cmsg(&msg)
        .map_err(std::io::Error::other)?;
    Ok((n as usize, src, dst))
}

fn sockaddr_storage_to_socketaddr(ss: &libc::sockaddr_storage) -> anyhow::Result<SocketAddr> {
    unsafe {
        match ss.ss_family as libc::c_int {
            libc::AF_INET => {
                let sa = &*(ss as *const _ as *const libc::sockaddr_in);
                Ok(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)),
                    u16::from_be(sa.sin_port),
                )))
            }
            libc::AF_INET6 => {
                let sa = &*(ss as *const _ as *const libc::sockaddr_in6);
                Ok(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(sa.sin6_addr.s6_addr),
                    u16::from_be(sa.sin6_port),
                    0,
                    0,
                )))
            }
            other => anyhow::bail!("unknown address family: {other}"),
        }
    }
}

// ── tproxy_udp_writeback ──────────────────────────────────────────────────────
//
// sing-box 的做法：新建一个 IP_TRANSPARENT socket，bind 到游戏服务器的 IP:port，
// 然后直接 send_to 客户端。客户端看到的源地址天然就是游戏服务器地址。
// 参考：sing-box tproxyPacketWriter.WritePacket

fn tproxy_udp_writeback(
    data: &[u8],
    client_addr: SocketAddr,  // 发给谁（客户端）
    server_addr: SocketAddr,  // bind 到哪（游戏服务器IP:port，作为伪造源地址）
    routing_mark: u32,        // SO_MARK，让新 socket 绕过 nftables TProxy 规则
) -> std::io::Result<()> {
    let sock = Socket::new(
        if server_addr.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 },
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    sock.set_reuse_address(true)?;
    sock.set_ip_transparent(true)?;
    sock.set_nonblocking(false)?;
    // 设置 SO_MARK，让这个 socket 发出的包匹配 nftables proxy_out 里的 GID/mark 豁免规则
    // 否则新建的 socket 没有 mark，发出的包会被 TProxy 规则再次拦截，回包变成死循环
    if routing_mark != 0 {
        unsafe {
            let fd = sock.as_raw_fd();
            let mark = routing_mark;
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &mark as *const u32 as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            );
        }
    }
    sock.bind(&server_addr.into())?;
    sock.send_to(data, &client_addr.into())?;
    Ok(())
}

fn extract_original_dst_from_cmsg(msg: &libc::msghdr) -> anyhow::Result<SocketAddr> {
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msg as *const _);
        while !cmsg.is_null() {
            let c = &*cmsg;
            if c.cmsg_level == libc::IPPROTO_IP && c.cmsg_type == libc::IP_ORIGDSTADDR {
                let sa = &*(libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in);
                return Ok(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)),
                    u16::from_be(sa.sin_port),
                )));
            }
            // IPV6_ORIGDSTADDR = 74
            if c.cmsg_level == libc::IPPROTO_IPV6 && c.cmsg_type == 74 {
                let sa = &*(libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in6);
                return Ok(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(sa.sin6_addr.s6_addr),
                    u16::from_be(sa.sin6_port),
                    0,
                    0,
                )));
            }
            cmsg = libc::CMSG_NXTHDR(msg as *const _, cmsg);
        }
    }
    anyhow::bail!("no original dst in cmsg")
}
