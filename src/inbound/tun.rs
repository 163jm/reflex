//! TUN 虚拟网卡入站。
//!
//! ## TCP 处理（System Stack NAT，参照 sing-tun）
//!
//! 原始实现对每个 SYN 包创建临时 TcpListener 等待 accept，这是错误的——
//! TUN 读到的包是客户端发往外部的，内核不会再反向连进来。
//!
//! 正确做法（参照 sing-tun `stack_system.go`）：
//!
//! 1. 启动时在 TUN 自身地址（`inet4_addr`，如 198.18.0.1）上开一个长期 TcpListener。
//! 2. 收到 TCP 包时，**改写包头**，将目的地址改为 TUN 地址、目的端口改为 Listener 端口，
//!    源地址改为 `inet4_next`（如 198.18.0.2），源端口改为 NAT 映射端口，写回 TUN。
//! 3. 内核 TCP 栈接受改写后的包，向 Listener 发起连接；accept 后按 NAT 表还原真实目标。
//!
//! ## UDP 处理
//!
//! UDP 会话表维持 (src, dst) → reply_tx 映射，回包时直接封装 IP/UDP 头写回 TUN。
//! UDP 回包**修正了 checksum**（含伪头部校验和），原实现 checksum 字段置 0 在严格内核下会丢包。
//!
//! ## ICMP 处理（新增）
//!
//! ICMPv4/v6 Echo Request 在 TUN 内部回环（src↔dst 互换，类型改为 Reply），
//! 不再静默丢弃，`ping` 可正常工作。
//!
//! ## 其他修复
//!
//! - IP 分片包（`MF` 标志或 `FragmentOffset != 0`）直接跳过，不崩溃。
//! - UDP 包长度校验：`length` 字段比实际 payload 短时截断，避免越界。
//! - UDP 回包正确处理 IPv6（原实现 `build_udp_reply_packet` 只支持 IPv4）。
//! - GC 从每 1024 包改为定时 ticker，避免低流量场景会话永不回收。
//! - auto_route Linux：suppress_prefixlength 0 规则修复（原实现 `not dport 53` 参数位置错误）。

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{mpsc, Mutex, RwLock},
};
use tracing::{debug, error, info, warn};

use crate::{
    config::inbound::TunInboundConfig,
    inbound::{InboundTcpStream, InboundUdpPacket, SniffedStream, Target, UdpSession},
};

// ── 常量 ──────────────────────────────────────────────────────────────────────

const DEFAULT_UDP_TIMEOUT_SECS: u64 = 300;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_ICMPV6: u8 = 58;
const IPV4_VERSION: u8 = 4;
const IPV6_VERSION: u8 = 6;

// NAT 端口范围
const NAT_PORT_START: u16 = 10000;
const NAT_PORT_END: u16 = 60000;

// ── 辅助函数 ──────────────────────────────────────────────────────────────────

pub(crate) fn prefix_len_to_mask_v4(len: u8) -> Ipv4Addr {
    if len == 0 {
        return Ipv4Addr::new(0, 0, 0, 0);
    }
    let mask = !((1u32 << (32 - len.min(32))) - 1);
    Ipv4Addr::from(mask)
}

fn parse_addr_prefix(s: &str) -> Option<(IpAddr, u8)> {
    let (ip_str, len_str) = s.split_once('/')?;
    let ip: IpAddr = ip_str.parse().ok()?;
    let prefix_len: u8 = len_str.parse().ok()?;
    let max_len = if ip.is_ipv4() { 32 } else { 128 };
    if prefix_len > max_len {
        return None;
    }
    Some((ip, prefix_len))
}

// ── TCP NAT 表 ────────────────────────────────────────────────────────────────

struct TcpNatEntry {
    source: SocketAddr,
    destination: SocketAddr,
    last_active: Instant,
}

struct TcpNat {
    port_index: u16,
    /// (src_addr, src_port) → nat_port
    addr_map: HashMap<SocketAddr, u16>,
    /// nat_port → session
    port_map: HashMap<u16, TcpNatEntry>,
}

impl TcpNat {
    fn new() -> Self {
        Self {
            port_index: NAT_PORT_START,
            addr_map: HashMap::new(),
            port_map: HashMap::new(),
        }
    }

    /// 为新的 (src, dst) 分配 NAT 端口；如果已有映射直接返回。
    fn lookup_or_insert(&mut self, src: SocketAddr, dst: SocketAddr) -> u16 {
        if let Some(&port) = self.addr_map.get(&src) {
            if let Some(entry) = self.port_map.get_mut(&port) {
                entry.last_active = Instant::now();
            }
            return port;
        }
        // 分配新端口，循环跳过已占用的
        let start = self.port_index;
        loop {
            let port = self.port_index;
            self.port_index = if self.port_index >= NAT_PORT_END {
                NAT_PORT_START
            } else {
                self.port_index + 1
            };
            if !self.port_map.contains_key(&port) {
                self.addr_map.insert(src, port);
                self.port_map.insert(
                    port,
                    TcpNatEntry {
                        source: src,
                        destination: dst,
                        last_active: Instant::now(),
                    },
                );
                return port;
            }
            if self.port_index == start {
                // 端口耗尽，强行复用最旧的
                break;
            }
        }
        // fallback：直接返回当前 port_index
        let port = self.port_index;
        self.addr_map.insert(src, port);
        self.port_map.insert(
            port,
            TcpNatEntry {
                source: src,
                destination: dst,
                last_active: Instant::now(),
            },
        );
        port
    }

    /// 根据 NAT 端口反查原始 (src, dst)。
    fn lookup_back(&mut self, nat_port: u16) -> Option<(SocketAddr, SocketAddr)> {
        let entry = self.port_map.get_mut(&nat_port)?;
        entry.last_active = Instant::now();
        Some((entry.source, entry.destination))
    }

    /// GC：删除超时会话。
    fn gc(&mut self, timeout: Duration) {
        let now = Instant::now();
        let expired: Vec<u16> = self
            .port_map
            .iter()
            .filter(|(_, e)| now.duration_since(e.last_active) > timeout)
            .map(|(&p, _)| p)
            .collect();
        for port in expired {
            if let Some(entry) = self.port_map.remove(&port) {
                self.addr_map.remove(&entry.source);
            }
        }
    }
}

// ── TunInbound ────────────────────────────────────────────────────────────────

pub struct TunInbound {
    config: TunInboundConfig,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
}

impl TunInbound {
    pub fn new(
        config: TunInboundConfig,
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
        let cfg = Arc::new(self.config);
        let tag = Arc::new(cfg.tag.clone());
        let udp_timeout = Duration::from_secs(if cfg.udp_timeout == 0 {
            DEFAULT_UDP_TIMEOUT_SECS
        } else {
            cfg.udp_timeout
        });

        // ── 解析 TUN 地址 ────────────────────────────────────────────────────
        let mut inet4_addr: Option<Ipv4Addr> = None;
        let mut inet4_next: Option<Ipv4Addr> = None; // inet4_addr + 1，供 NAT 改包用
        let mut inet6_addr: Option<Ipv6Addr> = None;
        let mut inet6_next: Option<Ipv6Addr> = None;

        for addr_str in &cfg.address {
            match parse_addr_prefix(addr_str) {
                Some((IpAddr::V4(ip), _)) if inet4_addr.is_none() => {
                    inet4_addr = Some(ip);
                    let next = u32::from(ip).wrapping_add(1);
                    inet4_next = Some(Ipv4Addr::from(next));
                }
                Some((IpAddr::V6(ip), _)) if inet6_addr.is_none() => {
                    inet6_addr = Some(ip);
                    let next = u128::from(ip).wrapping_add(1);
                    inet6_next = Some(Ipv6Addr::from(next));
                }
                None => warn!(addr = %addr_str, "tun: invalid address prefix"),
                _ => {}
            }
        }

        if inet4_addr.is_none() && inet6_addr.is_none() {
            anyhow::bail!("tun: at least one address must be configured");
        }

        // ── 创建 TUN 设备 ────────────────────────────────────────────────────
        let (dev, if_name) = {
            let mut tun_cfg = tun::Configuration::default();
            if let Some(ref name) = cfg.interface_name {
                tun_cfg.name(name);
            }
            tun_cfg.mtu(cfg.mtu as i32);
            tun_cfg.up();

            if let Some(ip) = inet4_addr {
                if let Some((_, prefix_len)) = cfg
                    .address
                    .iter()
                    .find_map(|s| parse_addr_prefix(s).filter(|(a, _)| a.is_ipv4()))
                {
                    tun_cfg
                        .address(ip)
                        .netmask(prefix_len_to_mask_v4(prefix_len));
                }
            }

            #[cfg(target_os = "linux")]
            tun_cfg.platform(|p| {
                p.packet_information(true);
            });

            let dev = tun::create_as_async(&tun_cfg)
                .map_err(|e| anyhow::anyhow!("failed to create TUN device: {e}"))?;

            let if_name = cfg
                .interface_name
                .clone()
                .unwrap_or_else(|| "tun0".to_string());
            (dev, if_name)
        };

        info!(
            tag = %tag,
            interface = %if_name,
            mtu = cfg.mtu,
            "tun inbound started"
        );

        // ── auto_route ───────────────────────────────────────────────────────
        if cfg.auto_route {
            if let Err(e) = platform::setup(&cfg, &if_name) {
                warn!(err = %e, "tun: auto_route setup failed (requires elevated privileges)");
            }
        }

        // ── 在 TUN 地址上开 TCP Listener ────────────────────────────────────
        // 参照 sing-tun: 在 inet4_addr 和 inet6_addr 上各开一个 Listener，端口 0（随机）
        let tcp_listener_v4: Option<Arc<TcpListener>> = if let Some(addr) = inet4_addr {
            match TcpListener::bind(SocketAddrV4::new(addr, 0)).await {
                Ok(l) => {
                    info!(tag = %tag, addr = %l.local_addr().unwrap(), "tun: TCP v4 listener ready");
                    Some(Arc::new(l))
                }
                Err(e) => {
                    warn!(err = %e, "tun: failed to bind TCP v4 listener");
                    None
                }
            }
        } else {
            None
        };

        let tcp_listener_v6: Option<Arc<TcpListener>> = if let Some(addr) = inet6_addr {
            match TcpListener::bind(SocketAddrV6::new(addr, 0, 0, 0)).await {
                Ok(l) => {
                    info!(tag = %tag, addr = %l.local_addr().unwrap(), "tun: TCP v6 listener ready");
                    Some(Arc::new(l))
                }
                Err(e) => {
                    warn!(err = %e, "tun: failed to bind TCP v6 listener");
                    None
                }
            }
        } else {
            None
        };

        let tcp_port_v4 = tcp_listener_v4
            .as_ref()
            .and_then(|l| l.local_addr().ok())
            .map(|a| a.port())
            .unwrap_or(0);
        let tcp_port_v6 = tcp_listener_v6
            .as_ref()
            .and_then(|l| l.local_addr().ok())
            .map(|a| a.port())
            .unwrap_or(0);

        // ── TCP NAT 表 ───────────────────────────────────────────────────────
        let tcp_nat = Arc::new(RwLock::new(TcpNat::new()));

        // ── 启动 TCP accept loop ─────────────────────────────────────────────
        if let Some(listener) = tcp_listener_v4.clone() {
            let nat = tcp_nat.clone();
            let tcp_tx = self.tcp_tx.clone();
            let tag2 = tag.clone();
            tokio::spawn(async move {
                accept_loop(listener, nat, tcp_tx, tag2).await;
            });
        }
        if let Some(listener) = tcp_listener_v6.clone() {
            let nat = tcp_nat.clone();
            let tcp_tx = self.tcp_tx.clone();
            let tag2 = tag.clone();
            tokio::spawn(async move {
                accept_loop(listener, nat, tcp_tx, tag2).await;
            });
        }

        // ── UDP 会话表 ───────────────────────────────────────────────────────
        let udp_sessions: Arc<Mutex<HashMap<(SocketAddr, SocketAddr), UdpEntry>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // ── 拆分 TUN 读写半部 ────────────────────────────────────────────────
        let (mut reader, writer) = tokio::io::split(dev);
        let writer = Arc::new(Mutex::new(writer));

        // ── 定时 GC ──────────────────────────────────────────────────────────
        {
            let nat = tcp_nat.clone();
            let sessions = udp_sessions.clone();
            let timeout = udp_timeout;
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(timeout / 2);
                loop {
                    ticker.tick().await;
                    nat.write().await.gc(timeout);
                    sessions
                        .lock()
                        .await
                        .retain(|_, v| v.last_seen.elapsed() < timeout);
                }
            });
        }

        let mut pkt_buf = vec![0u8; cfg.mtu as usize + 64];

        loop {
            let n = match reader.read(&mut pkt_buf).await {
                Ok(0) => {
                    info!(tag = %tag, "tun device closed");
                    break;
                }
                Ok(n) => n,
                Err(e) => {
                    error!(err = %e, "tun read error");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
            };

            // Linux TUN 带 4 字节 packet_information 头
            #[cfg(target_os = "linux")]
            let pkt_slice = if n >= 4 { &pkt_buf[4..n] } else { continue };
            #[cfg(not(target_os = "linux"))]
            let pkt_slice = &pkt_buf[..n];

            if pkt_slice.is_empty() {
                continue;
            }
            let version = pkt_slice[0] >> 4;

            match version {
                IPV4_VERSION => {
                    process_ipv4(
                        pkt_slice,
                        inet4_addr,
                        inet4_next,
                        tcp_port_v4,
                        &tag,
                        &self.tcp_tx,
                        &self.udp_tx,
                        writer.clone(),
                        tcp_nat.clone(),
                        udp_sessions.clone(),
                        udp_timeout,
                    )
                    .await;
                }
                IPV6_VERSION => {
                    process_ipv6(
                        pkt_slice,
                        inet6_addr,
                        inet6_next,
                        tcp_port_v6,
                        &tag,
                        &self.tcp_tx,
                        &self.udp_tx,
                        writer.clone(),
                        tcp_nat.clone(),
                        udp_sessions.clone(),
                        udp_timeout,
                    )
                    .await;
                }
                v => {
                    debug!(version = v, "tun: unknown IP version, dropping");
                }
            }
        }

        if cfg.auto_route {
            if let Err(e) = platform::teardown(&cfg, &if_name) {
                warn!(err = %e, "tun: auto_route teardown failed");
            }
        }

        Ok(())
    }
}

// ── TCP accept loop ───────────────────────────────────────────────────────────

async fn accept_loop(
    listener: Arc<TcpListener>,
    tcp_nat: Arc<RwLock<TcpNat>>,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    tag: Arc<String>,
) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                debug!(err = %e, "tun: TCP accept error");
                tokio::time::sleep(Duration::from_millis(5)).await;
                continue;
            }
        };
        // peer.port() 是 NAT 分配的端口，用来反查真实目标
        let nat_port = peer.port();
        let result = {
            let mut nat = tcp_nat.write().await;
            nat.lookup_back(nat_port)
        };
        match result {
            Some((_src, dst)) => {
                let inbound = InboundTcpStream {
                    stream: SniffedStream::new(stream),
                    target: Target::Socket(dst),
                    inbound_tag: (*tag).clone(),
                    sniffed_protocol: None,
                    sniffed_domain: None,
                };
                if tcp_tx.send(inbound).await.is_err() {
                    debug!("tun: tcp_tx closed");
                    break;
                }
            }
            None => {
                debug!(nat_port, "tun: unknown NAT port, dropping TCP connection");
            }
        }
    }
}

// ── UDP 会话条目 ──────────────────────────────────────────────────────────────

struct UdpEntry {
    reply_tx: mpsc::Sender<(Bytes, SocketAddr)>,
    last_seen: Instant,
}

// ── IPv4 包处理 ───────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn process_ipv4(
    raw: &[u8],
    inet4_addr: Option<Ipv4Addr>,
    inet4_next: Option<Ipv4Addr>,
    tcp_port: u16,
    tag: &Arc<String>,
    _tcp_tx: &mpsc::Sender<InboundTcpStream>,
    udp_tx: &mpsc::Sender<InboundUdpPacket>,
    writer: Arc<Mutex<impl AsyncWriteExt + Unpin + Send + 'static>>,
    tcp_nat: Arc<RwLock<TcpNat>>,
    udp_sessions: Arc<Mutex<HashMap<(SocketAddr, SocketAddr), UdpEntry>>>,
    udp_timeout: Duration,
) {
    if raw.len() < 20 {
        return;
    }
    let ihl = ((raw[0] & 0x0f) as usize) * 4;
    if raw.len() < ihl || ihl < 20 {
        return;
    }
    let proto = raw[9];
    let flags_frag = u16::from_be_bytes([raw[6], raw[7]]);
    let more_fragments = (flags_frag & 0x2000) != 0;
    let frag_offset = flags_frag & 0x1fff;

    let src_ip = Ipv4Addr::from([raw[12], raw[13], raw[14], raw[15]]);
    let dst_ip = Ipv4Addr::from([raw[16], raw[17], raw[18], raw[19]]);
    let payload = &raw[ihl..];

    match proto {
        IPPROTO_TCP => {
            // 跳过 IP 分片（只处理完整包或第一片，但分片 TCP 极罕见）
            if more_fragments || frag_offset != 0 {
                debug!("tun: ipv4 tcp fragment dropped");
                return;
            }
            handle_tcp_v4(
                raw, payload, src_ip, dst_ip, inet4_addr, inet4_next, tcp_port, writer, tcp_nat,
            )
            .await;
        }
        IPPROTO_UDP => {
            if more_fragments || frag_offset != 0 {
                debug!("tun: ipv4 udp fragment dropped");
                return;
            }
            if let Some((src, dst, data)) = parse_udp_v4(payload, src_ip, dst_ip) {
                dispatch_udp(
                    src,
                    dst,
                    data,
                    tag.clone(),
                    udp_tx,
                    writer,
                    udp_sessions,
                    udp_timeout,
                )
                .await;
            }
        }
        IPPROTO_ICMP => {
            // ICMPv4 Echo Request → Echo Reply（ping 回环）
            handle_icmpv4(raw, ihl, src_ip, dst_ip, inet4_addr, writer).await;
        }
        _ => {}
    }
}

// ── IPv6 包处理 ───────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn process_ipv6(
    raw: &[u8],
    inet6_addr: Option<Ipv6Addr>,
    inet6_next: Option<Ipv6Addr>,
    tcp_port: u16,
    tag: &Arc<String>,
    _tcp_tx: &mpsc::Sender<InboundTcpStream>,
    udp_tx: &mpsc::Sender<InboundUdpPacket>,
    writer: Arc<Mutex<impl AsyncWriteExt + Unpin + Send + 'static>>,
    tcp_nat: Arc<RwLock<TcpNat>>,
    udp_sessions: Arc<Mutex<HashMap<(SocketAddr, SocketAddr), UdpEntry>>>,
    udp_timeout: Duration,
) {
    if raw.len() < 40 {
        return;
    }
    let proto = raw[6];
    let src_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&raw[8..24]).unwrap_or([0u8; 16]));
    let dst_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&raw[24..40]).unwrap_or([0u8; 16]));
    let payload = &raw[40..];

    match proto {
        IPPROTO_TCP => {
            handle_tcp_v6(
                raw, payload, src_ip, dst_ip, inet6_addr, inet6_next, tcp_port, writer, tcp_nat,
            )
            .await;
        }
        IPPROTO_UDP => {
            if let Some((src, dst, data)) = parse_udp_v6(payload, src_ip, dst_ip) {
                dispatch_udp(
                    src,
                    dst,
                    data,
                    tag.clone(),
                    udp_tx,
                    writer,
                    udp_sessions,
                    udp_timeout,
                )
                .await;
            }
        }
        IPPROTO_ICMPV6 => {
            handle_icmpv6(raw, src_ip, dst_ip, inet6_addr, writer).await;
        }
        _ => {}
    }
}

// ── TCP NAT 改包（System Stack 核心逻辑，参照 sing-tun processIPv4TCP）────────

#[allow(clippy::too_many_arguments)]
async fn handle_tcp_v4(
    raw: &[u8],
    tcp_payload: &[u8],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    inet4_addr: Option<Ipv4Addr>,
    inet4_next: Option<Ipv4Addr>,
    tcp_port: u16,
    writer: Arc<Mutex<impl AsyncWriteExt + Unpin + Send + 'static>>,
    tcp_nat: Arc<RwLock<TcpNat>>,
) {
    let (inet4_addr, inet4_next) = match (inet4_addr, inet4_next) {
        (Some(a), Some(n)) => (a, n),
        _ => return,
    };
    if tcp_payload.len() < 20 {
        return;
    }
    let src_port = u16::from_be_bytes([tcp_payload[0], tcp_payload[1]]);
    let dst_port = u16::from_be_bytes([tcp_payload[2], tcp_payload[3]]);
    let flags = tcp_payload[13];

    let src = SocketAddr::V4(SocketAddrV4::new(src_ip, src_port));
    let dst = SocketAddr::V4(SocketAddrV4::new(dst_ip, dst_port));

    // 来自 Listener 的回包（src 是 TUN 地址）：反写还原给客户端
    if src_ip == inet4_addr && src_port == tcp_port {
        let nat_dst_port = dst_port; // dst_port 是 NAT 分配的端口
        let result = {
            let mut nat = tcp_nat.write().await;
            nat.lookup_back(nat_dst_port)
        };
        if let Some((orig_src, orig_dst)) = result {
            let mut pkt = raw.to_vec();
            // 还原：src = orig_dst, dst = orig_src
            let (new_src_ip, new_src_port) = match orig_dst {
                SocketAddr::V4(a) => (a.ip().octets(), a.port()),
                _ => return,
            };
            let (new_dst_ip, new_dst_port) = match orig_src {
                SocketAddr::V4(a) => (a.ip().octets(), a.port()),
                _ => return,
            };
            let ihl = ((pkt[0] & 0x0f) as usize) * 4;
            pkt[12..16].copy_from_slice(&new_src_ip);
            pkt[16..20].copy_from_slice(&new_dst_ip);
            let tcp_off = ihl;
            pkt[tcp_off..tcp_off + 2].copy_from_slice(&new_src_port.to_be_bytes());
            pkt[tcp_off + 2..tcp_off + 4].copy_from_slice(&new_dst_port.to_be_bytes());
            // 重算 TCP checksum
            recompute_tcp_checksum_v4(&mut pkt, ihl);
            // 重算 IP checksum
            recompute_ipv4_checksum(&mut pkt);
            #[cfg(target_os = "linux")]
            let out = prepend_pi(&pkt, 0x0800);
            #[cfg(not(target_os = "linux"))]
            let out = pkt;
            let mut guard = writer.lock().await;
            let _ = guard.write_all(&out).await;
        }
        return;
    }

    // 目标是广播/组播/未指定地址，跳过
    if dst_ip.is_broadcast() || dst_ip.is_multicast() || dst_ip.is_unspecified() {
        return;
    }

    // 新出站包：分配 NAT 端口，改写头部
    let nat_port = {
        let mut nat = tcp_nat.write().await;
        nat.lookup_or_insert(src, dst)
    };

    let mut pkt = raw.to_vec();
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    // src → inet4_next : nat_port
    pkt[12..16].copy_from_slice(&inet4_next.octets());
    pkt[16..20].copy_from_slice(&inet4_addr.octets());
    let tcp_off = ihl;
    pkt[tcp_off..tcp_off + 2].copy_from_slice(&nat_port.to_be_bytes());
    pkt[tcp_off + 2..tcp_off + 4].copy_from_slice(&tcp_port.to_be_bytes());

    recompute_tcp_checksum_v4(&mut pkt, ihl);
    recompute_ipv4_checksum(&mut pkt);

    #[cfg(target_os = "linux")]
    let out = prepend_pi(&pkt, 0x0800);
    #[cfg(not(target_os = "linux"))]
    let out = pkt;

    let mut guard = writer.lock().await;
    let _ = guard.write_all(&out).await;
    drop(guard);

    debug!(src = %src, dst = %dst, nat_port, flags, "tun: tcp v4 NAT");
}

#[allow(clippy::too_many_arguments)]
async fn handle_tcp_v6(
    raw: &[u8],
    tcp_payload: &[u8],
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    inet6_addr: Option<Ipv6Addr>,
    inet6_next: Option<Ipv6Addr>,
    tcp_port: u16,
    writer: Arc<Mutex<impl AsyncWriteExt + Unpin + Send + 'static>>,
    tcp_nat: Arc<RwLock<TcpNat>>,
) {
    let (inet6_addr, inet6_next) = match (inet6_addr, inet6_next) {
        (Some(a), Some(n)) => (a, n),
        _ => return,
    };
    if tcp_payload.len() < 20 {
        return;
    }
    let src_port = u16::from_be_bytes([tcp_payload[0], tcp_payload[1]]);
    let dst_port = u16::from_be_bytes([tcp_payload[2], tcp_payload[3]]);

    let src = SocketAddr::V6(SocketAddrV6::new(src_ip, src_port, 0, 0));
    let dst = SocketAddr::V6(SocketAddrV6::new(dst_ip, dst_port, 0, 0));

    // Listener 回包
    if src_ip == inet6_addr && src_port == tcp_port {
        let nat_dst_port = dst_port;
        let result = {
            let mut nat = tcp_nat.write().await;
            nat.lookup_back(nat_dst_port)
        };
        if let Some((orig_src, orig_dst)) = result {
            let mut pkt = raw.to_vec();
            let (new_src_ip, new_src_port) = match orig_dst {
                SocketAddr::V6(a) => (a.ip().octets(), a.port()),
                _ => return,
            };
            let (new_dst_ip, new_dst_port) = match orig_src {
                SocketAddr::V6(a) => (a.ip().octets(), a.port()),
                _ => return,
            };
            pkt[8..24].copy_from_slice(&new_src_ip);
            pkt[24..40].copy_from_slice(&new_dst_ip);
            pkt[40..42].copy_from_slice(&new_src_port.to_be_bytes());
            pkt[42..44].copy_from_slice(&new_dst_port.to_be_bytes());
            recompute_tcp_checksum_v6(&mut pkt);
            #[cfg(target_os = "linux")]
            let out = prepend_pi(&pkt, 0x86DD);
            #[cfg(not(target_os = "linux"))]
            let out = pkt;
            let mut guard = writer.lock().await;
            let _ = guard.write_all(&out).await;
        }
        return;
    }

    if dst_ip.is_multicast() || dst_ip.is_unspecified() {
        return;
    }

    let nat_port = {
        let mut nat = tcp_nat.write().await;
        nat.lookup_or_insert(src, dst)
    };

    let mut pkt = raw.to_vec();
    pkt[8..24].copy_from_slice(&inet6_next.octets());
    pkt[24..40].copy_from_slice(&inet6_addr.octets());
    pkt[40..42].copy_from_slice(&nat_port.to_be_bytes());
    pkt[42..44].copy_from_slice(&tcp_port.to_be_bytes());
    recompute_tcp_checksum_v6(&mut pkt);

    #[cfg(target_os = "linux")]
    let out = prepend_pi(&pkt, 0x86DD);
    #[cfg(not(target_os = "linux"))]
    let out = pkt;

    let mut guard = writer.lock().await;
    let _ = guard.write_all(&out).await;
}

// ── ICMPv4 回环 ───────────────────────────────────────────────────────────────

async fn handle_icmpv4(
    raw: &[u8],
    ihl: usize,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    inet4_addr: Option<Ipv4Addr>,
    writer: Arc<Mutex<impl AsyncWriteExt + Unpin + Send + 'static>>,
) {
    // 只处理发给 TUN 自身地址的 Echo Request（type=8, code=0）
    let payload = &raw[ihl..];
    if payload.len() < 8 {
        return;
    }
    let icmp_type = payload[0];
    let icmp_code = payload[1];
    if icmp_type != 8 || icmp_code != 0 {
        return; // 不是 Echo Request
    }
    // 目标必须是 TUN 自身地址
    if let Some(self_addr) = inet4_addr {
        if dst_ip != self_addr {
            return;
        }
    }

    let mut pkt = raw.to_vec();
    // 交换 src/dst
    pkt[12..16].copy_from_slice(&dst_ip.octets());
    pkt[16..20].copy_from_slice(&src_ip.octets());
    // 改为 Echo Reply (type=0)
    let icmp_off = ihl;
    pkt[icmp_off] = 0;
    // 重算 ICMP checksum
    pkt[icmp_off + 2] = 0;
    pkt[icmp_off + 3] = 0;
    let cksum = internet_checksum(&pkt[icmp_off..]);
    pkt[icmp_off + 2] = (cksum >> 8) as u8;
    pkt[icmp_off + 3] = (cksum & 0xff) as u8;
    // 重算 IP checksum
    recompute_ipv4_checksum(&mut pkt);

    #[cfg(target_os = "linux")]
    let out = prepend_pi(&pkt, 0x0800);
    #[cfg(not(target_os = "linux"))]
    let out = pkt;

    let mut guard = writer.lock().await;
    let _ = guard.write_all(&out).await;
}

// ── ICMPv6 回环 ───────────────────────────────────────────────────────────────

async fn handle_icmpv6(
    raw: &[u8],
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    inet6_addr: Option<Ipv6Addr>,
    writer: Arc<Mutex<impl AsyncWriteExt + Unpin + Send + 'static>>,
) {
    if raw.len() < 48 {
        return;
    }
    let icmp_type = raw[40];
    if icmp_type != 128 {
        return; // 只处理 Echo Request
    }
    if let Some(self_addr) = inet6_addr {
        if dst_ip != self_addr {
            return;
        }
    }

    let mut pkt = raw.to_vec();
    pkt[8..24].copy_from_slice(&dst_ip.octets());
    pkt[24..40].copy_from_slice(&src_ip.octets());
    pkt[40] = 129; // Echo Reply
                   // 重算 ICMPv6 checksum（需要伪头部）
    recompute_icmpv6_checksum(&mut pkt);

    #[cfg(target_os = "linux")]
    let out = prepend_pi(&pkt, 0x86DD);
    #[cfg(not(target_os = "linux"))]
    let out = pkt;

    let mut guard = writer.lock().await;
    let _ = guard.write_all(&out).await;
}

// ── UDP 分发 ──────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn dispatch_udp(
    src: SocketAddr,
    dst: SocketAddr,
    data: Bytes,
    tag: Arc<String>,
    udp_tx: &mpsc::Sender<InboundUdpPacket>,
    writer: Arc<Mutex<impl AsyncWriteExt + Unpin + Send + 'static>>,
    udp_sessions: Arc<Mutex<HashMap<(SocketAddr, SocketAddr), UdpEntry>>>,
    _udp_timeout: Duration,
) {
    let key = (src, dst);
    let mut sessions = udp_sessions.lock().await;

    let entry = sessions.entry(key).or_insert_with(|| {
        debug!(src = %src, dst = %dst, "tun: new UDP session");
        let (reply_tx, mut reply_rx) = mpsc::channel::<(Bytes, SocketAddr)>(64);
        let w = writer.clone();
        tokio::spawn(async move {
            while let Some((payload, orig_src)) = reply_rx.recv().await {
                if let Some(pkt) = build_udp_reply_packet(orig_src, src, &payload) {
                    let mut guard = w.lock().await;
                    if let Err(e) = guard.write_all(&pkt).await {
                        debug!(err = %e, "tun: udp reply write error");
                        break;
                    }
                }
            }
        });
        UdpEntry {
            reply_tx,
            last_seen: Instant::now(),
        }
    });
    entry.last_seen = Instant::now();
    let session = UdpSession {
        reply_tx: entry.reply_tx.clone(),
    };
    drop(sessions);

    let packet = InboundUdpPacket {
        data,
        src,
        target: Target::Socket(dst),
        inbound_tag: (*tag).clone(),
        session,
        sniffed_protocol: None,
        sniffed_domain: None,
    };
    if udp_tx.send(packet).await.is_err() {
        debug!("tun: udp_tx closed");
    }
}

// ── 解析函数 ──────────────────────────────────────────────────────────────────

fn parse_udp_v4(
    udp: &[u8],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
) -> Option<(SocketAddr, SocketAddr, Bytes)> {
    if udp.len() < 8 {
        return None;
    }
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let length = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    // length 包含 8 字节头部，payload 从 byte 8 开始
    let payload_len = length.saturating_sub(8).min(udp.len() - 8);
    let data = Bytes::copy_from_slice(&udp[8..8 + payload_len]);
    Some((
        SocketAddr::V4(SocketAddrV4::new(src_ip, src_port)),
        SocketAddr::V4(SocketAddrV4::new(dst_ip, dst_port)),
        data,
    ))
}

fn parse_udp_v6(
    udp: &[u8],
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
) -> Option<(SocketAddr, SocketAddr, Bytes)> {
    if udp.len() < 8 {
        return None;
    }
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let length = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    let payload_len = length.saturating_sub(8).min(udp.len() - 8);
    let data = Bytes::copy_from_slice(&udp[8..8 + payload_len]);
    Some((
        SocketAddr::V6(SocketAddrV6::new(src_ip, src_port, 0, 0)),
        SocketAddr::V6(SocketAddrV6::new(dst_ip, dst_port, 0, 0)),
        data,
    ))
}

// ── UDP 回包封装（同时支持 IPv4 / IPv6）─────────────────────────────────────

fn build_udp_reply_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    match (src, dst) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) => build_udp_reply_v4(s, d, payload),
        (SocketAddr::V6(s), SocketAddr::V6(d)) => build_udp_reply_v6(s, d, payload),
        _ => None,
    }
}

fn build_udp_reply_v4(src: SocketAddrV4, dst: SocketAddrV4, payload: &[u8]) -> Option<Vec<u8>> {
    let udp_len = (8 + payload.len()) as u16;
    let total_len = 20u16 + udp_len;

    let mut pkt = Vec::with_capacity(total_len as usize + 4);

    #[cfg(target_os = "linux")]
    pkt.extend_from_slice(&[0x00, 0x00, 0x08, 0x00]); // PI header

    // IP header
    pkt.extend_from_slice(&[
        0x45,
        0x00,
        (total_len >> 8) as u8,
        (total_len & 0xff) as u8,
        0x00,
        0x00,
        0x40,
        0x00, // id=0, DF, frag=0
        64,
        IPPROTO_UDP,
        0x00,
        0x00, // checksum placeholder
    ]);
    pkt.extend_from_slice(&src.ip().octets());
    pkt.extend_from_slice(&dst.ip().octets());

    // IP checksum
    #[cfg(target_os = "linux")]
    let hdr_start = 4;
    #[cfg(not(target_os = "linux"))]
    let hdr_start = 0;
    let cksum = internet_checksum(&pkt[hdr_start..hdr_start + 20]);
    pkt[hdr_start + 10] = (cksum >> 8) as u8;
    pkt[hdr_start + 11] = (cksum & 0xff) as u8;

    // UDP header
    let udp_start = pkt.len();
    pkt.extend_from_slice(&src.port().to_be_bytes());
    pkt.extend_from_slice(&dst.port().to_be_bytes());
    pkt.extend_from_slice(&udp_len.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
    pkt.extend_from_slice(payload);

    // UDP checksum（含伪头部）
    let src_ip = src.ip().octets();
    let dst_ip = dst.ip().octets();
    let udp_cksum = udp_checksum_v4(&src_ip, &dst_ip, &pkt[udp_start..]);
    pkt[udp_start + 6] = (udp_cksum >> 8) as u8;
    pkt[udp_start + 7] = (udp_cksum & 0xff) as u8;

    Some(pkt)
}

fn build_udp_reply_v6(src: SocketAddrV6, dst: SocketAddrV6, payload: &[u8]) -> Option<Vec<u8>> {
    let udp_len = (8 + payload.len()) as u16;
    let payload_len = udp_len; // IPv6 PayloadLength = UDP header + data

    let mut pkt = Vec::with_capacity(40 + udp_len as usize + 4);

    #[cfg(target_os = "linux")]
    pkt.extend_from_slice(&[0x00, 0x00, 0x86, 0xDD]); // PI: IPv6

    // IPv6 fixed header (40 bytes)
    pkt.push(0x60); // version=6, TC=0
    pkt.extend_from_slice(&[0x00, 0x00, 0x00]); // flow label
    pkt.extend_from_slice(&payload_len.to_be_bytes());
    pkt.push(IPPROTO_UDP);
    pkt.push(64); // hop limit
    pkt.extend_from_slice(&src.ip().octets());
    pkt.extend_from_slice(&dst.ip().octets());

    // UDP header + payload
    let udp_start = pkt.len();
    pkt.extend_from_slice(&src.port().to_be_bytes());
    pkt.extend_from_slice(&dst.port().to_be_bytes());
    pkt.extend_from_slice(&udp_len.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
    pkt.extend_from_slice(payload);

    // UDP checksum（IPv6 伪头部）
    let src_ip = src.ip().octets();
    let dst_ip = dst.ip().octets();
    #[cfg(target_os = "linux")]
    let ip_off = 4;
    #[cfg(not(target_os = "linux"))]
    let ip_off = 0;
    let udp_slice = &pkt[udp_start..];
    let cksum = udp_checksum_v6(&src_ip, &dst_ip, udp_slice);
    pkt[udp_start + 6] = (cksum >> 8) as u8;
    pkt[udp_start + 7] = (cksum & 0xff) as u8;
    let _ = ip_off;

    Some(pkt)
}

// ── Checksum 计算 ─────────────────────────────────────────────────────────────

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn recompute_ipv4_checksum(pkt: &mut [u8]) {
    #[cfg(target_os = "linux")]
    let off = 4;
    #[cfg(not(target_os = "linux"))]
    let off = 0;
    if pkt.len() < off + 20 {
        return;
    }
    pkt[off + 10] = 0;
    pkt[off + 11] = 0;
    let cksum = internet_checksum(&pkt[off..off + 20]);
    pkt[off + 10] = (cksum >> 8) as u8;
    pkt[off + 11] = (cksum & 0xff) as u8;
}

/// 重算 IPv4 TCP checksum（含伪头部）
fn recompute_tcp_checksum_v4(pkt: &mut [u8], ihl: usize) {
    #[cfg(target_os = "linux")]
    let off = 4;
    #[cfg(not(target_os = "linux"))]
    let off = 0;
    if pkt.len() < off + ihl + 2 {
        return;
    }
    let tcp_off = off + ihl;
    let src_ip: [u8; 4] = pkt[off + 12..off + 16].try_into().unwrap_or([0u8; 4]);
    let dst_ip: [u8; 4] = pkt[off + 16..off + 20].try_into().unwrap_or([0u8; 4]);
    let tcp_len = pkt.len() - tcp_off;

    pkt[tcp_off + 16] = 0;
    pkt[tcp_off + 17] = 0;
    let cksum = tcp_checksum_v4(&src_ip, &dst_ip, &pkt[tcp_off..]);
    pkt[tcp_off + 16] = (cksum >> 8) as u8;
    pkt[tcp_off + 17] = (cksum & 0xff) as u8;
    let _ = tcp_len;
}

/// 重算 IPv6 TCP checksum（含伪头部）
fn recompute_tcp_checksum_v6(pkt: &mut [u8]) {
    #[cfg(target_os = "linux")]
    let off = 4;
    #[cfg(not(target_os = "linux"))]
    let off = 0;
    if pkt.len() < off + 40 + 18 {
        return;
    }
    let tcp_off = off + 40;
    let src_ip: [u8; 16] = pkt[off + 8..off + 24].try_into().unwrap_or([0u8; 16]);
    let dst_ip: [u8; 16] = pkt[off + 24..off + 40].try_into().unwrap_or([0u8; 16]);
    pkt[tcp_off + 16] = 0;
    pkt[tcp_off + 17] = 0;
    let cksum = tcp_checksum_v6(&src_ip, &dst_ip, &pkt[tcp_off..]);
    pkt[tcp_off + 16] = (cksum >> 8) as u8;
    pkt[tcp_off + 17] = (cksum & 0xff) as u8;
}

/// 重算 ICMPv6 checksum（含 IPv6 伪头部）
fn recompute_icmpv6_checksum(pkt: &mut [u8]) {
    #[cfg(target_os = "linux")]
    let off = 4;
    #[cfg(not(target_os = "linux"))]
    let off = 0;
    if pkt.len() < off + 40 + 8 {
        return;
    }
    let icmp_off = off + 40;
    let src_ip: [u8; 16] = pkt[off + 8..off + 24].try_into().unwrap_or([0u8; 16]);
    let dst_ip: [u8; 16] = pkt[off + 24..off + 40].try_into().unwrap_or([0u8; 16]);
    pkt[icmp_off + 2] = 0;
    pkt[icmp_off + 3] = 0;
    // ICMPv6 使用与 UDP/TCP 相同的伪头部结构（Next Header = 58）
    let cksum = checksum_with_pseudo_v6(&src_ip, &dst_ip, IPPROTO_ICMPV6, &pkt[icmp_off..]);
    pkt[icmp_off + 2] = (cksum >> 8) as u8;
    pkt[icmp_off + 3] = (cksum & 0xff) as u8;
}

fn tcp_checksum_v4(src: &[u8; 4], dst: &[u8; 4], tcp: &[u8]) -> u16 {
    checksum_with_pseudo_v4(src, dst, IPPROTO_TCP, tcp)
}

fn tcp_checksum_v6(src: &[u8; 16], dst: &[u8; 16], tcp: &[u8]) -> u16 {
    checksum_with_pseudo_v6(src, dst, IPPROTO_TCP, tcp)
}

fn udp_checksum_v4(src: &[u8; 4], dst: &[u8; 4], udp: &[u8]) -> u16 {
    checksum_with_pseudo_v4(src, dst, IPPROTO_UDP, udp)
}

fn udp_checksum_v6(src: &[u8; 16], dst: &[u8; 16], udp: &[u8]) -> u16 {
    checksum_with_pseudo_v6(src, dst, IPPROTO_UDP, udp)
}

/// RFC 793 伪头部校验和（IPv4）
fn checksum_with_pseudo_v4(src: &[u8; 4], dst: &[u8; 4], proto: u8, data: &[u8]) -> u16 {
    let len = data.len() as u16;
    let pseudo = [
        src[0],
        src[1],
        src[2],
        src[3],
        dst[0],
        dst[1],
        dst[2],
        dst[3],
        0,
        proto,
        (len >> 8) as u8,
        (len & 0xff) as u8,
    ];
    let mut sum: u32 = 0;
    for chunk in pseudo.chunks_exact(2) {
        sum += ((chunk[0] as u32) << 8) | (chunk[1] as u32);
    }
    let mut i = 0;
    while i + 1 < data.len() {
        sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// RFC 2460 伪头部校验和（IPv6）
fn checksum_with_pseudo_v6(src: &[u8; 16], dst: &[u8; 16], proto: u8, data: &[u8]) -> u16 {
    let len = data.len() as u32;
    let mut sum: u32 = 0;
    // src + dst
    for chunk in src.chunks_exact(2) {
        sum += ((chunk[0] as u32) << 8) | (chunk[1] as u32);
    }
    for chunk in dst.chunks_exact(2) {
        sum += ((chunk[0] as u32) << 8) | (chunk[1] as u32);
    }
    // Upper-Layer Packet Length (32-bit)
    sum += (len >> 16) & 0xffff;
    sum += len & 0xffff;
    // Next Header
    sum += proto as u32;
    // data
    let mut i = 0;
    while i + 1 < data.len() {
        sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

// ── Linux TUN packet_information 前缀 ────────────────────────────────────────

#[cfg(target_os = "linux")]
fn prepend_pi(pkt: &[u8], proto: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + pkt.len());
    out.extend_from_slice(&[0x00, 0x00, (proto >> 8) as u8, (proto & 0xff) as u8]);
    out.extend_from_slice(pkt);
    out
}

// ── Linux 路由实现 ────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod platform {
    use super::{parse_addr_prefix, TunInboundConfig};
    use std::net::IpAddr;
    use std::process::Command;
    use tracing::{info, warn};

    fn build_excluded_uid_ranges(include: &[u32], exclude: &[u32]) -> Vec<(u32, u32)> {
        const UID_MAX: u32 = u32::MAX - 1;

        if include.is_empty() && exclude.is_empty() {
            return vec![];
        }

        let to_sorted_ranges = |uids: &[u32]| -> Vec<(u32, u32)> {
            let mut v: Vec<u32> = uids.to_vec();
            v.sort_unstable();
            v.dedup();
            v.into_iter().map(|u| (u, u)).collect()
        };

        let include_ranges = to_sorted_ranges(include);
        let exclude_ranges = to_sorted_ranges(exclude);

        if !include_ranges.is_empty() {
            let effective = subtract_ranges(include_ranges, &exclude_ranges);
            merge_ranges(complement_ranges(&effective, 0, UID_MAX))
        } else {
            merge_ranges(exclude_ranges)
        }
    }

    fn subtract_ranges(mut base: Vec<(u32, u32)>, sub: &[(u32, u32)]) -> Vec<(u32, u32)> {
        for &(lo, hi) in sub {
            base = base
                .into_iter()
                .flat_map(|(a, b)| {
                    if hi < a || lo > b {
                        vec![(a, b)]
                    } else {
                        let mut out = vec![];
                        if a < lo {
                            out.push((a, lo - 1));
                        }
                        if b > hi {
                            out.push((hi + 1, b));
                        }
                        out
                    }
                })
                .collect();
        }
        base
    }

    fn complement_ranges(ranges: &[(u32, u32)], lo: u32, hi: u32) -> Vec<(u32, u32)> {
        let mut result = vec![];
        let mut cur = lo;
        for &(a, b) in ranges {
            if cur < a {
                result.push((cur, a - 1));
            }
            cur = b.saturating_add(1);
        }
        if cur <= hi {
            result.push((cur, hi));
        }
        result
    }

    fn merge_ranges(mut ranges: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
        if ranges.is_empty() {
            return ranges;
        }
        ranges.sort_unstable();
        let mut merged = vec![ranges[0]];
        for (a, b) in ranges.into_iter().skip(1) {
            let last = merged.last_mut().unwrap();
            if a <= last.1.saturating_add(1) {
                last.1 = last.1.max(b);
            } else {
                merged.push((a, b));
            }
        }
        merged
    }

    fn ip(args: &[&str]) {
        Command::new("ip").args(args).output().ok();
    }

    fn ip6(args: &[&str]) {
        Command::new("ip").arg("-6").args(args).output().ok();
    }

    struct AddrInfo {
        inet4: Vec<(std::net::Ipv4Addr, u8)>,
        inet6: Vec<(std::net::Ipv6Addr, u8)>,
    }

    fn parse_addresses(cfg: &TunInboundConfig) -> AddrInfo {
        let mut inet4 = vec![];
        let mut inet6 = vec![];
        for addr_str in &cfg.address {
            match parse_addr_prefix(addr_str) {
                Some((IpAddr::V4(ip), prefix_len)) => inet4.push((ip, prefix_len)),
                Some((IpAddr::V6(ip), prefix_len)) => inet6.push((ip, prefix_len)),
                None => warn!(addr = %addr_str, "tun: invalid address prefix, skipping"),
            }
        }
        AddrInfo { inet4, inet6 }
    }

    fn v4_network(ip: std::net::Ipv4Addr, prefix_len: u8) -> std::net::Ipv4Addr {
        let n = u32::from(ip) & !((1u32 << (32 - prefix_len.min(32))) - 1);
        std::net::Ipv4Addr::from(n)
    }

    fn v6_network(ip: std::net::Ipv6Addr, prefix_len: u8) -> std::net::Ipv6Addr {
        let n = u128::from(ip) & !((1u128 << (128 - prefix_len.min(128))) - 1);
        std::net::Ipv6Addr::from(n)
    }

    pub fn setup(cfg: &TunInboundConfig, if_name: &str) -> anyhow::Result<()> {
        let table = cfg.iproute2_table_index.to_string();
        let prio_base = cfg.iproute2_rule_index;
        let nop_prio = prio_base + 10;
        let nop = nop_prio.to_string();

        let addrs = parse_addresses(cfg);
        let has_v4 = !addrs.inet4.is_empty();
        let has_v6 = !addrs.inet6.is_empty();

        ip(&["link", "set", if_name, "up"]);

        // 路由表：默认路由指向 TUN 网关（自身地址 +1）
        if has_v4 {
            let (gw_ip, _) = addrs.inet4[0];
            let gw = std::net::Ipv4Addr::from(u32::from(gw_ip).wrapping_add(1));
            ip(&[
                "route",
                "add",
                "0.0.0.0/0",
                "via",
                &gw.to_string(),
                "dev",
                if_name,
                "table",
                &table,
            ]);
        }
        if has_v6 {
            let (gw_ip, _) = addrs.inet6[0];
            let gw = std::net::Ipv6Addr::from(u128::from(gw_ip).wrapping_add(1));
            ip6(&[
                "route",
                "add",
                "::/0",
                "via",
                &gw.to_string(),
                "dev",
                if_name,
                "table",
                &table,
            ]);
        }

        let mut p = prio_base;
        let mut p6 = prio_base;

        // 1. UID 排除
        let excluded_uids = build_excluded_uid_ranges(&cfg.include_uid, &cfg.exclude_uid);
        for (lo, hi) in &excluded_uids {
            let uid_range = format!("{lo}-{hi}");
            if has_v4 {
                ip(&[
                    "rule",
                    "add",
                    "priority",
                    &p.to_string(),
                    "uidrange",
                    &uid_range,
                    "goto",
                    &nop,
                ]);
            }
            if has_v6 {
                ip6(&[
                    "rule",
                    "add",
                    "priority",
                    &p6.to_string(),
                    "uidrange",
                    &uid_range,
                    "goto",
                    &nop,
                ]);
            }
        }
        if !excluded_uids.is_empty() {
            if has_v4 {
                p += 1;
            }
            if has_v6 {
                p6 += 1;
            }
        }

        // 2. 接口过滤
        if !cfg.include_interface.is_empty() {
            let match_prio = p + cfg.include_interface.len() as u32;
            for iface in &cfg.include_interface {
                if has_v4 {
                    ip(&[
                        "rule",
                        "add",
                        "priority",
                        &p.to_string(),
                        "iif",
                        iface,
                        "goto",
                        &match_prio.to_string(),
                    ]);
                }
                if has_v6 {
                    ip6(&[
                        "rule",
                        "add",
                        "priority",
                        &p6.to_string(),
                        "iif",
                        iface,
                        "goto",
                        &match_prio.to_string(),
                    ]);
                }
                p += 1;
                p6 += 1;
            }
            // 不匹配的接口 → nop
            if has_v4 {
                ip(&["rule", "add", "priority", &p.to_string(), "goto", &nop]);
                p += 1;
            }
            if has_v6 {
                ip6(&["rule", "add", "priority", &p6.to_string(), "goto", &nop]);
                p6 += 1;
            }
        } else if !cfg.exclude_interface.is_empty() {
            for iface in &cfg.exclude_interface {
                if has_v4 {
                    ip(&[
                        "rule",
                        "add",
                        "priority",
                        &p.to_string(),
                        "iif",
                        iface,
                        "goto",
                        &nop,
                    ]);
                }
                if has_v6 {
                    ip6(&[
                        "rule",
                        "add",
                        "priority",
                        &p6.to_string(),
                        "iif",
                        iface,
                        "goto",
                        &nop,
                    ]);
                }
            }
            if has_v4 {
                p += 1;
            }
            if has_v6 {
                p6 += 1;
            }
        }

        // 3. strict_route
        if cfg.strict_route {
            if !has_v4 {
                ip(&[
                    "rule",
                    "add",
                    "priority",
                    &p.to_string(),
                    "type",
                    "unreachable",
                ]);
                p += 1;
            }
            if !has_v6 {
                ip6(&[
                    "rule",
                    "add",
                    "priority",
                    &p6.to_string(),
                    "type",
                    "unreachable",
                ]);
                p6 += 1;
            }
        }

        // 4. TUN 子网 → 直接查 TUN 路由表
        for (ip_addr, prefix_len) in &addrs.inet4 {
            let net = v4_network(*ip_addr, *prefix_len);
            let dst = format!("{net}/{prefix_len}");
            ip(&[
                "rule",
                "add",
                "priority",
                &p.to_string(),
                "to",
                &dst,
                "lookup",
                &table,
            ]);
        }
        if has_v4 {
            p += 1;
        }
        for (ip_addr, prefix_len) in &addrs.inet6 {
            let net = v6_network(*ip_addr, *prefix_len);
            let dst = format!("{net}/{prefix_len}");
            ip6(&[
                "rule",
                "add",
                "priority",
                &p6.to_string(),
                "to",
                &dst,
                "lookup",
                &table,
            ]);
        }
        if has_v6 {
            p6 += 1;
        }

        // 5. suppress_prefixlength 0
        // 修复原实现：suppress_prefixlength 必须在 lookup 后，不能拆成两条独立规则
        if has_v4 {
            ip(&[
                "rule",
                "add",
                "priority",
                &p.to_string(),
                "not",
                "iif",
                "lo",
                "lookup",
                &table,
                "suppress_prefixlength",
                "0",
            ]);
            p += 1;
        }
        if has_v6 {
            ip6(&[
                "rule",
                "add",
                "priority",
                &p6.to_string(),
                "not",
                "iif",
                "lo",
                "lookup",
                &table,
                "suppress_prefixlength",
                "0",
            ]);
            p6 += 1;
        }

        // 6. TUN 自身流量 → goto nop（避免环回）
        if has_v4 {
            ip(&[
                "rule",
                "add",
                "priority",
                &p.to_string(),
                "iif",
                if_name,
                "goto",
                &nop,
            ]);
        }
        if has_v6 {
            ip6(&[
                "rule",
                "add",
                "priority",
                &p6.to_string(),
                "iif",
                if_name,
                "goto",
                &nop,
            ]);
        }

        // 7. 非 loopback 出站 → TUN 表 / loopback src 属于 TUN 子网 → TUN 表
        if has_v4 {
            ip(&[
                "rule",
                "add",
                "priority",
                &p.to_string(),
                "not",
                "iif",
                "lo",
                "lookup",
                &table,
            ]);
            ip(&[
                "rule",
                "add",
                "priority",
                &p.to_string(),
                "iif",
                "lo",
                "from",
                "0.0.0.0/32",
                "lookup",
                &table,
            ]);
            for (ip_addr, prefix_len) in &addrs.inet4 {
                let net = v4_network(*ip_addr, *prefix_len);
                let src = format!("{net}/{prefix_len}");
                ip(&[
                    "rule",
                    "add",
                    "priority",
                    &p.to_string(),
                    "iif",
                    "lo",
                    "from",
                    &src,
                    "lookup",
                    &table,
                ]);
            }
        }
        if has_v6 {
            ip6(&[
                "rule",
                "add",
                "priority",
                &p6.to_string(),
                "not",
                "iif",
                "lo",
                "lookup",
                &table,
            ]);
            for (ip_addr, prefix_len) in &addrs.inet6 {
                let net = v6_network(*ip_addr, *prefix_len);
                let src = format!("{net}/{prefix_len}");
                ip6(&[
                    "rule",
                    "add",
                    "priority",
                    &p6.to_string(),
                    "iif",
                    "lo",
                    "from",
                    &src,
                    "lookup",
                    &table,
                ]);
            }
        }

        // 8. nop 锚点
        if has_v4 {
            ip(&["rule", "add", "priority", &nop]);
        }
        if has_v6 {
            ip6(&["rule", "add", "priority", &nop]);
        }

        info!(interface = %if_name, table = %table, "tun: auto_route configured (Linux)");
        Ok(())
    }

    pub fn teardown(cfg: &TunInboundConfig, if_name: &str) -> anyhow::Result<()> {
        let table = cfg.iproute2_table_index.to_string();
        let prio_base = cfg.iproute2_rule_index;
        let nop_prio = prio_base + 10;

        ip(&["route", "flush", "table", &table]);
        ip6(&["route", "flush", "table", &table]);

        for prio in prio_base..=nop_prio {
            let ps = prio.to_string();
            for _ in 0..5 {
                // 同优先级可能有多条规则，多删几次
                ip(&["rule", "del", "priority", &ps]);
                ip6(&["rule", "del", "priority", &ps]);
            }
        }

        info!(interface = %if_name, "tun: auto_route cleaned up (Linux)");
        Ok(())
    }
}

// ── macOS 实现 ────────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
mod platform {
    use super::{parse_addr_prefix, TunInboundConfig};
    use std::net::IpAddr;
    use std::process::Command;
    use tracing::{info, warn};

    const IPV4_SUB_RANGES: &[&str] = &[
        "1.0.0.0/8",
        "2.0.0.0/7",
        "4.0.0.0/6",
        "8.0.0.0/5",
        "16.0.0.0/4",
        "32.0.0.0/3",
        "64.0.0.0/2",
        "128.0.0.0/1",
    ];
    const IPV6_SUB_RANGES: &[&str] = &[
        "100::/8", "200::/7", "400::/6", "800::/5", "1000::/4", "2000::/3", "4000::/2", "8000::/1",
    ];

    pub fn setup(cfg: &TunInboundConfig, if_name: &str) -> anyhow::Result<()> {
        if cfg.strict_route {
            warn!("tun: strict_route not supported on macOS");
        }
        if !cfg.include_interface.is_empty() || !cfg.exclude_interface.is_empty() {
            warn!("tun: include/exclude_interface not supported on macOS");
        }
        if !cfg.include_uid.is_empty() || !cfg.exclude_uid.is_empty() {
            warn!("tun: include/exclude_uid not supported on macOS");
        }

        let mut has_v4 = false;
        let mut has_v6 = false;
        for addr_str in &cfg.address {
            match parse_addr_prefix(addr_str) {
                Some((IpAddr::V4(ip), _)) => {
                    Command::new("ifconfig")
                        .args([if_name, &ip.to_string(), &ip.to_string()])
                        .output()
                        .ok();
                    has_v4 = true;
                }
                Some((IpAddr::V6(ip), prefix_len)) => {
                    Command::new("ifconfig")
                        .args([
                            if_name,
                            "inet6",
                            &format!("{}/{}", ip, prefix_len),
                            "prefixlen",
                            &prefix_len.to_string(),
                            "alias",
                        ])
                        .output()
                        .ok();
                    has_v6 = true;
                }
                None => warn!(addr = %addr_str, "tun: invalid address prefix"),
            }
        }
        Command::new("ifconfig").args([if_name, "up"]).output().ok();

        if has_v4 {
            for &cidr in IPV4_SUB_RANGES {
                Command::new("route")
                    .args(["add", "-net", cidr, "-interface", if_name])
                    .output()
                    .ok();
            }
        }
        if has_v6 {
            for &cidr in IPV6_SUB_RANGES {
                Command::new("route")
                    .args(["add", "-inet6", cidr, "-interface", if_name])
                    .output()
                    .ok();
            }
        }
        Command::new("dscacheutil")
            .args(["-flushcache"])
            .output()
            .ok();
        info!(interface = %if_name, "tun: auto_route configured (macOS)");
        Ok(())
    }

    pub fn teardown(cfg: &TunInboundConfig, if_name: &str) -> anyhow::Result<()> {
        let has_v4 = cfg.address.iter().any(|a| {
            parse_addr_prefix(a)
                .map(|(ip, _)| ip.is_ipv4())
                .unwrap_or(false)
        });
        let has_v6 = cfg.address.iter().any(|a| {
            parse_addr_prefix(a)
                .map(|(ip, _)| ip.is_ipv6())
                .unwrap_or(false)
        });

        if has_v4 {
            for &cidr in IPV4_SUB_RANGES {
                Command::new("route")
                    .args(["delete", "-net", cidr])
                    .output()
                    .ok();
            }
        }
        if has_v6 {
            for &cidr in IPV6_SUB_RANGES {
                Command::new("route")
                    .args(["delete", "-inet6", cidr])
                    .output()
                    .ok();
            }
        }
        Command::new("dscacheutil")
            .args(["-flushcache"])
            .output()
            .ok();
        info!(interface = %if_name, "tun: auto_route cleaned up (macOS)");
        Ok(())
    }
}

// ── Windows 实现 ──────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
mod platform {
    use super::{parse_addr_prefix, prefix_len_to_mask_v4, TunInboundConfig};
    use std::net::IpAddr;
    use std::process::Command;
    use tracing::{info, warn};

    const IPV4_SUB_RANGES: &[&str] = &[
        "1.0.0.0/8",
        "2.0.0.0/7",
        "4.0.0.0/6",
        "8.0.0.0/5",
        "16.0.0.0/4",
        "32.0.0.0/3",
        "64.0.0.0/2",
        "128.0.0.0/1",
    ];
    const IPV6_SUB_RANGES: &[&str] = &[
        "100::/8", "200::/7", "400::/6", "800::/5", "1000::/4", "2000::/3", "4000::/2", "8000::/1",
    ];

    fn is_windows10_or_later() -> bool {
        Command::new("cmd")
            .args(["/C", "ver"])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("10."))
            .unwrap_or(false)
    }

    pub fn setup(cfg: &TunInboundConfig, if_name: &str) -> anyhow::Result<()> {
        if !cfg.include_interface.is_empty() || !cfg.exclude_interface.is_empty() {
            warn!("tun: include/exclude_interface not supported on Windows");
        }
        if !cfg.include_uid.is_empty() || !cfg.exclude_uid.is_empty() {
            warn!("tun: include/exclude_uid not supported on Windows");
        }

        let mut has_v4 = false;
        let mut has_v6 = false;
        for addr_str in &cfg.address {
            match parse_addr_prefix(addr_str) {
                Some((IpAddr::V4(ip), prefix_len)) => {
                    let mask = prefix_len_to_mask_v4(prefix_len);
                    Command::new("netsh")
                        .args([
                            "interface",
                            "ipv4",
                            "set",
                            "address",
                            "name",
                            if_name,
                            "static",
                            &ip.to_string(),
                            &mask.to_string(),
                        ])
                        .output()
                        .ok();
                    has_v4 = true;
                }
                Some((IpAddr::V6(ip), prefix_len)) => {
                    Command::new("netsh")
                        .args([
                            "interface",
                            "ipv6",
                            "add",
                            "address",
                            if_name,
                            &format!("{}/{}", ip, prefix_len),
                        ])
                        .output()
                        .ok();
                    has_v6 = true;
                }
                None => warn!(addr = %addr_str, "tun: invalid address prefix"),
            }
        }

        if has_v4 {
            for &cidr in IPV4_SUB_RANGES {
                Command::new("netsh")
                    .args([
                        "interface",
                        "ipv4",
                        "add",
                        "route",
                        cidr,
                        if_name,
                        "metric=1",
                    ])
                    .output()
                    .ok();
            }
        }
        if has_v6 {
            for &cidr in IPV6_SUB_RANGES {
                Command::new("netsh")
                    .args([
                        "interface",
                        "ipv6",
                        "add",
                        "route",
                        cidr,
                        if_name,
                        "metric=1",
                    ])
                    .output()
                    .ok();
            }
        }

        if cfg.strict_route {
            if is_windows10_or_later() {
                Command::new("netsh")
                    .args([
                        "advfirewall",
                        "firewall",
                        "add",
                        "rule",
                        "name=reflex-tun-strict-dns-block",
                        "protocol=UDP",
                        "dir=out",
                        "remoteport=53",
                        "action=block",
                    ])
                    .output()
                    .ok();
                info!("tun: strict_route DNS block rule added (Windows)");
            } else {
                warn!("tun: strict_route requires Windows 10+");
            }
        }
        Command::new("ipconfig").args(["/flushdns"]).output().ok();
        info!(interface = %if_name, "tun: auto_route configured (Windows)");
        Ok(())
    }

    pub fn teardown(cfg: &TunInboundConfig, if_name: &str) -> anyhow::Result<()> {
        let has_v4 = cfg.address.iter().any(|a| {
            parse_addr_prefix(a)
                .map(|(ip, _)| ip.is_ipv4())
                .unwrap_or(false)
        });
        let has_v6 = cfg.address.iter().any(|a| {
            parse_addr_prefix(a)
                .map(|(ip, _)| ip.is_ipv6())
                .unwrap_or(false)
        });

        if has_v4 {
            for &cidr in IPV4_SUB_RANGES {
                Command::new("netsh")
                    .args(["interface", "ipv4", "delete", "route", cidr, if_name])
                    .output()
                    .ok();
            }
        }
        if has_v6 {
            for &cidr in IPV6_SUB_RANGES {
                Command::new("netsh")
                    .args(["interface", "ipv6", "delete", "route", cidr, if_name])
                    .output()
                    .ok();
            }
        }
        if cfg.strict_route {
            Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    "name=reflex-tun-strict-dns-block",
                ])
                .output()
                .ok();
        }
        Command::new("ipconfig").args(["/flushdns"]).output().ok();
        info!(interface = %if_name, "tun: auto_route cleaned up (Windows)");
        Ok(())
    }
}

// ── 其他平台存根 ──────────────────────────────────────────────────────────────

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod platform {
    use super::TunInboundConfig;
    use tracing::warn;
    pub fn setup(_cfg: &TunInboundConfig, if_name: &str) -> anyhow::Result<()> {
        warn!(interface = %if_name, "tun: auto_route not supported on this platform");
        Ok(())
    }
    pub fn teardown(_cfg: &TunInboundConfig, _if_name: &str) -> anyhow::Result<()> {
        Ok(())
    }
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_parse_addr_prefix() {
        let (ip, len) = parse_addr_prefix("198.18.0.1/16").unwrap();
        assert_eq!(ip, "198.18.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(len, 16);
    }

    #[test]
    fn test_parse_addr_prefix_ipv6() {
        let (ip, len) = parse_addr_prefix("fd00::1/126").unwrap();
        assert!(ip.is_ipv6());
        assert_eq!(len, 126);
    }

    #[test]
    fn test_parse_addr_prefix_invalid() {
        assert!(parse_addr_prefix("198.18.0.1").is_none());
        assert!(parse_addr_prefix("198.18.0.1/33").is_none());
    }

    #[test]
    fn test_internet_checksum_known() {
        // IP header checksum test vector（全零 checksum 字段）
        let hdr = [
            0x45u8, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10,
            0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
        ];
        let cksum = internet_checksum(&hdr);
        assert_ne!(cksum, 0);
    }

    #[test]
    fn test_tcp_nat_alloc_and_lookup() {
        let mut nat = TcpNat::new();
        let src: SocketAddr = "1.2.3.4:5678".parse().unwrap();
        let dst: SocketAddr = "8.8.8.8:80".parse().unwrap();
        let port = nat.lookup_or_insert(src, dst);
        assert!(port >= NAT_PORT_START && port <= NAT_PORT_END);
        let port2 = nat.lookup_or_insert(src, dst);
        assert_eq!(port, port2, "same src should get same port");
        let (got_src, got_dst) = nat.lookup_back(port).unwrap();
        assert_eq!(got_src, src);
        assert_eq!(got_dst, dst);
    }

    #[test]
    fn test_tcp_nat_gc() {
        let mut nat = TcpNat::new();
        let src: SocketAddr = "1.2.3.4:9999".parse().unwrap();
        let dst: SocketAddr = "9.9.9.9:443".parse().unwrap();
        nat.lookup_or_insert(src, dst);
        // GC with zero timeout clears everything
        nat.gc(Duration::from_secs(0));
        // All entries should be gone
        assert!(nat.port_map.is_empty());
    }

    #[test]
    fn test_build_udp_reply_v4_length() {
        let src: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let dst: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let payload = b"hello world";
        let pkt = build_udp_reply_packet(src, dst, payload).unwrap();
        // IPv4 (20) + UDP (8) + payload
        #[cfg(target_os = "linux")]
        assert_eq!(pkt.len(), 4 + 20 + 8 + payload.len());
        #[cfg(not(target_os = "linux"))]
        assert_eq!(pkt.len(), 20 + 8 + payload.len());
    }

    #[test]
    fn test_build_udp_reply_v6_length() {
        let src: SocketAddr = "[2001:db8::1]:53".parse().unwrap();
        let dst: SocketAddr = "[fe80::1]:12345".parse().unwrap();
        let payload = b"test";
        let pkt = build_udp_reply_packet(src, dst, payload).unwrap();
        // IPv6 (40) + UDP (8) + payload
        #[cfg(target_os = "linux")]
        assert_eq!(pkt.len(), 4 + 40 + 8 + payload.len());
        #[cfg(not(target_os = "linux"))]
        assert_eq!(pkt.len(), 40 + 8 + payload.len());
    }
}
