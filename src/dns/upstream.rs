//! DNS 上游实现：UDP、TCP、DoH（HTTP/1.1 + HTTP/2 + TLS）、DoT、DoQ、内置 rcode、FakeIP。
//!
//! 每个上游可携带一个可选的 `detour`（出站对象），当 detour 存在时：
//!   - UDP  → 降级为经由隧道的 TCP 查询（代理隧道不支持裸 UDP）
//!   - TCP  → 经由隧道的 TCP 查询
//!   - DoH  → 经由隧道的 CONNECT 隧道，再做 TLS + HTTP
//!   - DoT  → 经由隧道的 CONNECT 隧道，再做 TLS
//!   - DoQ  → 不支持经由 TCP detour（QUIC 依赖 UDP），detour 存在时忽略并直连

use std::{
    collections::HashMap,
    future::Future,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

use crate::experimental::CacheFile;
use bytes::Bytes;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::timeout,
};
use tracing::debug;

use crate::config::dns::{DnsProtocol, DnsServerConfig, RcodeAction};
use crate::dns::{make_noerror_empty, make_nxdomain, make_refused};
use crate::outbound::Outbound;

// ── 主结构 ────────────────────────────────────────────────────────────────────

pub struct DnsUpstream {
    pub tag: String,
    pub kind: UpstreamKind,
    pub timeout: Duration,
    /// 发出查询所走的出站通道；None 表示直连。
    pub detour: Option<Arc<dyn Outbound>>,
    /// 用于解析本 upstream 域名的 bootstrap DNS（仅当 address 为域名形式时有意义）。
    pub domain_resolver: Option<Arc<DnsUpstream>>,
    /// 直连 UDP 上游的复用 socket（IPv4）
    udp_socket_v4: Arc<Mutex<Option<Arc<UdpSocket>>>>,
    /// 直连 UDP 上游的复用 socket（IPv6）
    udp_socket_v6: Arc<Mutex<Option<Arc<UdpSocket>>>>,
    /// 全局 SO_MARK（来自 global.routing_mark），0 表示不设置
    pub routing_mark: u32,
}

pub enum UpstreamKind {
    Udp {
        addr: SocketAddr,
    },
    /// DNS-over-TCP：每次查询建立新 TCP 连接，2 字节长度前缀帧
    Tcp {
        addr: SocketAddr,
    },
    /// DNS-over-HTTPS：HTTP/2（优先）→ 回退 HTTP/1.1，Content-Type: application/dns-message
    /// 直连时走 rustls；经 detour 时走隧道 TCP + rustls
    Doh {
        host: String,
        port: u16,
        path: String,
        /// 若 host 是域名，此字段缓存已解析的 IP（由 domain_resolver 懒初始化）
        resolved_addr: std::sync::Mutex<Option<std::net::IpAddr>>,
        /// rustls 配置（含系统根证书 + SNI）
        #[cfg(feature = "outbound-net")]
        tls_cfg: std::sync::Arc<rustls::ClientConfig>,
        /// insecure 标记，用于 non-outbound-net 分支提示
        insecure: bool,
    },
    /// DNS-over-TLS：TCP + TLS 握手，2 字节长度前缀帧
    Dot {
        addr: SocketAddr,
        sni: String,
        #[cfg(feature = "outbound-net")]
        tls_cfg: std::sync::Arc<rustls::ClientConfig>,
    },
    /// DNS-over-QUIC（RFC 9250）：QUIC 流，2 字节长度前缀帧
    Doq {
        addr: SocketAddr,
        sni: String,
        #[cfg(feature = "outbound-net")]
        quic_cfg: std::sync::Arc<quinn::ClientConfig>,
    },
    Rcode {
        action: RcodeAction,
    },
    /// FakeIP：从内存地址池按需分配假 IP
    FakeIp {
        store: Arc<FakeIpStore>,
    },
}

impl DnsUpstream {
    /// 不带 detour 的构造（向后兼容）。
    pub fn from_config(cfg: &DnsServerConfig) -> anyhow::Result<Self> {
        Self::from_config_with_detour(cfg, None)
    }

    /// 带 detour 的构造。
    pub fn from_config_with_detour(
        cfg: &DnsServerConfig,
        detour: Option<Arc<dyn Outbound>>,
    ) -> anyhow::Result<Self> {
        Self::from_config_full(cfg, detour, None, None)
    }

    /// 完整构造：支持 detour + CacheFile。
    pub fn from_config_full(
        cfg: &DnsServerConfig,
        detour: Option<Arc<dyn Outbound>>,
        cache_file: Option<Arc<CacheFile>>,
        domain_resolver: Option<Arc<DnsUpstream>>,
    ) -> anyhow::Result<Self> {
        Self::from_config_full_with_reader(cfg, detour, cache_file, None, domain_resolver)
    }

    /// 同上，额外接受 cache_reader 用于 fakeip 恢复。
    pub fn from_config_full_with_reader(
        cfg: &DnsServerConfig,
        detour: Option<Arc<dyn Outbound>>,
        cache_file: Option<Arc<CacheFile>>,
        cache_reader: Option<Arc<crate::experimental::CacheFileReader>>,
        domain_resolver: Option<Arc<DnsUpstream>>,
    ) -> anyhow::Result<Self> {
        let t = Duration::from_secs(cfg.timeout);
        let kind = match cfg.protocol() {
            DnsProtocol::Rcode => UpstreamKind::Rcode {
                action: cfg
                    .rcode()
                    .ok_or_else(|| anyhow::anyhow!("invalid rcode in '{}'", cfg.tag))?,
            },

            DnsProtocol::Doh => {
                let (host, port, path) = parse_doh_url(&cfg.address)?;
                let pre_resolved = host.parse::<std::net::IpAddr>().ok();

                #[cfg(feature = "outbound-net")]
                {
                    let tls_cfg = build_rustls_client_config(cfg)?;
                    UpstreamKind::Doh {
                        host,
                        port,
                        path,
                        resolved_addr: std::sync::Mutex::new(pre_resolved),
                        tls_cfg,
                        insecure: cfg.insecure,
                    }
                }
                #[cfg(not(feature = "outbound-net"))]
                {
                    UpstreamKind::Doh {
                        host,
                        port,
                        path,
                        resolved_addr: std::sync::Mutex::new(pre_resolved),
                        insecure: cfg.insecure,
                    }
                }
            }

            DnsProtocol::Tcp => UpstreamKind::Tcp {
                addr: parse_addr(
                    cfg.address.strip_prefix("tcp://").unwrap_or(&cfg.address),
                    53,
                )?,
            },

            DnsProtocol::Udp => UpstreamKind::Udp {
                addr: parse_addr(
                    cfg.address.strip_prefix("udp://").unwrap_or(&cfg.address),
                    53,
                )?,
            },

            DnsProtocol::Dot => {
                #[cfg(feature = "outbound-net")]
                {
                    let raw = cfg.address.strip_prefix("tls://").unwrap_or(&cfg.address);
                    let addr = parse_addr(raw, 853)?;
                    let sni = cfg.sni.clone().unwrap_or_else(|| addr.ip().to_string());
                    let tls_cfg = build_rustls_client_config(cfg)?;
                    UpstreamKind::Dot { addr, sni, tls_cfg }
                }
                #[cfg(not(feature = "outbound-net"))]
                {
                    anyhow::bail!(
                        "DoT requires the 'outbound-net' feature; upstream '{}' cannot be used",
                        cfg.tag
                    )
                }
            }

            DnsProtocol::Doq => {
                #[cfg(feature = "outbound-net")]
                {
                    let raw = cfg.address.strip_prefix("quic://").unwrap_or(&cfg.address);
                    let addr = parse_addr(raw, 853)?;
                    let sni = cfg.sni.clone().unwrap_or_else(|| addr.ip().to_string());
                    let quic_cfg = build_doq_quic_config(cfg)?;
                    UpstreamKind::Doq {
                        addr,
                        sni,
                        quic_cfg,
                    }
                }
                #[cfg(not(feature = "outbound-net"))]
                {
                    anyhow::bail!(
                        "DoQ requires the 'outbound-net' feature; upstream '{}' cannot be used",
                        cfg.tag
                    )
                }
            }

            DnsProtocol::FakeIp => {
                let fi_cfg = cfg.fakeip.as_ref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "dns server '{}': address is 'fakeip://' but 'fakeip' config is missing",
                        cfg.tag
                    )
                })?;
                let store = FakeIpStore::new_with_cache(fi_cfg, cache_file, cache_reader)
                    .map_err(|e| anyhow::anyhow!("dns server '{}' fakeip store: {e}", cfg.tag))?;
                UpstreamKind::FakeIp {
                    store: Arc::new(store),
                }
            }
        };

        if detour.is_some() {
            let detour_tag = detour.as_ref().map(|d| d.tag()).unwrap_or("?");
            debug!(
                upstream = %cfg.tag,
                detour = %detour_tag,
                "dns upstream will route queries via detour"
            );
        }

        Ok(Self {
            tag: cfg.tag.clone(),
            kind,
            timeout: t,
            detour,
            domain_resolver,
            udp_socket_v4: Arc::new(Mutex::new(None)),
            udp_socket_v6: Arc::new(Mutex::new(None)),
            routing_mark: 0,
        })
    }

    /// 设置 SO_MARK，返回 Self（用于链式调用）。
    pub fn with_mark(mut self, mark: u32) -> Self {
        self.routing_mark = mark;
        self
    }

    /// 设置解析策略（同步到内部 fakeip store，如果有的话）。
    pub fn with_strategy(self, s: crate::config::dns::ResolveStrategy) -> Self {
        if let UpstreamKind::FakeIp { ref store } = self.kind {
            store.set_strategy(s);
        }
        self
    }

    /// 获取或创建与 addr 对应协议族的持久 UDP socket。
    async fn get_or_create_udp_socket(&self, addr: SocketAddr) -> anyhow::Result<Arc<UdpSocket>> {
        let slot = if addr.is_ipv6() {
            &self.udp_socket_v6
        } else {
            &self.udp_socket_v4
        };
        {
            let guard = slot.lock().unwrap();
            if let Some(s) = guard.as_ref() {
                return Ok(s.clone());
            }
        }
        let bind: SocketAddr = if addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        }
        .parse()?;
        let sock = UdpSocket::bind(bind).await?;
        crate::outbound::apply_mark_to_udp(&sock, self.routing_mark)?;
        let sock = Arc::new(sock);
        {
            let mut guard = slot.lock().unwrap();
            if guard.is_none() {
                *guard = Some(sock.clone());
            }
            Ok(guard.as_ref().unwrap().clone())
        }
    }

    /// 用本 upstream 解析一个主机名，返回第一个 IP（供 DoH/DoT domain_resolver 使用）。
    #[cfg(feature = "outbound-net")]
    fn resolve_host<'a>(
        &'a self,
        host: &'a str,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<std::net::IpAddr>> + Send + 'a>> {
        Box::pin(async move {
            use crate::dns::{build_query_bytes, extract_first_ip_from_resp};
            let q = build_query_bytes(host, 1u16);
            if let Ok(resp) = self.query(q.into()).await {
                if let Some(ip) = extract_first_ip_from_resp(&resp, 1) {
                    return Ok(ip);
                }
            }
            let q = build_query_bytes(host, 28u16);
            if let Ok(resp) = self.query(q.into()).await {
                if let Some(ip) = extract_first_ip_from_resp(&resp, 28) {
                    return Ok(ip);
                }
            }
            anyhow::bail!("domain_resolver failed to resolve host '{host}'")
        })
    }

    pub fn query(
        &self,
        msg: Bytes,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Bytes>> + Send + '_>> {
        Box::pin(async move {
            match &self.kind {
                UpstreamKind::Rcode { action } => Ok(rcode_reply(&msg, *action)),

                UpstreamKind::FakeIp { store } => Ok(store.reply(&msg)),

                // ── UDP ───────────────────────────────────────────────────────
                UpstreamKind::Udp { addr } => {
                    if let Some(ob) = &self.detour {
                        debug!(upstream=%self.tag, detour=%ob.tag(), addr=%addr,
                            "dns udp query routed via detour as TCP");
                        timeout(
                            self.timeout,
                            tcp_query_via_detour(
                                ob.as_ref(),
                                addr.ip().to_string(),
                                addr.port(),
                                msg,
                            ),
                        )
                        .await?
                    } else {
                        let sock = self.get_or_create_udp_socket(*addr).await?;
                        timeout(
                            self.timeout,
                            udp_query_with_socket(sock, *addr, msg, self.routing_mark),
                        )
                        .await?
                    }
                }

                // ── TCP ───────────────────────────────────────────────────────
                UpstreamKind::Tcp { addr } => {
                    if let Some(ob) = &self.detour {
                        debug!(upstream=%self.tag, detour=%ob.tag(), addr=%addr,
                            "dns tcp query routed via detour");
                        timeout(
                            self.timeout,
                            tcp_query_via_detour(
                                ob.as_ref(),
                                addr.ip().to_string(),
                                addr.port(),
                                msg,
                            ),
                        )
                        .await?
                    } else {
                        timeout(self.timeout, tcp_query(*addr, msg, self.routing_mark)).await?
                    }
                }

                // ── DoH ───────────────────────────────────────────────────────
                #[cfg(feature = "outbound-net")]
                UpstreamKind::Doh {
                    host,
                    port,
                    path,
                    resolved_addr,
                    tls_cfg,
                    ..
                } => {
                    let ip = resolve_or_cached(
                        resolved_addr,
                        host,
                        *port,
                        self.domain_resolver.as_ref(),
                        &self.tag,
                    )
                    .await?;

                    if let Some(ob) = &self.detour {
                        debug!(upstream=%self.tag, detour=%ob.tag(), host=%host,
                            "dns doh query routed via detour");
                        timeout(
                            self.timeout,
                            doh_query_via_detour(
                                ob.as_ref(),
                                host,
                                *port,
                                path,
                                tls_cfg.clone(),
                                msg,
                            ),
                        )
                        .await?
                    } else {
                        timeout(
                            self.timeout,
                            doh_query_direct(ip, host, *port, path, tls_cfg.clone(), msg),
                        )
                        .await?
                    }
                }

                // feature 未开启时的 DoH 分支（insecure 字段仍可访问）
                #[cfg(not(feature = "outbound-net"))]
                UpstreamKind::Doh { .. } => {
                    anyhow::bail!("DoH requires the 'outbound-net' feature")
                }

                // ── DoT ───────────────────────────────────────────────────────
                #[cfg(feature = "outbound-net")]
                UpstreamKind::Dot { addr, sni, tls_cfg } => {
                    if let Some(ob) = &self.detour {
                        debug!(upstream=%self.tag, detour=%ob.tag(), addr=%addr,
                            "dns dot query routed via detour");
                        timeout(
                            self.timeout,
                            dot_query_via_detour(
                                ob.as_ref(),
                                addr.ip().to_string(),
                                addr.port(),
                                sni,
                                tls_cfg.clone(),
                                msg,
                            ),
                        )
                        .await?
                    } else {
                        timeout(
                            self.timeout,
                            dot_query(*addr, sni, tls_cfg.clone(), msg, self.routing_mark),
                        )
                        .await?
                    }
                }

                #[cfg(not(feature = "outbound-net"))]
                UpstreamKind::Dot { .. } => {
                    anyhow::bail!("DoT requires the 'outbound-net' feature")
                }

                // ── DoQ ───────────────────────────────────────────────────────
                #[cfg(feature = "outbound-net")]
                UpstreamKind::Doq {
                    addr,
                    sni,
                    quic_cfg,
                } => {
                    if self.detour.is_some() {
                        debug!(upstream=%self.tag,
                            "dns doq does not support TCP detour, falling back to direct");
                    }
                    timeout(
                        self.timeout,
                        doq_query(*addr, sni, quic_cfg.clone(), msg, self.routing_mark),
                    )
                    .await?
                }

                #[cfg(not(feature = "outbound-net"))]
                UpstreamKind::Doq { .. } => {
                    anyhow::bail!("DoQ requires the 'outbound-net' feature")
                }
            }
        })
    }
}

// ── 地址解析辅助 ─────────────────────────────────────────────────────────────

#[cfg(feature = "outbound-net")]
async fn resolve_or_cached(
    cache: &std::sync::Mutex<Option<std::net::IpAddr>>,
    host: &str,
    port: u16,
    domain_resolver: Option<&Arc<DnsUpstream>>,
    tag: &str,
) -> anyhow::Result<std::net::IpAddr> {
    {
        let cached = *cache.lock().unwrap();
        if let Some(ip) = cached {
            return Ok(ip);
        }
    }
    let ip = if let Some(resolver) = domain_resolver {
        debug!(upstream=%tag, domain_resolver=%resolver.tag, host=%host,
            "resolving host via domain_resolver");
        resolver.resolve_host(host).await?
    } else {
        tokio::net::lookup_host(format!("{host}:{port}"))
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("system DNS lookup failed for {host}"))?
            .ip()
    };
    *cache.lock().unwrap() = Some(ip);
    Ok(ip)
}

// ── TLS 配置构建（outbound-net） ──────────────────────────────────────────────

#[cfg(feature = "outbound-net")]
fn build_rustls_client_config(
    cfg: &DnsServerConfig,
) -> anyhow::Result<std::sync::Arc<rustls::ClientConfig>> {
    use rustls::RootCertStore;

    let mut root_store = RootCertStore::empty();
    // 加载系统根证书
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        let _ = root_store.add(cert);
    }

    let tls_config = if cfg.insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(crate::outbound::tls::NoVerifier))
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    Ok(std::sync::Arc::new(tls_config))
}

/// 构建 DNS-over-QUIC 专用 quinn::ClientConfig
#[cfg(feature = "outbound-net")]
fn build_doq_quic_config(
    cfg: &DnsServerConfig,
) -> anyhow::Result<std::sync::Arc<quinn::ClientConfig>> {
    use rustls::RootCertStore;

    let mut root_store = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        let _ = root_store.add(cert);
    }

    let mut tls_config = if cfg.insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(crate::outbound::tls::NoVerifier))
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    // RFC 9250 要求 ALPN = "doq"
    tls_config.alpn_protocols = vec![b"doq".to_vec()];

    let mut transport = quinn::TransportConfig::default();
    transport
        .max_idle_timeout(Some(quinn::VarInt::from_u32(30_000).into()))
        .keep_alive_interval(Some(Duration::from_secs(10)));

    let mut quic_cfg = quinn::ClientConfig::new(std::sync::Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?,
    ));
    quic_cfg.transport_config(std::sync::Arc::new(transport));

    Ok(std::sync::Arc::new(quic_cfg))
}

// ── 协议实现：UDP ─────────────────────────────────────────────────────────────

async fn udp_query(addr: SocketAddr, msg: Bytes, mark: u32) -> anyhow::Result<Bytes> {
    let bind: SocketAddr = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    }
    .parse()?;
    let sock = UdpSocket::bind(bind).await?;
    #[cfg(target_os = "linux")]
    crate::outbound::apply_mark_to_udp(&sock, mark)?;
    sock.send_to(&msg, addr).await?;
    let mut buf = vec![0u8; 4096];
    let (n, _) = sock.recv_from(&mut buf).await?;
    if n >= 3 && (buf[2] & 0x02) != 0 {
        debug!(addr=%addr, "dns udp TC bit, retry over TCP");
        return tcp_query(addr, msg, mark).await;
    }
    Ok(Bytes::copy_from_slice(&buf[..n]))
}

async fn udp_query_with_socket(
    sock: Arc<UdpSocket>,
    addr: SocketAddr,
    msg: Bytes,
    mark: u32,
) -> anyhow::Result<Bytes> {
    sock.send_to(&msg, addr).await?;
    let mut buf = vec![0u8; 4096];
    let (n, from) = sock.recv_from(&mut buf).await?;
    if from != addr {
        return udp_query(addr, msg, mark).await;
    }
    if n >= 3 && (buf[2] & 0x02) != 0 {
        debug!(addr=%addr, "dns udp TC bit, retry over TCP");
        return tcp_query(addr, msg, mark).await;
    }
    Ok(Bytes::copy_from_slice(&buf[..n]))
}

// ── 协议实现：TCP ─────────────────────────────────────────────────────────────

async fn tcp_query(
    addr: SocketAddr,
    msg: Bytes,
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))] mark: u32,
) -> anyhow::Result<Bytes> {
    let mut stream = TcpStream::connect(addr)
        .await
        .map_err(|e| anyhow::anyhow!("TCP connect to {addr} failed: {e}"))?;
    #[cfg(target_os = "linux")]
    crate::outbound::apply_mark_to_tcp(&stream, mark)?;
    tcp_framed_exchange(&mut stream, msg).await
}

async fn tcp_query_via_detour(
    outbound: &dyn Outbound,
    host: String,
    port: u16,
    msg: Bytes,
) -> anyhow::Result<Bytes> {
    let mut stream = outbound.connect_tcp(&host, port).await?;
    tcp_framed_exchange(stream.as_mut(), msg).await
}

// ── 协议实现：DoT ─────────────────────────────────────────────────────────────

#[cfg(feature = "outbound-net")]
async fn dot_query(
    addr: SocketAddr,
    sni: &str,
    tls_cfg: std::sync::Arc<rustls::ClientConfig>,
    msg: Bytes,
    mark: u32,
) -> anyhow::Result<Bytes> {
    let tcp = TcpStream::connect(addr)
        .await
        .map_err(|e| anyhow::anyhow!("DoT TCP connect to {addr} failed: {e}"))?;
    crate::outbound::apply_mark_to_tcp(&tcp, mark)?;
    let mut tls = crate::outbound::tls::connect_tls(tcp, sni, tls_cfg)
        .await
        .map_err(|e| anyhow::anyhow!("DoT TLS handshake with {sni} failed: {e}"))?;
    tcp_framed_exchange(&mut tls, msg).await
}

#[cfg(feature = "outbound-net")]
async fn dot_query_via_detour(
    outbound: &dyn Outbound,
    host: String,
    port: u16,
    sni: &str,
    tls_cfg: std::sync::Arc<rustls::ClientConfig>,
    msg: Bytes,
) -> anyhow::Result<Bytes> {
    // 先通过 detour 建立 TCP 隧道，再在上面套 TLS
    let tcp_stream = outbound.connect_tcp(&host, port).await?;
    // connect_tcp 返回 Box<dyn AsyncReadWrite>，需要转为 TcpStream-like
    // 这里利用 tokio-rustls 支持任意 AsyncRead+AsyncWrite 的能力
    let tls = dot_tls_on_boxed(tcp_stream, sni, tls_cfg).await?;
    // tls 实现了 AsyncRead+AsyncWrite，可直接用
    let mut tls = tls;
    tcp_framed_exchange(&mut tls, msg).await
}

#[cfg(feature = "outbound-net")]
async fn dot_tls_on_boxed(
    stream: Box<dyn crate::outbound::AsyncReadWrite>,
    sni: &str,
    tls_cfg: std::sync::Arc<rustls::ClientConfig>,
) -> anyhow::Result<tokio_rustls::client::TlsStream<BoxStream>> {
    use rustls::pki_types::ServerName;
    use tokio_rustls::TlsConnector;

    let connector = TlsConnector::from(tls_cfg);
    let server_name =
        ServerName::try_from(sni.to_string()).map_err(|_| anyhow::anyhow!("invalid SNI: {sni}"))?;
    let tls = connector
        .connect(server_name, BoxStream(stream))
        .await
        .map_err(|e| anyhow::anyhow!("DoT TLS handshake via detour with {sni} failed: {e}"))?;
    Ok(tls)
}

// 将 Box<dyn AsyncReadWrite> 包装成实现 AsyncRead+AsyncWrite 的新类型，
// 供 tokio-rustls 使用。
#[cfg(feature = "outbound-net")]
struct BoxStream(Box<dyn crate::outbound::AsyncReadWrite>);

#[cfg(feature = "outbound-net")]
impl tokio::io::AsyncRead for BoxStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_read(cx, buf)
    }
}

#[cfg(feature = "outbound-net")]
impl tokio::io::AsyncWrite for BoxStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut *self.0).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_shutdown(cx)
    }
}

// ── 协议实现：DoQ ─────────────────────────────────────────────────────────────

#[cfg(feature = "outbound-net")]
async fn doq_query(
    addr: SocketAddr,
    sni: &str,
    quic_cfg: std::sync::Arc<quinn::ClientConfig>,
    msg: Bytes,
    mark: u32,
) -> anyhow::Result<Bytes> {
    let bind: SocketAddr = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    }
    .parse()?;
    let mut endpoint = crate::outbound::new_marked_quic_endpoint(bind, mark)
        .map_err(|e| anyhow::anyhow!("DoQ endpoint bind failed: {e}"))?;
    endpoint.set_default_client_config((*quic_cfg).clone());

    let conn = endpoint
        .connect(addr, sni)
        .map_err(|e| anyhow::anyhow!("DoQ connect config error: {e}"))?
        .await
        .map_err(|e| anyhow::anyhow!("DoQ QUIC connect to {addr} failed: {e}"))?;

    // RFC 9250: 每个查询用独立的 QUIC 双向流
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| anyhow::anyhow!("DoQ open stream failed: {e}"))?;

    // 写入（2 字节长度前缀 + DNS wire）
    let len = msg.len() as u16;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(&msg).await?;
    send.finish()
        .map_err(|e| anyhow::anyhow!("DoQ stream finish failed: {e}"))?;

    // 读取响应
    let resp_len =
        recv.read_u16()
            .await
            .map_err(|e| anyhow::anyhow!("DoQ read response length failed: {e}"))? as usize;
    anyhow::ensure!(resp_len <= 65535, "DoQ response too large: {resp_len}");
    let mut buf = vec![0u8; resp_len];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| anyhow::anyhow!("DoQ read response body failed: {e}"))?;

    conn.close(quinn::VarInt::from_u32(0), b"");
    Ok(Bytes::from(buf))
}

// ── 协议实现：DoH ─────────────────────────────────────────────────────────────

/// 直连 DoH：直接连到已解析好的 IP，TLS SNI 用原始域名。
/// 尝试 HTTP/2（ALPN h2），失败回退 HTTP/1.1。
#[cfg(feature = "outbound-net")]
async fn doh_query_direct(
    ip: std::net::IpAddr,
    host: &str,
    port: u16,
    path: &str,
    tls_cfg: std::sync::Arc<rustls::ClientConfig>,
    msg: Bytes,
) -> anyhow::Result<Bytes> {
    let addr = SocketAddr::new(ip, port);
    let tcp = TcpStream::connect(addr)
        .await
        .map_err(|e| anyhow::anyhow!("DoH TCP connect to {addr} failed: {e}"))?;

    // 构建带 h2 ALPN 的 TLS 配置
    let mut cfg = (*tls_cfg).clone();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let cfg = std::sync::Arc::new(cfg);

    let tls = crate::outbound::tls::connect_tls(tcp, host, cfg)
        .await
        .map_err(|e| anyhow::anyhow!("DoH TLS handshake with {host} failed: {e}"))?;

    let negotiated = tls.get_ref().1.alpn_protocol();
    if negotiated == Some(b"h2") {
        doh_h2_query(tls, host, port, path, msg).await
    } else {
        doh_h1_query(tls, host, port, path, msg).await
    }
}

/// 经 detour 的 DoH：通过 CONNECT 隧道建立 TCP，再套 TLS，再做 HTTP。
#[cfg(feature = "outbound-net")]
async fn doh_query_via_detour(
    outbound: &dyn Outbound,
    host: &str,
    port: u16,
    path: &str,
    tls_cfg: std::sync::Arc<rustls::ClientConfig>,
    msg: Bytes,
) -> anyhow::Result<Bytes> {
    let tcp_stream = outbound.connect_tcp(host, port).await?;

    let mut cfg = (*tls_cfg).clone();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let cfg = std::sync::Arc::new(cfg);

    let tls = dot_tls_on_boxed(tcp_stream, host, cfg)
        .await
        .map_err(|e| anyhow::anyhow!("DoH TLS handshake via detour with {host} failed: {e}"))?;

    let negotiated = tls.get_ref().1.alpn_protocol();
    if negotiated == Some(b"h2") {
        doh_h2_query(tls, host, port, path, msg).await
    } else {
        doh_h1_query(tls, host, port, path, msg).await
    }
}

/// HTTP/1.1 DoH（application/dns-message POST），Connection: close 模式。
#[cfg(feature = "outbound-net")]
async fn doh_h1_query<S>(
    mut stream: S,
    host: &str,
    port: u16,
    path: &str,
    msg: Bytes,
) -> anyhow::Result<Bytes>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let body = msg.as_ref();
    let request = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}:{port}\r\n\
         Content-Type: application/dns-message\r\n\
         Accept: application/dns-message\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(body).await?;

    // 读取全部响应（Connection: close 保证服务端关闭连接后 read_to_end 返回）
    let mut resp_buf = Vec::with_capacity(4096);
    stream.read_to_end(&mut resp_buf).await?;

    parse_doh_http_response(&resp_buf)
}

/// HTTP/2 DoH，复用单个 h2 连接。
#[cfg(feature = "outbound-net")]
async fn doh_h2_query<S>(
    stream: S,
    host: &str,
    port: u16,
    path: &str,
    msg: Bytes,
) -> anyhow::Result<Bytes>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    use h2::client;

    let (send_req, conn) = client::handshake(stream)
        .await
        .map_err(|e| anyhow::anyhow!("h2 handshake failed: {e}"))?;
    // 在后台驱动连接
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let uri = format!("https://{}:{}{}", host, port, path)
        .parse::<http::Uri>()
        .map_err(|e| anyhow::anyhow!("invalid DoH URI: {e}"))?;

    let req = http::Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .header("content-length", msg.len().to_string())
        .body(())
        .map_err(|e| anyhow::anyhow!("h2 request build failed: {e}"))?;

    // ready() 消费 send_req 并返回 ReadySendRequest，send_request() 在其上调用
    let mut ready = send_req
        .ready()
        .await
        .map_err(|e| anyhow::anyhow!("h2 send_request not ready: {e}"))?;
    let (resp_future, mut send_stream) = ready
        .send_request(req, false)
        .map_err(|e| anyhow::anyhow!("h2 send_request failed: {e}"))?;

    send_stream
        .send_data(msg, true)
        .map_err(|e| anyhow::anyhow!("h2 send_data failed: {e}"))?;

    let mut response = resp_future
        .await
        .map_err(|e| anyhow::anyhow!("h2 response failed: {e}"))?;

    let status = response.status();
    anyhow::ensure!(
        status == http::StatusCode::OK,
        "DoH h2 server returned non-200: {status}"
    );

    let body = response.body_mut();
    let mut data = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|e| anyhow::anyhow!("h2 body read failed: {e}"))?;
        data.extend_from_slice(&chunk);
    }

    Ok(Bytes::from(data))
}

/// 解析 HTTP/1.x 响应，提取 body。
#[cfg(feature = "outbound-net")]
fn parse_doh_http_response(resp: &[u8]) -> anyhow::Result<Bytes> {
    let header_end = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("malformed DoH HTTP response: no header boundary"))?;

    let status_line_end = resp.iter().position(|&b| b == b'\r').unwrap_or(header_end);
    let status_line = std::str::from_utf8(&resp[..status_line_end]).unwrap_or("");
    anyhow::ensure!(
        status_line.contains("200"),
        "DoH server returned non-200: {status_line}"
    );

    let body_start = header_end + 4;
    // 查找 Content-Length
    let headers_str = std::str::from_utf8(&resp[..header_end]).unwrap_or("");
    let content_length: Option<usize> = headers_str
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split_once(':').map(|x| x.1))
        .and_then(|v| v.trim().parse().ok());

    let body = if let Some(len) = content_length {
        anyhow::ensure!(
            body_start + len <= resp.len(),
            "DoH response body truncated (expected {len} bytes)"
        );
        &resp[body_start..body_start + len]
    } else {
        &resp[body_start..]
    };

    anyhow::ensure!(!body.is_empty(), "DoH response body is empty");
    Ok(Bytes::copy_from_slice(body))
}

// ── 共用帧收发（DNS-over-TCP / DoT / DoQ） ───────────────────────────────────

/// DNS over TCP/TLS/QUIC-stream 帧格式：2 字节大端长度前缀
async fn tcp_framed_exchange<S>(stream: &mut S, msg: Bytes) -> anyhow::Result<Bytes>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + ?Sized,
{
    stream.write_all(&(msg.len() as u16).to_be_bytes()).await?;
    stream.write_all(&msg).await?;
    let len = stream.read_u16().await? as usize;
    anyhow::ensure!(len >= 12, "dns tcp response too short: {len}");
    anyhow::ensure!(len <= 65535, "dns tcp response too large: {len}");
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(Bytes::from(buf))
}

fn rcode_reply(query: &[u8], action: RcodeAction) -> Bytes {
    match action {
        RcodeAction::Refused => make_refused(query),
        RcodeAction::Success => make_noerror_empty(query),
        RcodeAction::NxDomain => make_nxdomain(query),
    }
}

// ── 地址解析 ──────────────────────────────────────────────────────────────────

fn parse_addr(s: &str, default_port: u16) -> anyhow::Result<SocketAddr> {
    if s.starts_with('[') {
        return Ok(s.parse()?);
    }
    if s.contains(':') {
        return Ok(s.parse()?);
    }
    Ok(format!("{s}:{default_port}").parse()?)
}

fn parse_doh_url(url: &str) -> anyhow::Result<(String, u16, String)> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| anyhow::anyhow!("DoH URL must start with https://: {url}"))?;

    let (host_port, path) = if let Some(pos) = rest.find('/') {
        (&rest[..pos], rest[pos..].to_string())
    } else {
        (rest, "/".to_string())
    };

    let (host, port) = if let Some(pos) = host_port.rfind(':') {
        let port: u16 = host_port[pos + 1..]
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid DoH port in: {url}"))?;
        (host_port[..pos].to_string(), port)
    } else {
        (host_port.to_string(), 443u16)
    };

    Ok((host, port, path))
}

// ── FakeIP 地址池 ─────────────────────────────────────────────────────────────

pub struct FakeIpStore {
    inet4_net: Option<(Ipv4Addr, Ipv4Addr)>,
    inet6_net: Option<(Ipv6Addr, Ipv6Addr)>,
    inner: Mutex<FakeIpInner>,
    cache_file: Option<Arc<CacheFile>>,
    exclude_domain: std::collections::HashSet<String>,
    exclude_domain_suffix: Vec<String>,
    /// 控制 fakeip 响应哪种记录类型（与 DnsResolver.strategy 联动）。
    /// 用 AtomicU8 存储，允许在 Arc<FakeIpStore> 下热更新（如 global.ipv6 变化时）。
    /// 值含义：0=PreferIpv4, 1=PreferIpv6, 2=Ipv4Only, 3=Ipv6Only
    pub strategy: std::sync::atomic::AtomicU8,
}

struct FakeIpInner {
    inet4_current: Option<Ipv4Addr>,
    inet6_current: Option<Ipv6Addr>,
    addr_to_domain: HashMap<std::net::IpAddr, String>,
    domain_to_v4: HashMap<String, Ipv4Addr>,
    domain_to_v6: HashMap<String, Ipv6Addr>,
}

impl FakeIpStore {
    pub fn new(cfg: &crate::config::dns::FakeIpConfig) -> anyhow::Result<Self> {
        Self::new_with_cache(cfg, None, None)
    }

    pub fn new_with_cache(
        cfg: &crate::config::dns::FakeIpConfig,
        cache_file: Option<Arc<CacheFile>>,
        cache_reader: Option<Arc<crate::experimental::CacheFileReader>>,
    ) -> anyhow::Result<Self> {
        let inet4_net = cfg
            .inet4_range
            .as_deref()
            .map(parse_ipv4_cidr)
            .transpose()?;
        let inet6_net = cfg
            .inet6_range
            .as_deref()
            .map(parse_ipv6_cidr)
            .transpose()?;

        if inet4_net.is_none() && inet6_net.is_none() {
            anyhow::bail!("fakeip: at least one of inet4_range or inet6_range must be set");
        }

        let inet4_current = inet4_net.map(|(start, _)| ipv4_next(start));
        let inet6_current = inet6_net.map(|(start, _)| ipv6_next(start));

        let mut inner = FakeIpInner {
            inet4_current,
            inet6_current,
            addr_to_domain: HashMap::new(),
            domain_to_v4: HashMap::new(),
            domain_to_v6: HashMap::new(),
        };

        if let (Some(ref cr), Some(ref cf)) = (&cache_reader, &cache_file) {
            if cf.store_fakeip {
                match cr.load_all_fakeip() {
                    Ok(records) => {
                        let count = records.len();
                        for (ip, domain) in records {
                            match ip {
                                std::net::IpAddr::V4(v4) => {
                                    if inet4_net.is_some_and(|(s, e)| v4 >= s && v4 <= e) {
                                        inner.addr_to_domain.insert(ip, domain.clone());
                                        inner.domain_to_v4.insert(domain, v4);
                                        if let Some(cur) = inner.inet4_current {
                                            if v4 >= cur {
                                                inner.inet4_current = Some(ipv4_next(v4));
                                            }
                                        }
                                    }
                                }
                                std::net::IpAddr::V6(v6) => {
                                    if inet6_net.is_some_and(|(s, e)| v6 >= s && v6 <= e) {
                                        inner.addr_to_domain.insert(ip, domain.clone());
                                        inner.domain_to_v6.insert(domain, v6);
                                        if let Some(cur) = inner.inet6_current {
                                            if v6 >= cur {
                                                inner.inet6_current = Some(ipv6_next(v6));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if let Some((_, end)) = inet4_net {
                            if inner.inet4_current.is_some_and(|c| c >= end) {
                                inner.inet4_current = Some(ipv4_next(inet4_net.unwrap().0));
                            }
                        }
                        if let Some((_, end)) = inet6_net {
                            if inner.inet6_current.is_some_and(|c| c >= end) {
                                inner.inet6_current = Some(ipv6_next(inet6_net.unwrap().0));
                            }
                        }
                        tracing::info!(count, "restored fakeip mappings from cache");
                    }
                    Err(e) => {
                        tracing::warn!(err=%e, "failed to load fakeip from cache, starting fresh");
                    }
                }
            }
        }

        Ok(Self {
            inet4_net,
            inet6_net,
            inner: Mutex::new(inner),
            cache_file,
            exclude_domain: cfg
                .exclude_domain
                .iter()
                .map(|d| d.to_ascii_lowercase())
                .collect(),
            exclude_domain_suffix: cfg
                .exclude_domain_suffix
                .iter()
                .map(|s| {
                    if s.starts_with('.') {
                        s.to_ascii_lowercase()
                    } else {
                        format!(".{}", s.to_ascii_lowercase())
                    }
                })
                .collect(),
            strategy: std::sync::atomic::AtomicU8::new(0), // 默认 PreferIpv4
        })
    }

    /// 设置 fakeip 的 strategy，与 ResolveStrategy 对应：
    /// PreferIpv4=0, PreferIpv6=1, Ipv4Only=2, Ipv6Only=3
    pub fn set_strategy(&self, s: crate::config::dns::ResolveStrategy) {
        use crate::config::dns::ResolveStrategy::*;
        let v = match s {
            PreferIpv4 => 0,
            PreferIpv6 => 1,
            Ipv4Only => 2,
            Ipv6Only => 3,
        };
        self.strategy.store(v, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn diag_sizes(&self) -> (usize, usize, usize) {
        let inner = self.inner.lock().unwrap();
        (
            inner.addr_to_domain.len(),
            inner.domain_to_v4.len(),
            inner.domain_to_v6.len(),
        )
    }

    pub fn contains(&self, addr: std::net::IpAddr) -> bool {
        match addr {
            std::net::IpAddr::V4(v4) => self.inet4_net.is_some_and(|(s, e)| v4 >= s && v4 <= e),
            std::net::IpAddr::V6(v6) => self.inet6_net.is_some_and(|(s, e)| v6 >= s && v6 <= e),
        }
    }

    pub fn lookup(&self, addr: std::net::IpAddr) -> Option<String> {
        self.inner
            .lock()
            .unwrap()
            .addr_to_domain
            .get(&addr)
            .cloned()
    }

    pub fn is_excluded(&self, domain: &str) -> bool {
        let lower = domain.to_ascii_lowercase();
        if self.exclude_domain.contains(&lower) {
            return true;
        }
        for suffix in &self.exclude_domain_suffix {
            if lower.ends_with(suffix.as_str()) || lower == suffix.trim_start_matches('.') {
                return true;
            }
        }
        false
    }

    pub fn reply(&self, query: &[u8]) -> Bytes {
        use crate::dns::{extract_qname, extract_qtype, make_nxdomain};

        let qtype = match extract_qtype(query) {
            Some(t) => t,
            None => return make_noerror_empty(query),
        };
        if qtype != 1 && qtype != 28 {
            return make_noerror_empty(query);
        }

        let qname = match extract_qname(query) {
            Some(n) => n,
            None => return make_noerror_empty(query),
        };

        if self.is_excluded(&qname) {
            tracing::debug!(domain=%qname, "fakeip: domain excluded, returning NXDOMAIN");
            return make_nxdomain(query);
        }

        // 读取当前 strategy：0=PreferIpv4, 1=PreferIpv6, 2=Ipv4Only, 3=Ipv6Only
        let strat = self.strategy.load(std::sync::atomic::Ordering::Relaxed);

        if qtype == 1 {
            // A 查询：Ipv6Only 时拒绝返回 IPv4 fakeip
            if strat == 3 {
                return make_noerror_empty(query);
            }
            match self.allocate_v4(&qname) {
                Some(ip) => build_a_response(query, ip),
                None => make_noerror_empty(query),
            }
        } else {
            // AAAA 查询：Ipv4Only 时拒绝返回 IPv6 fakeip
            if strat == 2 {
                return make_noerror_empty(query);
            }
            match self.allocate_v6(&qname) {
                Some(ip) => build_aaaa_response(query, ip),
                None => make_noerror_empty(query),
            }
        }
    }

    fn allocate_v4(&self, domain: &str) -> Option<Ipv4Addr> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(&existing) = inner.domain_to_v4.get(domain) {
            if let Some(ref cf) = self.cache_file {
                cf.touch_fakeip_entry(std::net::IpAddr::V4(existing));
            }
            return Some(existing);
        }
        let (start, end) = self.inet4_net?;
        let current = inner.inet4_current?;
        let next = if ipv4_next(current) >= end {
            ipv4_next(start)
        } else {
            ipv4_next(current)
        };
        inner.inet4_current = Some(next);
        if let Some(old_domain) = inner.addr_to_domain.remove(&std::net::IpAddr::V4(next)) {
            inner.domain_to_v4.remove(&old_domain);
        }
        inner
            .addr_to_domain
            .insert(std::net::IpAddr::V4(next), domain.to_string());
        inner.domain_to_v4.insert(domain.to_string(), next);
        if let Some(ref cf) = self.cache_file {
            cf.store_fakeip_entry(std::net::IpAddr::V4(next), domain);
        }
        Some(next)
    }

    fn allocate_v6(&self, domain: &str) -> Option<Ipv6Addr> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(&existing) = inner.domain_to_v6.get(domain) {
            if let Some(ref cf) = self.cache_file {
                cf.touch_fakeip_entry(std::net::IpAddr::V6(existing));
            }
            return Some(existing);
        }
        let (start, end) = self.inet6_net?;
        let current = inner.inet6_current?;
        let next = if ipv6_next(current) >= end {
            ipv6_next(start)
        } else {
            ipv6_next(current)
        };
        inner.inet6_current = Some(next);
        if let Some(old_domain) = inner.addr_to_domain.remove(&std::net::IpAddr::V6(next)) {
            inner.domain_to_v6.remove(&old_domain);
        }
        inner
            .addr_to_domain
            .insert(std::net::IpAddr::V6(next), domain.to_string());
        inner.domain_to_v6.insert(domain.to_string(), next);
        if let Some(ref cf) = self.cache_file {
            cf.store_fakeip_entry(std::net::IpAddr::V6(next), domain);
        }
        Some(next)
    }
}

// ── FakeIP wire 应答构造 ──────────────────────────────────────────────────────

fn build_a_response(query: &[u8], ip: Ipv4Addr) -> Bytes {
    build_ip_response(query, 1, &ip.octets())
}

fn build_aaaa_response(query: &[u8], ip: Ipv6Addr) -> Bytes {
    build_ip_response(query, 28, &ip.octets())
}

fn build_ip_response(query: &[u8], rtype: u16, rdata: &[u8]) -> Bytes {
    if query.len() < 12 {
        return make_noerror_empty(query);
    }
    const TTL: u32 = 1;
    let mut resp = Vec::with_capacity(query.len() + 16 + rdata.len());
    resp.extend_from_slice(&query[..2]);
    resp.extend_from_slice(&[0x81, 0x80]);
    resp.extend_from_slice(&[0x00, 0x01]);
    resp.extend_from_slice(&[0x00, 0x01]);
    resp.extend_from_slice(&[0x00, 0x00]);
    resp.extend_from_slice(&[0x00, 0x00]);
    resp.extend_from_slice(&query[12..]);
    resp.extend_from_slice(&[0xC0, 0x0C]);
    resp.extend_from_slice(&rtype.to_be_bytes());
    resp.extend_from_slice(&[0x00, 0x01]);
    resp.extend_from_slice(&TTL.to_be_bytes());
    resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    resp.extend_from_slice(rdata);
    Bytes::from(resp)
}

// ── CIDR 解析 ────────────────────────────────────────────────────────────────

fn parse_ipv4_cidr(s: &str) -> anyhow::Result<(Ipv4Addr, Ipv4Addr)> {
    let (addr_str, prefix_str) = s
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("invalid IPv4 CIDR: {s}"))?;
    let addr: Ipv4Addr = addr_str
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid IPv4 address in CIDR: {s}"))?;
    let prefix: u32 = prefix_str
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid prefix length in CIDR: {s}"))?;
    anyhow::ensure!(prefix <= 32, "IPv4 prefix length must be ≤ 32: {s}");
    let mask = if prefix == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix)
    };
    let net = u32::from(addr) & mask;
    let bcast = net | !mask;
    Ok((Ipv4Addr::from(net), Ipv4Addr::from(bcast)))
}

fn parse_ipv6_cidr(s: &str) -> anyhow::Result<(Ipv6Addr, Ipv6Addr)> {
    let (addr_str, prefix_str) = s
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("invalid IPv6 CIDR: {s}"))?;
    let addr: Ipv6Addr = addr_str
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid IPv6 address in CIDR: {s}"))?;
    let prefix: u32 = prefix_str
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid prefix length in CIDR: {s}"))?;
    anyhow::ensure!(prefix <= 128, "IPv6 prefix length must be ≤ 128: {s}");
    let raw = u128::from(addr);
    let mask = if prefix == 0 {
        0u128
    } else {
        !0u128 << (128 - prefix)
    };
    let net = raw & mask;
    let last = net | !mask;
    Ok((Ipv6Addr::from(net), Ipv6Addr::from(last)))
}

fn ipv4_next(addr: Ipv4Addr) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(addr).wrapping_add(1))
}
fn ipv6_next(addr: Ipv6Addr) -> Ipv6Addr {
    Ipv6Addr::from(u128::from(addr).wrapping_add(1))
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_addr_bare() {
        assert_eq!(
            parse_addr("8.8.8.8", 53).unwrap(),
            "8.8.8.8:53".parse().unwrap()
        );
    }
    #[test]
    fn parse_addr_with_port() {
        assert_eq!(
            parse_addr("8.8.8.8:5353", 53).unwrap(),
            "8.8.8.8:5353".parse().unwrap()
        );
    }
    #[test]
    fn parse_addr_ipv6() {
        assert_eq!(
            parse_addr("[::1]:53", 53).unwrap(),
            "[::1]:53".parse().unwrap()
        );
    }

    #[test]
    fn parse_doh_standard() {
        let (h, p, path) = parse_doh_url("https://1.1.1.1/dns-query").unwrap();
        assert_eq!(h, "1.1.1.1");
        assert_eq!(p, 443);
        assert_eq!(path, "/dns-query");
    }
    #[test]
    fn parse_doh_custom_port() {
        let (h, p, path) = parse_doh_url("https://dns.example.com:8443/resolve").unwrap();
        assert_eq!(h, "dns.example.com");
        assert_eq!(p, 8443);
        assert_eq!(path, "/resolve");
    }
    #[test]
    fn parse_doh_no_path() {
        let (h, p, path) = parse_doh_url("https://dns.example.com").unwrap();
        assert_eq!(h, "dns.example.com");
        assert_eq!(p, 443);
        assert_eq!(path, "/");
    }
    #[test]
    fn parse_doh_bad_scheme() {
        assert!(parse_doh_url("http://1.1.1.1/dns-query").is_err());
    }

    #[test]
    fn rcode_refused() {
        let q = &[0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        let r = rcode_reply(q, RcodeAction::Refused);
        assert_eq!(r[0], 0xAB);
        assert_eq!(r[3] & 0x0F, 5);
    }
    #[test]
    fn rcode_nxdomain() {
        let q = &[0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        assert_eq!(rcode_reply(q, RcodeAction::NxDomain)[3] & 0x0F, 3);
    }
    #[test]
    fn rcode_success() {
        let q = &[0, 2, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        assert_eq!(rcode_reply(q, RcodeAction::Success)[3] & 0x0F, 0);
    }

    use crate::config::dns::FakeIpConfig;

    fn make_fakeip_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut msg = vec![
            0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in name.split('.') {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0x00);
        msg.extend_from_slice(&qtype.to_be_bytes());
        msg.extend_from_slice(&[0x00, 0x01]);
        msg
    }

    fn new_store_v4() -> FakeIpStore {
        FakeIpStore::new(&FakeIpConfig {
            inet4_range: Some("198.18.0.0/15".into()),
            inet6_range: None,
            exclude_domain: vec![],
            exclude_domain_suffix: vec![],
        })
        .unwrap()
    }

    #[test]
    fn fakeip_a_query_returns_valid_ip() {
        let store = new_store_v4();
        let q = make_fakeip_query("example.com", 1);
        let resp = store.reply(&q);
        assert_eq!(resp[3] & 0x0F, 0);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);
    }

    #[test]
    fn fakeip_idempotent_same_domain() {
        let store = new_store_v4();
        let q = make_fakeip_query("same.example.com", 1);
        let r1 = store.reply(&q);
        let r2 = store.reply(&q);
        assert_eq!(&r1[r1.len() - 4..], &r2[r2.len() - 4..]);
    }

    #[test]
    fn fakeip_different_domains_get_different_ips() {
        let store = new_store_v4();
        let r1 = store.reply(&make_fakeip_query("a.com", 1));
        let r2 = store.reply(&make_fakeip_query("b.com", 1));
        assert_ne!(&r1[r1.len() - 4..], &r2[r2.len() - 4..]);
    }

    #[test]
    fn fakeip_reverse_lookup() {
        let store = new_store_v4();
        let resp = store.reply(&make_fakeip_query("lookup.example.com", 1));
        let ip_bytes: [u8; 4] = resp[resp.len() - 4..].try_into().unwrap();
        let ip = std::net::IpAddr::V4(Ipv4Addr::from(ip_bytes));
        assert!(store.contains(ip));
        assert_eq!(store.lookup(ip).as_deref(), Some("lookup.example.com"));
    }

    #[test]
    fn fakeip_non_ip_query_returns_noerror_empty() {
        let store = new_store_v4();
        let resp = store.reply(&make_fakeip_query("txt.example.com", 16));
        assert_eq!(resp[3] & 0x0F, 0);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0);
    }

    #[test]
    fn fakeip_aaaa_no_inet6() {
        let store = new_store_v4();
        let resp = store.reply(&make_fakeip_query("v6.example.com", 28));
        assert_eq!(resp[3] & 0x0F, 0);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0);
    }

    #[test]
    fn fakeip_ipv6_allocation() {
        let store = FakeIpStore::new(&FakeIpConfig {
            inet4_range: None,
            inet6_range: Some("fc00::/18".into()),
            exclude_domain: vec![],
            exclude_domain_suffix: vec![],
        })
        .unwrap();
        let resp = store.reply(&make_fakeip_query("v6only.example.com", 28));
        assert_eq!(resp[3] & 0x0F, 0);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);
        let ip_bytes: [u8; 16] = resp[resp.len() - 16..].try_into().unwrap();
        let ip = std::net::IpAddr::V6(Ipv6Addr::from(ip_bytes));
        assert!(store.contains(ip));
        assert_eq!(store.lookup(ip).as_deref(), Some("v6only.example.com"));
    }

    #[test]
    fn fakeip_missing_config_errors() {
        assert!(FakeIpStore::new(&FakeIpConfig {
            inet4_range: None,
            inet6_range: None,
            exclude_domain: vec![],
            exclude_domain_suffix: vec![],
        })
        .is_err());
    }

    #[test]
    fn fakeip_cidr_parse_v4() {
        let (start, end) = parse_ipv4_cidr("198.18.0.0/15").unwrap();
        assert_eq!(start, Ipv4Addr::new(198, 18, 0, 0));
        assert_eq!(end, Ipv4Addr::new(198, 19, 255, 255));
    }

    #[test]
    fn fakeip_cidr_parse_v6() {
        let (start, _) = parse_ipv6_cidr("fc00::/18").unwrap();
        assert_eq!(start, "fc00::".parse::<Ipv6Addr>().unwrap());
    }
}
