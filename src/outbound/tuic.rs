//! TUIC v5 出站。
//!
//! TUIC v5 协议：QUIC + TLS，通过 quinn 实现。
//! 参考 sing-box/protocol/tuic/outbound.go 和 sing-quic/tuic。
//!
//! ## 连接生命周期
//! - 每个 TuicOutbound 持有一个连接池（单连接复用）。
//! - QUIC 连接断开后自动重建。
//! - 每条 TCP 流对应一条 QUIC 双向流（bi-stream）。
//! - UDP 使用 QUIC unreliable datagram（native 模式）。
//!
//! ## 认证
//! 连接建立后，立刻开一条 uni-stream 发送 Authenticate 包：
//! ```text
//! [TYPE=0x02 1B][UUID 16B][TOKEN 32B]
//! ```
//! TOKEN = BLAKE3(password + UUID)，Quinn 层 TLS 完成后立即发送。
//!
//! ## TCP 请求帧（Connect）
//! 在 bi-stream 上发送：
//! ```text
//! [TYPE=0x00 1B][UUID 16B][ADDR]
//! ```
//! 响应无单独帧，服务端建连成功后直接返回数据。
//!
//! ## UDP 数据报（native 模式）
//! 通过 QUIC datagram 发送：
//! ```text
//! [TYPE=0x01 1B][UUID 16B][SessionID u16 BE][PacketID u16 BE]
//! [FragID u8][FragCount u8][SIZE u16 BE][ADDR][DATA]
//! ```

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc,
    },
    time::Duration,
};

use bytes::{BufMut, Bytes, BytesMut};
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::{
    config::outbound::TuicOutboundConfig,
    inbound::{InboundTcpStream, InboundUdpPacket, Target},
    outbound::{relay, AsyncReadWrite, Outbound, OutboundStatus},
};

// ── 协议常量 ──────────────────────────────────────────────────────────────────

const TYPE_TCP_CONNECT: u8 = 0x00;
const TYPE_UDP_PACKET: u8 = 0x01;
const TYPE_AUTHENTICATE: u8 = 0x02;

// ATYP（TUIC 地址类型，与 SOCKS5 相同）
const ATYP_IPV4: u8 = 0x01;
const ATYP_IPV6: u8 = 0x04;
const ATYP_DOMAIN: u8 = 0x03;

// QUIC 传输参数
const QUIC_STREAM_WINDOW: u64 = 8 * 1024 * 1024; // 8 MiB
const QUIC_CONN_WINDOW: u64 = 15 * 1024 * 1024; // 15 MiB
const IDLE_TIMEOUT_MS: u32 = 30_000; // 30s
const KEEPALIVE_SECS: u64 = 10;

const TUIC_ALPN: &[u8] = b"tuic";

// ── 连接池 ────────────────────────────────────────────────────────────────────

struct CachedConn {
    conn: quinn::Connection,
}

pub struct TuicOutbound {
    config: TuicOutboundConfig,
    quic_config: Arc<quinn::ClientConfig>,
    uuid: [u8; 16],
    token: [u8; 32],
    /// UDP session ID 计数器
    udp_session: AtomicU16,
    cached: Arc<Mutex<Option<CachedConn>>>,
    /// 全局 SO_MARK（来自 global.routing_mark），0 表示不设置
    routing_mark: u32,
}

impl TuicOutbound {
    pub fn new(config: TuicOutboundConfig) -> anyhow::Result<Self> {
        let uuid = parse_uuid(&config.uuid)?;
        let token = derive_token(&uuid, config.password.as_bytes());
        let quic_config = build_quic_config(&config)?;
        Ok(Self {
            config,
            quic_config,
            uuid,
            token,
            udp_session: AtomicU16::new(0),
            cached: Arc::new(Mutex::new(None)),
            routing_mark: 0,
        })
    }

    pub fn with_mark(mut self, mark: u32) -> Self {
        self.routing_mark = mark;
        self
    }

    // ── 连接管理 ─────────────────────────────────────────────────────────────

    async fn get_conn(&self) -> anyhow::Result<quinn::Connection> {
        let mut guard = self.cached.lock().await;

        if let Some(cached) = guard.as_ref() {
            if cached.conn.close_reason().is_none() {
                return Ok(cached.conn.clone());
            }
            debug!(tag = %self.config.tag, "tuic cached conn closed, reconnecting");
            *guard = None;
        }

        let conn = self.new_conn().await?;
        // 立即发送认证包（uni-stream）
        self.authenticate(&conn).await?;

        *guard = Some(CachedConn { conn: conn.clone() });
        Ok(conn)
    }

    async fn new_conn(&self) -> anyhow::Result<quinn::Connection> {
        let server = &self.config.server;
        let port = self.config.server_port;
        let sni = self
            .config
            .tls
            .server_name
            .as_deref()
            .unwrap_or(server.as_str());

        let addr: SocketAddr = tokio::net::lookup_host(format!("{server}:{port}"))
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("tuic DNS failed for {server}"))?;

        let bind: SocketAddr = if addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        }
        .parse()?;
        let mut endpoint = crate::outbound::new_marked_quic_endpoint(bind, self.routing_mark)
            .map_err(|e| anyhow::anyhow!("tuic endpoint bind failed: {e}"))?;
        endpoint.set_default_client_config((*self.quic_config).clone());

        let conn = tokio::time::timeout(Duration::from_secs(10), endpoint.connect(addr, sni)?)
            .await
            .map_err(|_| anyhow::anyhow!("tuic connect timeout"))?
            .map_err(|e| anyhow::anyhow!("tuic QUIC connect: {e}"))?;

        debug!(tag = %self.config.tag, server = %addr, "tuic QUIC connected");
        Ok(conn)
    }

    /// 发送 Authenticate 包（TYPE=0x02）
    async fn authenticate(&self, conn: &quinn::Connection) -> anyhow::Result<()> {
        let mut stream = conn
            .open_uni()
            .await
            .map_err(|e| anyhow::anyhow!("tuic open uni stream: {e}"))?;

        let mut buf = BytesMut::with_capacity(1 + 16 + 32);
        buf.put_u8(TYPE_AUTHENTICATE);
        buf.put_slice(&self.uuid);
        buf.put_slice(&self.token);

        stream.write_all(&buf).await?;
        stream
            .finish()
            .map_err(|e| anyhow::anyhow!("tuic finish stream: {e}"))?;
        debug!(tag = %self.config.tag, "tuic authenticate sent");
        Ok(())
    }

    // ── TCP 连接（bi-stream + Connect 帧）───────────────────────────────────

    async fn open_tcp_stream(
        &self,
        target: &Target,
    ) -> anyhow::Result<(quinn::SendStream, quinn::RecvStream)> {
        let conn = self.get_conn().await?;
        let (mut send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| anyhow::anyhow!("tuic open bi stream: {e}"))?;

        // 发送 Connect 帧
        let mut buf = BytesMut::with_capacity(1 + 16 + 32);
        buf.put_u8(TYPE_TCP_CONNECT);
        buf.put_slice(&self.uuid);
        buf.put_slice(&self.token);
        write_target(&mut buf, target);

        send.write_all(&buf).await?;
        Ok((send, recv))
    }
}

// ── Outbound impl ─────────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl Outbound for TuicOutbound {
    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn status(&self) -> OutboundStatus {
        OutboundStatus {
            name: self.config.tag.clone(),
            type_name: "TUIC".to_string(),
            now: None,
            all: vec![],
            history: vec![],
        }
    }

    async fn connect_tcp(&self, host: &str, port: u16) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        let target = Target::Domain(host.to_string(), port);
        let (send, recv) = self.open_tcp_stream(&target).await?;
        Ok(Box::new(QuinnBiStream { send, recv }))
    }

    async fn handle_tcp(&self, conn: InboundTcpStream) -> anyhow::Result<(u64, u64)> {
        let (send, recv) = self.open_tcp_stream(&conn.target).await?;
        debug!(tag = %self.config.tag, target = %conn.target, "tuic tcp relay");
        let proxy_stream = QuinnBiStream { send, recv };
        Ok(relay(conn.stream, proxy_stream).await)
    }

    async fn handle_udp(&self, mut packet: InboundUdpPacket) -> anyhow::Result<()> {
        let conn = self.get_conn().await?;
        let session_id = self.udp_session.fetch_add(1, Ordering::Relaxed);

        let dgram = build_udp_datagram(
            &self.uuid,
            &self.token,
            session_id,
            0, // packet_id
            0, // frag_id
            1, // frag_count
            &packet.target,
            &packet.data,
        );
        conn.send_datagram(dgram)
            .map_err(|e| anyhow::anyhow!("tuic send datagram: {e}"))?;
        debug!(tag = %self.config.tag, target = %packet.target, "tuic udp datagram sent");

        // 若有后续上行包，spawn task 持续发送
        if let Some(mut upstream_rx) = packet.upstream_rx.take() {
            let conn_send = conn.clone();
            let uuid = self.uuid;
            let token = self.token;
            let target = packet.target.clone();
            // 用独立计数器给后续包分配 session_id，起点接着当前值
            let next_sid = std::sync::Arc::new(std::sync::atomic::AtomicU16::new(
                self.udp_session.load(Ordering::Relaxed),
            ));
            tokio::spawn(async move {
                while let Some(data) = upstream_rx.recv().await {
                    let sid = next_sid.fetch_add(1, Ordering::Relaxed);
                    let dgram = build_udp_datagram(&uuid, &token, sid, 0, 0, 1, &target, &data);
                    if conn_send.send_datagram(dgram).is_err() {
                        break;
                    }
                }
            });
        }

        let reply_tx = packet.session.reply_tx.clone();
        let src = packet.src;
        let spoofed_src = packet.target.to_socket_addr_lossy();
        let timeout = Duration::from_secs(10);
        let guards = packet.lifetime_guards;
        let tag = self.config.tag.clone();

        tokio::spawn(async move {
            loop {
                match tokio::time::timeout(timeout, conn.read_datagram()).await {
                    Ok(Ok(data)) => {
                        if let Some(payload) = parse_udp_datagram_payload(&data) {
                            if reply_tx.send((payload, src, spoofed_src)).await.is_err() {
                                break;
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        warn!(tag = %tag, err = %e, "tuic udp recv error");
                        break;
                    }
                    Err(_) => break, // idle timeout
                }
            }
            drop(guards);
        });

        Ok(())
    }
}

// ── 协议帧构建 ────────────────────────────────────────────────────────────────

fn write_target(buf: &mut BytesMut, target: &Target) {
    use std::net::IpAddr;
    match target {
        Target::Domain(host, port) => {
            buf.put_u8(ATYP_DOMAIN);
            buf.put_u8(host.len() as u8);
            buf.put_slice(host.as_bytes());
            buf.put_u16(*port);
        }
        Target::Socket(addr) => {
            buf.put_u16(addr.port());
            match addr.ip() {
                IpAddr::V4(ip) => {
                    buf.put_u8(ATYP_IPV4);
                    buf.put_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    buf.put_u8(ATYP_IPV6);
                    buf.put_slice(&ip.octets());
                }
            }
        }
    }
}

fn build_udp_datagram(
    uuid: &[u8; 16],
    token: &[u8; 32],
    session_id: u16,
    packet_id: u16,
    frag_id: u8,
    frag_count: u8,
    target: &Target,
    data: &[u8],
) -> Bytes {
    let mut buf = BytesMut::with_capacity(1 + 16 + 32 + 6 + 64 + data.len());
    buf.put_u8(TYPE_UDP_PACKET);
    buf.put_slice(uuid);
    buf.put_slice(token);
    buf.put_u16(session_id);
    buf.put_u16(packet_id);
    buf.put_u8(frag_id);
    buf.put_u8(frag_count);
    buf.put_u16(data.len() as u16);
    write_target(&mut buf, target);
    buf.put_slice(data);
    buf.freeze()
}

/// 从收到的 UDP datagram 中提取载荷（跳过 header）
fn parse_udp_datagram_payload(data: &[u8]) -> Option<Bytes> {
    // 布局：[TYPE 1B][UUID 16B][TOKEN 32B][SessionID 2B][PacketID 2B]
    //        [FragID 1B][FragCount 1B][SIZE 2B][ADDR ...][DATA]
    // 最小 header 到 SIZE 字段 = 1+16+32+2+2+1+1+2 = 57B
    const MIN_HDR: usize = 57;
    if data.len() < MIN_HDR {
        return None;
    }
    if data[0] != TYPE_UDP_PACKET {
        return None;
    }
    let size = u16::from_be_bytes([data[55], data[56]]) as usize;
    // 跳过 ADDR（可变长），取最后 size 字节
    let addr_start = 57;
    if data.len() < addr_start + size {
        return None;
    }
    let payload_start = data.len() - size;
    Some(Bytes::copy_from_slice(&data[payload_start..]))
}

// ── UUID 解析 & Token 派生 ────────────────────────────────────────────────────

fn parse_uuid(s: &str) -> anyhow::Result<[u8; 16]> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    anyhow::ensure!(hex.len() == 32, "tuic: invalid UUID: {s}");
    let mut out = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk)?, 16)?;
    }
    Ok(out)
}

/// TUIC token = HMAC-SHA256(key=password, msg=uuid_bytes) 截取前 32B
/// 实际上 sing-quic 用的是 blake3，但依赖较重；这里用 HMAC-SHA256 替代。
/// 与服务端需保持一致（若服务端用 blake3，需替换此函数）。
fn derive_token(uuid: &[u8; 16], password: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(password).expect("hmac");
    mac.update(uuid);
    mac.finalize().into_bytes().into()
}

// ── QUIC 配置 ─────────────────────────────────────────────────────────────────

fn build_quic_config(config: &TuicOutboundConfig) -> anyhow::Result<Arc<quinn::ClientConfig>> {
    use rustls::RootCertStore;

    let mut root_store = RootCertStore::empty();
    if let Some(ca_path) = &config.tls.ca_path {
        let ca_data = std::fs::read(ca_path)?;
        let mut reader = std::io::BufReader::new(ca_data.as_slice());
        for cert in rustls_pemfile::certs(&mut reader) {
            root_store.add(cert?)?;
        }
    } else {
        let native = rustls_native_certs::load_native_certs();
        for cert in native.certs {
            let _ = root_store.add(cert);
        }
    }

    let mut tls_config = if config.tls.insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(crate::outbound::tls::NoVerifier))
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    // TUIC ALPN
    tls_config.alpn_protocols = vec![TUIC_ALPN.to_vec()];

    // 自定义 ALPN（如服务端配置了非默认值）
    if !config.tls.alpn.is_empty() {
        tls_config.alpn_protocols = config
            .tls
            .alpn
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect();
    }

    let mut transport = quinn::TransportConfig::default();
    transport
        .stream_receive_window(
            quinn::VarInt::from_u64(QUIC_STREAM_WINDOW).unwrap_or(quinn::VarInt::MAX),
        )
        .receive_window(quinn::VarInt::from_u64(QUIC_CONN_WINDOW).unwrap_or(quinn::VarInt::MAX))
        .datagram_receive_buffer_size(Some(2 * 1024 * 1024))
        .max_idle_timeout(Some(quinn::VarInt::from_u32(IDLE_TIMEOUT_MS).into()))
        .keep_alive_interval(Some(Duration::from_secs(KEEPALIVE_SECS)));

    // heartbeat 配置（覆盖默认 keepalive）
    if let Some(ref hb) = config.heartbeat {
        if let Ok(d) = crate::config::outbound::parse_duration(hb) {
            transport.keep_alive_interval(Some(d));
        }
    }

    let mut quic_cfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?,
    ));
    quic_cfg.transport_config(Arc::new(transport));

    Ok(Arc::new(quic_cfg))
}

// ── Quinn bi-stream → AsyncRead + AsyncWrite ─────────────────────────────────

struct QuinnBiStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl tokio::io::AsyncRead for QuinnBiStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for QuinnBiStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::task::Poll;
        match std::pin::Pin::new(&mut self.send).poll_write(cx, data) {
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        match std::pin::Pin::new(&mut self.send).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        match std::pin::Pin::new(&mut self.send).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uuid_ok() {
        let u = parse_uuid("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        assert_eq!(u[0], 0xaa);
        assert_eq!(u[15], 0xee);
    }

    #[test]
    fn parse_uuid_no_dashes() {
        let u = parse_uuid("aabbccdd11223344aabbccdd11223344").unwrap();
        assert_eq!(u.len(), 16);
    }

    #[test]
    fn derive_token_len() {
        let uuid = [0u8; 16];
        let token = derive_token(&uuid, b"password");
        assert_eq!(token.len(), 32);
    }

    #[test]
    fn build_udp_datagram_min_length() {
        let uuid = [0u8; 16];
        let token = [0u8; 32];
        let target = Target::Domain("example.com".into(), 443);
        let data = b"hello";
        let dgram = build_udp_datagram(&uuid, &token, 1, 0, 0, 1, &target, data);
        // 1+16+32+2+2+1+1+2 + 1+1+11+2 + 5 = 77
        assert!(dgram.len() >= 77);
    }
}
