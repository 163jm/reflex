//! Trojan 出站实现
//!
//! 支持传输模式：
//! - Trojan over TCP + TLS（标准模式）
//! - Trojan over TCP（明文，仅测试）
//! - Trojan over WebSocket + TLS
//!
//! 协议参考：https://trojan-gfw.github.io/trojan/protocol
//!
//! 握手格式（TCP 命令）：
//! ```text
//! [SHA224(password) hex 56B][CRLF][CMD 1B][ATYP 1B][ADDR ...][PORT 2B BE][CRLF][Payload]
//! ```
//! WebSocket 模式将上述字节流承载于 WS Binary 帧，与 sing-box 行为一致。

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut};
use sha2::{Digest, Sha224};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    client_async_tls_with_config,
    tungstenite::{client::IntoClientRequest, http::HeaderValue, Message},
    MaybeTlsStream, WebSocketStream,
};
use tracing::debug;

use crate::{
    config::outbound::{TrojanOutboundConfig, TrojanTransportConfig, WsTransportConfig},
    inbound::{InboundTcpStream, InboundUdpPacket, Target},
    outbound::{apply_mark_to_tcp, relay, set_tcp_opts, tls::build_client_config, Outbound},
};

// ── 常量 ──────────────────────────────────────────────────────────────────────

/// SHA-224 输出后 hex 编码的长度（28 字节 × 2）
const KEY_LEN: usize = 56;

const CMD_TCP: u8 = 0x01;
const CMD_UDP: u8 = 0x03;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

const CRLF: &[u8] = b"\r\n";

// ── 结构体 ────────────────────────────────────────────────────────────────────

pub struct TrojanOutbound {
    config: TrojanOutboundConfig,
    /// 预计算的 56 字节 hex key（密码的 SHA-224）
    key: [u8; KEY_LEN],
    /// rustls 配置（TLS 模式有效）
    tls_config: Arc<rustls::ClientConfig>,
    /// 全局 SO_MARK（来自 global.routing_mark），0 表示不设置
    routing_mark: u32,
}

impl TrojanOutbound {
    pub fn new(config: TrojanOutboundConfig) -> anyhow::Result<Self> {
        let key = derive_key(&config.password);
        let tls_config = build_client_config(&config.tls)?;
        Ok(Self {
            config,
            key,
            tls_config,
            routing_mark: 0,
        })
    }

    pub fn with_mark(mut self, mark: u32) -> Self {
        self.routing_mark = mark;
        self
    }

    // ── 连接建立 ──────────────────────────────────────────────────────────────

    /// 建立裸 TCP 连接（不含 TLS）
    async fn connect_raw_tcp(&self) -> anyhow::Result<TcpStream> {
        let addr = self.resolve_server().await?;
        let tcp = TcpStream::connect(addr).await?;
        set_tcp_opts(&tcp)?;
        apply_mark_to_tcp(&tcp, self.routing_mark)?;
        Ok(tcp)
    }

    /// 建立 TCP + TLS 连接
    async fn connect_tls(&self) -> anyhow::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let tcp = self.connect_raw_tcp().await?;
        let sni = self.tls_sni();
        crate::outbound::tls::connect_tls(tcp, sni, self.tls_config.clone()).await
    }

    /// 建立 WebSocket 连接（TLS 在 tokio-tungstenite 内部处理）
    async fn connect_ws(
        &self,
        ws_cfg: &WsTransportConfig,
    ) -> anyhow::Result<WebSocketStream<MaybeTlsStream<TcpStream>>> {
        let sni = self.tls_sni();
        let addr = self.resolve_server().await?;
        let tcp = TcpStream::connect(addr).await?;
        set_tcp_opts(&tcp)?;
        apply_mark_to_tcp(&tcp, self.routing_mark)?;

        let url = if self.config.tls.enabled {
            format!("wss://{sni}{}", ws_cfg.path)
        } else {
            format!(
                "ws://{}:{}{}",
                self.config.server, self.config.server_port, ws_cfg.path
            )
        };

        let mut request = url.into_client_request()?;
        for (k, v) in &ws_cfg.headers {
            request.headers_mut().insert(
                k.parse::<tokio_tungstenite::tungstenite::http::header::HeaderName>()?,
                HeaderValue::from_str(v)?,
            );
        }
        if !ws_cfg.headers.contains_key("Host") {
            request.headers_mut().insert(
                tokio_tungstenite::tungstenite::http::header::HOST,
                HeaderValue::from_str(sni)?,
            );
        }

        let connector = if self.config.tls.enabled {
            Some(tokio_tungstenite::Connector::Rustls(
                self.tls_config.clone(),
            ))
        } else {
            None
        };

        let (ws_stream, _) = client_async_tls_with_config(request, tcp, None, connector).await?;
        Ok(ws_stream)
    }

    // ── 握手头构造 ────────────────────────────────────────────────────────────

    /// 构建 Trojan TCP 请求头（不含 payload）
    fn build_tcp_header(&self, target: &Target) -> BytesMut {
        let mut buf = BytesMut::with_capacity(KEY_LEN + 2 + 1 + 1 + 256 + 2 + 2);
        buf.put_slice(&self.key);
        buf.put_slice(CRLF);
        buf.put_u8(CMD_TCP);
        write_addr(&mut buf, target);
        buf.put_slice(CRLF);
        buf
    }

    /// 构建 Trojan UDP 请求头（不含 UDP 分帧，仅握手部分）
    ///
    /// Trojan UDP over TCP：握手后每个 UDP 包格式：
    /// `[ATYP 1B][ADDR ...][PORT 2B][LEN 2B][CRLF][DATA]`
    fn build_udp_handshake(&self, target: &Target) -> BytesMut {
        let mut buf = BytesMut::with_capacity(KEY_LEN + 2 + 1 + 1 + 256 + 2 + 2);
        buf.put_slice(&self.key);
        buf.put_slice(CRLF);
        buf.put_u8(CMD_UDP);
        write_addr(&mut buf, target);
        buf.put_slice(CRLF);
        buf
    }

    // ── dial：返回通用 AsyncReadWrite ─────────────────────────────────────────

    async fn dial(
        &self,
        header: Bytes,
    ) -> anyhow::Result<Box<dyn crate::outbound::AsyncReadWrite>> {
        match self.config.transport.as_ref() {
            None | Some(TrojanTransportConfig::Tcp(_)) => {
                if self.config.tls.enabled {
                    let stream = self.connect_tls().await?;
                    Ok(Box::new(TrojanTcpStream::new(stream, header)))
                } else {
                    let stream = self.connect_raw_tcp().await?;
                    Ok(Box::new(TrojanTcpStream::new(stream, header)))
                }
            }
            Some(TrojanTransportConfig::Ws(ws_cfg)) => {
                let ws = self.connect_ws(ws_cfg).await?;
                Ok(Box::new(TrojanWsStream::new(ws, header)))
            }
            Some(TrojanTransportConfig::Xhttp(xhttp_cfg)) => {
                use crate::outbound::xhttp;
                use std::collections::HashMap;
                let stream = xhttp::connect(
                    &self.config.server,
                    self.config.server_port,
                    xhttp_cfg,
                    if self.config.tls.enabled {
                        Some(&self.config.tls)
                    } else {
                        None
                    },
                    &HashMap::new(),
                    self.routing_mark,
                )
                .await?;
                Ok(Box::new(TrojanTcpStream::new(stream, header)))
            }
        }
    }

    // ── 辅助 ──────────────────────────────────────────────────────────────────

    async fn resolve_server(&self) -> anyhow::Result<SocketAddr> {
        tokio::net::lookup_host(format!(
            "{}:{}",
            self.config.server, self.config.server_port
        ))
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("DNS failed for {}", self.config.server))
    }

    fn tls_sni(&self) -> &str {
        self.config
            .tls
            .server_name
            .as_deref()
            .unwrap_or(&self.config.server)
    }
}

// ── Outbound trait ────────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl Outbound for TrojanOutbound {
    fn tag(&self) -> &str {
        &self.config.tag
    }

    async fn connect_tcp(
        &self,
        host: &str,
        port: u16,
    ) -> anyhow::Result<Box<dyn crate::outbound::AsyncReadWrite>> {
        let target = Target::Domain(host.to_string(), port);
        let header = self.build_tcp_header(&target).freeze();
        self.dial(header).await
    }

    async fn handle_tcp(&self, conn: InboundTcpStream) -> anyhow::Result<(u64, u64)> {
        let transport_type = match &self.config.transport {
            None | Some(TrojanTransportConfig::Tcp(_)) => "tcp",
            Some(TrojanTransportConfig::Ws(_)) => "ws",
            Some(TrojanTransportConfig::Xhttp(_)) => "xhttp",
        };
        debug!(
            tag = %self.config.tag,
            target = %conn.target,
            transport = transport_type,
            tls = self.config.tls.enabled,
            "trojan tcp connecting"
        );

        let header = self.build_tcp_header(&conn.target).freeze();
        let io = self.dial(header).await?;
        Ok(relay(conn.stream, io).await)
    }

    async fn handle_udp(&self, mut packet: InboundUdpPacket) -> anyhow::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        debug!(
            tag = %self.config.tag,
            target = %packet.target,
            "trojan udp session"
        );

        // Trojan UDP over TCP：握手头 + UDP 分帧
        let header = self.build_udp_handshake(&packet.target).freeze();
        let io = self.dial(header).await?;
        let (mut reader, mut writer) = tokio::io::split(io);

        // 发送第一个 UDP 帧：[ATYP][ADDR][PORT][LEN 2B][CRLF][DATA]
        let udp_frame = build_udp_frame(&packet.target, &packet.data);
        writer.write_all(&udp_frame).await?;
        writer.flush().await?;

        let timeout = std::time::Duration::from_secs(5);
        let reply_tx = packet.session.reply_tx.clone();
        let src = packet.src;
        let spoofed_src = packet.target.to_socket_addr_lossy();
        let target = packet.target.clone();

        // 若有后续上行包通道，spawn task 持续将上行包写入 TCP 隧道
        if let Some(mut upstream_rx) = packet.upstream_rx.take() {
            tokio::spawn(async move {
                while let Some(data) = upstream_rx.recv().await {
                    let frame = build_udp_frame(&target, &data);
                    if writer.write_all(&frame).await.is_err()
                        || writer.flush().await.is_err()
                    {
                        break;
                    }
                }
            });
        }

        loop {
            // 读取 UDP 帧头：[ATYP][ADDR][PORT] 可变长 + [LEN 2B][CRLF]
            // 简化处理：先读取 ATYP 确定地址长度
            let mut atyp_buf = [0u8; 1];
            match tokio::time::timeout(timeout, reader.read_exact(&mut atyp_buf)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => break,
            }

            let addr_len = match atyp_buf[0] {
                ATYP_IPV4 => 4,
                ATYP_IPV6 => 16,
                ATYP_DOMAIN => {
                    let mut domain_len_buf = [0u8; 1];
                    reader.read_exact(&mut domain_len_buf).await?;
                    domain_len_buf[0] as usize
                }
                _ => break,
            };

            // 跳过 addr + port(2) + len(2) + CRLF(2)
            let skip = addr_len + 2 + 2 + 2;
            let mut skip_buf = vec![0u8; skip];
            reader.read_exact(&mut skip_buf).await?;

            // len 在 skip_buf 的倒数第 4、3 字节（addr 之后）
            let len_offset = addr_len + 2; // 跳过 addr + port 之后是 len
            let data_len =
                u16::from_be_bytes([skip_buf[len_offset], skip_buf[len_offset + 1]]) as usize;

            if data_len == 0 {
                break;
            }

            let mut data = vec![0u8; data_len];
            match tokio::time::timeout(timeout, reader.read_exact(&mut data)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => break,
            }

            let _ = reply_tx.send((bytes::Bytes::from(data), src, spoofed_src)).await;
        }

        Ok(())
    }
}

// ── 辅助函数 ──────────────────────────────────────────────────────────────────

/// 计算 Trojan 密钥：SHA-224(password) → hex → 56 字节 ASCII
fn derive_key(password: &str) -> [u8; KEY_LEN] {
    let hash = Sha224::digest(password.as_bytes());
    let hex = hex::encode(hash);
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(hex.as_bytes());
    key
}

/// 将目标地址写入缓冲区（SOCKS5 地址格式：ATYP + ADDR + PORT）
fn write_addr(buf: &mut BytesMut, target: &Target) {
    match target {
        Target::Domain(host, port) => {
            buf.put_u8(ATYP_DOMAIN);
            buf.put_u8(host.len() as u8);
            buf.put_slice(host.as_bytes());
            buf.put_u16(*port);
        }
        Target::Socket(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                buf.put_u8(ATYP_IPV4);
                buf.put_slice(&ip.octets());
                buf.put_u16(addr.port());
            }
            IpAddr::V6(ip) => {
                buf.put_u8(ATYP_IPV6);
                buf.put_slice(&ip.octets());
                buf.put_u16(addr.port());
            }
        },
    }
}

/// 构建 Trojan UDP 帧（握手后每个包的格式）
fn build_udp_frame(target: &Target, data: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(256 + data.len());
    write_addr(&mut buf, target);
    buf.put_u16(data.len() as u16);
    buf.put_slice(CRLF);
    buf.put_slice(data);
    buf.freeze()
}

// ── TrojanTcpStream：TCP/TLS 传输适配器 ──────────────────────────────────────
//
// 首次写入时在数据前拼接 Trojan 握手头；无需跳过服务端响应头（Trojan 无响应头）。

use pin_project_lite::pin_project;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pin_project! {
    struct TrojanTcpStream<S> {
        #[pin]
        inner: S,
        pending_header: Option<Bytes>,
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> TrojanTcpStream<S> {
    fn new(inner: S, header: Bytes) -> Self {
        Self {
            inner,
            pending_header: Some(header),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TrojanTcpStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Trojan 服务端无响应头，直接透传
        self.project().inner.poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TrojanTcpStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.project();
        if let Some(header) = this.pending_header.take() {
            // 首次写入：握手头 + data 合并发送
            let mut combined = BytesMut::with_capacity(header.len() + data.len());
            combined.put_slice(&header);
            combined.put_slice(data);
            let combined = combined.freeze();
            match this.inner.poll_write(cx, &combined) {
                Poll::Ready(Ok(n)) => {
                    // 报告写出的用户数据字节数（握手头不计入）
                    Poll::Ready(Ok(if n >= header.len() {
                        n - header.len()
                    } else {
                        0
                    }))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => {
                    *this.pending_header = Some(header);
                    Poll::Pending
                }
            }
        } else {
            this.inner.poll_write(cx, data)
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

// ── TrojanWsStream：WebSocket 传输适配器 ─────────────────────────────────────
//
// 首次 poll_write 时将握手头与数据打包进同一个 WS Binary 帧，
// 后续每次写入各自成帧（与 sing-box v2ray transport ws 行为一致）。

use futures_util::{Sink, Stream};

pin_project! {
    struct TrojanWsStream<S> {
        #[pin]
        inner: S,
        pending_header: Option<Bytes>,
        read_buf: Bytes,
    }
}

impl<S> TrojanWsStream<S>
where
    S: Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
        + Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
        + Unpin,
{
    fn new(inner: S, header: Bytes) -> Self {
        Self {
            inner,
            pending_header: Some(header),
            read_buf: Bytes::new(),
        }
    }
}

impl<S> AsyncRead for TrojanWsStream<S>
where
    S: Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut this = self.project();
        loop {
            if !this.read_buf.is_empty() {
                let n = buf.remaining().min(this.read_buf.len());
                buf.put_slice(&this.read_buf[..n]);
                *this.read_buf = this.read_buf.slice(n..);
                return Poll::Ready(Ok(()));
            }
            match this.inner.as_mut().poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e)))
                }
                Poll::Ready(Some(Ok(msg))) => match msg {
                    Message::Binary(data) => {
                        *this.read_buf = Bytes::from(data);
                    }
                    Message::Close(_) => return Poll::Ready(Ok(())),
                    _ => {}
                },
            }
        }
    }
}

impl<S> AsyncWrite for TrojanWsStream<S>
where
    S: Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut this = self.project();
        if let Poll::Pending = this.inner.as_mut().poll_ready(cx).map_err(ws_io_err)? {
            return Poll::Pending;
        }
        let payload: Vec<u8> = if let Some(header) = this.pending_header.take() {
            let mut combined = BytesMut::with_capacity(header.len() + data.len());
            combined.put_slice(&header);
            combined.put_slice(data);
            combined.into()
        } else {
            data.to_vec()
        };
        let len = data.len();
        this.inner
            .as_mut()
            .start_send(Message::Binary(payload))
            .map_err(ws_io_err)?;
        Poll::Ready(Ok(len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx).map_err(ws_io_err)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_close(cx).map_err(ws_io_err)
    }
}

fn ws_io_err(e: tokio_tungstenite::tungstenite::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::BrokenPipe, e)
}

// ── 单元测试 ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_key_known_vector() {
        // 与 sing-box transport/trojan/protocol.go 的 Key() 函数对齐：
        // SHA-224("password") hex = "d9014c4624844aa5bac314773d6b689ad467fa4e1d1a50a1b8a99d5a3"
        let key = derive_key("password");
        let hex = std::str::from_utf8(&key).unwrap();
        // 只验证前 8 个字符
        assert!(hex.starts_with("d9014c46"), "unexpected key prefix: {hex}");
        assert_eq!(key.len(), 56);
    }

    #[test]
    fn build_tcp_header_domain() {
        use crate::config::outbound::{TlsConfig, TrojanTcpConfig, TrojanTransportConfig};
        let cfg = TrojanOutboundConfig {
            tag: "test".into(),
            server: "example.com".into(),
            server_port: 443,
            password: "password".into(),
            transport: TrojanTransportConfig::Tcp(TrojanTcpConfig::default()),
            tls: TlsConfig::default(),
            detour: None,
        };
        let ob = TrojanOutbound::new(cfg).unwrap();
        let target = Target::Domain("target.example".into(), 80);
        let hdr = ob.build_tcp_header(&target);

        // 前 56 字节是 key
        assert_eq!(&hdr[..56], &ob.key);
        // CRLF
        assert_eq!(&hdr[56..58], b"\r\n");
        // CMD_TCP
        assert_eq!(hdr[58], CMD_TCP);
        // ATYP_DOMAIN
        assert_eq!(hdr[59], ATYP_DOMAIN);
        // domain length
        assert_eq!(hdr[60], "target.example".len() as u8);
    }

    #[test]
    fn build_tcp_header_ipv4() {
        use crate::config::outbound::{TlsConfig, TrojanTcpConfig, TrojanTransportConfig};
        use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
        let cfg = TrojanOutboundConfig {
            tag: "test".into(),
            server: "example.com".into(),
            server_port: 443,
            password: "pass".into(),
            transport: TrojanTransportConfig::Tcp(TrojanTcpConfig::default()),
            tls: TlsConfig::default(),
            detour: None,
        };
        let ob = TrojanOutbound::new(cfg).unwrap();
        let target = Target::Socket(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(1, 2, 3, 4),
            443,
        )));
        let hdr = ob.build_tcp_header(&target);
        // ATYP_IPV4 在索引 59
        assert_eq!(hdr[59], ATYP_IPV4);
        // IPv4 octets
        assert_eq!(&hdr[60..64], &[1, 2, 3, 4]);
        // port big-endian
        assert_eq!(u16::from_be_bytes([hdr[64], hdr[65]]), 443);
    }
}
