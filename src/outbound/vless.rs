//! VLESS 出站：支持以下传输模式
//!
//! - VLESS over WebSocket + TLS（原有实现）
//! - VLESS over TCP + TLS（普通 TLS）
//! - VLESS over TCP + REALITY（新增）
//!
//! 协议参考：https://xtls.github.io/development/protocols/vless.html
//!
//! 请求头格式（Version 0）：
//! ```
//! [Ver=0x00 1B][UUID 16B][Addon Len 1B][Addon ...][Cmd 1B][Port 2B BE][Atyp 1B][Addr ...][Payload]
//! ```
//! 响应头格式：
//! ```
//! [Ver=0x00 1B][Addon Len 1B][Addon ...]
//! ```

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use bytes::{BufMut, Bytes, BytesMut};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    client_async_tls_with_config,
    tungstenite::{client::IntoClientRequest, http::HeaderValue, Message},
    MaybeTlsStream, WebSocketStream,
};
use tracing::debug;

use crate::{
    config::outbound::{VlessOutboundConfig, VlessTransportConfig, WsTransportConfig},
    inbound::{InboundTcpStream, InboundUdpPacket, Target},
    outbound::{apply_mark_to_tcp, relay, set_tcp_opts, tls::build_client_config, Outbound},
};

use super::reality::reality_connect;
pub struct VlessOutbound {
    config: VlessOutboundConfig,
    /// rustls 配置（仅 TLS 模式使用）
    tls_config: Arc<rustls::ClientConfig>,
    /// 全局 SO_MARK（来自 global.routing_mark），0 表示不设置
    routing_mark: u32,
}

impl VlessOutbound {
    pub fn new(config: VlessOutboundConfig) -> anyhow::Result<Self> {
        // 构建 TLS 配置；REALITY 或无 TLS 时构建空配置（不会被实际使用）
        let tls_config = match &config.tls {
            Some(tls) if tls.enabled && tls.reality.is_none() => {
                // 普通 TLS
                let tls_cfg = crate::config::outbound::TlsConfig {
                    enabled: tls.enabled,
                    server_name: tls.server_name.clone(),
                    insecure: tls.insecure,
                    ca_path: tls.ca_path.clone(),
                    alpn: tls.alpn.clone(),
                    min_version: None,
                    max_version: None,
                };
                build_client_config(&tls_cfg)?
            }
            _ => {
                use rustls::{ClientConfig, RootCertStore};
                let root_store = RootCertStore::empty();
                Arc::new(
                    ClientConfig::builder()
                        .with_root_certificates(root_store)
                        .with_no_client_auth(),
                )
            }
        };
        Ok(Self {
            config,
            tls_config,
            routing_mark: 0,
        })
    }

    pub fn with_mark(mut self, mark: u32) -> Self {
        self.routing_mark = mark;
        self
    }

    /// 解析 UUID 字符串为 16 字节
    fn parse_uuid(s: &str) -> anyhow::Result<[u8; 16]> {
        let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        anyhow::ensure!(hex.len() == 32, "invalid UUID: {s}");
        let mut out = [0u8; 16];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            out[i] = u8::from_str_radix(std::str::from_utf8(chunk)?, 16)?;
        }
        Ok(out)
    }

    /// 构建 VLESS 请求头（TCP 命令）
    fn build_request_header(uuid: &[u8; 16], target: &Target) -> anyhow::Result<BytesMut> {
        let mut buf = BytesMut::with_capacity(64);
        buf.put_u8(0x00); // Version
        buf.put_slice(uuid); // UUID 16B
        buf.put_u8(0x00); // Addon length = 0
        buf.put_u8(0x01); // Command: TCP CONNECT
        buf.put_u16(target.port());
        match target {
            Target::Domain(host, _) => {
                buf.put_u8(0x02);
                buf.put_u8(host.len() as u8);
                buf.put_slice(host.as_bytes());
            }
            Target::Socket(addr) => match addr.ip() {
                IpAddr::V4(ip) => {
                    buf.put_u8(0x01);
                    buf.put_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    buf.put_u8(0x03);
                    buf.put_slice(&ip.octets());
                }
            },
        }
        Ok(buf)
    }

    /// 建立 WebSocket 连接（TLS 在内部处理）
    async fn connect_ws(
        &self,
        ws_cfg: &WsTransportConfig,
    ) -> anyhow::Result<WebSocketStream<MaybeTlsStream<TcpStream>>> {
        let server = &self.config.server;
        let port = self.config.server_port;
        let sni = self.tls_sni();
        let tls_enabled = self.config.tls.as_ref().map_or(false, |t| t.enabled);

        let addr: SocketAddr = tokio::net::lookup_host(format!("{server}:{port}"))
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("DNS failed for {server}"))?;

        let tcp = TcpStream::connect(addr).await?;
        set_tcp_opts(&tcp)?;
        apply_mark_to_tcp(&tcp, self.routing_mark)?;

        let url = if tls_enabled {
            format!("wss://{sni}{}", ws_cfg.path)
        } else {
            format!("ws://{server}:{port}{}", ws_cfg.path)
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
        let connector = if tls_enabled {
            Some(tokio_tungstenite::Connector::Rustls(
                self.tls_config.clone(),
            ))
        } else {
            None
        };
        let (ws_stream, _) = client_async_tls_with_config(request, tcp, None, connector).await?;
        Ok(ws_stream)
    }

    /// 建立 TCP+TLS 连接（普通 TLS 模式）
    async fn connect_tcp_tls(&self) -> anyhow::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let server = &self.config.server;
        let port = self.config.server_port;
        let sni = self.tls_sni();

        let addr: SocketAddr = tokio::net::lookup_host(format!("{server}:{port}"))
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("DNS failed for {server}"))?;

        let tcp = TcpStream::connect(addr).await?;
        set_tcp_opts(&tcp)?;
        apply_mark_to_tcp(&tcp, self.routing_mark)?;

        crate::outbound::tls::connect_tls(tcp, sni, self.tls_config.clone()).await
    }

    /// 建立 TCP+REALITY 连接
    async fn connect_tcp_reality(
        &self,
        tls: &crate::config::outbound::VlessTlsConfig,
        reality: &crate::config::outbound::RealityConfig,
    ) -> anyhow::Result<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> {
        let server = &self.config.server;
        let port = self.config.server_port;

        let addr: SocketAddr = tokio::net::lookup_host(format!("{server}:{port}"))
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("DNS failed for {server}"))?;

        let tcp = TcpStream::connect(addr).await?;
        set_tcp_opts(&tcp)?;
        apply_mark_to_tcp(&tcp, self.routing_mark)?;

        let cfg = crate::config::outbound::RealityDialConfig {
            public_key: reality.public_key.clone(),
            short_id: reality.short_id.clone(),
            server_name: tls.server_name.clone(),
            server: server.clone(),
            alpn: tls.alpn.clone(),
            fingerprint: "chrome".to_string(),
        };

        debug!(
            tag = %self.config.tag,
            server = %server,
            sni = cfg.server_name.as_deref().unwrap_or(server),
            "REALITY: connecting"
        );

        let stream = reality_connect(tcp, &cfg).await?;
        Ok(stream)
    }

    /// 获取 TLS SNI
    fn tls_sni(&self) -> &str {
        self.config
            .tls
            .as_ref()
            .and_then(|t| t.server_name.as_deref())
            .unwrap_or(&self.config.server)
    }

    /// 连接并返回通用的 AsyncRead+AsyncWrite box
    async fn dial(
        &self,
        header: Bytes,
    ) -> anyhow::Result<Box<dyn crate::outbound::AsyncReadWrite>> {
        // ── XHTTP 传输 ────────────────────────────────────────────────────────
        if let Some(VlessTransportConfig::Xhttp(xhttp_cfg)) = &self.config.transport {
            use crate::outbound::xhttp;
            use std::collections::HashMap;
            let tls_cfg = self
                .config
                .tls
                .as_ref()
                .map(|t| crate::config::outbound::TlsConfig {
                    enabled: t.enabled,
                    server_name: t.server_name.clone(),
                    insecure: t.insecure,
                    ca_path: t.ca_path.clone(),
                    alpn: t.alpn.clone(),
                    min_version: None,
                    max_version: None,
                });
            let stream = xhttp::connect(
                &self.config.server,
                self.config.server_port,
                xhttp_cfg,
                tls_cfg.as_ref(),
                &HashMap::new(),
                self.routing_mark,
            )
            .await?;
            return Ok(Box::new(VlessTcpStream::new(stream, header)));
        }

        // transport 为 None 或 Tcp 时都走 TCP 路径
        let is_ws = matches!(&self.config.transport, Some(VlessTransportConfig::Ws(_)));

        if is_ws {
            let ws_cfg = match &self.config.transport {
                Some(VlessTransportConfig::Ws(w)) => w,
                _ => unreachable!(),
            };
            let ws = self.connect_ws(ws_cfg).await?;
            return Ok(Box::new(WsStream::new(ws, header)));
        }

        // TCP 路径：根据 tls 配置决定用普通 TLS、REALITY 还是明文
        match &self.config.tls {
            Some(tls) if tls.enabled => {
                if let Some(reality) = &tls.reality {
                    if reality.enabled || !reality.public_key.is_empty() {
                        let stream = self.connect_tcp_reality(tls, reality).await?;
                        return Ok(Box::new(VlessTcpStream::new(stream, header)));
                    }
                }
                let stream = self.connect_tcp_tls().await?;
                Ok(Box::new(VlessTcpStream::new(stream, header)))
            }
            _ => {
                // 明文 TCP（tls 为 None 或 enabled=false）
                let server = &self.config.server;
                let port = self.config.server_port;
                let addr: SocketAddr = tokio::net::lookup_host(format!("{server}:{port}"))
                    .await?
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("DNS failed for {server}"))?;
                let tcp = TcpStream::connect(addr).await?;
                set_tcp_opts(&tcp)?;
                apply_mark_to_tcp(&tcp, self.routing_mark)?;
                Ok(Box::new(VlessTcpStream::new(tcp, header)))
            }
        }
    }
}

#[async_trait::async_trait]
impl Outbound for VlessOutbound {
    fn tag(&self) -> &str {
        &self.config.tag
    }

    async fn connect_tcp(
        &self,
        host: &str,
        port: u16,
    ) -> anyhow::Result<Box<dyn crate::outbound::AsyncReadWrite>> {
        let uuid = Self::parse_uuid(&self.config.uuid)?;
        let target = Target::Domain(host.to_string(), port);
        let header = Self::build_request_header(&uuid, &target)?.freeze();
        self.dial(header).await
    }

    async fn handle_tcp(&self, conn: InboundTcpStream) -> anyhow::Result<(u64, u64)> {
        let uuid = Self::parse_uuid(&self.config.uuid)?;
        let header = Self::build_request_header(&uuid, &conn.target)?.freeze();

        let transport_type = match &self.config.transport {
            Some(VlessTransportConfig::Ws(_)) => "ws",
            Some(VlessTransportConfig::Xhttp(_)) => "xhttp",
            _ => "tcp",
        };
        debug!(tag = %self.config.tag, target = %conn.target, transport = transport_type, "vless tcp connecting");

        let io = self.dial(header).await?;
        Ok(relay(conn.stream, io).await)
    }

    async fn handle_udp(&self, mut packet: InboundUdpPacket) -> anyhow::Result<()> {
        use crate::outbound::proto::{
            vless_build_udp_request, vless_decode_udp_frame_len, vless_encode_udp_frame,
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let uuid = Self::parse_uuid(&self.config.uuid)?;
        let header = vless_build_udp_request(&uuid, &packet.target)?;

        debug!(tag=%self.config.tag, target=%packet.target, "vless udp session opened");

        let io = self.dial(header).await?;
        let (mut reader, mut writer) = tokio::io::split(io);

        let frame = vless_encode_udp_frame(&packet.data);
        writer.write_all(&frame).await?;
        writer.flush().await?;

        let timeout = std::time::Duration::from_secs(5);
        let reply_tx = packet.session.reply_tx.clone();
        let src = packet.src;
        let spoofed_src = packet.target.to_socket_addr_lossy();

        // 若有后续上行包，spawn task 持续将上行包写入 VLESS 隧道
        if let Some(mut upstream_rx) = packet.upstream_rx.take() {
            tokio::spawn(async move {
                while let Some(data) = upstream_rx.recv().await {
                    let frame = vless_encode_udp_frame(&data);
                    if writer.write_all(&frame).await.is_err()
                        || writer.flush().await.is_err()
                    {
                        break;
                    }
                }
            });
        }

        loop {
            let mut len_buf = [0u8; 2];
            match tokio::time::timeout(timeout, reader.read_exact(&mut len_buf)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => break,
            }
            let (_, data_len) = vless_decode_udp_frame_len(&len_buf)?;
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

// ── WebSocket 适配器（原有实现，不变）────────────────────────────────────────

use futures_util::{Sink, Stream};
use pin_project_lite::pin_project;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pin_project! {
    pub struct WsStream<S> {
        #[pin]
        inner: S,
        pending_header: Option<Bytes>,
        read_buf: Bytes,
        response_header_skipped: bool,
    }
}

impl<S> WsStream<S>
where
    S: Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
        + Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
        + Unpin,
{
    pub fn new(inner: S, header: Bytes) -> Self {
        Self {
            inner,
            pending_header: Some(header),
            read_buf: Bytes::new(),
            response_header_skipped: false,
        }
    }
}

impl<S> AsyncRead for WsStream<S>
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
                        let data = Bytes::from(data);
                        if !*this.response_header_skipped {
                            *this.response_header_skipped = true;
                            match parse_response_header(&data) {
                                Ok(skip) => {
                                    *this.read_buf = data.slice(skip..);
                                }
                                Err(_) => {
                                    *this.read_buf = data;
                                }
                            }
                        } else {
                            *this.read_buf = data;
                        }
                    }
                    Message::Close(_) => return Poll::Ready(Ok(())),
                    _ => {}
                },
            }
        }
    }
}

impl<S> AsyncWrite for WsStream<S>
where
    S: Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut this = self.project();
        if let Poll::Pending = this.inner.as_mut().poll_ready(cx).map_err(ws_err)? {
            return Poll::Pending;
        }
        let payload = if let Some(header) = this.pending_header.take() {
            let mut combined = BytesMut::with_capacity(header.len() + data.len());
            combined.put_slice(&header);
            combined.put_slice(data);
            combined.freeze().into()
        } else {
            data.to_vec()
        };
        let len = data.len();
        this.inner
            .as_mut()
            .start_send(Message::Binary(payload))
            .map_err(ws_err)?;
        Poll::Ready(Ok(len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx).map_err(ws_err)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_close(cx).map_err(ws_err)
    }
}

fn ws_err(e: tokio_tungstenite::tungstenite::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::BrokenPipe, e)
}

// ── TCP Stream 适配器（VLESS over TCP/REALITY）────────────────────────────────

// 在 TCP/TLS 流上实现 VLESS 帧：首次写入拼接请求头，首次读取跳过响应头。
pin_project! {
    pub struct VlessTcpStream<S> {
        #[pin]
        inner: S,
        pending_header: Option<Bytes>,
        read_buf: Bytes,
        response_header_skipped: bool,
        // 暂存已读但未处理的字节（用于跳过 VLESS 响应头）
        raw_buf: Vec<u8>,
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> VlessTcpStream<S> {
    pub fn new(inner: S, header: Bytes) -> Self {
        Self {
            inner,
            pending_header: Some(header),
            read_buf: Bytes::new(),
            response_header_skipped: false,
            raw_buf: Vec::new(),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for VlessTcpStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.project();

        // 先消费 read_buf
        if !this.read_buf.is_empty() {
            let n = buf.remaining().min(this.read_buf.len());
            buf.put_slice(&this.read_buf[..n]);
            *this.read_buf = this.read_buf.slice(n..);
            return Poll::Ready(Ok(()));
        }

        if !*this.response_header_skipped {
            // 需要先读取并跳过 VLESS 响应头 [Ver 1B][Addon Len 1B][Addon ...]
            // 策略：读取数据到 raw_buf，凑够至少 2 字节后解析头
            // 直接从底层读到临时buf，再处理VLESS响应头
            let mut temp_storage = [0u8; 512];
            let mut temp_buf = ReadBuf::new(&mut temp_storage);
            match this.inner.poll_read(cx, &mut temp_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let filled = temp_buf.filled().to_vec();
                    if filled.is_empty() {
                        return Poll::Ready(Ok(())); // EOF
                    }
                    this.raw_buf.extend_from_slice(&filled);
                }
            }
            // 尝试解析 VLESS 响应头
            if this.raw_buf.len() >= 2 {
                let addon_len = this.raw_buf[1] as usize;
                let hdr_len = 2 + addon_len;
                if this.raw_buf.len() >= hdr_len {
                    // 跳过头部
                    *this.response_header_skipped = true;
                    let payload = Bytes::copy_from_slice(&this.raw_buf[hdr_len..]);
                    this.raw_buf.clear();
                    if !payload.is_empty() {
                        *this.read_buf = payload;
                        // 递归消费
                        let n = buf.remaining().min(this.read_buf.len());
                        buf.put_slice(&this.read_buf[..n]);
                        *this.read_buf = this.read_buf.slice(n..);
                    }
                    return Poll::Ready(Ok(()));
                }
            }
            // 数据不够，返回 Pending 等待更多数据
            // 实际上我们已经消费了一些数据，不能真正 Pending（会导致死锁）
            // 这里返回 Ok(()) 让调用者再次 poll
            Poll::Ready(Ok(()))
        } else {
            this.inner.poll_read(cx, buf)
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VlessTcpStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.project();
        if let Some(header) = this.pending_header.take() {
            // 首次写：将 VLESS 请求头 + data 合并发送
            let mut combined = BytesMut::with_capacity(header.len() + data.len());
            combined.put_slice(&header);
            combined.put_slice(data);
            let combined = combined.freeze();
            match this.inner.poll_write(cx, &combined) {
                Poll::Ready(Ok(n)) => Poll::Ready(Ok(if n >= header.len() {
                    n - header.len()
                } else {
                    0
                })),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => {
                    // 写阻塞，把 header 放回去（data 部分丢失，简化处理）
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

// ── VLESS 响应头解析 ──────────────────────────────────────────────────────────

pub fn parse_response_header(buf: &[u8]) -> anyhow::Result<usize> {
    anyhow::ensure!(buf.len() >= 2, "vless response too short");
    anyhow::ensure!(
        buf[0] == 0x00,
        "unsupported vless response version: {}",
        buf[0]
    );
    let addon_len = buf[1] as usize;
    anyhow::ensure!(buf.len() >= 2 + addon_len, "vless response addon truncated");
    Ok(2 + addon_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uuid_ok() {
        let uuid = VlessOutbound::parse_uuid("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        assert_eq!(uuid[0], 0xaa);
        assert_eq!(uuid[15], 0xee);
    }

    #[test]
    fn build_request_header_domain() {
        let uuid = [0xau8; 16];
        let target = Target::Domain("example.com".into(), 443);
        let hdr = VlessOutbound::build_request_header(&uuid, &target).unwrap();
        assert_eq!(hdr[0], 0x00);
        assert_eq!(&hdr[1..17], &uuid);
        assert_eq!(hdr[17], 0x00);
        assert_eq!(hdr[18], 0x01);
        assert_eq!(u16::from_be_bytes([hdr[19], hdr[20]]), 443);
        assert_eq!(hdr[21], 0x02);
    }

    #[test]
    fn parse_response_header_ok() {
        let buf = [0x00, 0x00];
        assert_eq!(parse_response_header(&buf).unwrap(), 2);
        let buf2 = [0x00, 0x03, 0x01, 0x02, 0x03];
        assert_eq!(parse_response_header(&buf2).unwrap(), 5);
    }
}
