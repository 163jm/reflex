//! VMess 出站。
//!
//! 支持 TCP over WebSocket (TLS) 和 TCP over TCP (TLS/plain)，
//! security 支持 auto / aes-128-gcm / chacha20-poly1305 / none。
//!
//! 实现参考 sing-vmess（AEAD 握手模式，alterId=0）。

mod aead;
mod frame;

use std::{net::SocketAddr, sync::Arc};

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    client_async_tls_with_config,
    tungstenite::{client::IntoClientRequest, http::HeaderValue, Message},
    MaybeTlsStream, WebSocketStream,
};
use tracing::debug;

use crate::{
    config::outbound::{VmessOutboundConfig, VmessTransportConfig, WsTransportConfig},
    inbound::{InboundTcpStream, InboundUdpPacket, Target},
    outbound::{
        apply_mark_to_tcp, relay, set_tcp_opts, tls::build_client_config, AsyncReadWrite, Outbound,
        OutboundStatus,
    },
};

use self::{
    aead::VmessStream,
    frame::{
        build_handshake, parse_response_header, parse_uuid, resolve_security, user_key,
        RequestHeader, CMD_TCP, CMD_UDP,
    },
};

// ── 主结构 ────────────────────────────────────────────────────────────────────

pub struct VmessOutbound {
    config: VmessOutboundConfig,
    tls_config: Arc<rustls::ClientConfig>,
    user_key: [u8; 16],
    security: u8,
    /// 全局 SO_MARK（来自 global.routing_mark），0 表示不设置
    routing_mark: u32,
}

impl VmessOutbound {
    pub fn new(config: VmessOutboundConfig) -> anyhow::Result<Self> {
        let uuid = parse_uuid(&config.uuid)?;
        let user_key = user_key(&uuid);
        let security = resolve_security(&config.security)?;
        let tls_config = build_client_config(&config.tls)?;
        Ok(Self {
            config,
            tls_config,
            user_key,
            security,
            routing_mark: 0,
        })
    }

    pub fn with_mark(mut self, mark: u32) -> Self {
        self.routing_mark = mark;
        self
    }

    // ── 建立底层连接 ────────────────────────────────────────────────────────

    async fn connect_raw(&self) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        match &self.config.transport {
            VmessTransportConfig::Ws(ws_cfg) => {
                let ws = self.connect_ws(ws_cfg).await?;
                Ok(Box::new(WsRawStream::new(ws)))
            }
            VmessTransportConfig::Xhttp(xhttp_cfg) => {
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
                Ok(Box::new(stream))
            }
            VmessTransportConfig::Tcp => self.connect_tcp_raw().await,
        }
    }

    async fn connect_tcp_raw(&self) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        let server = &self.config.server;
        let port = self.config.server_port;
        let addr: SocketAddr = tokio::net::lookup_host(format!("{server}:{port}"))
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("DNS failed for {server}"))?;
        let tcp = TcpStream::connect(addr).await?;
        set_tcp_opts(&tcp)?;
        apply_mark_to_tcp(&tcp, self.routing_mark)?;
        if self.config.tls.enabled {
            use crate::outbound::tls::connect_tls;
            let sni = self
                .config
                .tls
                .server_name
                .as_deref()
                .unwrap_or(server.as_str());
            let tls = connect_tls(tcp, sni, self.tls_config.clone()).await?;
            Ok(Box::new(tls))
        } else {
            Ok(Box::new(tcp))
        }
    }

    async fn connect_ws(
        &self,
        ws_cfg: &WsTransportConfig,
    ) -> anyhow::Result<WebSocketStream<MaybeTlsStream<TcpStream>>> {
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
            .ok_or_else(|| anyhow::anyhow!("DNS failed for {server}"))?;
        let tcp = TcpStream::connect(addr).await?;
        set_tcp_opts(&tcp)?;
        apply_mark_to_tcp(&tcp, self.routing_mark)?;
        let scheme = if self.config.tls.enabled { "wss" } else { "ws" };
        let url = format!("{scheme}://{sni}{}", ws_cfg.path);
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

    // ── VMess 握手 ───────────────────────────────────────────────────────────

    async fn handshake(
        &self,
        mut raw: Box<dyn AsyncReadWrite>,
        target: &Target,
        command: u8,
    ) -> anyhow::Result<VmessStream<Box<dyn AsyncReadWrite>>> {
        let req_hdr = RequestHeader::new(self.security, command);

        // 1. 发送握手帧（AuthID + EncLen + ConnNonce + EncHeader）
        let handshake_bytes = build_handshake(&self.user_key, &req_hdr, target);
        raw.write_all(&handshake_bytes).await?;
        raw.flush().await?;

        // 2. 读取响应头
        // AEAD 响应：[EncLen 2+16B][EncHeader 4+16B] = 38 字节
        const RESP_TOTAL: usize = (2 + 16) + (4 + 16);
        let mut resp_buf = vec![0u8; RESP_TOTAL];
        raw.read_exact(&mut resp_buf).await?;

        let (token, _) = parse_response_header(&resp_buf, &req_hdr.req_key, &req_hdr.req_nonce)?;
        anyhow::ensure!(
            token == req_hdr.resp_header,
            "vmess: response token mismatch (got {token:#04x}, expected {:#04x})",
            req_hdr.resp_header
        );

        debug!(tag = %self.config.tag, target = %target, "vmess handshake ok");

        // 3. 包装为 VmessStream
        Ok(VmessStream::new(
            raw,
            self.security,
            req_hdr.option,
            &req_hdr.req_key,
            &req_hdr.req_nonce,
        ))
    }
}

// ── Outbound impl ─────────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl Outbound for VmessOutbound {
    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn status(&self) -> OutboundStatus {
        OutboundStatus {
            name: self.config.tag.clone(),
            type_name: "VMess".to_string(),
            now: None,
            all: vec![],
            history: vec![],
        }
    }

    async fn connect_tcp(&self, host: &str, port: u16) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        let target = Target::Domain(host.to_string(), port);
        let raw = self.connect_raw().await?;
        let stream = self.handshake(raw, &target, CMD_TCP).await?;
        Ok(Box::new(stream))
    }

    async fn handle_tcp(&self, conn: InboundTcpStream) -> anyhow::Result<(u64, u64)> {
        let raw = self.connect_raw().await?;
        let vmess = self.handshake(raw, &conn.target, CMD_TCP).await?;
        debug!(tag = %self.config.tag, target = %conn.target, "vmess tcp relay");
        Ok(relay(conn.stream, vmess).await)
    }

    async fn handle_udp(&self, mut packet: InboundUdpPacket) -> anyhow::Result<()> {
        let raw = self.connect_raw().await?;
        let mut vmess = self.handshake(raw, &packet.target, CMD_UDP).await?;
        debug!(tag = %self.config.tag, target = %packet.target, "vmess udp relay");

        // 发送第一个包
        vmess.write_all(&packet.data).await?;
        vmess.flush().await?;

        let reply_tx = packet.session.reply_tx.clone();
        let src = packet.src;
        let spoofed_src = packet.target.to_socket_addr_lossy();
        let timeout = std::time::Duration::from_secs(10);
        let mut buf = vec![0u8; 65535];

        // 若有后续上行包，spawn task 持续写入 vmess 隧道
        if let Some(mut upstream_rx) = packet.upstream_rx.take() {
            let (mut vmess_rd, mut vmess_wr) = tokio::io::split(vmess);
            tokio::spawn(async move {
                while let Some(data) = upstream_rx.recv().await {
                    if vmess_wr.write_all(&data).await.is_err()
                        || vmess_wr.flush().await.is_err()
                    {
                        break;
                    }
                }
            });
            loop {
                match tokio::time::timeout(timeout, vmess_rd.read(&mut buf)).await {
                    Ok(Ok(0)) | Err(_) => break,
                    Ok(Ok(n)) => {
                        let _ = reply_tx
                            .send((Bytes::copy_from_slice(&buf[..n]), src, spoofed_src))
                            .await;
                    }
                    Ok(Err(_)) => break,
                }
            }
        } else {
            loop {
                match tokio::time::timeout(timeout, vmess.read(&mut buf)).await {
                    Ok(Ok(0)) | Err(_) => break,
                    Ok(Ok(n)) => {
                        let _ = reply_tx
                            .send((Bytes::copy_from_slice(&buf[..n]), src, spoofed_src))
                            .await;
                    }
                    Ok(Err(_)) => break,
                }
            }
        }
        Ok(())
    }
}

// ── WebSocket → AsyncRead + AsyncWrite 适配器（无 VLESS 头处理）─────────────

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures_util::{Sink, Stream};
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pin_project! {
    struct WsRawStream<S> {
        #[pin]
        inner: S,
        read_buf: Bytes,
    }
}

impl<S> WsRawStream<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            read_buf: Bytes::new(),
        }
    }
}

impl<S> AsyncRead for WsRawStream<S>
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
                    Message::Binary(data) => *this.read_buf = Bytes::from(data),
                    Message::Close(_) => return Poll::Ready(Ok(())),
                    _ => {}
                },
            }
        }
    }
}

impl<S> AsyncWrite for WsRawStream<S>
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
        let len = data.len();
        this.inner
            .as_mut()
            .start_send(Message::Binary(data.to_vec()))
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
