//! SOCKS5 / SOCKS4a / SOCKS4 出站实现。
//!
//! 协议参考：
//! - SOCKS5: RFC 1928 + RFC 1929（USER/PASS 认证）
//! - SOCKS4a: SOCKS4 扩展，支持域名（DSTIP = 0.0.0.x，域名跟在 USERID\0 后）
//! - SOCKS4: 仅支持 IPv4 目标地址
//!
//! 与 sing-box 行为对齐：
//! - SOCKS4 时客户端在本地解析域名（`resolve` 模式）
//! - SOCKS4a/5 时将域名传给代理服务器解析
//! - UDP ASSOCIATE 仅 SOCKS5 支持；SOCKS4/4a 收到 UDP 请求时记录警告并丢弃

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tracing::{debug, warn};

use crate::{
    config::outbound::{SocksOutboundConfig, SocksVersion},
    inbound::{InboundTcpStream, InboundUdpPacket, Target},
    outbound::{
        apply_mark_to_tcp, apply_mark_to_udp, relay, resolve_target, set_tcp_opts, Outbound,
        OutboundStatus,
    },
};

// ── SOCKS 常量 ────────────────────────────────────────────────────────────────

// SOCKS5 握手
const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_NO_AUTH: u8 = 0x00;
const SOCKS5_USER_PASS_AUTH: u8 = 0x02;
const SOCKS5_NO_ACCEPTABLE: u8 = 0xFF;
const SOCKS5_AUTH_VERSION: u8 = 0x01;
const SOCKS5_AUTH_SUCCESS: u8 = 0x00;

// SOCKS5 命令
const SOCKS5_CMD_CONNECT: u8 = 0x01;
const SOCKS5_CMD_UDP_ASSOCIATE: u8 = 0x03;

// SOCKS5 地址类型
const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_ATYP_IPV6: u8 = 0x04;

// SOCKS5 应答
const SOCKS5_REP_SUCCESS: u8 = 0x00;

// SOCKS4/4a
const SOCKS4_VERSION: u8 = 0x04;
const SOCKS4_CMD_CONNECT: u8 = 0x01;
const SOCKS4_REP_SUCCESS: u8 = 0x5A;

// ── 出站结构体 ────────────────────────────────────────────────────────────────

pub struct SocksOutbound {
    config: SocksOutboundConfig,
    version: SocksVersion,
    /// 全局 SO_MARK（来自 global.routing_mark），0 表示不设置
    routing_mark: u32,
}

impl SocksOutbound {
    pub fn new(config: SocksOutboundConfig) -> anyhow::Result<Self> {
        let version = config.parsed_version()?;
        Ok(Self {
            config,
            version,
            routing_mark: 0,
        })
    }

    pub fn with_mark(mut self, mark: u32) -> Self {
        self.routing_mark = mark;
        self
    }

    // ── 连接到代理服务器 ──────────────────────────────────────────────────────

    async fn connect_proxy(&self) -> anyhow::Result<TcpStream> {
        let addr: SocketAddr = tokio::net::lookup_host(format!(
            "{}:{}",
            self.config.server, self.config.server_port
        ))
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("socks: DNS lookup failed for {}", self.config.server))?;
        let stream = TcpStream::connect(addr).await?;
        set_tcp_opts(&stream)?;
        apply_mark_to_tcp(&stream, self.routing_mark)?;
        Ok(stream)
    }

    // ── SOCKS5 握手 ───────────────────────────────────────────────────────────

    /// 完成 SOCKS5 握手（认证协商 + CONNECT/UDP ASSOCIATE），
    /// 返回已完成握手的 TcpStream。
    async fn socks5_handshake(
        &self,
        stream: &mut TcpStream,
        target: &Target,
        cmd: u8,
    ) -> anyhow::Result<()> {
        // ── 1. 方法协商 ────────────────────────────────────────────────────────
        let has_auth = self.config.username.is_some();
        if has_auth {
            // 提供两种方法：NO_AUTH 和 USER/PASS
            stream
                .write_all(&[SOCKS5_VERSION, 2, SOCKS5_NO_AUTH, SOCKS5_USER_PASS_AUTH])
                .await?;
        } else {
            stream
                .write_all(&[SOCKS5_VERSION, 1, SOCKS5_NO_AUTH])
                .await?;
        }

        let mut resp = [0u8; 2];
        stream.read_exact(&mut resp).await?;
        anyhow::ensure!(
            resp[0] == SOCKS5_VERSION,
            "socks5: unexpected server version"
        );
        anyhow::ensure!(
            resp[1] != SOCKS5_NO_ACCEPTABLE,
            "socks5: server rejected all auth methods"
        );

        // ── 2. 认证（如果服务端选了 USER/PASS）─────────────────────────────────
        if resp[1] == SOCKS5_USER_PASS_AUTH {
            let user = self.config.username.as_deref().unwrap_or("");
            let pass = self.config.password.as_deref().unwrap_or("");
            anyhow::ensure!(
                user.len() <= 255 && pass.len() <= 255,
                "socks5: username/password too long"
            );

            let mut auth = Vec::with_capacity(3 + user.len() + pass.len());
            auth.push(SOCKS5_AUTH_VERSION);
            auth.push(user.len() as u8);
            auth.extend_from_slice(user.as_bytes());
            auth.push(pass.len() as u8);
            auth.extend_from_slice(pass.as_bytes());
            stream.write_all(&auth).await?;

            let mut auth_resp = [0u8; 2];
            stream.read_exact(&mut auth_resp).await?;
            anyhow::ensure!(
                auth_resp[1] == SOCKS5_AUTH_SUCCESS,
                "socks5: authentication failed"
            );
        }

        // ── 3. 发送请求（CONNECT 或 UDP ASSOCIATE）────────────────────────────
        // 格式：VER CMD RSV ATYP [ADDR] PORT(2B BE)
        let mut req = Vec::with_capacity(32);
        req.extend_from_slice(&[SOCKS5_VERSION, cmd, 0x00]);

        match target {
            Target::Socket(addr) => match addr.ip() {
                IpAddr::V4(ip) => {
                    req.push(SOCKS5_ATYP_IPV4);
                    req.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    req.push(SOCKS5_ATYP_IPV6);
                    req.extend_from_slice(&ip.octets());
                }
            },
            Target::Domain(host, _) => {
                anyhow::ensure!(host.len() <= 255, "socks5: domain too long");
                req.push(SOCKS5_ATYP_DOMAIN);
                req.push(host.len() as u8);
                req.extend_from_slice(host.as_bytes());
            }
        }
        let port = match target {
            Target::Socket(a) => a.port(),
            Target::Domain(_, p) => *p,
        };
        req.extend_from_slice(&port.to_be_bytes());
        stream.write_all(&req).await?;

        // ── 4. 读取应答 ────────────────────────────────────────────────────────
        // 格式：VER REP RSV ATYP [ADDR] PORT
        let mut hdr = [0u8; 4];
        stream.read_exact(&mut hdr).await?;
        anyhow::ensure!(hdr[0] == SOCKS5_VERSION, "socks5: bad reply version");
        anyhow::ensure!(
            hdr[1] == SOCKS5_REP_SUCCESS,
            "socks5: server refused, REP=0x{:02x}",
            hdr[1]
        );

        // 跳过绑定地址字段（BND.ADDR + BND.PORT）
        match hdr[3] {
            SOCKS5_ATYP_IPV4 => {
                let mut skip = [0u8; 6]; // 4B IP + 2B port
                stream.read_exact(&mut skip).await?;
            }
            SOCKS5_ATYP_IPV6 => {
                let mut skip = [0u8; 18]; // 16B IP + 2B port
                stream.read_exact(&mut skip).await?;
            }
            SOCKS5_ATYP_DOMAIN => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let mut skip = vec![0u8; len[0] as usize + 2]; // domain + 2B port
                stream.read_exact(&mut skip).await?;
            }
            other => anyhow::bail!("socks5: unknown BND.ATYP=0x{other:02x}"),
        }

        Ok(())
    }

    // ── SOCKS4 / 4a 握手 ──────────────────────────────────────────────────────

    /// SOCKS4 握手（仅 IPv4）。
    /// SOCKS4a 扩展：当 DSTIP = 0.0.0.x（x ≠ 0）时，域名跟在 USERID\0 后。
    async fn socks4_handshake(
        &self,
        stream: &mut TcpStream,
        target: &Target,
    ) -> anyhow::Result<()> {
        // SOCKS4 不支持域名，需在本地解析
        let (ip_bytes, port, domain): ([u8; 4], u16, Option<String>) = match target {
            Target::Socket(addr) => match addr.ip() {
                IpAddr::V4(ip) => (ip.octets(), addr.port(), None),
                IpAddr::V6(_) => anyhow::bail!("socks4: IPv6 target not supported"),
            },
            Target::Domain(host, port) => {
                if self.version == SocksVersion::V4a {
                    // SOCKS4a：DSTIP = 0.0.0.1，域名附在 USERID 后
                    ([0, 0, 0, 1], *port, Some(host.clone()))
                } else {
                    // SOCKS4：在本地解析域名
                    let addr = resolve_target(target).await?;
                    match addr.ip() {
                        IpAddr::V4(ip) => (ip.octets(), addr.port(), None),
                        IpAddr::V6(_) => {
                            anyhow::bail!("socks4: resolved to IPv6, not supported")
                        }
                    }
                }
            }
        };

        // 格式：VER CMD DSTPORT(2B) DSTIP(4B) USERID\0 [DOMAIN\0]
        let mut req = Vec::with_capacity(16);
        req.push(SOCKS4_VERSION);
        req.push(SOCKS4_CMD_CONNECT);
        req.extend_from_slice(&port.to_be_bytes());
        req.extend_from_slice(&ip_bytes);
        req.push(0x00); // USERID（空）+ NUL 终止符

        if let Some(ref domain) = domain {
            req.extend_from_slice(domain.as_bytes());
            req.push(0x00); // 域名 NUL 终止符
        }

        stream.write_all(&req).await?;

        // 应答：8 字节，VN(1) + CD(1) + DSTPORT(2) + DSTIP(4)
        let mut resp = [0u8; 8];
        stream.read_exact(&mut resp).await?;
        anyhow::ensure!(
            resp[0] == 0x00,
            "socks4: unexpected VN byte: 0x{:02x}",
            resp[0]
        );
        anyhow::ensure!(
            resp[1] == SOCKS4_REP_SUCCESS,
            "socks4: server refused, CD=0x{:02x}",
            resp[1]
        );

        Ok(())
    }

    // ── 建立隧道连接 ──────────────────────────────────────────────────────────

    /// 建立经由 SOCKS 代理的 TCP 隧道，返回已完成握手的 TcpStream。
    async fn connect_tunnel(&self, target: &Target) -> anyhow::Result<TcpStream> {
        let mut stream = self.connect_proxy().await?;
        match self.version {
            SocksVersion::V5 => {
                self.socks5_handshake(&mut stream, target, SOCKS5_CMD_CONNECT)
                    .await?
            }
            SocksVersion::V4a | SocksVersion::V4 => {
                self.socks4_handshake(&mut stream, target).await?
            }
        }
        Ok(stream)
    }

    // ── SOCKS5 UDP ASSOCIATE ──────────────────────────────────────────────────

    /// 通过 SOCKS5 UDP ASSOCIATE 发送单个 UDP 数据包并读取响应。
    ///
    /// 流程：
    /// 1. 建立 TCP 控制连接并完成 UDP ASSOCIATE 握手，获取代理的 UDP relay 地址
    /// 2. 绑定本地 UDP socket，向 relay 地址发送封装好的数据报
    /// 3. 读取响应，去掉 SOCKS5 UDP 头后通过 reply_tx 返回
    /// 4. TCP 控制连接保持到函数返回（drop 即可，代理会同时关闭 UDP relay）
    async fn socks5_udp(&self, mut packet: InboundUdpPacket) -> anyhow::Result<()> {
        // ── 1. UDP ASSOCIATE ───────────────────────────────────────────────────
        // 目标地址填 0.0.0.0:0（表示"我要发任意目标"，RFC 1928 §4）
        let placeholder = Target::Socket("0.0.0.0:0".parse()?);
        let mut ctrl = self.connect_proxy().await?;
        self.socks5_handshake(&mut ctrl, &placeholder, SOCKS5_CMD_UDP_ASSOCIATE)
            .await?;

        // 读取 BND 地址：握手里 read_exact 已消费了应答头，现在重新握手时
        // 我们需要解析 BND 地址。这里绕开方式：改用低层握手并手动读取 BND。
        // 由于 socks5_handshake 已读完应答，我们在 ctrl 里的绑定地址是
        // 握手结束时服务端在 REP 中给出的 BND.ADDR:BND.PORT。
        //
        // 实际上 socks5_handshake 已经跳过了 BND 字段（skip 逻辑）。
        // 为了拿到 relay 地址，我们用独立的低层函数重新协商。
        drop(ctrl);

        let relay_addr = self.socks5_udp_associate_get_relay().await?;

        // ── 2. 封装 UDP 数据报（SOCKS5 UDP 请求头）──────────────────────────────
        // 格式：RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT(2) DATA
        let build_dgram = |target: &Target, data: &[u8]| -> Vec<u8> {
            let mut dgram: Vec<u8> = Vec::with_capacity(data.len() + 22);
            dgram.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV + FRAG=0
            match target {
                Target::Socket(addr) => match addr.ip() {
                    IpAddr::V4(ip) => {
                        dgram.push(SOCKS5_ATYP_IPV4);
                        dgram.extend_from_slice(&ip.octets());
                        dgram.extend_from_slice(&addr.port().to_be_bytes());
                    }
                    IpAddr::V6(ip) => {
                        dgram.push(SOCKS5_ATYP_IPV6);
                        dgram.extend_from_slice(&ip.octets());
                        dgram.extend_from_slice(&addr.port().to_be_bytes());
                    }
                },
                Target::Domain(host, port) => {
                    dgram.push(SOCKS5_ATYP_DOMAIN);
                    dgram.push(host.len() as u8);
                    dgram.extend_from_slice(host.as_bytes());
                    dgram.extend_from_slice(&port.to_be_bytes());
                }
            }
            dgram.extend_from_slice(data);
            dgram
        };

        // ── 3. 发送并持续接收 ─────────────────────────────────────────────────
        let local_bind = if relay_addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let udp = std::sync::Arc::new(tokio::net::UdpSocket::bind(local_bind).await?);
        apply_mark_to_udp(&udp, self.routing_mark)?;
        udp.send_to(&build_dgram(&packet.target, &packet.data), relay_addr).await?;

        // 若有后续上行包，spawn task 持续封装并发送
        if let Some(mut upstream_rx) = packet.upstream_rx.take() {
            let udp_send = udp.clone();
            let target_clone = packet.target.clone();
            tokio::spawn(async move {
                while let Some(data) = upstream_rx.recv().await {
                    let dgram = build_dgram(&target_clone, &data);
                    if udp_send.send_to(&dgram, relay_addr).await.is_err() {
                        break;
                    }
                }
            });
        }

        // ── 4. 持续接收回包，去掉 SOCKS5 UDP 头后转发 ────────────────────────
        let mut buf = vec![0u8; 65535];
        let reply_tx = packet.session.reply_tx.clone();
        let src = packet.src;
        let spoofed_src = packet.target.to_socket_addr_lossy();

        while let Ok(Ok((n, _from))) = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            udp.recv_from(&mut buf),
        )
        .await
        {
            match socks5_udp_strip_header(&buf[..n]) {
                Ok(payload) => {
                    let _ = reply_tx
                        .send((bytes::Bytes::copy_from_slice(payload), src, spoofed_src))
                        .await;
                }
                Err(_) => continue,
            }
        }

        Ok(())
    }

    /// 发起 UDP ASSOCIATE 并返回代理分配的 UDP relay 地址。
    /// 与 socks5_handshake 不同，这里手动解析 BND.ADDR:BND.PORT。
    async fn socks5_udp_associate_get_relay(&self) -> anyhow::Result<SocketAddr> {
        let mut stream = self.connect_proxy().await?;

        // ── 方法协商（复用 socks5_handshake 前两步逻辑）─────────────────────
        let has_auth = self.config.username.is_some();
        if has_auth {
            stream
                .write_all(&[SOCKS5_VERSION, 2, SOCKS5_NO_AUTH, SOCKS5_USER_PASS_AUTH])
                .await?;
        } else {
            stream
                .write_all(&[SOCKS5_VERSION, 1, SOCKS5_NO_AUTH])
                .await?;
        }
        let mut resp = [0u8; 2];
        stream.read_exact(&mut resp).await?;
        anyhow::ensure!(resp[0] == SOCKS5_VERSION, "socks5 udp: unexpected version");
        anyhow::ensure!(
            resp[1] != SOCKS5_NO_ACCEPTABLE,
            "socks5 udp: no acceptable method"
        );
        if resp[1] == SOCKS5_USER_PASS_AUTH {
            let user = self.config.username.as_deref().unwrap_or("");
            let pass = self.config.password.as_deref().unwrap_or("");
            let mut auth = Vec::with_capacity(3 + user.len() + pass.len());
            auth.push(SOCKS5_AUTH_VERSION);
            auth.push(user.len() as u8);
            auth.extend_from_slice(user.as_bytes());
            auth.push(pass.len() as u8);
            auth.extend_from_slice(pass.as_bytes());
            stream.write_all(&auth).await?;
            let mut ar = [0u8; 2];
            stream.read_exact(&mut ar).await?;
            anyhow::ensure!(ar[1] == SOCKS5_AUTH_SUCCESS, "socks5 udp: auth failed");
        }

        // ── UDP ASSOCIATE 请求（目标 0.0.0.0:0）────────────────────────────
        let req = [
            SOCKS5_VERSION,
            SOCKS5_CMD_UDP_ASSOCIATE,
            0x00,
            SOCKS5_ATYP_IPV4,
            0,
            0,
            0,
            0, // 0.0.0.0
            0,
            0, // port 0
        ];
        stream.write_all(&req).await?;

        // ── 读取应答并解析 BND 地址 ──────────────────────────────────────────
        let mut hdr = [0u8; 4];
        stream.read_exact(&mut hdr).await?;
        anyhow::ensure!(hdr[0] == SOCKS5_VERSION, "socks5 udp: bad reply version");
        anyhow::ensure!(
            hdr[1] == SOCKS5_REP_SUCCESS,
            "socks5 udp: UDP ASSOCIATE refused, REP=0x{:02x}",
            hdr[1]
        );

        let relay_addr = match hdr[3] {
            SOCKS5_ATYP_IPV4 => {
                let mut buf = [0u8; 6];
                stream.read_exact(&mut buf).await?;
                let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                let port = u16::from_be_bytes([buf[4], buf[5]]);
                SocketAddr::new(IpAddr::V4(ip), port)
            }
            SOCKS5_ATYP_IPV6 => {
                let mut buf = [0u8; 18];
                stream.read_exact(&mut buf).await?;
                let ip: [u8; 16] = buf[..16].try_into().unwrap();
                let port = u16::from_be_bytes([buf[16], buf[17]]);
                SocketAddr::new(IpAddr::V6(ip.into()), port)
            }
            other => anyhow::bail!("socks5 udp: unsupported BND.ATYP=0x{other:02x}"),
        };

        // 如果代理返回 0.0.0.0，则用代理服务器 IP 代替
        let relay_addr = if relay_addr.ip().is_unspecified() {
            let proxy_addr: SocketAddr = tokio::net::lookup_host(format!(
                "{}:{}",
                self.config.server, self.config.server_port
            ))
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("socks5 udp: cannot resolve proxy host"))?;
            SocketAddr::new(proxy_addr.ip(), relay_addr.port())
        } else {
            relay_addr
        };

        // 保持 TCP 控制连接存活（不 drop），通过 Box::leak 泄漏到 task
        // 让它在 UDP 会话期间保持打开——实际上对于单发单收场景可以 drop，
        // 部分代理不依赖控制连接来维护 relay 绑定，但 RFC 要求保持。
        // 用 spawn 保活到超时后自然退出。
        tokio::spawn(async move {
            // 持有 stream 直到它被关闭（5 s 超时与 UDP 一致）
            tokio::time::sleep(std::time::Duration::from_secs(6)).await;
            drop(stream);
        });

        Ok(relay_addr)
    }
}

// ── Outbound trait 实现 ───────────────────────────────────────────────────────

#[async_trait::async_trait]
impl Outbound for SocksOutbound {
    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn status(&self) -> OutboundStatus {
        let type_name = match self.version {
            SocksVersion::V5 => "SOCKS5",
            SocksVersion::V4a => "SOCKS4a",
            SocksVersion::V4 => "SOCKS4",
        };
        OutboundStatus {
            name: self.config.tag.clone(),
            type_name: type_name.to_string(),
            now: None,
            all: vec![],
            history: vec![],
        }
    }

    async fn handle_tcp(&self, conn: InboundTcpStream) -> anyhow::Result<(u64, u64)> {
        debug!(
            tag = %self.config.tag,
            target = %conn.target,
            version = ?self.version,
            "socks tcp"
        );
        let remote = self.connect_tunnel(&conn.target).await?;
        let (up, down) = relay(conn.stream, remote).await;
        debug!(tag = %self.config.tag, up, down, "socks tcp done");
        Ok((up, down))
    }

    async fn handle_udp(&self, packet: InboundUdpPacket) -> anyhow::Result<()> {
        match self.version {
            SocksVersion::V5 => {
                debug!(
                    tag = %self.config.tag,
                    target = %packet.target,
                    "socks5 udp"
                );
                self.socks5_udp(packet).await
            }
            SocksVersion::V4 | SocksVersion::V4a => {
                warn!(
                    tag = %self.config.tag,
                    target = %packet.target,
                    "socks4/4a does not support UDP, dropping packet"
                );
                Ok(())
            }
        }
    }

    /// 建立经由 SOCKS 代理的 TCP 隧道，供 DNS upstream detour 使用。
    async fn connect_tcp(
        &self,
        host: &str,
        port: u16,
    ) -> anyhow::Result<Box<dyn crate::outbound::AsyncReadWrite>> {
        let target = Target::Domain(host.to_string(), port);
        let stream = self.connect_tunnel(&target).await?;
        Ok(Box::new(stream))
    }
}

// ── 辅助函数 ──────────────────────────────────────────────────────────────────

/// 去掉 SOCKS5 UDP 头，返回 payload 切片。
/// 格式：RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT(2) DATA
fn socks5_udp_strip_header(buf: &[u8]) -> anyhow::Result<&[u8]> {
    anyhow::ensure!(buf.len() >= 4, "socks5 udp: response too short");
    // buf[0..2] = RSV, buf[2] = FRAG
    let header_len = match buf[3] {
        SOCKS5_ATYP_IPV4 => 4 + 4 + 2,  // ATYP + IPv4(4) + port(2)
        SOCKS5_ATYP_IPV6 => 4 + 16 + 2, // ATYP + IPv6(16) + port(2)
        SOCKS5_ATYP_DOMAIN => {
            anyhow::ensure!(buf.len() >= 5, "socks5 udp: domain header truncated");
            4 + 1 + buf[4] as usize + 2 // ATYP + len(1) + domain + port(2)
        }
        other => anyhow::bail!("socks5 udp: unknown ATYP=0x{other:02x} in response"),
    };
    anyhow::ensure!(buf.len() >= header_len, "socks5 udp: response truncated");
    Ok(&buf[header_len..])
}

// ── 单元测试 ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::outbound::{SocksOutboundConfig, SocksVersion};

    fn make_config(version: Option<&str>) -> SocksOutboundConfig {
        SocksOutboundConfig {
            tag: "test".into(),
            server: "127.0.0.1".into(),
            server_port: 1080,
            version: version.map(str::to_string),
            username: None,
            password: None,
        }
    }

    #[test]
    fn version_parsing() {
        assert_eq!(
            make_config(None).parsed_version().unwrap(),
            SocksVersion::V5
        );
        assert_eq!(
            make_config(Some("5")).parsed_version().unwrap(),
            SocksVersion::V5
        );
        assert_eq!(
            make_config(Some("4a")).parsed_version().unwrap(),
            SocksVersion::V4a
        );
        assert_eq!(
            make_config(Some("4")).parsed_version().unwrap(),
            SocksVersion::V4
        );
        assert!(make_config(Some("6")).parsed_version().is_err());
    }

    #[test]
    fn udp_strip_header_ipv4() {
        // RSV(2) FRAG(1) ATYP_IPV4(1) IP(4) PORT(2) DATA
        let mut buf = vec![0x00, 0x00, 0x00, SOCKS5_ATYP_IPV4];
        buf.extend_from_slice(&[1, 2, 3, 4]); // IP
        buf.extend_from_slice(&[0x00, 0x50]); // port 80
        buf.extend_from_slice(b"hello");
        let payload = socks5_udp_strip_header(&buf).unwrap();
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn udp_strip_header_domain() {
        // RSV(2) FRAG(1) ATYP_DOMAIN(1) LEN(1) DOMAIN PORT(2) DATA
        let domain = b"example.com";
        let mut buf = vec![0x00, 0x00, 0x00, SOCKS5_ATYP_DOMAIN, domain.len() as u8];
        buf.extend_from_slice(domain);
        buf.extend_from_slice(&[0x01, 0xBB]); // port 443
        buf.extend_from_slice(b"world");
        let payload = socks5_udp_strip_header(&buf).unwrap();
        assert_eq!(payload, b"world");
    }
}
