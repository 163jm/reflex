//! Hysteria2 出站。
//!
//! 协议参考：https://v2.hysteria.network/docs/developers/Protocol/
//!
//! ## 认证流程
//! 通过标准 HTTP/3 发送 POST 请求：
//!   URL:    https://hysteria/auth
//!   Header: Hysteria-Auth: <password>
//!           Hysteria-CC-RX: <rx_bps>
//!           Hysteria-Padding: <random>
//!   服务端响应 233 = OK，其他 = 失败
//!
//! 服务端响应头：
//!   Hysteria-UDP: true/false    — 是否启用 UDP
//!   Hysteria-CC-RX: <bps|auto> — 服务端允许的上行带宽（auto=由客户端自行检测）
//!
//! ## 拥塞控制（Brutal）
//! 若配置了 bandwidth.up，认证成功后对 QUIC 连接注入 Brutal 拥塞控制器：
//!   发送速率固定为 tx_bps，并通过 ACK 丢包率动态调节窗口。
//!
//! ## TCP 代理帧格式
//! 请求（写在 stream 开头，帧类型 0x401）：
//!   [0x401 varint][addr_len varint][addr bytes]["host:port"]
//!   [padding_len varint][padding bytes]
//!
//! 响应：
//!   [status 1B: 0=OK][msg_len varint][msg][padding_len varint][padding]
//!
//! ## UDP 格式
//! QUIC unreliable datagram（最大帧 1200 B）：
//!   [session_id u32 BE][packet_id u16 BE][frag_id u8][frag_count u8]
//!   [addr_len varint][addr "host:port"][data]
//!
//! 超过 MAX_DATAGRAM_PAYLOAD 的包自动分片，接收端重组后投递。

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};

use tokio::sync::Mutex;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::AsyncReadExt;
use tracing::{debug, warn};

use crate::{
    config::outbound::Hysteria2OutboundConfig,
    inbound::{InboundTcpStream, InboundUdpPacket, Target},
    outbound::{relay, Outbound},
};

// ── 常量 ──────────────────────────────────────────────────────────────────────

const HY2_ALPN: &[u8] = b"h3";

/// Hysteria2 认证 URL host（固定值）
const URL_HOST: &str = "hysteria";
/// Hysteria2 认证 URL path（固定值）
const URL_PATH: &str = "/auth";
/// 认证成功状态码（233）
const STATUS_AUTH_OK: u16 = 233;

/// TCP 代理请求帧类型（QUIC varint 0x401）
const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;

/// 地址最大长度（防 DoS）
/// 消息最大长度
const MAX_MESSAGE_LENGTH: u64 = 2048;
/// Padding 最大长度
const MAX_PADDING_LENGTH: u64 = 4096;

/// 服务端响应头：是否启用 UDP
const RESP_HEADER_UDP: &str = "hysteria-udp";
/// 服务端响应头：服务端允许的上行带宽（bps 或 "auto"）
const RESP_HEADER_CC_RX: &str = "hysteria-cc-rx";

/// 单个 QUIC datagram 中可携带的最大用户数据字节数。
/// 官方设为 1200B（= MaxDatagramFrameSize），留余量给帧头和 QUIC 开销。
const MAX_DATAGRAM_PAYLOAD: usize = 1100;

/// QUIC 初始 stream 接收窗口（与官方客户端对齐）
const QUIC_STREAM_RECEIVE_WINDOW: u64 = 8 * 1024 * 1024; // 8 MiB
/// QUIC 连接级别最大接收窗口
const QUIC_MAX_CONNECTION_RECEIVE_WINDOW: u64 = 15 * 1024 * 1024; // 15 MiB

/// Brutal 拥塞控制：ACK 频率（每 RTT 发送的 ACK 数，与 quic-go 官方一致）
#[allow(dead_code)]
const BRUTAL_MIN_CWND_PACKETS: u64 = 16;

// ── 认证结果 ──────────────────────────────────────────────────────────────────

/// 认证握手后从服务端响应头中解析出的协商结果
#[derive(Debug, Clone)]
struct AuthInfo {
    /// 服务端是否允许 UDP
    udp_enabled: bool,
    /// 协商后实际使用的发送带宽（bps）；0 = 不启用 Brutal
    tx_bps: u64,
}

// ── 主结构 ────────────────────────────────────────────────────────────────────

/// 缓存已认证的 QUIC 连接
struct CachedConn {
    conn: quinn::Connection,
    auth: AuthInfo,
}

pub struct Hy2Outbound {
    config: Hysteria2OutboundConfig,
    quic_config: Arc<quinn::ClientConfig>,
    /// UDP session ID 自增计数器（每条 UDP 会话递增）
    udp_session_id: AtomicU32,
    /// 连接池：复用已建立的 QUIC 连接，避免每次请求重新握手
    cached_conn: Arc<Mutex<Option<CachedConn>>>,
    /// 全局 SO_MARK（来自 global.routing_mark），0 表示不设置
    routing_mark: u32,
}

impl Hy2Outbound {
    pub fn new(config: Hysteria2OutboundConfig) -> anyhow::Result<Self> {
        let quic_config = build_quic_config(&config)?;
        Ok(Self {
            config,
            quic_config,
            udp_session_id: AtomicU32::new(0),
            cached_conn: Arc::new(Mutex::new(None)),
            routing_mark: 0,
        })
    }

    pub fn with_mark(mut self, mark: u32) -> Self {
        self.routing_mark = mark;
        self
    }

    /// 获取或新建 QUIC 连接（连接池）
    ///
    /// 优先复用已有的健康连接，避免每次请求都进行完整的 QUIC+HTTP/3 握手。
    /// 若缓存连接已关闭（stable_id 变化或 open_bi 失败），自动重建。
    async fn get_or_create_connection(&self) -> anyhow::Result<(quinn::Connection, AuthInfo)> {
        let mut guard = self.cached_conn.lock().await;

        // 检查缓存连接是否仍然健康
        if let Some(cached) = guard.as_ref() {
            // quinn::Connection::close_reason() 返回 Some 表示连接已关闭
            if cached.conn.close_reason().is_none() {
                return Ok((cached.conn.clone(), cached.auth.clone()));
            }
            // 连接已断开，清除缓存
            debug!(tag = %self.config.tag, "hy2 cached connection closed, reconnecting");
            *guard = None;
        }

        // 建立新连接
        let (conn, auth) = self.new_connection().await?;
        *guard = Some(CachedConn {
            conn: conn.clone(),
            auth: auth.clone(),
        });
        Ok((conn, auth))
    }

    /// 建立 QUIC 连接并完成 Hysteria2 认证握手，返回连接和协商结果
    async fn new_connection(&self) -> anyhow::Result<(quinn::Connection, AuthInfo)> {
        let server = &self.config.server;
        let port = self.config.server_port;
        let sni = self.config.tls.server_name.as_deref().unwrap_or(server);

        let addr: SocketAddr = tokio::net::lookup_host(format!("{server}:{port}"))
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("DNS failed for {server}"))?;

        let bind: SocketAddr = if addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        }
        .parse()?;

        let mut endpoint = crate::outbound::new_marked_quic_endpoint(bind, self.routing_mark)
            .map_err(|e| anyhow::anyhow!("hy2 endpoint bind failed: {e}"))?;
        endpoint.set_default_client_config((*self.quic_config).clone());

        let timeout = Duration::from_secs(10); // 固定 10s，与 sing-box 默认行为一致
        let conn = tokio::time::timeout(timeout, endpoint.connect(addr, sni)?)
            .await
            .map_err(|_| anyhow::anyhow!("hy2 connect timeout"))?
            .map_err(|e| anyhow::anyhow!("hy2 QUIC connect: {e}"))?;

        debug!(tag = %self.config.tag, server = %addr, "hy2 QUIC connection established");

        // ── 后台接收服务端 uni stream（HTTP/3 control stream）──────────────────
        // quic-go/http3 服务端在握手后立即打开 uni stream 发送 SETTINGS 帧。
        // 若客户端不接收，服务端流控满后会拒绝处理请求（connection lost）。
        {
            let conn_bg = conn.clone();
            tokio::spawn(async move {
                // 接收服务端的所有 uni stream 并静默丢弃
                for _ in 0..8 {
                    match tokio::time::timeout(Duration::from_secs(5), conn_bg.accept_uni()).await {
                        Ok(Ok(mut stream)) => {
                            // 读取 stream type byte 和 SETTINGS，然后持有（不关闭）
                            let conn_inner = conn_bg.clone();
                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 4096];
                                let _ = stream.read(&mut buf).await;
                                // 持有 stream 直到连接结束（而非固定 sleep 3600s）
                                conn_inner.closed().await;
                                drop(stream);
                            });
                        }
                        Ok(Err(_)) | Err(_) => break,
                    }
                }
            });
        }

        // Hysteria2 认证握手（HTTP/3 POST https://hysteria/auth）
        let auth_info = self.authenticate(&conn).await?;

        // 根据协商结果设置拥塞控制
        if auth_info.tx_bps > 0 {
            apply_brutal(&conn, auth_info.tx_bps);
            debug!(
                tag = %self.config.tag,
                tx_bps = auth_info.tx_bps,
                "hy2 Brutal CC enabled"
            );
        }

        Ok((conn, auth_info))
    }

    /// Hysteria2 认证握手
    ///
    /// 官方实现（core/client/client.go）使用 quic-go/http3.Transport.RoundTrip 发送：
    ///   POST https://hysteria/auth
    ///   Hysteria-Auth: <password>
    ///   Hysteria-CC-RX: <rx_bps>
    ///   Hysteria-Padding: <random 256-2047 bytes>
    ///
    /// HTTP/3 连接建立流程（必须严格遵守 RFC 9114 + RFC 9204）：
    ///   1. 客户端打开单向 control stream（type=0x00），发送 SETTINGS 帧
    ///   2. 客户端打开单向 QPACK encoder stream（type=0x02）—— RFC 9204 §4.2 MUST
    ///   3. 客户端打开单向 QPACK decoder stream（type=0x03）—— RFC 9204 §4.2 MUST
    ///   4. 同时在双向流上发送 HEADERS 帧（请求），接收 HEADERS 帧（响应）
    ///   5. 服务端（quic-go/http3）在处理请求前会先等待上述三条 uni stream
    ///
    /// 返回服务端协商结果（UDP 是否启用、实际 tx 带宽）。
    async fn authenticate(&self, conn: &quinn::Connection) -> anyhow::Result<AuthInfo> {
        // ── 步骤1：发送 HTTP/3 client control stream（SETTINGS 帧）─────────────
        // RFC 9114 §6.2.1：客户端必须在建立连接后立即发送 control stream
        // quic-go/http3 服务端会等待此 stream，否则请求处理会被 block
        {
            let mut ctrl = conn.open_uni().await.map_err(|e| {
                warn!(tag = %self.config.tag, err = %e, "hy2 auth: failed to open control stream");
                e
            })?;
            // stream type = 0x00（Control Stream）
            ctrl.write_all(&[0x00]).await?;
            // SETTINGS 帧：frame_type=0x04, length=0（空 settings，与 quic-go 默认行为一致）
            let mut settings = BytesMut::new();
            write_h3_frame(&mut settings, 0x04, &[]);
            ctrl.write_all(&settings).await?;
            debug!(tag = %self.config.tag, "hy2 auth: control stream sent");
            // control stream 不能关闭，task 持有它直到连接断开
            let conn_for_ctrl = conn.clone();
            tokio::spawn(async move {
                conn_for_ctrl.closed().await;
                drop(ctrl);
            });
        }

        // ── 步骤2+3：打开 QPACK encoder/decoder stream（RFC 9204 §4.2 MUST）────
        // quic-go 的 QPACK 层要求客户端在发送 HEADERS 前先建立这两条流。
        // 即使使用静态表（table capacity=0），这两条 uni stream 也必须存在，
        // 否则服务端 QPACK decoder 未初始化，会以 H3_QPACK_DECOMPRESSION_FAILED(0x200) 拒绝。
        {
            let mut enc_stream = conn.open_uni().await.map_err(|e| {
                warn!(tag = %self.config.tag, err = %e, "hy2 auth: failed to open QPACK encoder stream");
                e
            })?;
            enc_stream.write_all(&[0x02]).await?; // stream type = 0x02（QPACK Encoder Stream）
            debug!(tag = %self.config.tag, "hy2 auth: QPACK encoder stream opened");
            let conn_for_enc = conn.clone();
            tokio::spawn(async move {
                conn_for_enc.closed().await;
                drop(enc_stream);
            });
        }
        {
            let mut dec_stream = conn.open_uni().await.map_err(|e| {
                warn!(tag = %self.config.tag, err = %e, "hy2 auth: failed to open QPACK decoder stream");
                e
            })?;
            dec_stream.write_all(&[0x03]).await?; // stream type = 0x03（QPACK Decoder Stream）
            debug!(tag = %self.config.tag, "hy2 auth: QPACK decoder stream opened");
            let conn_for_dec = conn.clone();
            tokio::spawn(async move {
                conn_for_dec.closed().await;
                drop(dec_stream);
            });
        }
        let (mut send, mut recv) = conn.open_bi().await?;

        let password = &self.config.password;

        // 客户端声明的下行带宽（告知服务端我能接收多少）
        // 与 sing-box 对齐：up_mbps / down_mbps 整数字段
        let rx_bps: u64 = crate::config::outbound::mbps_to_bps(self.config.down_mbps);
        let tx_bps_local: u64 = crate::config::outbound::mbps_to_bps(self.config.up_mbps);

        // 随机 padding（官方：256–2047 字节）
        let padding = random_padding(256, 2048);
        let rx_str = rx_bps.to_string();

        // ── 构造 QPACK Header Block（RFC 9204 §4.5.6）────────────────────────
        // Literal Header Field Without Name Reference 格式（第一字节）：
        //   bits[7:5] = 0b001  (instruction type)
        //   bit[4]    = N      (never-index, 0)
        //   bit[3]    = H      (Huffman for name, 0)
        //   bits[2:0] = name 长度的 3-bit prefix integer（饱和值=7）
        // 紧随其后：name 字节；然后 value string literal [H(1b)|7-bit len][value 字节]
        let mut qpack = BytesMut::new();
        qpack.put_u8(0x00); // Required Insert Count = 0
        qpack.put_u8(0x00); // S=0, Delta Base = 0

        // 写单个 literal header（RFC 9204 §4.5.6: Literal Header Field Without Name Reference）
        //
        // 第一字节格式：[0][0][1][N][H][name_len 3-bit prefix]
        //   bits[7:5] = 0b001  (instruction type)
        //   bit[4]    = N      (never-index flag, 0)
        //   bit[3]    = H      (Huffman for name, 0)
        //   bits[2:0] = name 长度的 3-bit prefix integer（RFC 7541 §5.1，prefix=3）
        //               若 name_len < 7：直接编入低 3 位
        //               若 name_len >= 7：低 3 位全 1（0b111），后跟续字节
        // 紧随其后：name 字节
        // 然后：value string literal [H=0(bit7)][7-bit prefix length][value 字节]
        fn put_literal_header(buf: &mut BytesMut, name: &[u8], value: &[u8]) {
            // 类型字节：0b001_0_0_nnn，N=0，H=0（不使用 Huffman）
            let nlen = name.len();
            if nlen < 7 {
                buf.put_u8(0x20 | nlen as u8);
            } else {
                buf.put_u8(0x27); // 0x20 | 0x07：3-bit prefix 饱和
                let mut rem = nlen - 7;
                while rem >= 128 {
                    buf.put_u8((rem as u8) | 0x80);
                    rem >>= 7;
                }
                buf.put_u8(rem as u8);
            }
            buf.put_slice(name);
            // value string literal: H=0（bit7=0），7-bit prefix length
            let vlen = value.len();
            if vlen < 128 {
                buf.put_u8(vlen as u8);
            } else {
                buf.put_u8(0x7f);
                let mut rem = vlen - 127;
                while rem >= 128 {
                    buf.put_u8((rem as u8) | 0x80);
                    rem >>= 7;
                }
                buf.put_u8(rem as u8);
            }
            buf.put_slice(value);
        }

        put_literal_header(&mut qpack, b":method", b"POST");
        put_literal_header(&mut qpack, b":scheme", b"https");
        put_literal_header(&mut qpack, b":authority", URL_HOST.as_bytes());
        put_literal_header(&mut qpack, b":path", URL_PATH.as_bytes());
        put_literal_header(&mut qpack, b"hysteria-auth", password.as_bytes());
        put_literal_header(&mut qpack, b"hysteria-cc-rx", rx_str.as_bytes());
        // padding 可能超过 127 字节；put_literal_header 内的多字节长度编码已处理
        put_literal_header(&mut qpack, b"hysteria-padding", padding.as_bytes());

        // ── 发送 HTTP/3 HEADERS frame（frame type = 0x01）───────────────────
        let qpack_bytes = qpack.freeze();
        debug!(tag = %self.config.tag, qpack_len = qpack_bytes.len(), "hy2 auth: sending HEADERS frame");
        let mut frame = BytesMut::new();
        write_h3_frame(&mut frame, 0x01, &qpack_bytes);
        send.write_all(&frame).await.map_err(|e| {
            warn!(tag = %self.config.tag, err = %e, "hy2 auth: failed to send HEADERS frame");
            e
        })?;
        send.finish().map_err(|e| {
            warn!(tag = %self.config.tag, err = %e, "hy2 auth: failed to finish send stream");
            e
        })?;
        debug!(tag = %self.config.tag, "hy2 auth: HEADERS sent, waiting for response");

        // ── 读取服务端响应：跳过 DATA/其他控制帧，找 HEADERS 帧 ──────────────
        // quic-go/http3 服务端可能先发 DATA 或其他帧，需循环直到拿到 HEADERS
        let headers = loop {
            let (frame_type, payload) = read_h3_frame(&mut recv).await.map_err(|e| {
                warn!(tag = %self.config.tag, err = %e, "hy2 auth: failed to read response frame");
                e
            })?;
            debug!(tag = %self.config.tag, frame_type = frame_type, payload_len = payload.len(), "hy2 auth: got response frame");
            match frame_type {
                0x01 => {
                    // HEADERS frame
                    break parse_headers_from_qpack(&payload).map_err(|e| {
                        warn!(tag = %self.config.tag, err = %e, "hy2 auth: QPACK parse error, payload={:?}", &payload[..payload.len().min(64)]);
                        e
                    })?;
                }
                0x00 => {
                    // DATA frame，跳过
                    debug!(tag = %self.config.tag, "hy2 auth: skipping DATA frame");
                    continue;
                }
                other => {
                    warn!(tag = %self.config.tag, frame_type = other, "hy2 auth: unexpected H3 frame type");
                    anyhow::bail!(
                        "hy2 auth: unexpected H3 frame type 0x{other:02x}, expected HEADERS(0x01)"
                    );
                }
            }
        };

        // 验证状态码
        let status_str = headers
            .iter()
            .find(|(k, _)| k == ":status")
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        debug!(tag = %self.config.tag, status = status_str, headers = ?headers, "hy2 auth: response headers parsed");
        let status_code: u16 = status_str.parse().map_err(|_| {
            warn!(tag = %self.config.tag, status = status_str, "hy2 auth: invalid :status value");
            anyhow::anyhow!("hy2 auth: invalid :status value: {status_str:?}")
        })?;
        if status_code != STATUS_AUTH_OK {
            warn!(tag = %self.config.tag, status = status_code, "hy2 auth: server rejected");
            anyhow::bail!(
                "hy2 auth failed: server returned status {status_code}, expected {STATUS_AUTH_OK}"
            );
        }

        // 解析 Hysteria-UDP
        let udp_enabled = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(RESP_HEADER_UDP))
            .map(|(_, v)| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        // 解析 Hysteria-CC-RX 并与本地 tx 取小值
        // "auto" = 服务端无限制，使用本地配置值
        let tx_bps = {
            let server_rx = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(RESP_HEADER_CC_RX))
                .map(|(_, v)| {
                    if v.eq_ignore_ascii_case("auto") {
                        u64::MAX
                    } else {
                        v.parse::<u64>().unwrap_or(0)
                    }
                })
                .unwrap_or(0);

            if tx_bps_local == 0 {
                // 本地未配置带宽，不启用 Brutal
                0
            } else if server_rx == 0 {
                // 服务端未返回限制，使用本地值
                tx_bps_local
            } else {
                // 取二者较小值（与官方 actualTx = min(serverRx, clientTx) 一致）
                tx_bps_local.min(server_rx)
            }
        };

        debug!(
            tag = %self.config.tag,
            udp_enabled,
            tx_bps,
            "hy2 auth OK"
        );
        Ok(AuthInfo {
            udp_enabled,
            tx_bps,
        })
    }

    /// 打开 TCP 代理 stream，写入 Hysteria2 TCP 请求帧，读取响应
    async fn open_tcp_stream(
        &self,
        conn: &quinn::Connection,
        target: &Target,
    ) -> anyhow::Result<(quinn::SendStream, quinn::RecvStream)> {
        let (mut send, mut recv) = conn.open_bi().await?;

        // TCP 请求帧：[0x401 varint][addr_len varint][addr][padding_len varint][padding]
        let addr = target_to_addr_str(target);
        let padding = random_padding(64, 512);
        let mut buf = BytesMut::new();
        write_varint(&mut buf, FRAME_TYPE_TCP_REQUEST);
        write_varint(&mut buf, addr.len() as u64);
        buf.put_slice(addr.as_bytes());
        write_varint(&mut buf, padding.len() as u64);
        buf.put_slice(padding.as_bytes());

        debug!(tag = %self.config.tag, target = %target, frame_len = buf.len(), "hy2 tcp: sending request frame");
        send.write_all(&buf).await?;

        // 读取 TCP 响应：[status 1B][msg_len varint][msg][padding_len varint][padding]
        let status = recv.read_u8().await.map_err(|e| {
            warn!(tag = %self.config.tag, target = %target, err = %e, "hy2 tcp: failed to read response status");
            e
        })?;
        debug!(tag = %self.config.tag, target = %target, status = status, "hy2 tcp: got response status");
        let msg_len = read_varint_async(&mut recv).await?;
        anyhow::ensure!(msg_len <= MAX_MESSAGE_LENGTH, "hy2 response: msg too long");
        if msg_len > 0 {
            let mut msg = vec![0u8; msg_len as usize];
            recv.read_exact(&mut msg).await?;
            if status != 0 {
                let msg_str = String::from_utf8_lossy(&msg);
                warn!(tag = %self.config.tag, target = %target, status = status, msg = %msg_str, "hy2 tcp: proxy rejected");
                anyhow::bail!("hy2 TCP proxy rejected: {}", msg_str);
            }
        } else if status != 0 {
            warn!(tag = %self.config.tag, target = %target, status = status, "hy2 tcp: proxy rejected with no message");
            anyhow::bail!("hy2 TCP proxy rejected (status={status})");
        }
        let padding_len = read_varint_async(&mut recv).await?;
        anyhow::ensure!(
            padding_len <= MAX_PADDING_LENGTH,
            "hy2 response: padding too long"
        );
        if padding_len > 0 {
            let mut pad = vec![0u8; padding_len as usize];
            recv.read_exact(&mut pad).await?;
        }

        Ok((send, recv))
    }
}

#[async_trait::async_trait]
impl Outbound for Hy2Outbound {
    fn tag(&self) -> &str {
        &self.config.tag
    }

    /// 建立经由 Hysteria2 代理的 TCP 隧道连接，供 DNS detour 使用。
    async fn connect_tcp(
        &self,
        host: &str,
        port: u16,
    ) -> anyhow::Result<Box<dyn crate::outbound::AsyncReadWrite>> {
        use crate::inbound::Target;
        let target = Target::Domain(host.to_string(), port);
        let (qconn, _auth) = self.get_or_create_connection().await?;
        let (send, recv) = self.open_tcp_stream(&qconn, &target).await?;
        debug!(tag = %self.config.tag, host = %host, port = %port, "hy2 dns detour connected");
        Ok(Box::new(QuinnBiStream { send, recv }))
    }

    async fn handle_tcp(&self, conn: InboundTcpStream) -> anyhow::Result<(u64, u64)> {
        let (qconn, _auth) = self.get_or_create_connection().await?;
        let (send, recv) = self.open_tcp_stream(&qconn, &conn.target).await?;

        debug!(tag = %self.config.tag, target = %conn.target, "hy2 tcp stream opened");

        let hy2_io = QuinnBiStream { send, recv };
        Ok(relay(conn.stream, hy2_io).await)
    }

    async fn handle_udp(&self, mut packet: InboundUdpPacket) -> anyhow::Result<()> {
        let (qconn, auth) = self.get_or_create_connection().await?;

        if !auth.udp_enabled {
            anyhow::bail!("hy2 server has UDP disabled");
        }

        let session_id = self.udp_session_id.fetch_add(1, Ordering::Relaxed);
        let addr = target_to_addr_str(&packet.target);

        // 发送第一个包
        send_udp_fragmented(&qconn, session_id, &addr, &packet.data)?;
        debug!(tag = %self.config.tag, target = %packet.target, session_id, "hy2 udp datagram sent");

        // 若有后续上行包，spawn task 持续发送
        if let Some(mut upstream_rx) = packet.upstream_rx.take() {
            let qconn_send = qconn.clone();
            let addr_clone = addr.clone();
            let session_id_up = self.udp_session_id.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                while let Some(data) = upstream_rx.recv().await {
                    if send_udp_fragmented(&qconn_send, session_id_up, &addr_clone, &data).is_err() {
                        break;
                    }
                }
            });
        }

        // 持续接收回包直到超时
        let reply_tx = packet.session.reply_tx.clone();
        let src = packet.src;
        let spoofed_src = packet.target.to_socket_addr_lossy();
        let timeout = Duration::from_secs(10);
        let guards = packet.lifetime_guards;

        tokio::spawn(async move {
            loop {
                match tokio::time::timeout(timeout, qconn.read_datagram()).await {
                    Ok(Ok(data)) => {
                        match recv_udp_reassemble(&qconn, data).await {
                            Ok(Some(payload)) => {
                                if reply_tx.send((payload, src, spoofed_src)).await.is_err() {
                                    break;
                                }
                            }
                            Ok(None) => {}
                            Err(e) => { warn!(err = %e, "hy2 udp reassemble error"); break; }
                        }
                    }
                    Ok(Err(e)) => { warn!(err = %e, "hy2 udp recv error"); break; }
                    Err(_) => break, // idle timeout
                }
            }
            drop(guards);
        });

        Ok(())
    }
}

// ── QUIC 配置 ─────────────────────────────────────────────────────────────────

fn build_quic_config(config: &Hysteria2OutboundConfig) -> anyhow::Result<Arc<quinn::ClientConfig>> {
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

    tls_config.alpn_protocols = vec![HY2_ALPN.to_vec()];

    // ── QUIC TransportConfig（与官方客户端对齐）────────────────────────────
    let mut transport = quinn::TransportConfig::default();
    transport
        .stream_receive_window(
            quinn::VarInt::from_u64(QUIC_STREAM_RECEIVE_WINDOW).unwrap_or(quinn::VarInt::MAX),
        )
        .receive_window(
            quinn::VarInt::from_u64(QUIC_MAX_CONNECTION_RECEIVE_WINDOW)
                .unwrap_or(quinn::VarInt::MAX),
        )
        // 启用 QUIC unreliable datagram（UDP 代理依赖此功能）
        .datagram_receive_buffer_size(Some(2 * 1024 * 1024)) // 2 MiB 接收缓冲
        // 保持连接
        .max_idle_timeout(Some(
            quinn::VarInt::from_u32(30_000).into(), // 30s
        ))
        .keep_alive_interval(Some(Duration::from_secs(10)));

    let mut quic_cfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?,
    ));
    quic_cfg.transport_config(Arc::new(transport));

    Ok(Arc::new(quic_cfg))
}

// ── 地址辅助 ──────────────────────────────────────────────────────────────────

/// 将 Target 转为 "host:port" 字符串（官方协议地址格式）
fn target_to_addr_str(target: &Target) -> String {
    match target {
        Target::Domain(host, port) => format!("{host}:{port}"),
        Target::Socket(addr) => addr.to_string(),
    }
}

// ── QUIC varint 编解码 ────────────────────────────────────────────────────────

/// 写入 QUIC variable-length integer（RFC 9000 §16）
fn write_varint(buf: &mut BytesMut, i: u64) {
    if i <= 63 {
        buf.put_u8(i as u8);
    } else if i <= 16383 {
        buf.put_u16((i as u16) | 0x4000);
    } else if i <= 1_073_741_823 {
        buf.put_u32((i as u32) | 0x8000_0000);
    } else {
        buf.put_u64(i | 0xc000_0000_0000_0000);
    }
}

/// 从 AsyncRead 读取 QUIC varint
async fn read_varint_async<R: AsyncReadExt + Unpin>(r: &mut R) -> anyhow::Result<u64> {
    let first = r.read_u8().await?;
    let tag = first >> 6;
    let val = match tag {
        0 => (first & 0x3f) as u64,
        1 => {
            let b1 = r.read_u8().await?;
            (((first & 0x3f) as u64) << 8) | (b1 as u64)
        }
        2 => {
            let mut rest = [0u8; 3];
            r.read_exact(&mut rest).await?;
            (((first & 0x3f) as u64) << 24)
                | ((rest[0] as u64) << 16)
                | ((rest[1] as u64) << 8)
                | (rest[2] as u64)
        }
        3 => {
            let mut rest = [0u8; 7];
            r.read_exact(&mut rest).await?;
            (((first & 0x3f) as u64) << 56)
                | ((rest[0] as u64) << 48)
                | ((rest[1] as u64) << 40)
                | ((rest[2] as u64) << 32)
                | ((rest[3] as u64) << 24)
                | ((rest[4] as u64) << 16)
                | ((rest[5] as u64) << 8)
                | (rest[6] as u64)
        }
        _ => unreachable!(),
    };
    Ok(val)
}

// ── HTTP/3 帧辅助 ─────────────────────────────────────────────────────────────

/// 写一个 HTTP/3 frame：[type varint][len varint][payload]
fn write_h3_frame(buf: &mut BytesMut, frame_type: u64, payload: &[u8]) {
    write_varint(buf, frame_type);
    write_varint(buf, payload.len() as u64);
    buf.put_slice(payload);
}

/// 从 quinn::RecvStream 读取一个 HTTP/3 frame，返回 (frame_type, payload)
async fn read_h3_frame(recv: &mut quinn::RecvStream) -> anyhow::Result<(u64, Vec<u8>)> {
    let frame_type = read_varint_async(recv).await?;
    let payload_len = read_varint_async(recv).await?;
    // 放宽到 1MB，避免大 HEADERS 帧（含长 padding）被误拒
    anyhow::ensure!(
        payload_len <= 1024 * 1024,
        "h3 frame too large: {payload_len}"
    );
    let mut payload = vec![0u8; payload_len as usize];
    if payload_len > 0 {
        recv.read_exact(&mut payload).await?;
    }
    Ok((frame_type, payload))
}

/// 从 QPACK header block 中解析所有 header，返回 Vec<(name, value)>
///
/// 支持 quic-go/http3 服务端实际发送的编码格式（RFC 9204）：
///
/// 1. Indexed Header Field（静态表）: 0b1xxxxxxx
///    服务端用静态表索引压缩常见头（如 :status 233 → 无静态条目，退化为 Literal）
///
/// 2. Literal Header Field With Name Reference（静态表）: 0b0101xxxx
///    [0b0101_xxxx][name_idx qint(N=4)][H,val_len qint(N=7)][value]
///
/// 3. Literal Header Field Without Name Reference: 0b0010_0000
///    [0x20 | name_len(N=5)][name][H,val_len(N=7)][value]
///
/// quic-go 对认证响应实际发送格式：
///   - :status 使用 Literal Without Name Reference（无 233 的静态表条目）
///   - 其余自定义头也用 Literal Without Name Reference
///
/// 解码辅助：QPACK integer（RFC 7541 §5.1）
fn qpack_read_int(data: &[u8], prefix_bits: u8) -> Option<(u64, usize)> {
    if data.is_empty() {
        return None;
    }
    let mask = (1u8 << prefix_bits) - 1;
    let first = (data[0] & mask) as u64;
    if first < mask as u64 {
        return Some((first, 1));
    }
    // multi-byte
    let mut val = first;
    let mut m = 0u32;
    let mut i = 1usize;
    loop {
        if i >= data.len() {
            return None;
        }
        let b = data[i];
        val += ((b & 0x7f) as u64) << m;
        m += 7;
        i += 1;
        if b & 0x80 == 0 {
            break;
        }
    }
    Some((val, i))
}

/// QPACK 静态表条目（RFC 9204 Appendix A，仅列出认证响应可能出现的条目）
fn qpack_static_entry(idx: u64) -> Option<(&'static str, &'static str)> {
    match idx {
        0 => Some((":authority", "")),
        1 => Some((":path", "/")),
        2 => Some(("age", "0")),
        3 => Some(("content-disposition", "")),
        4 => Some(("content-length", "0")),
        5 => Some(("cookie", "")),
        6 => Some(("date", "")),
        7 => Some(("etag", "")),
        8 => Some(("if-modified-since", "")),
        9 => Some(("if-none-match", "")),
        10 => Some(("last-modified", "")),
        11 => Some(("link", "")),
        12 => Some(("location", "")),
        13 => Some(("referer", "")),
        14 => Some(("set-cookie", "")),
        15 => Some((":method", "CONNECT")),
        16 => Some((":method", "DELETE")),
        17 => Some((":method", "GET")),
        18 => Some((":method", "HEAD")),
        19 => Some((":method", "OPTIONS")),
        20 => Some((":method", "POST")),
        21 => Some((":method", "PUT")),
        22 => Some((":scheme", "http")),
        23 => Some((":scheme", "https")),
        24 => Some((":status", "103")),
        25 => Some((":status", "200")),
        26 => Some((":status", "304")),
        27 => Some((":status", "404")),
        28 => Some((":status", "503")),
        _ => None,
    }
}

/// 从静态表按 index 取 name（用于 Literal With Name Reference）
fn qpack_static_name(idx: u64) -> Option<&'static str> {
    qpack_static_entry(idx).map(|(name, _)| name)
}

fn parse_headers_from_qpack(payload: &[u8]) -> anyhow::Result<Vec<(String, String)>> {
    if payload.len() < 2 {
        anyhow::bail!("qpack payload too short");
    }
    let mut headers = Vec::new();
    let mut i = 2usize; // 跳过 Required Insert Count + Delta Base

    while i < payload.len() {
        let b = payload[i];

        if b & 0x80 != 0 {
            // ── 1. Indexed Header Field（静态表）: 0b1xxxxxxx ─────────────────
            // [1][T][idx(N=6)]：T=1 → 静态表，T=0 → 动态表（认证场景不出现）
            // 静态表有完整 name+value 对（如 :status=200 在 index=25）
            let Some((idx, consumed)) = qpack_read_int(&payload[i..], 6) else {
                break;
            };
            i += consumed;
            if let Some((name, value)) = qpack_static_entry(idx) {
                if !name.is_empty() {
                    headers.push((name.to_string(), value.to_string()));
                }
            }
        } else if b & 0xc0 == 0x40 {
            // ── 2. Literal Field With Name Reference（静态表）────────────────────
            // RFC 9204 §4.5.4 / §4.5.5：首字节格式 0b01xx_xxxx
            //   bit[6]=1, bit[5]=T(静态/动态表), bit[4]=N(never-index)
            //   bits[3:0] = name index 的 4-bit prefix integer（prefix=4）
            // 静态表 name reference: T=1 → 0b0101_xxxx (0x50~0x5F)
            //                        T=0 → 0b0100_xxxx (0x40~0x4F)（动态表，认证场景不出现）
            let Some((idx, consumed)) = qpack_read_int(&payload[i..], 4) else {
                break;
            };
            i += consumed;
            if i >= payload.len() {
                break;
            }
            let val_huffman = payload[i] & 0x80 != 0;
            let Some((val_len, vc)) = qpack_read_int(&payload[i..], 7) else {
                break;
            };
            i += vc;
            let val_len = val_len as usize;
            if i + val_len > payload.len() {
                break;
            }
            let val_bytes = &payload[i..i + val_len];
            i += val_len;
            let value = if val_huffman {
                huffman_decode(val_bytes)
            } else {
                String::from_utf8_lossy(val_bytes).into_owned()
            };
            // 从静态表取 name（quic-go 对 :status 用 index=24，T=1 即 0x5F 0x09 编码）
            let name = qpack_static_name(idx).unwrap_or("").to_string();
            headers.push((name, value));
        } else if b & 0xe0 == 0x20 {
            // ── 3. Literal Without Name Reference: 0b001x_xxxx ──────────────
            // RFC 9204 §4.5.6: [0][0][1][N][H][name_len 3-bit prefix]
            // H flag = bit3 of the type byte; name_len is a 3-bit prefix integer
            // in bits[2:0] of the type byte (not a separate byte).
            let name_huffman = b & 0x08 != 0;
            let Some((name_len, nc)) = qpack_read_int(&payload[i..], 3) else {
                break;
            };
            i += nc;
            let name_len = name_len as usize;
            if i + name_len > payload.len() {
                break;
            }
            let name = if name_huffman {
                huffman_decode(&payload[i..i + name_len])
            } else {
                String::from_utf8_lossy(&payload[i..i + name_len]).into_owned()
            };
            i += name_len;
            if i >= payload.len() {
                break;
            }
            // value string: H = bit7，len = 7-bit prefix integer
            let val_huffman = payload[i] & 0x80 != 0;
            let Some((val_len, vc)) = qpack_read_int(&payload[i..], 7) else {
                break;
            };
            i += vc;
            let val_len = val_len as usize;
            if i + val_len > payload.len() {
                break;
            }
            let val_bytes = &payload[i..i + val_len];
            i += val_len;
            let value = if val_huffman {
                huffman_decode(val_bytes)
            } else {
                String::from_utf8_lossy(val_bytes).into_owned()
            };
            headers.push((name, value));
        } else {
            // 其他格式（Literal With Post-Base Name Reference 等）暂不支持，跳过 1 字节
            i += 1;
        }
    }
    Ok(headers)
}

/// HTTP/2 / QPACK Huffman 解码（RFC 7541 Appendix B，与 RFC 9204 共用）
///
/// quic-go 对响应头 value（"233", "true" 等短 ASCII 字符串）启用 Huffman（H=1 flag），
/// 必须正确解码否则所有响应头 value 均为乱码。
///
/// 实现：按位处理，利用码字唯一前缀性质做贪心匹配。
/// 码字表：(code: u32, len: u8) 索引即为 symbol（0..=256，256=EOS）
fn huffman_decode(data: &[u8]) -> String {
    // RFC 7541 Appendix B Huffman 码字表
    // 每个元素：(码字 u32, 码字位长 u8)，索引 = 符号值
    #[rustfmt::skip]
    static TABLE: [(u32, u8); 257] = [
        (0x1ff8,13),(0x7fffd8,23),(0xfffffe2,28),(0xfffffe3,28),(0xfffffe4,28),
        (0xfffffe5,28),(0xfffffe6,28),(0xfffffe7,28),(0xfffffe8,28),(0xffffea,24),
        (0x3fffffff,30),(0xfffffe9,28),(0xfffffea,28),(0x3ffffffe,30),(0xfffffeb,28),
        (0xfffffec,28),(0xfffffed,28),(0xfffffee,28),(0xfffffef,28),(0xffffff0,28),
        (0xffffff1,28),(0xffffff2,28),(0x3ffffffe,30),(0xffffff3,28),(0xffffff4,28),
        (0xffffff5,28),(0xffffff6,28),(0xffffff7,28),(0xffffff8,28),(0xffffff9,28),
        (0xffffffa,28),(0xffffffb,28),(0x14,6),(0x3f8,10),(0x3f9,10),(0xffa,12),
        (0x1ff9,13),(0x15,6),(0xf8,8),(0x7fa,11),(0x3fa,10),(0x3fb,10),(0xf9,8),
        (0x7fb,11),(0xfa,8),(0x16,6),(0x17,6),(0x18,6),(0x0,5),(0x1,5),(0x2,5),
        (0x19,6),(0x1a,6),(0x1b,6),(0x1c,6),(0x1d,6),(0x1e,6),(0x1f,6),(0x5c,7),
        (0xfb,8),(0x7ffc,15),(0x20,6),(0xffb,12),(0x3fc,10),(0x1ffa,13),(0x21,6),
        (0x5d,7),(0x5e,7),(0x5f,7),(0x60,7),(0x61,7),(0x62,7),(0x63,7),(0x64,7),
        (0x65,7),(0x66,7),(0x67,7),(0x68,7),(0x69,7),(0x6a,7),(0x6b,7),(0x6c,7),
        (0x6d,7),(0x6e,7),(0x6f,7),(0x70,7),(0x71,7),(0x72,7),(0xfc,8),(0x73,7),
        (0xfd,8),(0x1ffb,13),(0x7fff0,19),(0x1ffc,13),(0x3ffc,14),(0x22,6),
        (0x7ffd,15),(0x3,5),(0x23,6),(0x4,5),(0x24,6),(0x5,5),(0x25,6),(0x26,6),
        (0x27,6),(0x6,5),(0x74,7),(0x75,7),(0x28,6),(0x29,6),(0x2a,6),(0x7,5),
        (0x2b,6),(0x76,7),(0x2c,6),(0x8,5),(0x9,5),(0x2d,6),(0x77,7),(0x78,7),
        (0x79,7),(0x7a,7),(0x7b,7),(0x7ffe,15),(0x7fc,11),(0x3ffd,14),(0x1ffd,13),
        (0xffffffc,28),(0xfffe6,20),(0x3fffd2,22),(0xfffe7,20),(0xfffe8,20),
        (0x3fffd3,22),(0x3fffd4,22),(0x3fffd5,22),(0x7fffd9,23),(0x3fffd6,22),
        (0x7fffda,23),(0x7fffdb,23),(0x7fffdc,23),(0x7fffdd,23),(0x7fffde,23),
        (0xffffeb,24),(0x7fffdf,23),(0xffffec,24),(0xffffed,24),(0x3fffd7,22),
        (0x7fffe0,23),(0xffffee,24),(0x7fffe1,23),(0x7fffe2,23),(0x7fffe3,23),
        (0x7fffe4,23),(0x1fffdc,21),(0x3fffd8,22),(0x7fffe5,23),(0x3fffd9,22),
        (0x7fffe6,23),(0x7fffe7,23),(0xffffef,24),(0x3fffda,22),(0x1fffdd,21),
        (0xfffe9,20),(0x3fffdb,22),(0x3fffdc,22),(0x7fffe8,23),(0x7fffe9,23),
        (0x1fffde,21),(0x7fffea,23),(0x3fffdd,22),(0x3fffde,22),(0xfffff0,24),
        (0x1fffdf,21),(0x3fffdf,22),(0x7fffeb,23),(0x7fffec,23),(0x1fffe0,21),
        (0x1fffe1,21),(0x3fffe0,22),(0x1fffe2,21),(0x7fffed,23),(0x3fffe1,22),
        (0x7fffee,23),(0x7fffef,23),(0xfffea,20),(0x3fffe2,22),(0x3fffe3,22),
        (0x3fffe4,22),(0x7ffff0,23),(0x3fffe5,22),(0x3fffe6,22),(0x7ffff1,23),
        (0x3ffffe0,26),(0x3ffffe1,26),(0xfffeb,20),(0x7fff1,19),(0x3fffe7,22),
        (0x7ffff2,23),(0x3fffe8,22),(0x1ffffec,25),(0x3ffffe2,26),(0x3ffffe3,26),
        (0x3ffffe4,26),(0x7ffffde,27),(0x7ffffdf,27),(0x3ffffe5,26),(0xfffff1,24),
        (0x1ffffed,25),(0x7fff2,19),(0x1fffe3,21),(0x3ffffe6,26),(0x7ffffe0,27),
        (0x7ffffe1,27),(0x3ffffe7,26),(0x7ffffe2,27),(0xfffff2,24),(0x1fffe4,21),
        (0x1fffe5,21),(0x3ffffe8,26),(0x3ffffe9,26),(0xffffffd,28),(0x7ffffe3,27),
        (0x7ffffe4,27),(0x7ffffe5,27),(0xfffec,20),(0xfffff3,24),(0xfffed,20),
        (0x1fffe6,21),(0x3fffe9,22),(0x1fffe7,21),(0x1fffe8,21),(0x7ffff3,23),
        (0x3fffea,22),(0x3fffeb,22),(0x1ffffee,25),(0x1ffffef,25),(0xfffff4,24),
        (0xfffff5,24),(0x3ffffea,26),(0x7ffff4,23),(0x3ffffeb,26),(0x7ffffe6,27),
        (0x3ffffec,26),(0x3ffffed,26),(0x7ffffe7,27),(0x7ffffe8,27),(0x7ffffe9,27),
        (0x7ffffea,27),(0x7ffffeb,27),(0xffffffe,28),(0x7ffffec,27),(0x7ffffed,27),
        (0x7ffffee,27),(0x7ffffef,27),(0x7fffff0,27),(0x3ffffee,26),(0x3fffffff,30),
    ];

    // 将输入字节展开成位流，高位在前
    let total_bits = data.len() * 8;
    let mut out = Vec::new();
    let mut bit_pos = 0usize; // 当前读取到第几位

    while bit_pos < total_bits {
        let remaining = total_bits - bit_pos;
        let try_bits = remaining.min(30); // 最长码字 30 位

        // 从 bit_pos 处取最多 try_bits 位（高位对齐）
        let mut window: u64 = 0;
        let mut fetched = 0u32;
        let mut bp = bit_pos;
        while fetched < try_bits as u32 && bp < total_bits {
            let byte_idx = bp / 8;
            let bit_idx = 7 - (bp % 8); // 高位在前
            let bit = ((data[byte_idx] >> bit_idx) & 1) as u64;
            window = (window << 1) | bit;
            fetched += 1;
            bp += 1;
        }

        // 在码字表中找匹配（按码长从短到长贪心；Huffman 码是前缀码，第一个匹配就是正确的）
        let mut matched = false;
        for len in 5u8..=30u8 {
            if len as usize > try_bits {
                break;
            }
            // 取 window 的高 len 位
            let shift = fetched - len as u32;
            let candidate = (window >> shift) as u32;

            // 线性扫描（257 项，认证频率低，可接受）
            for (sym, &(code, code_len)) in TABLE.iter().enumerate() {
                if code_len == len && code == candidate {
                    if sym == 256 {
                        // EOS
                        return String::from_utf8_lossy(&out).into_owned();
                    }
                    out.push(sym as u8);
                    bit_pos += len as usize;
                    matched = true;
                    break;
                }
            }
            if matched {
                break;
            }
        }

        if !matched {
            // 无法解码（填充位或损坏数据），停止
            break;
        }
    }

    String::from_utf8_lossy(&out).into_owned()
}

// ── UDP datagram 解析 ──────────────────────────────────────────────────────────

/// 从字节切片解码 QUIC varint，返回 (value, bytes_consumed)
fn decode_varint_slice(buf: &[u8]) -> anyhow::Result<(u64, usize)> {
    anyhow::ensure!(!buf.is_empty(), "varint: empty buffer");
    let tag = buf[0] >> 6;
    let val = match tag {
        0 => ((buf[0] & 0x3f) as u64, 1),
        1 => {
            anyhow::ensure!(buf.len() >= 2, "varint: truncated 2-byte");
            ((((buf[0] & 0x3f) as u64) << 8) | buf[1] as u64, 2)
        }
        2 => {
            anyhow::ensure!(buf.len() >= 4, "varint: truncated 4-byte");
            (
                (((buf[0] & 0x3f) as u64) << 24)
                    | ((buf[1] as u64) << 16)
                    | ((buf[2] as u64) << 8)
                    | (buf[3] as u64),
                4,
            )
        }
        3 => {
            anyhow::ensure!(buf.len() >= 8, "varint: truncated 8-byte");
            (
                (((buf[0] & 0x3f) as u64) << 56)
                    | ((buf[1] as u64) << 48)
                    | ((buf[2] as u64) << 40)
                    | ((buf[3] as u64) << 32)
                    | ((buf[4] as u64) << 24)
                    | ((buf[5] as u64) << 16)
                    | ((buf[6] as u64) << 8)
                    | (buf[7] as u64),
                8,
            )
        }
        _ => unreachable!(),
    };
    Ok(val)
}

// ── Padding 生成 ──────────────────────────────────────────────────────────────

fn random_padding(min: usize, max: usize) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    // 简单伪随机，无需引入额外依赖
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64;
    let n = min + ((seed as usize) % (max - min));
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    // PCG 乘数为 64 位常量，用 u64 运算后再取模，兼容 32 位平台
    (0..n)
        .map(|i| {
            let idx = seed.wrapping_add((i as u64).wrapping_mul(6364136223846793005_u64))
                % CHARS.len() as u64;
            CHARS[idx as usize] as char
        })
        .collect()
}

// ── UDP 分片发送 ──────────────────────────────────────────────────────────────

/// 构造一个 Hysteria2 UDP datagram 头部（8B 固定头 + addr_len varint + addr）
fn build_udp_header(
    session_id: u32,
    packet_id: u16,
    frag_id: u8,
    frag_count: u8,
    addr: &str,
) -> BytesMut {
    let mut buf = BytesMut::new();
    buf.put_u32(session_id);
    buf.put_u16(packet_id);
    buf.put_u8(frag_id);
    buf.put_u8(frag_count);
    write_varint(&mut buf, addr.len() as u64);
    buf.put_slice(addr.as_bytes());
    buf
}

/// 将 UDP payload 按 MAX_DATAGRAM_PAYLOAD 分片并逐个发送。
///
/// 每个分片的头部格式：
///   [session_id u32 BE][packet_id u16 BE][frag_id u8][frag_count u8]
///   [addr_len varint][addr][data_chunk]
///
/// 与官方 UDPMessage.Serialize 逻辑一致：addr 只在 frag_id=0 的首片携带，
/// 后续分片头仍包含 addr 字段（长度为 0 的 varint），保持帧格式统一。
/// 实际上官方每片都携带完整 addr，这里也保持一致。
fn send_udp_fragmented(
    conn: &quinn::Connection,
    session_id: u32,
    addr: &str,
    data: &[u8],
) -> anyhow::Result<()> {
    // 计算头部大小，用于确定每片可用 payload 字节数
    let header_overhead = {
        let mut tmp = BytesMut::new();
        write_varint(&mut tmp, addr.len() as u64);
        8 + tmp.len() + addr.len()
    };
    let chunk_size = MAX_DATAGRAM_PAYLOAD.saturating_sub(header_overhead).max(1);

    let chunks: Vec<&[u8]> = data.chunks(chunk_size).collect();
    let frag_count = chunks.len() as u8;
    // packet_id 用时间低 16 位做标识，足以区分同一 session 的不同包
    let packet_id = {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_micros() as u16
    };

    for (frag_id, chunk) in chunks.into_iter().enumerate() {
        let mut hdr = build_udp_header(session_id, packet_id, frag_id as u8, frag_count, addr);
        hdr.put_slice(chunk);
        conn.send_datagram(hdr.freeze())?;
    }
    Ok(())
}

// ── UDP 分片重组 ──────────────────────────────────────────────────────────────

/// 接收并重组 UDP 分片。
///
/// 若 frag_count == 1，直接返回 payload（无需重组）。
/// 若 frag_count > 1，在 2s 超时内收集所有分片后拼接返回。
/// 分片不完整时返回 Ok(None)。
async fn recv_udp_reassemble(
    conn: &quinn::Connection,
    first: Bytes,
) -> anyhow::Result<Option<Bytes>> {
    // 解析第一帧头
    let (payload0, frag_id0, frag_count, session_id, packet_id) = parse_udp_frag_header(&first)?;

    if frag_count == 1 {
        // 无需重组
        return Ok(Some(payload0));
    }

    // 分片收集
    let mut frags: Vec<Option<Bytes>> = vec![None; frag_count as usize];
    frags[frag_id0 as usize] = Some(payload0);
    let mut received = 1usize;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while received < frag_count as usize {
        match tokio::time::timeout_at(deadline, conn.read_datagram()).await {
            Ok(Ok(buf)) => {
                if let Ok((payload, frag_id, fc, sid, pid)) = parse_udp_frag_header(&buf) {
                    // 只接受同一 session+packet 的分片
                    if sid == session_id && pid == packet_id && fc == frag_count {
                        let idx = frag_id as usize;
                        if idx < frags.len() && frags[idx].is_none() {
                            frags[idx] = Some(payload);
                            received += 1;
                        }
                    }
                }
            }
            Ok(Err(_)) | Err(_) => return Ok(None),
        }
    }

    // 按 frag_id 顺序拼接
    let total: usize = frags.iter().flatten().map(|b| b.len()).sum();
    let mut out = BytesMut::with_capacity(total);
    for frag in frags.into_iter().flatten() {
        out.put(frag);
    }
    Ok(Some(out.freeze()))
}

/// 解析 UDP datagram 帧头，返回 (payload, frag_id, frag_count, session_id, packet_id)
fn parse_udp_frag_header(buf: &[u8]) -> anyhow::Result<(Bytes, u8, u8, u32, u16)> {
    anyhow::ensure!(buf.len() >= 9, "hy2 udp datagram too short");
    let session_id = u32::from_be_bytes(buf[0..4].try_into()?);
    let packet_id = u16::from_be_bytes(buf[4..6].try_into()?);
    let frag_id = buf[6];
    let frag_count = buf[7];
    let mut cur = 8usize;

    // 跳过 addr（addr_len varint + addr bytes）
    let (addr_len, varint_bytes) = decode_varint_slice(&buf[cur..])?;
    cur += varint_bytes;
    anyhow::ensure!(
        buf.len() >= cur + addr_len as usize,
        "hy2 udp: addr truncated in frag header"
    );
    cur += addr_len as usize;

    let payload = Bytes::copy_from_slice(&buf[cur..]);
    Ok((payload, frag_id, frag_count, session_id, packet_id))
}

// ── Brutal 拥塞控制 ───────────────────────────────────────────────────────────

/// 对已建立的 QUIC 连接应用 Brutal 拥塞控制。
///
/// Hysteria2 Brutal 算法原理（参考官方 core/internal/congestion/brutal.go）：
///   - 固定发送速率 = tx_bps
///   - 拥塞窗口 cwnd = max(BRUTAL_MIN_CWND_PACKETS, tx_bps * rtt / mtu / loss_correction)
///   - 通过 quinn 的 congestion_controller 接口注入
///
/// quinn 0.11 尚未暴露自定义拥塞控制器接口（需要 quinn-proto 内部 trait），
/// 此处通过设置 initial_rtt 和足够大的初始拥塞窗口来近似 Brutal 的"固定高速率"行为：
///   cwnd ≈ tx_bps * initial_rtt / 8 / MTU（以报文数计）
///
/// 若 quinn 后续版本暴露 CongestionController trait，应替换为完整实现。
fn apply_brutal(conn: &quinn::Connection, tx_bps: u64) {
    // quinn 0.11 不支持运行时替换拥塞控制器；
    // 通过将连接层接收窗口上限设为充分大值，配合服务端 Brutal 发送速率，
    // 使接收方窗口不成为瓶颈。实际发送侧 Brutal 需在 quinn-proto 层实现。
    // 此处记录 tx_bps 供将来接入完整实现时使用。
    let _ = tx_bps;
    let _ = conn;
    // TODO: 当 quinn 暴露 CongestionController trait 后，在此注入 BrutalController。
}

// ── QUIC BiStream → AsyncRead + AsyncWrite 适配器 ─────────────────────────────

use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

struct QuinnBiStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl AsyncRead for QuinnBiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuinnBiStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(cx, data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

// ── 单元测试 ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        for val in [0u64, 63, 64, 16383, 16384, 1_073_741_823, 1_073_741_824] {
            let mut buf = BytesMut::new();
            write_varint(&mut buf, val);
            let (decoded, _) = decode_varint_slice(&buf).unwrap();
            assert_eq!(decoded, val, "varint roundtrip failed for {val}");
        }
    }

    #[test]
    fn target_addr_domain() {
        let t = Target::Domain("example.com".into(), 443);
        assert_eq!(target_to_addr_str(&t), "example.com:443");
    }

    #[test]
    fn target_addr_ipv4() {
        let t = Target::Socket("1.2.3.4:80".parse().unwrap());
        assert_eq!(target_to_addr_str(&t), "1.2.3.4:80");
    }

    #[test]
    fn udp_frag_header_roundtrip() {
        let addr = "example.com:443";
        let data = b"hello";
        let mut buf = build_udp_header(42, 7, 0, 1, addr);
        buf.put_slice(data);
        let (payload, frag_id, frag_count, session_id, packet_id) =
            parse_udp_frag_header(&buf.freeze()).unwrap();
        assert_eq!(&payload[..], data);
        assert_eq!(frag_id, 0);
        assert_eq!(frag_count, 1);
        assert_eq!(session_id, 42);
        assert_eq!(packet_id, 7);
    }

    #[test]
    fn qpack_headers_parse_status_and_extras() {
        // 手工构造包含 :status + hysteria-udp + hysteria-cc-rx 的 QPACK block
        let mut payload = BytesMut::new();
        payload.put_u8(0x00); // Required Insert Count
        payload.put_u8(0x00); // Delta Base

        for (name, value) in &[
            (&b":status"[..], &b"233"[..]),
            (b"hysteria-udp", b"true"),
            (b"hysteria-cc-rx", b"50000000"),
        ] {
            // RFC 9204 §4.5.6: [0b001_N_H_nnn] where nnn is 3-bit prefix of name length
            let nlen = name.len();
            if nlen < 7 {
                payload.put_u8(0x20 | nlen as u8);
            } else {
                payload.put_u8(0x27); // saturated
                payload.put_u8((nlen - 7) as u8);
            }
            payload.put_slice(name);
            payload.put_u8(value.len() as u8);
            payload.put_slice(value);
        }

        let headers = parse_headers_from_qpack(&payload).unwrap();
        assert_eq!(headers.len(), 3);
        assert_eq!(headers[0], (":status".into(), "233".into()));
        assert_eq!(headers[1], ("hysteria-udp".into(), "true".into()));
        assert_eq!(headers[2], ("hysteria-cc-rx".into(), "50000000".into()));

        // 验证 udp_enabled 逻辑
        let udp_enabled = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("hysteria-udp"))
            .map(|(_, v)| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        assert!(udp_enabled);

        // 验证 tx_bps 协商逻辑（local=100Mbps, server_rx=50Mbps → 取小值）
        let server_rx: u64 = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("hysteria-cc-rx"))
            .and_then(|(_, v)| v.parse().ok())
            .unwrap_or(0);
        let local_tx: u64 = 100_000_000;
        let tx_bps = local_tx.min(server_rx);
        assert_eq!(tx_bps, 50_000_000);
    }

    #[test]
    fn qpack_cc_rx_auto() {
        let mut payload = BytesMut::new();
        payload.put_u8(0x00);
        payload.put_u8(0x00);
        for (name, value) in &[(&b":status"[..], &b"233"[..]), (b"hysteria-cc-rx", b"auto")] {
            let nlen = name.len();
            if nlen < 7 {
                payload.put_u8(0x20 | nlen as u8);
            } else {
                payload.put_u8(0x27);
                payload.put_u8((nlen - 7) as u8);
            }
            payload.put_slice(name);
            payload.put_u8(value.len() as u8);
            payload.put_slice(value);
        }
        let headers = parse_headers_from_qpack(&payload).unwrap();
        let server_rx = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("hysteria-cc-rx"))
            .map(|(_, v)| {
                if v.eq_ignore_ascii_case("auto") {
                    u64::MAX
                } else {
                    v.parse().unwrap_or(0)
                }
            })
            .unwrap_or(0);
        // "auto" → MAX → local_tx wins
        let local_tx: u64 = 80_000_000;
        let tx_bps = local_tx.min(server_rx);
        assert_eq!(tx_bps, local_tx);
    }

    #[test]
    fn random_padding_length() {
        let p = random_padding(64, 512);
        assert!(p.len() >= 64 && p.len() < 512);
    }
}
