//! AnyTLS 出站实现
//!
//! 协议参考：https://github.com/anytls/anytls-go/blob/main/docs/protocol.md
//!
//! ## 架构
//! ```text
//! TCP/UDP -> AnyTlsStream -> AnyTlsSession -> TLS -> TCP
//! ```
//!
//! ## 认证流程
//! TLS 握手完成后，客户端发送：
//! `[sha256(password) 32B][padding_len u16 BE][padding(全0) ...]`
//!
//! ## 会话层帧格式
//! `[cmd u8][streamId u32 BE][data_len u16 BE][data ...]`
//!
//! ## 会话复用
//! 多个 Stream 共用同一 TLS 连接。Stream 关闭后 Session 回到空闲池备用。
//!
//! ## UDP 处理
//! UDP 使用 sing-box UDP-over-TCP v2 协议承载：
//! 向服务端发起目标为 `sp.v2.udp-over-tcp.arpa:443` 的 TCP 代理请求，
//! 然后在该 Stream 上运行 UoT v2 协议封装 UDP 包。

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use md5::Md5;
use rand::Rng;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Notify};
use tracing::{debug, warn};

use crate::{
    config::outbound::AnyTlsOutboundConfig,
    inbound::{InboundTcpStream, InboundUdpPacket, Target},
    outbound::{apply_mark_to_tcp, relay, set_tcp_opts, tls::build_client_config, Outbound},
};

// ── 协议常量 ──────────────────────────────────────────────────────────────────

const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_ALERT: u8 = 5;
const CMD_UPDATE_PADDING: u8 = 6;
const CMD_SYNACK: u8 = 7;
const CMD_HEART_REQUEST: u8 = 8;
const CMD_HEART_RESPONSE: u8 = 9;
const CMD_SERVER_SETTINGS: u8 = 10;

/// 帧头开销：cmd(1) + streamId(4) + data_len(2)
const FRAME_HEADER_SIZE: usize = 7;

/// UoT v2 魔法地址（目标为此地址的 TCP 请求走 UoT v2 协议）
const UOT_MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";
const UOT_MAGIC_PORT: u16 = 443;

/// SOCKS5 地址类型
const SOCKS_ATYP_IPV4: u8 = 0x01;
const SOCKS_ATYP_DOMAIN: u8 = 0x03;
const SOCKS_ATYP_IPV6: u8 = 0x04;

/// padding 检查标记
const PADDING_CHECK_MARK: i32 = -1;

// ── 默认 Padding 方案 ─────────────────────────────────────────────────────────

const DEFAULT_PADDING_SCHEME: &[u8] = b"stop=8\n\
0=30-30\n\
1=100-400\n\
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n\
3=9-9,500-1000\n\
4=500-1000\n\
5=500-1000\n\
6=500-1000\n\
7=500-1000";

// ── PaddingScheme ─────────────────────────────────────────────────────────────

#[derive(Clone)]
struct PaddingScheme {
    stop: u32,
    /// 原始 scheme 文本（每次需要重新随机化范围）
    raw: Vec<u8>,
    md5_hex: String,
}

impl PaddingScheme {
    fn parse(raw: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(raw).ok()?;
        let mut stop = 0u32;
        let mut has_stop = false;

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (key, val) = line.split_once('=')?;
            if key.trim() == "stop" {
                stop = val.trim().parse().ok()?;
                has_stop = true;
            }
        }
        if !has_stop {
            return None;
        }

        let md5_hex = format!("{:x}", Md5::digest(raw));
        Some(PaddingScheme {
            stop,
            raw: raw.to_vec(),
            md5_hex,
        })
    }

    /// 为指定包号生成本次实际尺寸列表（每次调用都重新随机化）
    fn generate_sizes(&self, pkt: u32) -> Vec<i32> {
        let text = match std::str::from_utf8(&self.raw) {
            Ok(s) => s,
            Err(_) => return vec![],
        };
        let key = pkt.to_string();
        let prefix = format!("{}=", key);
        for line in text.lines() {
            if line.trim().starts_with(&prefix) {
                if let Some(val) = line.trim().get(prefix.len()..) {
                    return Self::parse_sizes(val.trim());
                }
            }
        }
        vec![]
    }

    fn parse_sizes(s: &str) -> Vec<i32> {
        let mut out = Vec::new();
        for part in s.split(',') {
            let part = part.trim();
            if part == "c" {
                out.push(PADDING_CHECK_MARK);
            } else if let Some((lo, hi)) = part.split_once('-') {
                let lo: i32 = lo.trim().parse().unwrap_or(0);
                let hi: i32 = hi.trim().parse().unwrap_or(0);
                let (lo, hi) = (lo.min(hi), lo.max(hi));
                if lo > 0 && hi > 0 {
                    if lo == hi {
                        out.push(lo);
                    } else {
                        let size = rand::thread_rng().gen_range(lo..hi);
                        out.push(size);
                    }
                }
            }
        }
        out
    }
}

// ── ClientPadding：客户端级别共享，可被服务端更新 ─────────────────────────────

struct ClientPadding {
    scheme: std::sync::RwLock<PaddingScheme>,
}

impl ClientPadding {
    fn new() -> Self {
        let scheme =
            PaddingScheme::parse(DEFAULT_PADDING_SCHEME).expect("default padding should parse");
        ClientPadding {
            scheme: std::sync::RwLock::new(scheme),
        }
    }

    fn get(&self) -> PaddingScheme {
        self.scheme.read().unwrap().clone()
    }

    fn update(&self, raw: &[u8]) -> bool {
        if let Some(new_scheme) = PaddingScheme::parse(raw) {
            *self.scheme.write().unwrap() = new_scheme;
            true
        } else {
            false
        }
    }

    fn md5(&self) -> String {
        self.scheme.read().unwrap().md5_hex.clone()
    }
}

// ── 向写任务发送的消息 ────────────────────────────────────────────────────────

enum WriteMsg {
    /// 控制帧字节（在缓冲模式下也直接写，不走 padding；如 FIN / HEART）
    Control(Vec<u8>),
    /// 数据帧字节（在缓冲模式下先缓冲）
    Frame(Vec<u8>),
    /// 停止缓冲，开始实际写出（附带触发帧，走 padding）
    Flush(Vec<u8>),
    /// 关闭连接
    Close,
}

// ── AnyTlsSession ─────────────────────────────────────────────────────────────

pub struct AnyTlsSession {
    /// 向写任务发送帧
    write_tx: mpsc::UnboundedSender<WriteMsg>,
    /// 活跃 Stream 数据通道表
    streams: Arc<tokio::sync::Mutex<HashMap<u32, mpsc::UnboundedSender<Bytes>>>>,
    /// 下一个 Stream ID（从 1 开始）
    next_stream_id: AtomicU32,
    /// 包计数器（用于 padding 逻辑）
    pkt_counter: AtomicU32,
    /// 服务端协议版本
    peer_version: AtomicU8,
    /// 是否已关闭
    is_closed: AtomicBool,
    /// 关闭通知
    closed_notify: Arc<Notify>,
    /// 共享 padding scheme
    padding: Arc<ClientPadding>,
    /// 当前是否处于缓冲模式（cmdSettings 发出前缓冲）
    buffering: AtomicBool,
    /// Session 序号
    pub seq: u64,
    /// 进入空闲池的时间
    pub idle_since: Mutex<Option<Instant>>,
}

impl AnyTlsSession {
    /// 创建 Session 并启动收发任务
    pub fn new(
        conn: Box<dyn crate::outbound::AsyncReadWrite>,
        padding: Arc<ClientPadding>,
        seq: u64,
    ) -> Arc<Self> {
        let (write_tx, write_rx) = mpsc::unbounded_channel::<WriteMsg>();
        let streams: Arc<tokio::sync::Mutex<HashMap<u32, mpsc::UnboundedSender<Bytes>>>> =
            Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let closed_notify = Arc::new(Notify::new());
        let (read_half, write_half) = tokio::io::split(conn);

        let session = Arc::new(AnyTlsSession {
            write_tx,
            streams: streams.clone(),
            next_stream_id: AtomicU32::new(0),
            pkt_counter: AtomicU32::new(0),
            peer_version: AtomicU8::new(1),
            is_closed: AtomicBool::new(false),
            closed_notify: closed_notify.clone(),
            padding,
            buffering: AtomicBool::new(true),
            seq,
            idle_since: Mutex::new(None),
        });

        // spawn 写任务
        tokio::spawn(write_task(write_half, write_rx, session.clone()));
        // spawn 接收循环
        tokio::spawn(recv_loop(read_half, session.clone()));

        session
    }

    pub fn is_closed(&self) -> bool {
        self.is_closed.load(Ordering::Acquire)
    }

    pub fn close(&self) {
        if !self.is_closed.swap(true, Ordering::AcqRel) {
            self.closed_notify.notify_waiters();
            let _ = self.write_tx.send(WriteMsg::Close);
        }
    }

    /// 构建帧字节序列
    fn build_frame(cmd: u8, sid: u32, data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(FRAME_HEADER_SIZE + data.len());
        buf.push(cmd);
        buf.extend_from_slice(&sid.to_be_bytes());
        buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
        buf.extend_from_slice(data);
        buf
    }

    /// 发送控制帧（FIN / HEART_RESPONSE 等，不走 padding 路径）
    fn write_control(&self, cmd: u8, sid: u32, data: &[u8]) -> std::io::Result<()> {
        let frame = Self::build_frame(cmd, sid, data);
        self.write_tx
            .send(WriteMsg::Control(frame))
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))
    }

    /// 发送数据帧（PSH）
    fn write_data(&self, sid: u32, data: &[u8]) -> std::io::Result<usize> {
        if self.is_closed() {
            return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        }
        let frame = Self::build_frame(CMD_PSH, sid, data);
        let len = data.len();
        self.write_tx
            .send(WriteMsg::Flush(frame))
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
        Ok(len)
    }

    /// 打开新 Stream
    pub async fn open_stream(self: &Arc<Self>) -> anyhow::Result<AnyTlsStream> {
        if self.is_closed() {
            anyhow::bail!("session is closed");
        }

        let sid = self.next_stream_id.fetch_add(1, Ordering::SeqCst) + 1;

        // 首个 Stream（sid==1）：先在缓冲模式下发 cmdSettings
        if sid == 1 {
            let md5 = self.padding.md5();
            let settings = format!("v=2\nclient=reflex/anytls\npadding-md5={}", md5);
            // buffering=true，Frame 消息被写任务缓冲
            let _ = self.write_tx.send(WriteMsg::Frame(
                Self::build_frame(CMD_SETTINGS, 0, settings.as_bytes()),
            ));
        }

        // 注册 stream 数据通道
        let (data_tx, data_rx) = mpsc::unbounded_channel::<Bytes>();
        self.streams.lock().await.insert(sid, data_tx);

        // cmdSYN 也加入缓冲（与 cmdSettings 合批，等 addr 写入触发 Flush）
        // 这样 pkt-0 = cmdSettings + cmdSYN + cmdPSH(addr) 合为一个 TLS 写调用，
        // 与 anytls 协议要求一致（"pkt1 包含 cmdSettings + cmdSYN + cmdPSH(addr)"）
        let _ = self.write_tx.send(WriteMsg::Frame(
            Self::build_frame(CMD_SYN, sid, &[]),
        ));
        // 标记 buffering=false：下一次 write_data（写代理目标地址）会触发 Flush
        self.buffering.store(false, Ordering::Release);

        Ok(AnyTlsStream {
            sid,
            session: self.clone(),
            data_rx,
            read_buf: Bytes::new(),
        })
    }

    /// 关闭 Stream（发 cmdFIN）
    fn close_stream_local(&self, sid: u32) {
        if !self.is_closed() {
            let _ = self.write_control(CMD_FIN, sid, &[]);
        }
        let streams = self.streams.clone();
        tokio::spawn(async move {
            streams.lock().await.remove(&sid);
        });
    }
}

// ── 写任务 ────────────────────────────────────────────────────────────────────

async fn write_task<W: AsyncWrite + Unpin + Send + 'static>(
    mut writer: W,
    mut rx: mpsc::UnboundedReceiver<WriteMsg>,
    session: Arc<AnyTlsSession>,
) {
    let mut pending: Vec<u8> = Vec::new();
    let mut buffering = true;

    while let Some(msg) = rx.recv().await {
        match msg {
            WriteMsg::Close => {
                let _ = writer.shutdown().await;
                return;
            }
            WriteMsg::Control(data) => {
                // 控制帧（FIN/HEART 等）直接写，不走 padding，不影响缓冲状态
                if writer.write_all(&data).await.is_err() {
                    session.close();
                    return;
                }
            }
            WriteMsg::Frame(data) => {
                if buffering {
                    pending.extend_from_slice(&data);
                } else {
                    let out = apply_padding(&session, data);
                    if writer.write_all(&out).await.is_err() {
                        session.close();
                        return;
                    }
                }
            }
            WriteMsg::Flush(data) => {
                // 停止缓冲，flush pending + current data 一起发出（走 padding）
                buffering = false;
                let combined = if !pending.is_empty() {
                    let mut c = std::mem::take(&mut pending);
                    c.extend_from_slice(&data);
                    c
                } else {
                    data
                };
                let out = apply_padding(&session, combined);
                if writer.write_all(&out).await.is_err() {
                    session.close();
                    return;
                }
            }
        }
    }
    let _ = writer.shutdown().await;
}

/// 对待发字节序列应用 padding 逻辑（参考 anytls-go session.go writeConn）
fn apply_padding(session: &AnyTlsSession, data: Vec<u8>) -> Vec<u8> {
    let pkt = session.pkt_counter.fetch_add(1, Ordering::SeqCst);
    let padding = session.padding.get();

    if pkt >= padding.stop {
        return data;
    }

    let sizes = padding.generate_sizes(pkt);
    if sizes.is_empty() {
        return data;
    }

    let mut out: Vec<u8> = Vec::with_capacity(data.len() + 512);
    let mut remaining = data;

    for size in sizes {
        if size == PADDING_CHECK_MARK {
            if remaining.is_empty() {
                break;
            } else {
                continue;
            }
        }
        let size = size as usize;
        let rem_len = remaining.len();

        if rem_len > size {
            // 这个包全是 payload
            out.extend_from_slice(&remaining[..size]);
            remaining = remaining[size..].to_vec();
        } else if rem_len > 0 {
            // payload 放完了，用 cmdWaste 填充到 size
            let padding_data_len = size.saturating_sub(rem_len + FRAME_HEADER_SIZE);
            out.extend_from_slice(&remaining);
            remaining.clear();
            if padding_data_len > 0 {
                // waste frame: [CMD_WASTE][streamId=0 4B][len 2B][zeros...]
                out.push(CMD_WASTE);
                out.extend_from_slice(&0u32.to_be_bytes());
                out.extend_from_slice(&(padding_data_len as u16).to_be_bytes());
                out.extend(std::iter::repeat(0u8).take(padding_data_len));
            }
        } else {
            // 纯 padding 包
            out.push(CMD_WASTE);
            out.extend_from_slice(&0u32.to_be_bytes());
            out.extend_from_slice(&(size as u16).to_be_bytes());
            out.extend(std::iter::repeat(0u8).take(size));
        }
    }

    if !remaining.is_empty() {
        out.extend_from_slice(&remaining);
    }
    out
}

// ── 接收循环 ──────────────────────────────────────────────────────────────────

async fn recv_loop<R: AsyncRead + Unpin + Send + 'static>(
    mut reader: R,
    session: Arc<AnyTlsSession>,
) {
    let mut hdr = [0u8; FRAME_HEADER_SIZE];

    loop {
        if session.is_closed() {
            return;
        }

        if reader.read_exact(&mut hdr).await.is_err() {
            session.close();
            return;
        }

        let cmd = hdr[0];
        let sid = u32::from_be_bytes(hdr[1..5].try_into().unwrap());
        let data_len = u16::from_be_bytes([hdr[5], hdr[6]]) as usize;

        match cmd {
            CMD_PSH => {
                if data_len > 0 {
                    let mut buf = vec![0u8; data_len];
                    if reader.read_exact(&mut buf).await.is_err() {
                        session.close();
                        return;
                    }
                    let streams = session.streams.lock().await;
                    if let Some(tx) = streams.get(&sid) {
                        let _ = tx.send(Bytes::from(buf));
                    }
                }
            }
            CMD_FIN => {
                session.streams.lock().await.remove(&sid);
            }
            CMD_WASTE | CMD_SYN => {
                // CMD_WASTE: 丢弃数据；CMD_SYN: 客户端侧不应收到
                if data_len > 0 {
                    let mut buf = vec![0u8; data_len];
                    if reader.read_exact(&mut buf).await.is_err() {
                        session.close();
                        return;
                    }
                }
            }
            CMD_ALERT => {
                if data_len > 0 {
                    let mut buf = vec![0u8; data_len];
                    if reader.read_exact(&mut buf).await.is_err() {
                        session.close();
                        return;
                    }
                    warn!(
                        seq = session.seq,
                        msg = %String::from_utf8_lossy(&buf),
                        "anytls server alert"
                    );
                }
                session.close();
                return;
            }
            CMD_UPDATE_PADDING => {
                if data_len > 0 {
                    let mut raw = vec![0u8; data_len];
                    if reader.read_exact(&mut raw).await.is_err() {
                        session.close();
                        return;
                    }
                    if session.padding.update(&raw) {
                        debug!(seq = session.seq, "anytls padding scheme updated");
                    } else {
                        warn!(seq = session.seq, "anytls padding scheme update failed (invalid)");
                    }
                }
            }
            CMD_SYNACK => {
                // v2：服务端确认 stream 打开
                if data_len > 0 {
                    let mut buf = vec![0u8; data_len];
                    if reader.read_exact(&mut buf).await.is_err() {
                        session.close();
                        return;
                    }
                    // 携带数据表示错误，关闭对应 stream
                    let streams = session.streams.lock().await;
                    if let Some(tx) = streams.get(&sid) {
                        // 关闭发送端使 stream 读到 EOF
                        drop(tx.clone());
                    }
                    drop(streams);
                    session.streams.lock().await.remove(&sid);
                }
            }
            CMD_HEART_REQUEST => {
                let _ = session
                    .write_tx
                    .send(WriteMsg::Control(AnyTlsSession::build_frame(
                        CMD_HEART_RESPONSE,
                        sid,
                        &[],
                    )));
            }
            CMD_HEART_RESPONSE => { /* 忽略 */ }
            CMD_SERVER_SETTINGS => {
                if data_len > 0 {
                    let mut buf = vec![0u8; data_len];
                    if reader.read_exact(&mut buf).await.is_err() {
                        session.close();
                        return;
                    }
                    if let Ok(text) = std::str::from_utf8(&buf) {
                        for line in text.lines() {
                            if let Some(v) = line.strip_prefix("v=") {
                                if let Ok(ver) = v.trim().parse::<u8>() {
                                    session.peer_version.store(ver, Ordering::Release);
                                }
                            }
                        }
                    }
                }
            }
            _ => {
                // 未知命令，读出数据丢弃
                if data_len > 0 {
                    let mut buf = vec![0u8; data_len];
                    if reader.read_exact(&mut buf).await.is_err() {
                        session.close();
                        return;
                    }
                }
            }
        }
    }
}

// ── AnyTlsStream ─────────────────────────────────────────────────────────────

pub struct AnyTlsStream {
    sid: u32,
    session: Arc<AnyTlsSession>,
    data_rx: mpsc::UnboundedReceiver<Bytes>,
    read_buf: Bytes,
}

impl Drop for AnyTlsStream {
    fn drop(&mut self) {
        self.session.close_stream_local(self.sid);
    }
}

impl AsyncRead for AnyTlsStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // 先消费 read_buf
        if !self.read_buf.is_empty() {
            let n = self.read_buf.len().min(buf.remaining());
            buf.put_slice(&self.read_buf[..n]);
            self.read_buf = self.read_buf.slice(n..);
            return std::task::Poll::Ready(Ok(()));
        }

        match self.data_rx.poll_recv(cx) {
            std::task::Poll::Ready(Some(data)) => {
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.read_buf = data.slice(n..);
                }
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(None) => {
                // channel 关闭 → EOF 或 session 关闭
                if self.session.is_closed() {
                    std::task::Poll::Ready(Err(std::io::Error::from(
                        std::io::ErrorKind::ConnectionReset,
                    )))
                } else {
                    std::task::Poll::Ready(Ok(())) // 正常 EOF
                }
            }
            std::task::Poll::Pending => {
                if self.session.is_closed() {
                    std::task::Poll::Ready(Err(std::io::Error::from(
                        std::io::ErrorKind::ConnectionReset,
                    )))
                } else {
                    std::task::Poll::Pending
                }
            }
        }
    }
}

impl AsyncWrite for AnyTlsStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Ready(self.session.write_data(self.sid, data))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.session.close_stream_local(self.sid);
        std::task::Poll::Ready(Ok(()))
    }
}

// ── AnyTlsClient ─────────────────────────────────────────────────────────────

struct ClientInner {
    /// 空闲会话池（按 seq 升序，pop 时取最后一个=最新的）
    idle_sessions: Vec<Arc<AnyTlsSession>>,
    /// 所有活跃会话
    all_sessions: HashMap<u64, Arc<AnyTlsSession>>,
    session_seq: u64,
}

pub struct AnyTlsClient {
    inner: Arc<tokio::sync::Mutex<ClientInner>>,
    padding: Arc<ClientPadding>,
    config: AnyTlsOutboundConfig,
    tls_config: Arc<rustls::ClientConfig>,
    routing_mark: u32,
    idle_timeout: Duration,
    min_idle_session: usize,
}

impl AnyTlsClient {
    pub fn new(
        config: AnyTlsOutboundConfig,
        tls_config: Arc<rustls::ClientConfig>,
        routing_mark: u32,
    ) -> anyhow::Result<Arc<Self>> {
        let idle_check_interval = config
            .idle_session_check_interval
            .as_deref()
            .and_then(|s| crate::config::outbound::parse_duration(s).ok())
            .unwrap_or(Duration::from_secs(30));

        let idle_timeout = config
            .idle_session_timeout
            .as_deref()
            .and_then(|s| crate::config::outbound::parse_duration(s).ok())
            .unwrap_or(Duration::from_secs(60));

        let min_idle_session = config.min_idle_session as usize;

        let client = Arc::new(Self {
            inner: Arc::new(tokio::sync::Mutex::new(ClientInner {
                idle_sessions: Vec::new(),
                all_sessions: HashMap::new(),
                session_seq: 0,
            })),
            padding: Arc::new(ClientPadding::new()),
            config,
            tls_config,
            routing_mark,
            idle_timeout,
            min_idle_session,
        });

        // spawn 空闲清理任务
        let c = client.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(idle_check_interval).await;
                c.cleanup_idle().await;
            }
        });

        Ok(client)
    }

    /// 获取或创建可用 Session
    async fn get_or_create_session(&self) -> anyhow::Result<Arc<AnyTlsSession>> {
        // 尝试从空闲池获取最新的 session
        {
            let mut inner = self.inner.lock().await;
            while let Some(s) = inner.idle_sessions.pop() {
                if !s.is_closed() {
                    debug!(seq = s.seq, "anytls reuse idle session");
                    return Ok(s);
                }
            }
        }
        self.create_session().await
    }

    async fn create_session(&self) -> anyhow::Result<Arc<AnyTlsSession>> {
        let conn = self.dial_tls().await?;
        let seq = {
            let mut inner = self.inner.lock().await;
            inner.session_seq += 1;
            inner.session_seq
        };
        let session = AnyTlsSession::new(conn, self.padding.clone(), seq);

        {
            let mut inner = self.inner.lock().await;
            inner.all_sessions.insert(seq, session.clone());
        }

        // 注册清理 hook
        {
            let inner = self.inner.clone();
            let s = session.clone();
            tokio::spawn(async move {
                s.closed_notify.notified().await;
                let mut g = inner.lock().await;
                g.all_sessions.remove(&s.seq);
                g.idle_sessions.retain(|x| x.seq != s.seq);
            });
        }

        debug!(seq, "anytls new session created");
        Ok(session)
    }

    async fn dial_tls(&self) -> anyhow::Result<Box<dyn crate::outbound::AsyncReadWrite>> {
        let addr = tokio::net::lookup_host(format!(
            "{}:{}",
            self.config.server, self.config.server_port
        ))
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("DNS failed for {}", self.config.server))?;

        let tcp = TcpStream::connect(addr).await?;
        set_tcp_opts(&tcp)?;
        apply_mark_to_tcp(&tcp, self.routing_mark)?;

        let sni = self
            .config
            .tls
            .server_name
            .as_deref()
            .unwrap_or(&self.config.server);
        let mut tls_stream =
            crate::outbound::tls::connect_tls(tcp, sni, self.tls_config.clone()).await?;

        // 认证帧：sha256(password)[32] + padding_len[2] + padding
        let pwd_hash = Sha256::digest(self.config.password.as_bytes());
        let padding = self.padding.get();
        let padding_sizes = padding.generate_sizes(0);
        let padding_len = padding_sizes.first().copied().unwrap_or(0).max(0) as usize;

        let mut auth = Vec::with_capacity(32 + 2 + padding_len);
        auth.extend_from_slice(&pwd_hash);
        auth.extend_from_slice(&(padding_len as u16).to_be_bytes());
        auth.extend(std::iter::repeat(0u8).take(padding_len));

        tls_stream.write_all(&auth).await?;
        tls_stream.flush().await?;

        Ok(Box::new(tls_stream))
    }

    /// 创建代理 Stream（TCP）
    pub async fn create_proxy(&self, target: &Target) -> anyhow::Result<AnyTlsStream> {
        let session = self.get_or_create_session().await?;
        let mut stream = session.open_stream().await?;
        // 发送目标地址（SOCKS5 addr 格式）
        let addr = encode_socks_addr(target);
        stream.write_all(&addr).await?;
        Ok(stream)
    }

    /// Stream 关闭后将 Session 放回空闲池
    pub async fn return_idle(&self, session: Arc<AnyTlsSession>) {
        if session.is_closed() {
            return;
        }
        *session.idle_since.lock().unwrap() = Some(Instant::now());
        let mut inner = self.inner.lock().await;
        // 按 seq 升序插入（pop 时取最大 seq，即最新的）
        let pos = inner
            .idle_sessions
            .partition_point(|s| s.seq < session.seq);
        inner.idle_sessions.insert(pos, session);
    }

    /// 清理超时空闲会话
    async fn cleanup_idle(&self) {
        let timeout = self.idle_timeout;
        let min_idle = self.min_idle_session;

        let mut inner = self.inner.lock().await;
        let idle = &mut inner.idle_sessions;
        let total = idle.len();

        // 保留最新的 min_idle 个（索引最高的）
        let keep_from = if total > min_idle { total - min_idle } else { 0 };

        let mut to_close: Vec<Arc<AnyTlsSession>> = Vec::new();
        for (i, s) in idle.iter().enumerate() {
            if i >= keep_from {
                break;
            }
            let expired = s
                .idle_since
                .lock()
                .unwrap()
                .map(|t| t.elapsed() > timeout)
                .unwrap_or(false);
            if expired {
                to_close.push(s.clone());
            }
        }
        idle.retain(|s| !to_close.iter().any(|c| c.seq == s.seq));
        drop(inner);

        for s in to_close {
            debug!(seq = s.seq, "anytls cleanup idle session");
            s.close();
        }
    }
}

// ── SOCKS5 地址编码 ───────────────────────────────────────────────────────────

fn encode_socks_addr(target: &Target) -> Vec<u8> {
    let mut buf = Vec::new();
    match target {
        Target::Domain(host, port) => {
            buf.push(SOCKS_ATYP_DOMAIN);
            buf.push(host.len() as u8);
            buf.extend_from_slice(host.as_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
        }
        Target::Socket(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                buf.push(SOCKS_ATYP_IPV4);
                buf.extend_from_slice(&ip.octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
            IpAddr::V6(ip) => {
                buf.push(SOCKS_ATYP_IPV6);
                buf.extend_from_slice(&ip.octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
        },
    }
    buf
}

// ── UDP-over-TCP v2 协议 ──────────────────────────────────────────────────────
//
// sing-box UoT v2 协议格式（在 anytls Stream 上）：
//
// 1. 客户端发送请求头（标识真实 UDP 目标）：
//    [version=2 u8][atyp u8][addr ...][port u16]
//
// 2. 每个 UDP 数据包（双向，不含 version 前缀）：
//    [atyp u8][addr ...][port u16][data_len u16][data ...]

fn build_uot_request(target: &Target) -> Vec<u8> {
    let mut buf = vec![2u8]; // version = 2
    write_socks_addr_to(&mut buf, target);
    buf
}

fn build_uot_packet(target: &Target, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    write_socks_addr_to(&mut buf, target);
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
    buf
}

fn write_socks_addr_to(buf: &mut Vec<u8>, target: &Target) {
    match target {
        Target::Domain(host, port) => {
            buf.push(SOCKS_ATYP_DOMAIN);
            buf.push(host.len() as u8);
            buf.extend_from_slice(host.as_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
        }
        Target::Socket(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                buf.push(SOCKS_ATYP_IPV4);
                buf.extend_from_slice(&ip.octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
            IpAddr::V6(ip) => {
                buf.push(SOCKS_ATYP_IPV6);
                buf.extend_from_slice(&ip.octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
        },
    }
}

async fn read_uot_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> anyhow::Result<(Target, Bytes)> {
    let mut atyp = [0u8; 1];
    reader.read_exact(&mut atyp).await?;

    let target = match atyp[0] {
        SOCKS_ATYP_IPV4 => {
            let mut buf = [0u8; 6]; // ip(4) + port(2)
            reader.read_exact(&mut buf).await?;
            let ip = std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Target::Socket(SocketAddr::new(IpAddr::V4(ip), port))
        }
        SOCKS_ATYP_IPV6 => {
            let mut buf = [0u8; 18]; // ip(16) + port(2)
            reader.read_exact(&mut buf).await?;
            let ip: [u8; 16] = buf[..16].try_into().unwrap();
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Target::Socket(SocketAddr::new(
                IpAddr::V6(std::net::Ipv6Addr::from(ip)),
                port,
            ))
        }
        SOCKS_ATYP_DOMAIN => {
            let mut dlen = [0u8; 1];
            reader.read_exact(&mut dlen).await?;
            let mut domain = vec![0u8; dlen[0] as usize];
            reader.read_exact(&mut domain).await?;
            let mut port_buf = [0u8; 2];
            reader.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);
            Target::Domain(String::from_utf8(domain)?, port)
        }
        other => anyhow::bail!("unknown UoT atyp: 0x{:02x}", other),
    };

    let mut len_buf = [0u8; 2];
    reader.read_exact(&mut len_buf).await?;
    let data_len = u16::from_be_bytes(len_buf) as usize;
    let mut data = vec![0u8; data_len];
    reader.read_exact(&mut data).await?;

    Ok((target, Bytes::from(data)))
}

// ── AnyTlsOutbound ────────────────────────────────────────────────────────────

pub struct AnyTlsOutbound {
    config: AnyTlsOutboundConfig,
    client: Arc<AnyTlsClient>,
}

impl AnyTlsOutbound {
    pub fn new(config: AnyTlsOutboundConfig) -> anyhow::Result<Self> {
        let tls_config = build_client_config(&config.tls)?;
        let client = AnyTlsClient::new(config.clone(), tls_config, 0)?;
        Ok(Self { config, client })
    }

    pub fn with_mark(self, mark: u32) -> Self {
        let tls_config =
            build_client_config(&self.config.tls).expect("TLS config rebuild failed");
        let client = AnyTlsClient::new(self.config.clone(), tls_config, mark)
            .expect("client rebuild failed");
        Self {
            config: self.config,
            client,
        }
    }
}

#[async_trait::async_trait]
impl Outbound for AnyTlsOutbound {
    fn tag(&self) -> &str {
        &self.config.tag
    }

    async fn connect_tcp(
        &self,
        host: &str,
        port: u16,
    ) -> anyhow::Result<Box<dyn crate::outbound::AsyncReadWrite>> {
        let target = Target::Domain(host.to_string(), port);
        let stream = self.client.create_proxy(&target).await?;
        Ok(Box::new(stream))
    }

    async fn handle_tcp(&self, conn: InboundTcpStream) -> anyhow::Result<(u64, u64)> {
        debug!(
            tag = %self.config.tag,
            target = %conn.target,
            "anytls tcp connecting"
        );

        let stream = self.client.create_proxy(&conn.target).await?;
        let session_ref = stream.session.clone();
        let result = relay(conn.stream, stream).await;

        // 中继完成，Session 放回空闲池
        self.client.return_idle(session_ref).await;

        Ok(result)
    }

    /// UDP 使用 sing-box UDP-over-TCP v2 协议承载。
    ///
    /// 流程：
    /// 1. 向服务端发起目标 = `sp.v2.udp-over-tcp.arpa:443` 的 TCP Stream
    /// 2. 写 UoT v2 请求头（包含真实目标地址）
    /// 3. 发送第一个 UDP 包
    /// 4. spawn task 持续写入后续上行包
    /// 5. 当前 task 持续读取下行 UDP 包并通过 reply_tx 回给入站
    async fn handle_udp(&self, mut packet: InboundUdpPacket) -> anyhow::Result<()> {
        debug!(
            tag = %self.config.tag,
            target = %packet.target,
            "anytls udp session (UoT v2)"
        );

        let uot_target = Target::Domain(UOT_MAGIC_ADDRESS.to_string(), UOT_MAGIC_PORT);
        let mut stream = self.client.create_proxy(&uot_target).await?;

        // 写 UoT v2 请求头
        let req_hdr = build_uot_request(&packet.target);
        stream.write_all(&req_hdr).await?;

        // 发送第一个 UDP 数据包
        let first = build_uot_packet(&packet.target, &packet.data);
        stream.write_all(&first).await?;

        let timeout = Duration::from_secs(30);
        let reply_tx = packet.session.reply_tx.clone();
        let src = packet.src;
        let spoofed_src = packet.target.to_socket_addr_lossy();

        let (mut read_half, mut write_half) = tokio::io::split(stream);

        // spawn 上行任务：持续将后续 UDP 包写入 Stream
        if let Some(mut upstream_rx) = packet.upstream_rx.take() {
            let target = packet.target.clone();
            tokio::spawn(async move {
                while let Some(data) = upstream_rx.recv().await {
                    let frame = build_uot_packet(&target, &data);
                    if write_half.write_all(&frame).await.is_err() {
                        break;
                    }
                }
            });
        }

        // 读取下行 UDP 包并回复给入站
        loop {
            match tokio::time::timeout(timeout, read_uot_packet(&mut read_half)).await {
                Ok(Ok((_target, data))) => {
                    let _ = reply_tx.send((data, src, spoofed_src)).await;
                }
                Ok(Err(e)) => {
                    let s = e.to_string();
                    if s.contains("eof") || s.contains("EOF")
                        || s.contains("closed") || s.contains("reset")
                    {
                        break;
                    }
                    return Err(e);
                }
                Err(_) => break, // timeout
            }
        }

        Ok(())
    }
}

// ── 单元测试 ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_scheme_parse_default() {
        let scheme = PaddingScheme::parse(DEFAULT_PADDING_SCHEME).unwrap();
        assert_eq!(scheme.stop, 8);
        assert!(!scheme.md5_hex.is_empty());
        assert_eq!(scheme.md5_hex.len(), 32);
    }

    #[test]
    fn padding_scheme_generate() {
        let scheme = PaddingScheme::parse(DEFAULT_PADDING_SCHEME).unwrap();
        // pkt=0: "0=30-30" → always 30
        let sizes = scheme.generate_sizes(0);
        assert_eq!(sizes.len(), 1);
        assert_eq!(sizes[0], 30);
        // pkt=8: stop=8 → out of range
        let sizes = scheme.generate_sizes(8);
        assert!(sizes.is_empty());
    }

    #[test]
    fn socks_addr_ipv4() {
        let target = Target::Socket("1.2.3.4:80".parse().unwrap());
        let b = encode_socks_addr(&target);
        assert_eq!(b[0], SOCKS_ATYP_IPV4);
        assert_eq!(&b[1..5], &[1, 2, 3, 4]);
        assert_eq!(u16::from_be_bytes([b[5], b[6]]), 80);
    }

    #[test]
    fn socks_addr_ipv6() {
        let target = Target::Socket("[::1]:443".parse().unwrap());
        let b = encode_socks_addr(&target);
        assert_eq!(b[0], SOCKS_ATYP_IPV6);
        assert_eq!(u16::from_be_bytes([b[17], b[18]]), 443);
    }

    #[test]
    fn socks_addr_domain() {
        let target = Target::Domain("example.com".into(), 443);
        let b = encode_socks_addr(&target);
        assert_eq!(b[0], SOCKS_ATYP_DOMAIN);
        assert_eq!(b[1], 11);
        assert_eq!(&b[2..13], b"example.com");
        assert_eq!(u16::from_be_bytes([b[13], b[14]]), 443);
    }

    #[test]
    fn uot_request_header() {
        let target = Target::Socket("8.8.8.8:53".parse().unwrap());
        let hdr = build_uot_request(&target);
        assert_eq!(hdr[0], 2u8); // version
        assert_eq!(hdr[1], SOCKS_ATYP_IPV4);
        assert_eq!(&hdr[2..6], &[8, 8, 8, 8]);
        assert_eq!(u16::from_be_bytes([hdr[6], hdr[7]]), 53);
    }

    #[test]
    fn uot_packet_build() {
        let target = Target::Socket("8.8.8.8:53".parse().unwrap());
        let data = b"dns-query";
        let pkt = build_uot_packet(&target, data);
        assert_eq!(pkt[0], SOCKS_ATYP_IPV4);
        let data_len = u16::from_be_bytes([pkt[7], pkt[8]]) as usize;
        assert_eq!(data_len, data.len());
        assert_eq!(&pkt[9..9 + data_len], data);
    }

    #[test]
    fn frame_build_syn() {
        let f = AnyTlsSession::build_frame(CMD_SYN, 42, &[]);
        assert_eq!(f[0], CMD_SYN);
        assert_eq!(u32::from_be_bytes(f[1..5].try_into().unwrap()), 42);
        assert_eq!(u16::from_be_bytes([f[5], f[6]]), 0);
        assert_eq!(f.len(), FRAME_HEADER_SIZE);
    }

    #[test]
    fn frame_build_psh() {
        let data = b"hello";
        let f = AnyTlsSession::build_frame(CMD_PSH, 1, data);
        assert_eq!(f[0], CMD_PSH);
        assert_eq!(u32::from_be_bytes(f[1..5].try_into().unwrap()), 1);
        assert_eq!(u16::from_be_bytes([f[5], f[6]]), 5);
        assert_eq!(&f[7..], data);
    }

    #[test]
    fn sha256_auth() {
        let hash = Sha256::digest(b"password");
        assert_eq!(hash.len(), 32);
        // sha256("password") 前 4 字节（参考 anytls-go 测试）
        assert_eq!(hash[0], 0x5e);
    }

    #[test]
    fn padding_apply_noop_after_stop() {
        // pkt >= stop → 直接返回原始数据
        // 构造一个 stop=0 的 scheme（所有 pkt 都超过 stop）
        let scheme = PaddingScheme {
            stop: 0,
            raw: b"stop=0".to_vec(),
            md5_hex: "deadbeef".to_string(),
        };
        let padding = Arc::new(ClientPadding {
            scheme: std::sync::RwLock::new(scheme),
        });
        let (tx, _rx) = mpsc::unbounded_channel();
        let session = AnyTlsSession {
            write_tx: tx,
            streams: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            next_stream_id: AtomicU32::new(0),
            pkt_counter: AtomicU32::new(0),
            peer_version: AtomicU8::new(1),
            is_closed: AtomicBool::new(false),
            closed_notify: Arc::new(Notify::new()),
            padding,
            buffering: AtomicBool::new(false),
            seq: 1,
            idle_since: Mutex::new(None),
        };
        let data = vec![1u8, 2, 3, 4];
        let out = apply_padding(&session, data.clone());
        assert_eq!(out, data);
    }
}
