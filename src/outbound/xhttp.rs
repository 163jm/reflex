//! XHTTP (SplitHTTP) 传输层实现
//!
//! 参照 Xray-core 的 `transport/internet/splithttp`，为 Reflex 的出站协议
//! （VLESS、VMess、Trojan、Shadowsocks）提供 xhttp 传输模式。
//!
//! # 工作原理
//!
//! XHTTP 将全双工流量拆分为两条单向 HTTP 链路：
//!
//! - **下行**：客户端发起一个长轮询 GET 请求，服务端通过流式响应体持续推送数据。
//! - **上行**：客户端将待发送数据分段，以 POST 请求依次上传。
//!
//! 两条链路通过 `session_id`（UUID）关联。
//!
//! # 支持的模式
//!
//! | mode         | 说明                                  |
//! |--------------|---------------------------------------|
//! | `stream-one` | 单次 POST，上行+下行复用同一连接      |
//! | `stream-up`  | 单次 POST 上行 + 独立 GET 下行        |
//! | `packet-up`  | 多段 POST 上行（默认）+ 独立 GET 下行 |

use std::{
    collections::HashMap,
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicI64, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

use bytes::Bytes;
use futures_util::StreamExt;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc,
};
use tracing::{debug, warn};
use uuid::Uuid;

use crate::config::outbound::{TlsConfig, XhttpTransportConfig};

// ── 公共接口 ─────────────────────────────────────────────────────────────────

/// 建立一条 XHTTP 双工流。
pub async fn connect(
    server: &str,
    port: u16,
    cfg: &XhttpTransportConfig,
    tls: Option<&TlsConfig>,
    extra_headers: &HashMap<String, String>,
) -> anyhow::Result<XhttpStream> {
    let tls_enabled = tls.map_or(false, |t| t.enabled);
    let scheme = if tls_enabled { "https" } else { "http" };

    let host = cfg
        .host
        .as_deref()
        .or_else(|| tls.and_then(|t| t.server_name.as_deref()))
        .unwrap_or(server);

    let raw_path = cfg.path.as_deref().unwrap_or("/");
    let path = normalize_path(raw_path);
    let base_url = format!("{scheme}://{server}:{port}{path}");

    let client = build_http_client(tls, cfg)?;

    let mode = cfg.mode.as_deref().unwrap_or("packet-up");

    let session_id = if mode != "stream-one" {
        Some(Uuid::new_v4().to_string())
    } else {
        None
    };

    debug!(mode, %base_url, ?session_id, "xhttp connecting");

    let mut headers = cfg.headers.clone();
    for (k, v) in extra_headers {
        headers.entry(k.clone()).or_insert_with(|| v.clone());
    }
    headers
        .entry("Host".to_string())
        .or_insert_with(|| host.to_string());

    let shared = Arc::new(XhttpShared {
        client,
        base_url,
        session_id,
        headers,
        seq: AtomicI64::new(0),
        max_post_bytes: cfg.sc_max_each_post_bytes.unwrap_or(1_000_000) as usize,
        min_post_interval_ms: cfg.sc_min_posts_interval_ms.unwrap_or(0),
        uplink_method: cfg
            .uplink_http_method
            .clone()
            .unwrap_or_else(|| "POST".to_string()),
    });

    match mode {
        "stream-one" => connect_stream_one(shared).await,
        "stream-up" => connect_stream_up_down(shared).await,
        _ => connect_packet_up(shared).await,
    }
}

// ── 内部共享状态 ──────────────────────────────────────────────────────────────

struct XhttpShared {
    client: reqwest::Client,
    base_url: String,
    session_id: Option<String>,
    headers: HashMap<String, String>,
    seq: AtomicI64,
    /// 每个 POST 最大字节数（对应 scMaxEachPostBytes）
    max_post_bytes: usize,
    /// 相邻 POST 最小间隔 ms（对应 scMinPostsIntervalMs），0 表示不限
    min_post_interval_ms: u64,
    /// 上行 HTTP 方法（对应 uplinkHTTPMethod），默认 "POST"
    uplink_method: String,
}

impl XhttpShared {
    fn apply_headers(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let mut b = builder;
        for (k, v) in &self.headers {
            b = b.header(k.as_str(), v.as_str());
        }
        b
    }

    fn stream_url(&self) -> String {
        match &self.session_id {
            Some(sid) => format!("{}?session={}", self.base_url, sid),
            None => self.base_url.clone(),
        }
    }

    fn packet_url(&self, seq: i64) -> String {
        match &self.session_id {
            Some(sid) => format!("{}{}?session={}&seq={}", self.base_url, seq, sid, seq),
            None => format!("{}{}", self.base_url, seq),
        }
    }
}

// ── 模式 1：stream-one ────────────────────────────────────────────────────────

async fn connect_stream_one(shared: Arc<XhttpShared>) -> anyhow::Result<XhttpStream> {
    let (body_tx, body_rx) = mpsc::channel::<Bytes>(64);
    let body = reqwest::Body::wrap_stream(
        tokio_stream::wrappers::ReceiverStream::new(body_rx).map(Ok::<Bytes, std::io::Error>),
    );

    let url = shared.stream_url();
    let method = reqwest::Method::from_bytes(shared.uplink_method.as_bytes())
        .unwrap_or(reqwest::Method::POST);
    let resp = shared
        .apply_headers(shared.client.request(method, &url))
        .body(body)
        .send()
        .await?;

    if !resp.status().is_success() {
        anyhow::bail!("xhttp stream-one: server returned {}", resp.status());
    }

    let read_half = RespBodyReader::new(resp);
    Ok(XhttpStream::new(read_half, XhttpWriter::Stream(body_tx)))
}

// ── 模式 2：stream-up + 独立 GET 下行 ────────────────────────────────────────

async fn connect_stream_up_down(shared: Arc<XhttpShared>) -> anyhow::Result<XhttpStream> {
    // 1. 建立下行 GET（长轮询）
    let down_url = shared.stream_url();
    let down_resp = shared
        .apply_headers(shared.client.get(&down_url))
        .send()
        .await?;
    if !down_resp.status().is_success() {
        anyhow::bail!("xhttp stream-down: server returned {}", down_resp.status());
    }
    let read_half = RespBodyReader::new(down_resp);

    // 2. 建立上行 POST（流式 body）
    let (body_tx, body_rx) = mpsc::channel::<Bytes>(64);
    let body = reqwest::Body::wrap_stream(
        tokio_stream::wrappers::ReceiverStream::new(body_rx).map(Ok::<Bytes, std::io::Error>),
    );
    let up_url = shared.stream_url();
    {
        let client = shared.client.clone();
        let method = reqwest::Method::from_bytes(shared.uplink_method.as_bytes())
            .unwrap_or(reqwest::Method::POST);
        let req = shared
            .apply_headers(client.request(method, &up_url))
            .body(body)
            .build()?;
        let client2 = shared.client.clone();
        tokio::spawn(async move {
            if let Err(e) = client2.execute(req).await {
                warn!("xhttp stream-up POST failed: {e}");
            }
        });
    }

    Ok(XhttpStream::new(read_half, XhttpWriter::Stream(body_tx)))
}

// ── 模式 3：packet-up（默认）─────────────────────────────────────────────────

async fn connect_packet_up(shared: Arc<XhttpShared>) -> anyhow::Result<XhttpStream> {
    // 1. 建立下行 GET
    let down_url = shared.stream_url();
    let down_resp = shared
        .apply_headers(shared.client.get(&down_url))
        .send()
        .await?;
    if !down_resp.status().is_success() {
        anyhow::bail!(
            "xhttp packet-up/stream-down: server returned {}",
            down_resp.status()
        );
    }
    let read_half = RespBodyReader::new(down_resp);

    // 2. 上行：通过 channel 发送数据块，后台任务负责分段 POST
    let (up_tx, mut up_rx) = mpsc::channel::<Bytes>(128);
    {
        let shared = shared.clone();
        tokio::spawn(async move {
            let mut buf = Vec::<u8>::new();
            let mut last_post = std::time::Instant::now();
            while let Some(chunk) = up_rx.recv().await {
                buf.extend_from_slice(&chunk);
                while buf.len() >= shared.max_post_bytes {
                    let payload: Bytes = buf.drain(..shared.max_post_bytes).collect();
                    // 限速：若距上次 POST 不足 min_post_interval_ms，先等待
                    if shared.min_post_interval_ms > 0 {
                        let elapsed = last_post.elapsed().as_millis() as u64;
                        if elapsed < shared.min_post_interval_ms {
                            tokio::time::sleep(tokio::time::Duration::from_millis(
                                shared.min_post_interval_ms - elapsed,
                            ))
                            .await;
                        }
                    }
                    if let Err(e) = post_packet(&shared, payload).await {
                        warn!("xhttp packet-up POST error: {e}");
                        return;
                    }
                    last_post = std::time::Instant::now();
                }
            }
            // 通道关闭，发送剩余数据
            if !buf.is_empty() {
                let payload = Bytes::from(buf);
                if let Err(e) = post_packet(&shared, payload).await {
                    warn!("xhttp packet-up final POST error: {e}");
                }
            }
        });
    }

    Ok(XhttpStream::new(read_half, XhttpWriter::Packet(up_tx)))
}

/// 发送一个带序号的上行请求（packet-up 模式），方法由 uplinkHTTPMethod 决定
async fn post_packet(shared: &XhttpShared, payload: Bytes) -> anyhow::Result<()> {
    let seq = shared.seq.fetch_add(1, Ordering::Relaxed);
    let url = shared.packet_url(seq);

    let method = reqwest::Method::from_bytes(shared.uplink_method.as_bytes())
        .unwrap_or(reqwest::Method::POST);

    let resp = shared
        .apply_headers(shared.client.request(method, &url))
        .body(payload)
        .send()
        .await?;

    if !resp.status().is_success() {
        anyhow::bail!("xhttp packet POST {seq}: server returned {}", resp.status());
    }
    Ok(())
}

// ── 下行响应体读取器 ──────────────────────────────────────────────────────────

struct RespBodyReader {
    rx: mpsc::Receiver<io::Result<Bytes>>,
    current: Bytes,
}

impl RespBodyReader {
    fn new(resp: reqwest::Response) -> Self {
        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(async move {
            let mut body = resp.bytes_stream();
            while let Some(item) = body.next().await {
                let chunk = item.map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e));
                if tx.send(chunk).await.is_err() {
                    break;
                }
            }
        });
        Self {
            rx,
            current: Bytes::new(),
        }
    }
}

impl AsyncRead for RespBodyReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if !this.current.is_empty() {
            let n = buf.remaining().min(this.current.len());
            buf.put_slice(&this.current[..n]);
            this.current = this.current.slice(n..);
            return Poll::Ready(Ok(()));
        }

        match this.rx.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(e)),
            Poll::Ready(Some(Ok(chunk))) => {
                if chunk.is_empty() {
                    return Poll::Ready(Ok(()));
                }
                let n = buf.remaining().min(chunk.len());
                buf.put_slice(&chunk[..n]);
                if n < chunk.len() {
                    this.current = chunk.slice(n..);
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}

// ── XhttpStream：对外暴露的双工流 ─────────────────────────────────────────────

pub struct XhttpStream {
    reader: RespBodyReader,
    writer: XhttpWriter,
}

enum XhttpWriter {
    /// stream-one / stream-up：直接发送到 HTTP body channel
    Stream(mpsc::Sender<Bytes>),
    /// packet-up：发送到上行积累 channel
    Packet(mpsc::Sender<Bytes>),
}

impl XhttpStream {
    fn new(reader: RespBodyReader, writer: XhttpWriter) -> Self {
        Self { reader, writer }
    }
}

impl AsyncRead for XhttpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for XhttpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let tx = match &this.writer {
            XhttpWriter::Stream(tx) | XhttpWriter::Packet(tx) => tx.clone(),
        };

        // 尝试立即发送；若 channel 已满，用 poll_reserve 等待空位
        match tx.try_send(Bytes::copy_from_slice(data)) {
            Ok(()) => Poll::Ready(Ok(data.len())),
            Err(mpsc::error::TrySendError::Full(_)) => {
                let waker = cx.waker().clone();
                tokio::spawn(async move {
                    let _ = tx.reserve().await;
                    waker.wake();
                });
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "xhttp: upload channel closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // 丢弃 sender 触发 channel 关闭，后台任务会发送剩余数据
        let this = self.get_mut();
        let (dead_tx, _) = mpsc::channel(1);
        match &mut this.writer {
            XhttpWriter::Stream(tx) => *tx = dead_tx,
            XhttpWriter::Packet(tx) => *tx = dead_tx,
        }
        Poll::Ready(Ok(()))
    }
}

// ── HTTP Client 构建 ──────────────────────────────────────────────────────────

fn build_http_client(
    tls: Option<&TlsConfig>,
    _cfg: &XhttpTransportConfig,
) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::ClientBuilder::new()
        .tcp_nodelay(true)
        .pool_max_idle_per_host(16);

    if let Some(tls_cfg) = tls {
        if tls_cfg.enabled {
            if tls_cfg.insecure {
                builder = builder.danger_accept_invalid_certs(true);
            }
            if let Some(ref ca_path) = tls_cfg.ca_path {
                let pem = std::fs::read(ca_path)?;
                let cert = reqwest::Certificate::from_pem(&pem)?;
                builder = builder.add_root_certificate(cert);
            }
        } else {
            // 明文模式，不配置 TLS
        }
    }

    Ok(builder.build()?)
}

// ── 辅助函数 ──────────────────────────────────────────────────────────────────

/// 确保路径以 '/' 开头，并以 '/' 结尾（与 Xray 行为一致）
fn normalize_path(path: &str) -> String {
    let p = if path.is_empty() || !path.starts_with('/') {
        format!("/{path}")
    } else {
        path.to_string()
    };
    if !p.ends_with('/') {
        format!("{p}/")
    } else {
        p
    }
}

// ── 单元测试 ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::normalize_path;

    #[test]
    fn test_normalize_path() {
        assert_eq!(normalize_path(""), "/");
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path("ws"), "/ws/");
        assert_eq!(normalize_path("/ws"), "/ws/");
        assert_eq!(normalize_path("/ws/"), "/ws/");
        assert_eq!(normalize_path("/a/b"), "/a/b/");
    }
}
