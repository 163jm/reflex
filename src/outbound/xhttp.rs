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
//!
//! # SO_MARK 支持
//!
//! 本模块使用 hyper + 自定义 MarkedConnector，在 TCP connect 之后立即调用
//! setsockopt(SO_MARK)，使 xhttp 出站流量与其他协议同等支持 routing_mark。

use std::{
    collections::HashMap,
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicI64, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::{BodyExt, Empty, Full, StreamBody};
use hyper::{
    body::{Frame, Incoming},
    header::{HeaderName, HeaderValue, HOST},
    Method, Request, StatusCode, Uri,
};
use hyper_util::client::legacy::Client;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    sync::mpsc,
};
use tokio_stream::wrappers::ReceiverStream;
use tower::Service;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::config::outbound::{TlsConfig, XhttpTransportConfig};
use crate::outbound::{apply_mark_to_tcp, set_tcp_opts};

// ── 公共接口 ─────────────────────────────────────────────────────────────────

/// 建立一条 XHTTP 双工流。
pub async fn connect(
    server: &str,
    port: u16,
    cfg: &XhttpTransportConfig,
    tls: Option<&TlsConfig>,
    extra_headers: &HashMap<String, String>,
    routing_mark: u32,
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

    let client = build_http_client(tls, cfg, routing_mark)?;

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

// ── 自定义 Connector（打 SO_MARK）────────────────────────────────────────────

/// 在 TCP connect 完成后立即设置 SO_MARK，然后可选地包一层 TLS。
#[derive(Clone)]
struct MarkedConnector {
    mark: u32,
    #[cfg(feature = "outbound-net")]
    tls: Option<Arc<rustls::ClientConfig>>,
    #[cfg(not(feature = "outbound-net"))]
    _tls: (),
}

impl MarkedConnector {
    fn new(mark: u32, tls_cfg: Option<Arc<rustls::ClientConfig>>) -> Self {
        Self {
            mark,
            #[cfg(feature = "outbound-net")]
            tls: tls_cfg,
            #[cfg(not(feature = "outbound-net"))]
            _tls: {
                let _ = tls_cfg;
            },
        }
    }
}

/// hyper 连接类型：裸 TCP 或 TLS over TCP
pub enum MaybeHttps {
    Plain(TcpStream),
    #[cfg(feature = "outbound-net")]
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
}

impl tokio::io::AsyncRead for MaybeHttps {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeHttps::Plain(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(feature = "outbound-net")]
            MaybeHttps::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for MaybeHttps {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            MaybeHttps::Plain(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(feature = "outbound-net")]
            MaybeHttps::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeHttps::Plain(s) => Pin::new(s).poll_flush(cx),
            #[cfg(feature = "outbound-net")]
            MaybeHttps::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeHttps::Plain(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(feature = "outbound-net")]
            MaybeHttps::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl hyper::rt::Read for MaybeHttps {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let b = unsafe { &mut *(buf.as_mut() as *mut [std::mem::MaybeUninit<u8>] as *mut [u8]) };
        let mut rb = ReadBuf::new(b);
        match tokio::io::AsyncRead::poll_read(self, cx, &mut rb) {
            Poll::Ready(Ok(())) => {
                let n = rb.filled().len();
                unsafe { buf.advance(n) };
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl hyper::rt::Write for MaybeHttps {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(self, cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        tokio::io::AsyncWrite::poll_flush(self, cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        tokio::io::AsyncWrite::poll_shutdown(self, cx)
    }
}

impl hyper_util::client::legacy::connect::Connection for MaybeHttps {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        hyper_util::client::legacy::connect::Connected::new()
    }
}

impl Service<Uri> for MarkedConnector {
    type Response = MaybeHttps;
    type Error = anyhow::Error;
    type Future = Pin<Box<dyn Future<Output = anyhow::Result<MaybeHttps>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<anyhow::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let mark = self.mark;
        #[cfg(feature = "outbound-net")]
        let tls_cfg = self.tls.clone();
        #[cfg(not(feature = "outbound-net"))]
        let tls_cfg: Option<Arc<rustls::ClientConfig>> = None;

        Box::pin(async move {
            let host = uri
                .host()
                .ok_or_else(|| anyhow::anyhow!("xhttp: missing host in URI"))?;
            let port = uri
                .port_u16()
                .unwrap_or(if uri.scheme_str() == Some("https") {
                    443
                } else {
                    80
                });

            // DNS 解析
            let addr: SocketAddr = tokio::net::lookup_host(format!("{host}:{port}"))
                .await?
                .next()
                .ok_or_else(|| anyhow::anyhow!("xhttp: DNS failed for {host}"))?;

            // TCP connect → 打 SO_MARK → 设 TCP 选项
            let tcp = TcpStream::connect(addr).await?;
            apply_mark_to_tcp(&tcp, mark)?;
            set_tcp_opts(&tcp)?;

            #[cfg(feature = "outbound-net")]
            if let Some(tls) = tls_cfg {
                let sni = rustls::pki_types::ServerName::try_from(host.to_string())
                    .map_err(|e| anyhow::anyhow!("xhttp: invalid SNI {host}: {e}"))?;
                let connector = tokio_rustls::TlsConnector::from(tls);
                let tls_stream = connector
                    .connect(sni, tcp)
                    .await
                    .map_err(|e| anyhow::anyhow!("xhttp: TLS handshake failed: {e}"))?;
                return Ok(MaybeHttps::Tls(tls_stream));
            }

            Ok(MaybeHttps::Plain(tcp))
        })
    }
}

// ── 类型别名：带 mark 的 hyper Client ────────────────────────────────────────

type XhttpClient = Client<MarkedConnector, XhttpBody>;

/// 上行 body 类型：可以是空 body、固定字节、或流式 channel
enum XhttpBody {
    Empty(Empty<Bytes>),
    Full(Full<Bytes>),
    Stream(
        StreamBody<
            futures_util::stream::Map<
                ReceiverStream<Bytes>,
                fn(Bytes) -> Result<Frame<Bytes>, io::Error>,
            >,
        >,
    ),
}

impl hyper::body::Body for XhttpBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            XhttpBody::Empty(b) => Pin::new(b).poll_frame(cx).map_err(|_| unreachable!()),
            XhttpBody::Full(b) => Pin::new(b).poll_frame(cx).map_err(|_| unreachable!()),
            XhttpBody::Stream(b) => Pin::new(b).poll_frame(cx),
        }
    }
}

fn stream_body(rx: mpsc::Receiver<Bytes>) -> XhttpBody {
    fn wrap(b: Bytes) -> Result<Frame<Bytes>, io::Error> {
        Ok(Frame::data(b))
    }
    XhttpBody::Stream(StreamBody::new(
        ReceiverStream::new(rx).map(wrap as fn(Bytes) -> Result<Frame<Bytes>, io::Error>),
    ))
}

// ── 内部共享状态 ──────────────────────────────────────────────────────────────

struct XhttpShared {
    client: XhttpClient,
    base_url: String,
    session_id: Option<String>,
    headers: HashMap<String, String>,
    seq: AtomicI64,
    max_post_bytes: usize,
    min_post_interval_ms: u64,
    uplink_method: String,
}

impl XhttpShared {
    fn apply_headers(&self, mut req: Request<XhttpBody>) -> Request<XhttpBody> {
        for (k, v) in &self.headers {
            if let (Ok(name), Ok(val)) = (
                HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_str(v),
            ) {
                req.headers_mut().insert(name, val);
            }
        }
        req
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

    fn build_request(
        &self,
        method: &Method,
        url: &str,
        body: XhttpBody,
    ) -> anyhow::Result<Request<XhttpBody>> {
        let uri: Uri = url.parse()?;
        let host = uri.host().unwrap_or("").to_string();
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header(HOST, &host)
            .body(body)?;
        // apply custom headers（覆盖同名 header）
        Ok(self.apply_headers(req))
    }
}

// ── 模式 1：stream-one ────────────────────────────────────────────────────────

async fn connect_stream_one(shared: Arc<XhttpShared>) -> anyhow::Result<XhttpStream> {
    let (body_tx, body_rx) = mpsc::channel::<Bytes>(64);
    let url = shared.stream_url();
    let method = parse_method(&shared.uplink_method);
    let req = shared.build_request(&method, &url, stream_body(body_rx))?;
    let resp = shared.client.request(req).await?;
    check_status(resp.status(), "stream-one")?;
    let read_half = RespBodyReader::new(resp.into_body());
    Ok(XhttpStream::new(read_half, XhttpWriter::Stream(body_tx)))
}

// ── 模式 2：stream-up + 独立 GET 下行 ────────────────────────────────────────

async fn connect_stream_up_down(shared: Arc<XhttpShared>) -> anyhow::Result<XhttpStream> {
    let down_url = shared.stream_url();
    let req = shared.build_request(&Method::GET, &down_url, XhttpBody::Empty(Empty::new()))?;
    let down_resp = shared.client.request(req).await?;
    check_status(down_resp.status(), "stream-down")?;
    let read_half = RespBodyReader::new(down_resp.into_body());

    let (body_tx, body_rx) = mpsc::channel::<Bytes>(64);
    let up_url = shared.stream_url();
    let method = parse_method(&shared.uplink_method);
    let req = shared.build_request(&method, &up_url, stream_body(body_rx))?;
    {
        let client = shared.client.clone();
        tokio::spawn(async move {
            if let Err(e) = client.request(req).await {
                warn!("xhttp stream-up POST failed: {e}");
            }
        });
    }

    Ok(XhttpStream::new(read_half, XhttpWriter::Stream(body_tx)))
}

// ── 模式 3：packet-up（默认）─────────────────────────────────────────────────

async fn connect_packet_up(shared: Arc<XhttpShared>) -> anyhow::Result<XhttpStream> {
    let down_url = shared.stream_url();
    let req = shared.build_request(&Method::GET, &down_url, XhttpBody::Empty(Empty::new()))?;
    let down_resp = shared.client.request(req).await?;
    check_status(down_resp.status(), "packet-up/stream-down")?;
    let read_half = RespBodyReader::new(down_resp.into_body());

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

async fn post_packet(shared: &XhttpShared, payload: Bytes) -> anyhow::Result<()> {
    let seq = shared.seq.fetch_add(1, Ordering::Relaxed);
    let url = shared.packet_url(seq);
    let method = parse_method(&shared.uplink_method);
    let req = shared.build_request(&method, &url, XhttpBody::Full(Full::new(payload)))?;
    let resp = shared.client.request(req).await?;
    check_status(resp.status(), &format!("packet POST {seq}"))
}

// ── 下行响应体读取器 ──────────────────────────────────────────────────────────

struct RespBodyReader {
    rx: mpsc::Receiver<io::Result<Bytes>>,
    current: Bytes,
}

impl RespBodyReader {
    fn new(body: Incoming) -> Self {
        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(async move {
            let mut stream = body;
            loop {
                match stream.frame().await {
                    None => break,
                    Some(Ok(frame)) => {
                        if let Ok(data) = frame.into_data() {
                            if tx.send(Ok(data)).await.is_err() {
                                break;
                            }
                        }
                    }
                    Some(Err(e)) => {
                        let _ = tx
                            .send(Err(io::Error::new(io::ErrorKind::BrokenPipe, e)))
                            .await;
                        break;
                    }
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
    Stream(mpsc::Sender<Bytes>),
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
    routing_mark: u32,
) -> anyhow::Result<XhttpClient> {
    let tls_enabled = tls.map_or(false, |t| t.enabled);

    #[cfg(feature = "outbound-net")]
    let rustls_cfg: Option<Arc<rustls::ClientConfig>> = if tls_enabled {
        if let Some(tls_cfg) = tls {
            Some(crate::outbound::tls::build_client_config(tls_cfg)?)
        } else {
            None
        }
    } else {
        None
    };
    #[cfg(not(feature = "outbound-net"))]
    let rustls_cfg: Option<Arc<rustls::ClientConfig>> = {
        let _ = tls_enabled;
        None
    };

    let connector = MarkedConnector::new(routing_mark, rustls_cfg);

    let client = Client::builder(hyper_util::rt::TokioExecutor::new())
        .http2_only(false)
        .build(connector);

    Ok(client)
}

// ── 辅助函数 ──────────────────────────────────────────────────────────────────

fn parse_method(s: &str) -> Method {
    Method::from_bytes(s.as_bytes()).unwrap_or(Method::POST)
}

fn check_status(status: StatusCode, ctx: &str) -> anyhow::Result<()> {
    if status.is_success() {
        Ok(())
    } else {
        anyhow::bail!("xhttp {ctx}: server returned {status}")
    }
}

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
