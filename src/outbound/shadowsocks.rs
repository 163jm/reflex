//! Shadowsocks 出站。
//!
//! 支持的加密套件（参照 sing-box shadowsocks outbound）：
//!
//! **AEAD（传统）**
//! - `aes-128-gcm`            — AES-128-GCM，key 16B
//! - `aes-256-gcm`            — AES-256-GCM，key 32B
//! - `chacha20-ietf-poly1305` — ChaCha20-Poly1305，key 32B
//!
//! **AEAD-2022**
//! - `2022-blake3-aes-128-gcm`       — PSK 16B
//! - `2022-blake3-aes-256-gcm`       — PSK 32B
//! - `2022-blake3-chacha20-poly1305` — PSK 32B
//!
//! **明文**
//! - `none` — 无加密（仅用于测试）
//!
//! # TCP 线路格式（AEAD）
//!
//! ```text
//! [salt (key_len B)]
//! [enc(len 2B) + tag 16B] [enc(payload) + tag 16B]  ← 首 payload = SOCKS5 地址
//! [enc(len 2B) + tag 16B] [enc(payload) + tag 16B]  ← 后续数据
//! ...
//! ```

use std::net::{IpAddr, SocketAddr};

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes128Gcm, Aes256Gcm,
};
use bytes::Bytes;
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use md5::{Digest as _, Md5};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tracing::debug;

use crate::{
    config::outbound::ShadowsocksOutboundConfig,
    inbound::{InboundTcpStream, InboundUdpPacket, Target},
    outbound::{apply_mark_to_tcp, apply_mark_to_udp, set_tcp_opts, Outbound, OutboundStatus},
};

// ── 加密方法 ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    Ss2022Aes128Gcm,
    Ss2022Aes256Gcm,
    Ss2022ChaCha20Poly1305,
    None,
}

impl Method {
    fn from_str(s: &str) -> anyhow::Result<Self> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "aes-128-gcm" => Self::Aes128Gcm,
            "aes-256-gcm" => Self::Aes256Gcm,
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Self::ChaCha20Poly1305,
            "2022-blake3-aes-128-gcm" => Self::Ss2022Aes128Gcm,
            "2022-blake3-aes-256-gcm" => Self::Ss2022Aes256Gcm,
            "2022-blake3-chacha20-poly1305" => Self::Ss2022ChaCha20Poly1305,
            "none" | "plain" => Self::None,
            other => anyhow::bail!("unsupported shadowsocks method: {other}"),
        })
    }

    fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Ss2022Aes128Gcm => 16,
            Self::Aes256Gcm
            | Self::ChaCha20Poly1305
            | Self::Ss2022Aes256Gcm
            | Self::Ss2022ChaCha20Poly1305 => 32,
            Self::None => 0,
        }
    }

    fn salt_len(self) -> usize {
        self.key_len()
    }

    fn is_2022(self) -> bool {
        matches!(
            self,
            Self::Ss2022Aes128Gcm | Self::Ss2022Aes256Gcm | Self::Ss2022ChaCha20Poly1305
        )
    }
}

const TAG_LEN: usize = 16;
const MAX_PAYLOAD: usize = 0x3FFF;

// ── 密钥派生 ──────────────────────────────────────────────────────────────────

/// EVP_BytesToKey（MD5 KDF）：密码字符串 → master key。
fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len);
    let mut prev: Vec<u8> = Vec::new();
    while key.len() < key_len {
        let mut h = Md5::new();
        h.update(&prev);
        h.update(password);
        prev = h.finalize().to_vec();
        key.extend_from_slice(&prev);
    }
    key.truncate(key_len);
    key
}

/// HKDF-SHA1：master key + salt → session subkey（传统 AEAD）。
fn hkdf_sha1(master_key: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
    let hk = Hkdf::<sha1::Sha1>::new(Some(salt), master_key);
    let mut okm = vec![0u8; key_len];
    hk.expand(b"ss-subkey", &mut okm)
        .expect("HKDF expand failed");
    okm
}

/// BLAKE3-KDF：PSK + salt → session subkey（AEAD-2022）。
fn ss2022_session_key(psk: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
    let blake3_key: [u8; 32] = if psk.len() == 32 {
        psk.try_into().unwrap()
    } else {
        let mut k = [0u8; 32];
        k.copy_from_slice(blake3::hash(psk).as_bytes());
        k
    };
    let derived = blake3::keyed_hash(&blake3_key, salt);
    derived.as_bytes()[..key_len].to_vec()
}

// ── AEAD 加解密器 ─────────────────────────────────────────────────────────────

struct AeadCipher {
    method: Method,
    subkey: Vec<u8>,
    counter: u64,
}

impl AeadCipher {
    fn new(method: Method, subkey: Vec<u8>) -> Self {
        Self {
            method,
            subkey,
            counter: 0,
        }
    }

    fn nonce(&self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&self.counter.to_le_bytes());
        n
    }

    /// 原地加密，追加 16B tag，递增 counter。
    fn seal(&mut self, buf: &mut Vec<u8>) -> anyhow::Result<()> {
        if self.method == Method::None {
            return Ok(());
        }
        let nonce = self.nonce();
        let tag = self.seal_inner(buf, &nonce)?;
        buf.extend_from_slice(&tag);
        self.counter = self.counter.wrapping_add(1);
        Ok(())
    }

    fn seal_inner(&self, buf: &mut Vec<u8>, nonce: &[u8; 12]) -> anyhow::Result<[u8; TAG_LEN]> {
        macro_rules! do_seal {
            ($C:ty) => {{
                let c = <$C>::new_from_slice(&self.subkey)
                    .map_err(|e| anyhow::anyhow!("cipher init: {e}"))?;
                let tag = c
                    .encrypt_in_place_detached(nonce.into(), b"", buf)
                    .map_err(|e| anyhow::anyhow!("encrypt: {e}"))?;
                let mut out = [0u8; TAG_LEN];
                out.copy_from_slice(tag.as_slice());
                out
            }};
        }
        Ok(match self.method {
            Method::Aes128Gcm | Method::Ss2022Aes128Gcm => do_seal!(Aes128Gcm),
            Method::Aes256Gcm | Method::Ss2022Aes256Gcm => do_seal!(Aes256Gcm),
            Method::ChaCha20Poly1305 | Method::Ss2022ChaCha20Poly1305 => do_seal!(ChaCha20Poly1305),
            Method::None => [0u8; TAG_LEN],
        })
    }

    /// 原地解密（含 trailing tag），去掉 tag，递增 counter。
    fn open(&mut self, buf: &mut Vec<u8>) -> anyhow::Result<()> {
        if self.method == Method::None {
            return Ok(());
        }
        anyhow::ensure!(buf.len() >= TAG_LEN, "ciphertext too short");
        let nonce = self.nonce();
        self.open_inner(buf, &nonce)?;
        self.counter = self.counter.wrapping_add(1);
        Ok(())
    }

    fn open_inner(&self, buf: &mut Vec<u8>, nonce: &[u8; 12]) -> anyhow::Result<()> {
        macro_rules! do_open {
            ($C:ty) => {{
                let c = <$C>::new_from_slice(&self.subkey)
                    .map_err(|e| anyhow::anyhow!("cipher init: {e}"))?;
                c.decrypt_in_place(nonce.into(), b"", buf)
                    .map_err(|e| anyhow::anyhow!("decrypt: {e}"))?;
            }};
        }
        match self.method {
            Method::Aes128Gcm | Method::Ss2022Aes128Gcm => do_open!(Aes128Gcm),
            Method::Aes256Gcm | Method::Ss2022Aes256Gcm => do_open!(Aes256Gcm),
            Method::ChaCha20Poly1305 | Method::Ss2022ChaCha20Poly1305 => do_open!(ChaCha20Poly1305),
            Method::None => {}
        }
        Ok(())
    }

    /// 预检解密（不递增 counter），仅用于提前读取 payload 长度。
    /// 成功返回 true 并修改 buf（去掉 tag），失败返回 false。
    fn open_inner_peek(&self, buf: &mut Vec<u8>, nonce: &[u8; 12]) -> bool {
        self.open_inner(buf, nonce).is_ok()
    }
}

// ── 拆分的读写两半 ────────────────────────────────────────────────────────────

/// 加密写半部：持有 WriteHalf<TcpStream> + enc cipher。
struct SsWriter {
    inner: WriteHalf<TcpStream>,
    enc: AeadCipher,
}

impl SsWriter {
    /// 写一个加密 chunk：[enc(len 2B)+tag][enc(payload)+tag]
    async fn write_chunk(&mut self, data: &[u8]) -> anyhow::Result<()> {
        let mut len_buf = (data.len() as u16).to_be_bytes().to_vec();
        self.enc.seal(&mut len_buf)?;

        let mut payload_buf = data.to_vec();
        self.enc.seal(&mut payload_buf)?;

        self.inner.write_all(&len_buf).await?;
        self.inner.write_all(&payload_buf).await?;
        Ok(())
    }

    async fn shutdown(&mut self) {
        let _ = self.inner.shutdown().await;
    }
}

/// 解密读半部：持有 ReadHalf<TcpStream> + dec cipher。
struct SsReader {
    inner: ReadHalf<TcpStream>,
    dec: AeadCipher,
}

impl SsReader {
    /// 读一个解密 chunk，返回明文。
    async fn read_chunk(&mut self) -> anyhow::Result<Vec<u8>> {
        let mut len_buf = vec![0u8; 2 + TAG_LEN];
        self.inner.read_exact(&mut len_buf).await?;
        self.dec.open(&mut len_buf)?;
        let payload_len = u16::from_be_bytes([len_buf[0], len_buf[1]]) as usize;

        let mut payload_buf = vec![0u8; payload_len + TAG_LEN];
        self.inner.read_exact(&mut payload_buf).await?;
        self.dec.open(&mut payload_buf)?;
        Ok(payload_buf)
    }
}

// ── 连接建立 ──────────────────────────────────────────────────────────────────

/// 建立 SS TCP 连接，发送 salt + 首个加密 chunk（目标地址），
/// 返回独立的 (SsReader, SsWriter)，可并发使用。
async fn ss_connect(
    server_addr: SocketAddr,
    method: Method,
    subkey: Vec<u8>,
    salt: Vec<u8>,
    first_payload: Vec<u8>,
    routing_mark: u32,
) -> anyhow::Result<(SsReader, SsWriter)> {
    let stream = TcpStream::connect(server_addr).await?;
    set_tcp_opts(&stream)?;
    apply_mark_to_tcp(&stream, routing_mark)?;

    let (rd, wr) = tokio::io::split(stream);
    let mut writer = SsWriter {
        inner: wr,
        enc: AeadCipher::new(method, subkey.clone()),
    };
    let reader = SsReader {
        inner: rd,
        dec: AeadCipher::new(method, subkey),
    };

    writer.inner.write_all(&salt).await?;
    writer.write_chunk(&first_payload).await?;

    Ok((reader, writer))
}

// ── 双向转发 ──────────────────────────────────────────────────────────────────

/// 在 inbound stream 和 SS 连接之间做双向透明转发。
/// 返回 `(upstream_bytes, downstream_bytes)`。
async fn relay_ss(
    inbound: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    mut ss_rd: SsReader,
    mut ss_wr: SsWriter,
) -> (u64, u64) {
    let (mut ib_rd, mut ib_wr) = tokio::io::split(inbound);

    // 上行：inbound → SS server
    let up = async move {
        let mut buf = vec![0u8; MAX_PAYLOAD];
        let mut total = 0u64;
        loop {
            let n = match ib_rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if ss_wr.write_chunk(&buf[..n]).await.is_err() {
                break;
            }
            total += n as u64;
        }
        ss_wr.shutdown().await;
        total
    };

    // 下行：SS server → inbound
    let down = async move {
        let mut total = 0u64;
        loop {
            let chunk = match ss_rd.read_chunk().await {
                Ok(c) => c,
                Err(_) => break,
            };
            if ib_wr.write_all(&chunk).await.is_err() {
                break;
            }
            total += chunk.len() as u64;
        }
        let _ = ib_wr.shutdown().await;
        total
    };

    tokio::join!(up, down)
}

// ── SS AEAD over 泛型流 ───────────────────────────────────────────────────────
//
// 当底层传输是 XhttpStream（或任意 AsyncRead+AsyncWrite）时，
// 我们不能使用 ReadHalf<TcpStream> 类型的 SsReader/SsWriter。
// 改用这套纯泛型实现，将 SS AEAD 帧逻辑封装成一个 AsyncRead+AsyncWrite 类型。

/// 将任意 AsyncRead+AsyncWrite 流包装成 SS AEAD 加解密流。
///
/// 写入侧：自动在每次 write 时对数据做 AEAD 分帧加密并写入底层流。
/// 读取侧：从底层流读取 SS AEAD 帧并解密后返回明文。
struct SsXhttpStream<S> {
    inner: S,
    enc: AeadCipher,
    dec: AeadCipher,
    /// 解密后的明文缓冲
    read_buf: Vec<u8>,
    /// 底层流读取缓冲（用于积累 SS 帧）
    raw_buf: Vec<u8>,
    /// 是否已完成 salt 发送
    salt_sent: bool,
    salt: Vec<u8>,
}

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static> SsXhttpStream<S> {
    fn new(inner: S, enc: AeadCipher, dec: AeadCipher, salt: Vec<u8>) -> Self {
        Self {
            inner,
            enc,
            dec,
            read_buf: Vec::new(),
            raw_buf: Vec::new(),
            salt_sent: false,
            salt,
        }
    }
}

// MAX_PAYLOAD 和 TAG_LEN 已在文件顶部定义（第 97-98 行），此处不重复定义。

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static> tokio::io::AsyncRead
    for SsXhttpStream<S>
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        let this = self.get_mut();

        // 先消费解密缓冲
        if !this.read_buf.is_empty() {
            let n = buf.remaining().min(this.read_buf.len());
            buf.put_slice(&this.read_buf[..n]);
            this.read_buf.drain(..n);
            return Poll::Ready(Ok(()));
        }

        // SS AEAD 帧格式：[enc(len 2B) + tag 16B][enc(payload) + tag 16B]
        // 注意：只有在 raw_buf 中同时有完整的 length chunk 和 payload chunk 时，
        // 才执行解密（避免 counter 提前递增）。
        loop {
            let len_chunk_size = 2 + TAG_LEN; // 18 字节

            if this.raw_buf.len() >= len_chunk_size {
                // 先用 seal_inner 的逆（open_inner）预解密，不递增 counter，
                // 只为读取 payload 长度。
                let nonce = this.dec.nonce();
                let mut len_peek = this.raw_buf[..len_chunk_size].to_vec();
                let peek_ok = this.dec.open_inner_peek(&mut len_peek, &nonce);
                if !peek_ok {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "SS AEAD length chunk decrypt failed",
                    )));
                }
                let payload_len = u16::from_be_bytes([len_peek[0], len_peek[1]]) as usize;
                let total_needed = len_chunk_size + payload_len + TAG_LEN;

                if this.raw_buf.len() >= total_needed {
                    // 现在 raw_buf 够用，真正执行两次 open（递增 counter）
                    let mut len_chunk = this.raw_buf[..len_chunk_size].to_vec();
                    if let Err(e) = this.dec.open(&mut len_chunk) {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("SS AEAD len open: {e}"),
                        )));
                    }
                    let mut payload_chunk = this.raw_buf[len_chunk_size..total_needed].to_vec();
                    if let Err(e) = this.dec.open(&mut payload_chunk) {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("SS AEAD payload open: {e}"),
                        )));
                    }
                    this.raw_buf.drain(..total_needed);
                    this.read_buf.extend_from_slice(&payload_chunk);

                    let n = buf.remaining().min(this.read_buf.len());
                    buf.put_slice(&this.read_buf[..n]);
                    this.read_buf.drain(..n);
                    return Poll::Ready(Ok(()));
                }
                // payload 还不够，继续读
            }

            // 从底层读取更多数据
            let mut tmp = [0u8; 4096];
            let mut tmp_buf = tokio::io::ReadBuf::new(&mut tmp);
            match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let filled = tmp_buf.filled();
                    if filled.is_empty() {
                        return Poll::Ready(Ok(())); // EOF
                    }
                    this.raw_buf.extend_from_slice(filled);
                }
            }
        }
    }
}

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static> tokio::io::AsyncWrite
    for SsXhttpStream<S>
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::task::Poll;
        let this = self.get_mut();

        // 构建完整的加密输出：[salt 若未发送][enc(len)][enc(payload)]
        let mut out = Vec::new();
        if !this.salt_sent {
            out.extend_from_slice(&this.salt);
            this.salt_sent = true;
        }

        // 分块，每块不超过 MAX_PAYLOAD
        let mut offset = 0;
        while offset < data.len() {
            let chunk_end = (offset + MAX_PAYLOAD).min(data.len());
            let chunk = &data[offset..chunk_end];
            let payload_len = chunk.len() as u16;

            // 加密 length
            let mut len_buf = payload_len.to_be_bytes().to_vec();
            if let Err(e) = this.enc.seal(&mut len_buf) {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("SS seal len: {e}"),
                )));
            }
            out.extend_from_slice(&len_buf);

            // 加密 payload
            let mut payload_buf = chunk.to_vec();
            if let Err(e) = this.enc.seal(&mut payload_buf) {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("SS seal payload: {e}"),
                )));
            }
            out.extend_from_slice(&payload_buf);
            offset = chunk_end;
        }

        // 一次性写入底层流
        match std::pin::Pin::new(&mut this.inner).poll_write(cx, &out) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(data.len())),
            other => other,
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// 在已建立的泛型流上初始化 SS AEAD 上下文，发送 salt + 首个加密 payload，
/// 返回可直接用于双向转发的 `SsXhttpStream`。
async fn ss_wrap_xhttp<S>(
    mut stream: S,
    method: Method,
    subkey: Vec<u8>,
    salt: Vec<u8>,
    first_payload: Vec<u8>,
) -> anyhow::Result<SsXhttpStream<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use tokio::io::AsyncWriteExt;

    let mut enc = AeadCipher::new(method, subkey.clone());
    let dec = AeadCipher::new(method, subkey);

    // 发送 salt（明文）
    stream.write_all(&salt).await?;

    // 加密并发送首个 payload（SOCKS5 目标地址）
    let payload_len = first_payload.len() as u16;
    let mut len_buf = payload_len.to_be_bytes().to_vec();
    enc.seal(&mut len_buf)?;
    stream.write_all(&len_buf).await?;

    let mut payload_buf = first_payload;
    enc.seal(&mut payload_buf)?;
    stream.write_all(&payload_buf).await?;

    Ok(SsXhttpStream::new(stream, enc, dec, Vec::new())) // salt 已发送，传空 vec
}

// ── 地址编码（SOCKS5 格式） ───────────────────────────────────────────────────

fn encode_target(target: &Target) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32);
    match target {
        Target::Socket(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                buf.push(0x01);
                buf.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                buf.push(0x04);
                buf.extend_from_slice(&ip.octets());
            }
        },
        Target::Domain(host, _) => {
            buf.push(0x03);
            let b = host.as_bytes();
            buf.push(b.len() as u8);
            buf.extend_from_slice(b);
        }
    }
    buf.extend_from_slice(&target.port().to_be_bytes());
    buf
}

// ── 主出站结构 ────────────────────────────────────────────────────────────────

pub struct ShadowsocksOutbound {
    config: ShadowsocksOutboundConfig,
    method: Method,
    /// 传统 AEAD：EVP_BytesToKey 派生的 master key；
    /// AEAD-2022：base64 解码的 PSK。
    key_material: Vec<u8>,
    /// 全局 SO_MARK（来自 global.routing_mark），0 表示不设置
    routing_mark: u32,
}

impl ShadowsocksOutbound {
    pub fn new(config: ShadowsocksOutboundConfig) -> anyhow::Result<Self> {
        let method = Method::from_str(&config.method)?;

        let key_material = if method.is_2022() {
            use base64::Engine as _;
            let psk = base64::engine::general_purpose::STANDARD
                .decode(config.password.trim())
                .map_err(|e| anyhow::anyhow!("2022 PSK base64 decode: {e}"))?;
            anyhow::ensure!(
                psk.len() == method.key_len(),
                "2022 PSK length mismatch: expected {} got {}",
                method.key_len(),
                psk.len()
            );
            psk
        } else if method == Method::None {
            Vec::new()
        } else {
            evp_bytes_to_key(config.password.as_bytes(), method.key_len())
        };

        Ok(Self {
            config,
            method,
            key_material,
            routing_mark: 0,
        })
    }

    pub fn with_mark(mut self, mark: u32) -> Self {
        self.routing_mark = mark;
        self
    }

    async fn server_addr(&self) -> anyhow::Result<SocketAddr> {
        let host = &self.config.server;
        let port = self.config.server_port;
        tokio::net::lookup_host(format!("{host}:{port}"))
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("DNS lookup failed for {host}"))
    }

    fn random_salt(&self) -> Vec<u8> {
        use rand::RngCore;
        let mut salt = vec![0u8; self.method.salt_len()];
        rand::thread_rng().fill_bytes(&mut salt);
        salt
    }

    fn derive_subkey(&self, salt: &[u8]) -> Vec<u8> {
        let key_len = self.method.key_len();
        if self.method.is_2022() {
            ss2022_session_key(&self.key_material, salt, key_len)
        } else {
            hkdf_sha1(&self.key_material, salt, key_len)
        }
    }

    /// 裸 TCP 模式的 SS 连接。
    /// XHTTP 模式由 `connect_ss_xhttp` 单独处理，`handle_tcp` 会提前分支，
    /// 不会调用到这里。
    async fn connect_ss(&self, target: &Target) -> anyhow::Result<(SsReader, SsWriter)> {
        let server_addr = self.server_addr().await?;
        let first_payload = encode_target(target);

        if self.method == Method::None {
            let stream = TcpStream::connect(server_addr).await?;
            set_tcp_opts(&stream)?;
            apply_mark_to_tcp(&stream, self.routing_mark)?;
            let (rd, mut wr) = tokio::io::split(stream);
            wr.write_all(&first_payload).await?;
            let reader = SsReader {
                inner: rd,
                dec: AeadCipher::new(Method::None, Vec::new()),
            };
            let writer = SsWriter {
                inner: wr,
                enc: AeadCipher::new(Method::None, Vec::new()),
            };
            return Ok((reader, writer));
        }

        let salt = self.random_salt();
        let subkey = self.derive_subkey(&salt);
        ss_connect(
            server_addr,
            self.method,
            subkey,
            salt,
            first_payload,
            self.routing_mark,
        )
        .await
    }

    /// 通过 XHTTP 传输建立 Shadowsocks 连接，返回双工异步 IO
    async fn connect_ss_xhttp(
        &self,
        target: &Target,
    ) -> anyhow::Result<Box<dyn crate::outbound::AsyncReadWrite>> {
        use crate::config::outbound::ShadowsocksTransportConfig;
        use crate::outbound::xhttp;
        use std::collections::HashMap;
        use tokio::io::AsyncWriteExt;

        let xhttp_cfg = match &self.config.transport {
            Some(ShadowsocksTransportConfig::Xhttp(cfg)) => cfg,
            _ => anyhow::bail!("connect_ss_xhttp called without xhttp config"),
        };

        let mut stream = xhttp::connect(
            &self.config.server,
            self.config.server_port,
            xhttp_cfg,
            self.config.tls.as_ref(),
            &HashMap::new(),
            self.routing_mark,
        )
        .await?;

        let first_payload = encode_target(target);

        if self.method == Method::None {
            // 明文模式：直接发送目标地址前缀
            stream.write_all(&first_payload).await?;
            return Ok(Box::new(stream));
        }

        // AEAD 模式：需要手动在 xhttp 流上做 SS 帧封装
        // 使用 ss_connect_generic 辅助（见下方）
        let salt = self.random_salt();
        let subkey = self.derive_subkey(&salt);
        Ok(Box::new(
            ss_wrap_xhttp(stream, self.method, subkey, salt, first_payload).await?,
        ))
    }
}

#[async_trait::async_trait]
impl Outbound for ShadowsocksOutbound {
    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn status(&self) -> OutboundStatus {
        OutboundStatus {
            name: self.config.tag.clone(),
            type_name: "Shadowsocks".to_string(),
            now: None,
            all: vec![],
            history: vec![],
        }
    }

    async fn handle_tcp(&self, conn: InboundTcpStream) -> anyhow::Result<(u64, u64)> {
        use crate::config::outbound::ShadowsocksTransportConfig;
        debug!(tag = %self.config.tag, target = %conn.target, "shadowsocks tcp relay");

        // XHTTP 传输模式：使用泛型 SS 封装流
        if matches!(
            &self.config.transport,
            Some(ShadowsocksTransportConfig::Xhttp(_))
        ) {
            let io = self.connect_ss_xhttp(&conn.target).await?;
            let (bytes_up, bytes_dn) = crate::outbound::relay(conn.stream, io).await;
            return Ok((bytes_up, bytes_dn));
        }

        // WebSocket 传输模式（预留，暂不实现——可扩展）
        // 裸 TCP 模式（原有实现）
        let (ss_rd, ss_wr) = self.connect_ss(&conn.target).await?;
        Ok(relay_ss(conn.stream, ss_rd, ss_wr).await)
    }

    async fn handle_udp(&self, mut packet: InboundUdpPacket) -> anyhow::Result<()> {
        use tokio::net::UdpSocket;

        debug!(tag = %self.config.tag, target = %packet.target, "shadowsocks udp relay");

        let server_addr = self.server_addr().await?;
        let local_bind = if server_addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
        let udp = std::sync::Arc::new(UdpSocket::bind(local_bind).await?);
        apply_mark_to_udp(&udp, self.routing_mark)?;
        udp.connect(server_addr).await?;

        // 发送第一个上行包（内联加密，避免 closure 持有 &self）
        {
            let mut addr_payload = encode_target(&packet.target);
            addr_payload.extend_from_slice(&packet.data);
            let wire = if self.method == Method::None {
                addr_payload
            } else {
                let salt = self.random_salt();
                let subkey = self.derive_subkey(&salt);
                let mut cipher = AeadCipher::new(self.method, subkey);
                cipher.seal(&mut addr_payload)?;
                let mut pkt = salt;
                pkt.extend_from_slice(&addr_payload);
                pkt
            };
            udp.send(&wire).await?;
        }

        // 若有后续上行包，spawn task 持续加密发送
        if let Some(mut upstream_rx) = packet.upstream_rx.take() {
            let udp_send = udp.clone();
            let target_clone = packet.target.clone();
            let method = self.method;
            let key_material = self.key_material.clone();
            tokio::spawn(async move {
                use rand::RngCore;
                while let Some(data) = upstream_rx.recv().await {
                    let mut addr_payload = encode_target(&target_clone);
                    addr_payload.extend_from_slice(&data);
                    let wire = if method == Method::None {
                        addr_payload
                    } else {
                        let mut salt = vec![0u8; method.salt_len()];
                        rand::thread_rng().fill_bytes(&mut salt);
                        let key_len = method.key_len();
                        let subkey = if method.is_2022() {
                            ss2022_session_key(&key_material, &salt, key_len)
                        } else {
                            hkdf_sha1(&key_material, &salt, key_len)
                        };
                        let mut cipher = AeadCipher::new(method, subkey);
                        if cipher.seal(&mut addr_payload).is_err() {
                            break;
                        }
                        let mut pkt = salt;
                        pkt.extend_from_slice(&addr_payload);
                        pkt
                    };
                    if udp_send.send(&wire).await.is_err() {
                        break;
                    }
                }
            });
        }

        // 持续接收回包
        let reply_tx = packet.session.reply_tx.clone();
        let src = packet.src;
        let spoofed_src = packet.target.to_socket_addr_lossy();
        let salt_len = self.method.salt_len();
        let timeout = std::time::Duration::from_secs(10);
        let mut buf = vec![0u8; 65535];

        loop {
            match tokio::time::timeout(timeout, udp.recv(&mut buf)).await {
                Ok(Ok(n)) if n > salt_len + TAG_LEN => {
                    let _ = reply_tx
                        .send((Bytes::copy_from_slice(&buf[salt_len..n]), src, spoofed_src))
                        .await;
                }
                _ => break,
            }
        }
        Ok(())
    }
}
