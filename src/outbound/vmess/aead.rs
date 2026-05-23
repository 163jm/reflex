//! VMess 数据传输层：AEAD 分帧读写器。
//!
//! 握手完成后，所有数据用带计数器的 AES-128-GCM / ChaCha20-Poly1305 加密。
//! 每帧格式：[len_masked 2B] [ciphertext + GCM_TAG 16B]
//!
//! Nonce：前 2 字节 = 大端计数器，后 10 字节取自 req_nonce[2..12]。
//! 发送用 req_key/req_nonce，接收用 SHA256(req_key)/SHA256(req_nonce) 的前 16 字节。

use std::{
    io::{self},
    pin::Pin,
    task::{Context, Poll},
};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm,
};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::frame::{OPT_CHUNK_MASKING, OPT_CHUNK_STREAM, SECURITY_AES128_GCM, SECURITY_NONE};

// ── AES tag 大小 ─────────────────────────────────────────────────────────────
// ── 枚举：支持的 AEAD 算法 ───────────────────────────────────────────────────

enum VmessAeadCipher {
    Aes128Gcm(Aes128Gcm),
    Chacha20Poly1305(ChaCha20Poly1305),
}

impl VmessAeadCipher {
    fn new(security: u8, key: &[u8]) -> Self {
        use super::frame::SECURITY_CHACHA20_POLY1305;
        match security {
            SECURITY_AES128_GCM => {
                VmessAeadCipher::Aes128Gcm(Aes128Gcm::new_from_slice(key).expect("aes key"))
            }
            SECURITY_CHACHA20_POLY1305 => {
                let full_key = chacha20_key(key);
                VmessAeadCipher::Chacha20Poly1305(
                    ChaCha20Poly1305::new_from_slice(&full_key).expect("chacha key"),
                )
            }
            _ => panic!("unsupported security: {security}"),
        }
    }

    fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        use aes_gcm::aead::generic_array::GenericArray;
        let n = GenericArray::from_slice(nonce);
        match self {
            VmessAeadCipher::Aes128Gcm(c) => c.encrypt(n, plaintext),
            VmessAeadCipher::Chacha20Poly1305(c) => c.encrypt(n, plaintext),
        }
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        use aes_gcm::aead::generic_array::GenericArray;
        let n = GenericArray::from_slice(nonce);
        match self {
            VmessAeadCipher::Aes128Gcm(c) => c.decrypt(n, ciphertext),
            VmessAeadCipher::Chacha20Poly1305(c) => c.decrypt(n, ciphertext),
        }
    }
}

fn chacha20_key(key: &[u8]) -> [u8; 32] {
    use md5::{Digest, Md5};
    let h1: [u8; 16] = Md5::digest(key).into();
    let h2: [u8; 16] = Md5::digest(&h1).into();
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&h1);
    out[16..].copy_from_slice(&h2);
    out
}

// ── Shake128 masking ─────────────────────────────────────────────────────────

fn make_shake128_reader(seed: &[u8]) -> impl XofReader {
    let mut h = Shake128::default();
    h.update(seed);
    h.finalize_xof()
}

fn next_mask_u16(reader: &mut dyn XofReader) -> u16 {
    let mut b = [0u8; 2];
    reader.read(&mut b);
    u16::from_be_bytes(b)
}

// ── Nonce ────────────────────────────────────────────────────────────────────

fn make_nonce(count: u16, base: &[u8; 16]) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..2].copy_from_slice(&count.to_be_bytes());
    n[2..].copy_from_slice(&base[2..12]);
    n
}

// ── 派生响应侧 key / nonce ───────────────────────────────────────────────────

pub fn resp_data_key(req_key: &[u8; 16]) -> [u8; 16] {
    use sha2::Digest;
    let h: [u8; 32] = sha2::Sha256::digest(req_key).into();
    h[..16].try_into().unwrap()
}

pub fn resp_data_nonce(req_nonce: &[u8; 16]) -> [u8; 16] {
    use sha2::Digest;
    let h: [u8; 32] = sha2::Sha256::digest(req_nonce).into();
    h[..16].try_into().unwrap()
}

// ── VmessEncoder（封装发送侧编码状态）────────────────────────────────────────

pub struct VmessEncoder {
    cipher: Option<VmessAeadCipher>,
    base_nonce: [u8; 16],
    count: u16,
    masking: Option<Box<dyn XofReader + Send>>,
    security: u8,
    option: u8,
}

impl VmessEncoder {
    pub fn new(security: u8, option: u8, key: &[u8; 16], nonce: &[u8; 16]) -> Self {
        let cipher = if security == SECURITY_NONE {
            None
        } else {
            Some(VmessAeadCipher::new(security, key))
        };
        let masking: Option<Box<dyn XofReader + Send>> = if option & OPT_CHUNK_MASKING != 0 {
            Some(Box::new(make_shake128_reader(nonce)))
        } else {
            None
        };
        Self {
            cipher,
            base_nonce: *nonce,
            count: 0,
            masking,
            security,
            option,
        }
    }

    pub fn encode(&mut self, plaintext: &[u8]) -> io::Result<Bytes> {
        if self.security == SECURITY_NONE && self.option & OPT_CHUNK_STREAM == 0 {
            return Ok(Bytes::copy_from_slice(plaintext));
        }
        if self.security == SECURITY_NONE {
            let mut len = plaintext.len() as u16;
            if let Some(ref mut m) = self.masking {
                len ^= next_mask_u16(m.as_mut());
            }
            let mut out = BytesMut::with_capacity(2 + plaintext.len());
            out.put_u16(len);
            out.put_slice(plaintext);
            return Ok(out.freeze());
        }
        let nonce = make_nonce(self.count, &self.base_nonce);
        self.count += 1;
        let ct = self
            .cipher
            .as_ref()
            .unwrap()
            .encrypt(&nonce, plaintext)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("vmess encrypt: {e:?}")))?;
        let mut chunk_len = ct.len() as u16;
        if let Some(ref mut m) = self.masking {
            chunk_len ^= next_mask_u16(m.as_mut());
        }
        let mut out = BytesMut::with_capacity(2 + ct.len());
        out.put_u16(chunk_len);
        out.put_slice(&ct);
        Ok(out.freeze())
    }
}

// ── VmessDecoder（封装接收侧解码状态）────────────────────────────────────────

enum DecodeState {
    NeedLen,
    NeedData(usize),
}

pub struct VmessDecoder {
    cipher: Option<VmessAeadCipher>,
    base_nonce: [u8; 16],
    count: u16,
    masking: Option<Box<dyn XofReader + Send>>,
    state: DecodeState,
    security: u8,
    option: u8,
}

impl VmessDecoder {
    pub fn new(security: u8, option: u8, key: &[u8; 16], nonce: &[u8; 16]) -> Self {
        let cipher = if security == SECURITY_NONE {
            None
        } else {
            Some(VmessAeadCipher::new(security, key))
        };
        let masking: Option<Box<dyn XofReader + Send>> = if option & OPT_CHUNK_MASKING != 0 {
            Some(Box::new(make_shake128_reader(nonce)))
        } else {
            None
        };
        Self {
            cipher,
            base_nonce: *nonce,
            count: 0,
            masking,
            state: DecodeState::NeedLen,
            security,
            option,
        }
    }

    /// 尝试从 raw_buf 中解码一个完整 chunk，返回明文或 None（数据不足）。
    pub fn try_decode(&mut self, raw: &mut BytesMut) -> io::Result<Option<Bytes>> {
        if self.security == SECURITY_NONE && self.option & OPT_CHUNK_STREAM == 0 {
            if raw.is_empty() {
                return Ok(None);
            }
            return Ok(Some(raw.split().freeze()));
        }
        loop {
            match self.state {
                DecodeState::NeedLen => {
                    if raw.len() < 2 {
                        return Ok(None);
                    }
                    let mut raw_len = u16::from_be_bytes([raw[0], raw[1]]) as usize;
                    raw.advance(2);
                    if let Some(ref mut m) = self.masking {
                        raw_len ^= next_mask_u16(m.as_mut()) as usize;
                    }
                    if raw_len == 0 {
                        return Ok(Some(Bytes::new())); // EOF 信号
                    }
                    self.state = DecodeState::NeedData(raw_len);
                }
                DecodeState::NeedData(expected) => {
                    if raw.len() < expected {
                        return Ok(None);
                    }
                    let chunk = raw.split_to(expected);
                    self.state = DecodeState::NeedLen;
                    let plain = if self.security == SECURITY_NONE {
                        chunk.freeze()
                    } else {
                        let nonce = make_nonce(self.count, &self.base_nonce);
                        self.count += 1;
                        let pt = self
                            .cipher
                            .as_ref()
                            .unwrap()
                            .decrypt(&nonce, &chunk)
                            .map_err(|e| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!("vmess decrypt: {e:?}"),
                                )
                            })?;
                        Bytes::from(pt)
                    };
                    return Ok(Some(plain));
                }
            }
        }
    }
}

// ── VmessReadHalf ─────────────────────────────────────────────────────────────

pub struct VmessReadHalf<R> {
    inner: R,
    decoder: VmessDecoder,
    raw_buf: BytesMut,
    decoded_buf: Bytes,
}

impl<R: AsyncRead + Unpin> VmessReadHalf<R> {
    pub fn new(inner: R, decoder: VmessDecoder) -> Self {
        Self {
            inner,
            decoder,
            raw_buf: BytesMut::new(),
            decoded_buf: Bytes::new(),
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for VmessReadHalf<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            // 先消费已解码缓冲
            if !this.decoded_buf.is_empty() {
                let n = buf.remaining().min(this.decoded_buf.len());
                buf.put_slice(&this.decoded_buf[..n]);
                let _ = this.decoded_buf.split_to(n);
                return Poll::Ready(Ok(()));
            }
            // 从 raw_buf 尝试解码
            match this.decoder.try_decode(&mut this.raw_buf)? {
                Some(data) if data.is_empty() => return Poll::Ready(Ok(())), // EOF chunk
                Some(data) => {
                    this.decoded_buf = data;
                    continue;
                }
                None => {}
            }
            // 从底层读更多数据
            let before = this.raw_buf.len();
            this.raw_buf.reserve(4096);
            let spare = this.raw_buf.spare_capacity_mut();
            let mut read_buf = ReadBuf::uninit(spare);
            match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    // SAFETY: read_buf.filled() 证明前 n 字节已初始化
                    unsafe { this.raw_buf.set_len(before + n) };
                }
            }
        }
    }
}

// ── VmessWriteHalf ────────────────────────────────────────────────────────────

pub struct VmessWriteHalf<W> {
    inner: W,
    encoder: VmessEncoder,
    pending: Bytes,
}

impl<W: AsyncWrite + Unpin> VmessWriteHalf<W> {
    pub fn new(inner: W, encoder: VmessEncoder) -> Self {
        Self {
            inner,
            encoder,
            pending: Bytes::new(),
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for VmessWriteHalf<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // 先把上次 pending 刷出去
        while !this.pending.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.pending) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(n)) => {
                    let _ = this.pending.split_to(n);
                }
            }
        }
        const MAX_CHUNK: usize = 15000;
        let chunk = &data[..data.len().min(MAX_CHUNK)];
        this.pending = this.encoder.encode(chunk)?;
        Poll::Ready(Ok(chunk.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while !this.pending.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.pending) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(n)) => {
                    let _ = this.pending.split_to(n);
                }
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// ── VmessStream（公开入口，用 tokio::io::split 安全拆分）──────────────────────

use tokio::io::{ReadHalf, WriteHalf};

pub struct VmessStream<S> {
    read: VmessReadHalf<ReadHalf<S>>,
    write: VmessWriteHalf<WriteHalf<S>>,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> VmessStream<S> {
    pub fn new(
        inner: S,
        security: u8,
        option: u8,
        req_key: &[u8; 16],
        req_nonce: &[u8; 16],
    ) -> Self {
        let resp_key = resp_data_key(req_key);
        let resp_nonce = resp_data_nonce(req_nonce);

        let encoder = VmessEncoder::new(security, option, req_key, req_nonce);
        let decoder = VmessDecoder::new(security, option, &resp_key, &resp_nonce);

        let (rh, wh) = tokio::io::split(inner);
        Self {
            read: VmessReadHalf::new(rh, decoder),
            write: VmessWriteHalf::new(wh, encoder),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> AsyncRead for VmessStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().read).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> AsyncWrite for VmessStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().write).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_shutdown(cx)
    }
}
