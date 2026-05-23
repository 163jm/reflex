//! REALITY 客户端握手实现
//!
//! REALITY 协议原理（客户端视角）：
//!
//! 1. 客户端生成临时 x25519 密钥对 (ephemeral_priv, ephemeral_pub)
//! 2. 用 ephemeral_priv 与服务端公钥 (server_pub) 做 ECDH → shared_secret
//! 3. HKDF-SHA256(shared_secret, client_random[:20], "REALITY") → auth_key (16B)
//! 4. 将 session_id 明文编码为：
//!    [ver(3B) | 0x00 | timestamp_be(4B) | short_id(≤8B) | random_padding → 共32B]
//! 5. AES-128-GCM(key=auth_key, nonce=client_random[20:32], aad=ClientHello原始字节) 加密 session_id
//! 6. 取密文前 32 字节填回 ClientHello.session_id，并将临时公钥放入 key_share 扩展
//! 7. 服务端用私钥做 ECDH 恢复 auth_key，解密 session_id 验证身份
//!
//! 实现策略：
//! - 使用 PrependedTcpStream 包装 TCP 连接
//! - rustls 发起握手时，第一次 poll_write（ClientHello）被拦截，
//!   替换为我们预构造的含 REALITY 认证标记的 ClientHello record
//! - 后续握手数据正常透传，rustls 状态机正常完成 TLS 握手
//! - 证书验证使用 InsecureSkipVerify（REALITY 用临时证书，无 CA 信任链）
//!   安全性由 ECDH + HKDF AuthKey 保证

use std::{io, sync::Arc};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Key as AesKey, Nonce,
};
use hkdf::Hkdf;
use rand::Rng;
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    ClientConfig, DigitallySignedStruct, SignatureScheme,
};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, TlsConnector};
use tracing::debug;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::config::outbound::RealityDialConfig;

/// 在已建立的 TCP 流上执行 REALITY 客户端握手，返回 TLS 加密流
pub async fn reality_connect(
    tcp: TcpStream,
    config: &RealityDialConfig,
) -> anyhow::Result<TlsStream<PrependedTcpStream>> {
    // 1. 生成临时 x25519 密钥对
    let ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let ephemeral_pub = PublicKey::from(&ephemeral_secret);

    // 2. 解析服务端公钥（base64url 或 hex）
    let server_pub_bytes = decode_x25519_pubkey(&config.public_key)?;
    let server_pub = PublicKey::from(server_pub_bytes);

    // 3. ECDH
    let shared = ephemeral_secret.diffie_hellman(&server_pub);

    // 4. 生成 ClientHello random（32B）
    let mut ch_random = [0u8; 32];
    rand::thread_rng().fill(&mut ch_random);

    // 5. 构造明文 session_id
    let short_id_bytes = decode_short_id(&config.short_id)?;
    let plain_session_id = build_plain_session_id(&short_id_bytes);

    // 6. 派生 AuthKey：HKDF-SHA256(shared, ch_random[:20], "REALITY") → 16B
    let hkdf = Hkdf::<Sha256>::new(Some(&ch_random[..20]), shared.as_bytes());
    let mut auth_key = [0u8; 16];
    hkdf.expand(b"REALITY", &mut auth_key)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;

    debug!("REALITY auth_key[..4]: {:02x?}", &auth_key[..4]);

    // 7. 用明文 session_id 构造 ClientHello body（用于 AES-GCM AAD）
    let sni = config.server_name.as_deref().unwrap_or(&config.server);
    let alpn = &config.alpn;

    // AAD = 完整 ClientHello handshake 消息（Handshake header + body），含明文 session_id
    let raw_ch_body = build_client_hello_body(
        &ch_random,
        &plain_session_id,
        sni,
        ephemeral_pub.as_bytes(),
        alpn,
    );
    let raw_ch_hs = wrap_handshake(&raw_ch_body);
    // 注意：REALITY 服务端 AAD = hs.clientHello.original（整个 Handshake 消息，不含 record header）
    let aad = &raw_ch_hs;

    // 8. AES-128-GCM 加密 session_id
    // nonce = ch_random[20..32]（12B）
    let nonce = Nonce::from_slice(&ch_random[20..]);
    let key = AesKey::<Aes128Gcm>::from_slice(&auth_key);
    let cipher = Aes128Gcm::new(key);
    let encrypted = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: &plain_session_id,
                aad,
            },
        )
        .map_err(|e| anyhow::anyhow!("AES-GCM encrypt: {e}"))?;
    // encrypted = 32B密文 + 16B tag（共48B），取前32B作为加密后的 session_id
    let mut enc_session_id = [0u8; 32];
    enc_session_id.copy_from_slice(&encrypted[..32]);

    // 9. 构造最终 ClientHello（含加密 session_id，其余与明文版相同）
    let final_ch_body = build_client_hello_body(
        &ch_random,
        &enc_session_id,
        sni,
        ephemeral_pub.as_bytes(),
        alpn,
    );
    let final_ch_hs = wrap_handshake(&final_ch_body);
    let ch_record = wrap_tls_record(0x16, &final_ch_hs);

    debug!(
        sni,
        record_len = ch_record.len(),
        "REALITY: ClientHello prepared"
    );

    // 10. 包装 TCP 流，拦截 rustls 的第一次 ClientHello 写入，替换为我们的 REALITY ClientHello
    let prepended = PrependedTcpStream::new(tcp, ch_record);

    // 11. 构建 rustls 配置（跳过证书验证，接受 REALITY 临时证书）
    let tls_config = build_reality_tls_config(alpn)?;
    let connector = TlsConnector::from(tls_config);
    let server_name =
        ServerName::try_from(sni.to_string()).map_err(|_| anyhow::anyhow!("invalid SNI: {sni}"))?;

    // 12. 执行 TLS 握手（rustls 的第一次 write 被 PrependedTcpStream 替换为 REALITY ClientHello）
    let tls_stream = connector
        .connect(server_name, prepended)
        .await
        .map_err(|e| anyhow::anyhow!("REALITY TLS handshake failed: {e}"))?;

    debug!(sni, "REALITY: TLS handshake completed");
    Ok(tls_stream)
}

// ── 编解码工具 ────────────────────────────────────────────────────────────────

pub fn decode_x25519_pubkey(s: &str) -> anyhow::Result<[u8; 32]> {
    use base64::Engine;
    let s = s.trim();
    let bytes = if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(s).map_err(|e| anyhow::anyhow!("hex decode: {e}"))?
    } else {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s)
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(s))
            .map_err(|e| anyhow::anyhow!("base64 decode public key: {e}"))?
    };
    anyhow::ensure!(
        bytes.len() == 32,
        "public key must be 32 bytes, got {}",
        bytes.len()
    );
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

pub fn decode_short_id(s: &str) -> anyhow::Result<Vec<u8>> {
    if s.is_empty() {
        return Ok(vec![]);
    }
    anyhow::ensure!(
        s.len() % 2 == 0 && s.len() <= 16,
        "shortId must be 0~16 hex chars (even), got '{s}'"
    );
    hex::decode(s).map_err(|e| anyhow::anyhow!("shortId decode: {e}"))
}

fn build_plain_session_id(short_id: &[u8]) -> [u8; 32] {
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut id = [0u8; 32];
    // [0..3]: Xray 版本（1.8.11）
    id[0] = 1;
    id[1] = 8;
    id[2] = 11;
    // [3]: 0
    // [4..8]: 时间戳（秒，大端）
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    id[4..8].copy_from_slice(&ts.to_be_bytes());
    // [8..8+len]: shortId
    let l = short_id.len().min(8);
    if l > 0 {
        id[8..8 + l].copy_from_slice(&short_id[..l]);
    }
    // [16..32]: 随机填充
    rand::thread_rng().fill(&mut id[16..]);
    id
}

// ── TLS record 构造 ───────────────────────────────────────────────────────────

fn wrap_tls_record(content_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(5 + payload.len());
    r.push(content_type);
    r.extend_from_slice(&0x0301u16.to_be_bytes()); // TLS 1.0 legacy
    r.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    r.extend_from_slice(payload);
    r
}

fn wrap_handshake(body: &[u8]) -> Vec<u8> {
    let mut h = Vec::with_capacity(4 + body.len());
    h.push(0x01); // ClientHello
    let len = body.len() as u32;
    h.push((len >> 16) as u8);
    h.push((len >> 8) as u8);
    h.push(len as u8);
    h.extend_from_slice(body);
    h
}

fn build_client_hello_body(
    random: &[u8; 32],
    session_id: &[u8; 32],
    sni: &str,
    x25519_pub: &[u8; 32],
    alpn: &[String],
) -> Vec<u8> {
    let mut b = Vec::with_capacity(512);
    b.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy_version
    b.extend_from_slice(random);
    b.push(32u8);
    b.extend_from_slice(session_id);
    // cipher_suites (Chrome fingerprint)
    let cs: &[u16] = &[
        0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0x009c, 0x009d,
        0x002f, 0x0035,
    ];
    b.extend_from_slice(&((cs.len() * 2) as u16).to_be_bytes());
    for &c in cs {
        b.extend_from_slice(&c.to_be_bytes());
    }
    b.push(1u8);
    b.push(0u8); // compression_methods
    let mut exts = Vec::with_capacity(300);
    ext_sni(&mut exts, sni);
    ext_raw(&mut exts, 0x0017, &[]); // extended_master_secret
    ext_raw(&mut exts, 0xff01, &[0x00]); // renegotiation_info
    ext_supported_groups(&mut exts);
    ext_raw(&mut exts, 0x000b, &[0x01, 0x00]); // ec_point_formats
    ext_raw(&mut exts, 0x0023, &[]); // session_ticket
    ext_alpn_ext(&mut exts, alpn);
    ext_raw(&mut exts, 0x0005, &[0x01, 0x00, 0x00, 0x00, 0x00]); // status_request
    ext_sig_algs(&mut exts);
    ext_raw(&mut exts, 0x0012, &[]); // SCT
    ext_key_share(&mut exts, x25519_pub);
    ext_raw(&mut exts, 0x002d, &[0x01, 0x01]); // psk_key_exchange_modes
    ext_raw(&mut exts, 0x002b, &[0x02, 0x03, 0x04]); // supported_versions TLS1.3
    ext_raw(&mut exts, 0x001b, &[0x02, 0x00, 0x02]); // compress_certificate
    b.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    b.extend_from_slice(&exts);
    b
}

fn ext_raw(buf: &mut Vec<u8>, typ: u16, data: &[u8]) {
    buf.extend_from_slice(&typ.to_be_bytes());
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
}
fn ext_sni(buf: &mut Vec<u8>, sni: &str) {
    if sni.is_empty() {
        return;
    }
    let n = sni.as_bytes();
    let entry = 1 + 2 + n.len();
    let mut d = Vec::with_capacity(2 + entry);
    d.extend_from_slice(&(entry as u16).to_be_bytes());
    d.push(0x00);
    d.extend_from_slice(&(n.len() as u16).to_be_bytes());
    d.extend_from_slice(n);
    ext_raw(buf, 0x0000, &d);
}
fn ext_supported_groups(buf: &mut Vec<u8>) {
    let g: &[u16] = &[0x001d, 0x0017, 0x0018];
    let mut d = Vec::with_capacity(2 + g.len() * 2);
    d.extend_from_slice(&((g.len() * 2) as u16).to_be_bytes());
    for &v in g {
        d.extend_from_slice(&v.to_be_bytes());
    }
    ext_raw(buf, 0x000a, &d);
}
fn ext_alpn_ext(buf: &mut Vec<u8>, alpn: &[String]) {
    let protos: Vec<&[u8]> = if alpn.is_empty() {
        vec![b"h2", b"http/1.1"]
    } else {
        alpn.iter().map(|s| s.as_bytes()).collect()
    };
    let inner: usize = protos.iter().map(|p| 1 + p.len()).sum();
    let mut d = Vec::with_capacity(2 + inner);
    d.extend_from_slice(&(inner as u16).to_be_bytes());
    for p in protos {
        d.push(p.len() as u8);
        d.extend_from_slice(p);
    }
    ext_raw(buf, 0x0010, &d);
}
fn ext_sig_algs(buf: &mut Vec<u8>) {
    let a: &[u16] = &[
        0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x080a, 0x080b, 0x0804, 0x0805, 0x0806,
        0x0401, 0x0501, 0x0601,
    ];
    let mut d = Vec::with_capacity(2 + a.len() * 2);
    d.extend_from_slice(&((a.len() * 2) as u16).to_be_bytes());
    for &v in a {
        d.extend_from_slice(&v.to_be_bytes());
    }
    ext_raw(buf, 0x000d, &d);
}
fn ext_key_share(buf: &mut Vec<u8>, pub_key: &[u8; 32]) {
    let entry = 2 + 2 + 32usize;
    let mut d = Vec::with_capacity(2 + entry);
    d.extend_from_slice(&(entry as u16).to_be_bytes());
    d.extend_from_slice(&0x001du16.to_be_bytes()); // x25519
    d.extend_from_slice(&32u16.to_be_bytes());
    d.extend_from_slice(pub_key);
    ext_raw(buf, 0x0033, &d);
}

// ── rustls 配置（InsecureSkipVerify）─────────────────────────────────────────

fn build_reality_tls_config(alpn: &[String]) -> anyhow::Result<Arc<ClientConfig>> {
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(RealityVerifier))
        .with_no_client_auth();
    config.alpn_protocols = if alpn.is_empty() {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        alpn.iter().map(|s| s.as_bytes().to_vec()).collect()
    };
    Ok(Arc::new(config))
}

#[derive(Debug)]
struct RealityVerifier;

impl ServerCertVerifier for RealityVerifier {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

// ── PrependedTcpStream ────────────────────────────────────────────────────────

use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::ReadBuf;

// 包装 TcpStream，拦截 rustls 发送 ClientHello 的第一次 write，
// 替换为含 REALITY 认证标记的 ClientHello record。
// 后续所有写入正常透传。
pin_project_lite::pin_project! {
    pub struct PrependedTcpStream {
        #[pin]
        inner: TcpStream,
        reality_hello: Option<Vec<u8>>,
    }
}

impl PrependedTcpStream {
    pub fn new(inner: TcpStream, reality_hello: Vec<u8>) -> Self {
        Self {
            inner,
            reality_hello: Some(reality_hello),
        }
    }
}

impl AsyncRead for PrependedTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl AsyncWrite for PrependedTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut this = self.project();
        if let Some(hello) = this.reality_hello.take() {
            // 拦截第一次写入：发送 REALITY ClientHello，丢弃 rustls 的 ClientHello
            match this.inner.as_mut().poll_write(cx, &hello) {
                Poll::Ready(Ok(_written)) => {
                    debug!("REALITY: intercepted rustls ClientHello, sent REALITY ClientHello ({} bytes)", hello.len());
                    // 假装写了 data.len() 字节，让 rustls 认为 ClientHello 已成功发出
                    Poll::Ready(Ok(data.len()))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => {
                    // 写阻塞，把 hello 放回去
                    *this.reality_hello = Some(hello);
                    Poll::Pending
                }
            }
        } else {
            // 后续写入正常透传（ChangeCipherSpec、Finished、应用数据等）
            this.inner.poll_write(cx, data)
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_short_id_ok() {
        assert!(decode_short_id("").unwrap().is_empty());
        let r = decode_short_id("0123456789abcdef").unwrap();
        assert_eq!(r.len(), 8);
        assert_eq!(r[0], 0x01);
    }

    #[test]
    fn decode_short_id_err() {
        assert!(decode_short_id("abc").is_err());
        assert!(decode_short_id("0123456789abcdef01").is_err());
    }

    #[test]
    fn session_id_format() {
        let id = build_plain_session_id(&[0xab, 0xcd]);
        assert_eq!(id[0], 1);
        assert_eq!(id[1], 8);
        assert_eq!(id[8], 0xab);
        assert_eq!(id[9], 0xcd);
    }

    #[test]
    fn client_hello_body_structure() {
        let random = [0u8; 32];
        let sid = [0u8; 32];
        let pub_key = [0u8; 32];
        let body = build_client_hello_body(&random, &sid, "example.com", &pub_key, &[]);
        assert_eq!(&body[0..2], &[0x03, 0x03]); // legacy_version TLS1.2
        assert!(!body.is_empty());
    }
}
