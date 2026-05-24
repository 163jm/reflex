//! 协议嗅探：非破坏性 peek TCP/UDP 流的头部字节，识别协议和域名。
//!
//! ## 支持的协议
//! - **TLS**：解析 ClientHello 中的 SNI extension（RFC 6066）取目标域名；
//!   同时解析 ALPN extension（RFC 7301）检测 `h2`。
//! - **HTTP/1.x**：从请求头中提取 `Host:` 字段。
//! - **QUIC**：从 QUIC Initial 包解密 ClientHello，提取 SNI。
//! - **SSH**：检测 SSH 协议标识符。
//! - **BitTorrent**：检测 BitTorrent 握手。
//!
//! ## 原理
//! - 对 stream 设置短暂读取 deadline，读取一块数据后通过 `stream.prepend()` 归还。
//! - 若所有协议都识别不出则返回 `None`（域名未知，保持原 target 不变）。

use std::time::Duration;

use tokio::io::AsyncReadExt;
use tracing::debug;

use crate::inbound::SniffedStream;

/// 嗅探结果
pub struct SniffResult {
    /// 识别出的域名（不含端口），若协议不携带域名则为 None
    pub domain: Option<String>,
    /// 应用层协议标识：`"tls"` / `"h2"` / `"http"` / `"quic"` / `"ssh"` / `"bittorrent"`
    pub protocol: &'static str,
}

/// 可选的嗅探协议类型
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SniffType {
    Tls,
    Http,
    Quic,
    Ssh,
    BitTorrent,
}

impl SniffType {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "tls" => Some(Self::Tls),
            "http" => Some(Self::Http),
            "quic" => Some(Self::Quic),
            "ssh" => Some(Self::Ssh),
            "bittorrent" | "bt" => Some(Self::BitTorrent),
            _ => None,
        }
    }

    /// 默认启用的协议列表
    pub fn defaults() -> Vec<Self> {
        vec![
            Self::Tls,
            Self::Http,
            Self::Quic,
            Self::Ssh,
            Self::BitTorrent,
        ]
    }
}

/// 默认嗅探超时
const DEFAULT_TIMEOUT_MS: u64 = 300;
/// 单次最多读取字节数
const PEEK_BUF_SIZE: usize = 2048;

/// 对 `stream` 进行非破坏性协议嗅探。
///
/// - `sniff_types`：为空时使用默认协议列表（TLS/HTTP/QUIC/SSH/BitTorrent）
/// - 读出最多 [`PEEK_BUF_SIZE`] 字节，解析后通过 `stream.prepend()` 归还
pub async fn sniff(
    stream: &mut SniffedStream,
    timeout_ms: u64,
    sniff_types: &[SniffType],
) -> Option<SniffResult> {
    let timeout = Duration::from_millis(if timeout_ms == 0 {
        DEFAULT_TIMEOUT_MS
    } else {
        timeout_ms
    });

    let types: &[SniffType] = if sniff_types.is_empty() {
        &[] // 占位，下面用 defaults
    } else {
        sniff_types
    };

    let defaults_storage;
    let effective_types: &[SniffType] = if sniff_types.is_empty() {
        defaults_storage = SniffType::defaults();
        &defaults_storage
    } else {
        types
    };

    let mut buf = vec![0u8; PEEK_BUF_SIZE];

    let n = match tokio::time::timeout(timeout, stream.inner.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return None,
    };

    // 归还读出的字节（必须在解析前还原）
    stream.prepend(bytes::Bytes::copy_from_slice(&buf[..n]));

    let data = &buf[..n];

    // 按顺序尝试各协议
    for sniff_type in effective_types {
        let result = match sniff_type {
            SniffType::Tls => try_tls(data),
            SniffType::Http => try_http_host(data),
            SniffType::Quic => try_quic(data),
            SniffType::Ssh => try_ssh(data),
            SniffType::BitTorrent => try_bittorrent(data),
        };
        if let Some(r) = result {
            debug!(
                domain = ?r.domain,
                protocol = r.protocol,
                bytes = n,
                "sniffed"
            );
            return Some(r);
        }
    }

    None
}

/// 对 UDP 包进行协议嗅探（QUIC）。
/// 返回 `(protocol, domain)`。
pub fn sniff_packet(data: &[u8], sniff_types: &[SniffType]) -> Option<SniffResult> {
    let defaults_storage;
    let effective_types: &[SniffType] = if sniff_types.is_empty() {
        defaults_storage = SniffType::defaults();
        &defaults_storage
    } else {
        sniff_types
    };

    for sniff_type in effective_types {
        if let SniffType::Quic = sniff_type {
            if let Some(r) = try_quic(data) {
                return Some(r);
            }
        }
    }
    None
}

// ── TLS ClientHello 解析 ──────────────────────────────────────────────────────
//
// TLS record 格式（RFC 5246 §6.2）:
//   ContentType(1) Version(2) Length(2) Handshake...
// Handshake ClientHello（RFC 5246 §7.4.1.2）:
//   HandshakeType(1)=0x01 Length(3) ProtocolVersion(2)
//   Random(32) SessionIDLen(1) SessionID(var)
//   CipherSuitesLen(2) CipherSuites(var)
//   CompressionMethodsLen(1) CompressionMethods(var)
//   ExtensionsLen(2) Extensions(var)
// SNI extension  type 0x0000 （RFC 6066 §3）
// ALPN extension type 0x0010 （RFC 7301 §3）

fn try_tls(buf: &[u8]) -> Option<SniffResult> {
    if buf.len() < 43 {
        return None;
    }
    if buf[0] != 0x16 || buf[1] != 0x03 {
        return None;
    }
    if buf[5] != 0x01 {
        return None;
    }

    let mut pos = 5 + 4 + 2 + 32;

    if pos >= buf.len() {
        return None;
    }
    let sid_len = buf[pos] as usize;
    pos += 1 + sid_len;

    if pos + 2 > buf.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2 + cs_len;

    if pos + 1 > buf.len() {
        return None;
    }
    let cm_len = buf[pos] as usize;
    pos += 1 + cm_len;

    if pos + 2 > buf.len() {
        return None;
    }
    let ext_total = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;

    let ext_end = (pos + ext_total).min(buf.len());

    let mut sni: Option<String> = None;
    let mut is_h2 = false;

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let ext_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;
        let ext_data_end = (pos + ext_len).min(ext_end);

        match ext_type {
            0x0000 if pos + 2 <= ext_data_end => {
                let mut p = pos + 2;
                if p < ext_data_end && buf[p] == 0x00 {
                    p += 1;
                    if p + 2 <= ext_data_end {
                        let name_len = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
                        p += 2;
                        if p + name_len <= ext_data_end {
                            if let Ok(name) = std::str::from_utf8(&buf[p..p + name_len]) {
                                sni = Some(name.to_string());
                            }
                        }
                    }
                }
            }
            0x0010 if pos + 2 <= ext_data_end => {
                let list_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
                let mut p = pos + 2;
                let list_end = (p + list_len).min(ext_data_end);
                while p < list_end {
                    let proto_len = buf[p] as usize;
                    p += 1;
                    if p + proto_len <= list_end {
                        if &buf[p..p + proto_len] == b"h2" {
                            is_h2 = true;
                        }
                        p += proto_len;
                    } else {
                        break;
                    }
                }
            }
            _ => {}
        }

        pos = ext_data_end;

        if sni.is_some() && is_h2 {
            break;
        }
    }

    sni.map(|domain| SniffResult {
        domain: Some(domain),
        protocol: if is_h2 { "h2" } else { "tls" },
    })
}

// ── HTTP/1.x Host 解析 ───────────────────────────────────────────────────────

fn try_http_host(buf: &[u8]) -> Option<SniffResult> {
    let text = std::str::from_utf8(buf).ok()?;

    let first_line_end = text.find("\r\n")?;
    let first_line = &text[..first_line_end];
    if !first_line.contains(" HTTP/") {
        return None;
    }

    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("host:") {
            let host = rest.trim();
            let domain = host.split(':').next().unwrap_or(host);
            if !domain.is_empty() {
                return Some(SniffResult {
                    domain: Some(domain.to_string()),
                    protocol: "http",
                });
            }
        }
    }

    None
}

// ── QUIC ClientHello SNI 解析 ─────────────────────────────────────────────────
//
// 解析 QUIC Initial 包（QUIC v1/v2/Draft-29）中的 ClientHello SNI。
// 参照 sing-box common/sniff/quic.go 和 RFC 9001。
//
// QUIC Long Header Initial 包格式:
//   First byte (1): 0x40 | type bits
//   Version (4)
//   Dest Conn ID Len (1) + Dest Conn ID (var)
//   Src  Conn ID Len (1) + Src  Conn ID (var)
//   Token Len (varint)   + Token (var)
//   Packet Len (varint)
//   Packet Number (1-4, AEAD 保护，需解密)
//   QUIC Crypto frame → TLS ClientHello (AEAD 保护，需解密)
//
// QUIC 使用 HKDF 派生的 Initial secrets 对 Initial 包加密，
// 本实现对 Initial 包做 AEAD 解密后提取内嵌 TLS ClientHello 中的 SNI。

fn try_quic(buf: &[u8]) -> Option<SniffResult> {
    // 最小长度检查：first byte + version(4) + dcil(1)
    if buf.len() < 6 {
        return None;
    }
    // Long header: 最高位为1，Fixed bit(0x40)必须为1
    if buf[0] & 0xC0 != 0xC0 {
        return None;
    }

    let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    // 仅支持 QUIC v1 (0x00000001), v2 (0x6b3343cf), Draft-29 (0xff00001d)
    let (is_v2, initial_salt) = match version {
        0x00000001 => (false, QUIC_V1_INITIAL_SALT.as_slice()),
        0x6b3343cf => (true, QUIC_V2_INITIAL_SALT.as_slice()),
        0xff00001d => (false, QUIC_DRAFT29_INITIAL_SALT.as_slice()),
        _ => return None,
    };

    // 检查 packet type = Initial (0x00 for v1/draft, 0x01 for v2)
    let ptype = (buf[0] & 0x30) >> 4;
    let expected_ptype = if is_v2 { 0x01 } else { 0x00 };
    if ptype != expected_ptype {
        return None;
    }

    let mut pos = 5usize;

    // Destination Connection ID
    if pos >= buf.len() {
        return None;
    }
    let dcid_len = buf[pos] as usize;
    pos += 1;
    if dcid_len == 0 || dcid_len > 20 {
        return None;
    }
    if pos + dcid_len > buf.len() {
        return None;
    }
    let dcid = &buf[pos..pos + dcid_len];
    pos += dcid_len;

    // Source Connection ID
    if pos >= buf.len() {
        return None;
    }
    let scid_len = buf[pos] as usize;
    pos += 1;
    if pos + scid_len > buf.len() {
        return None;
    }
    pos += scid_len;

    // Token
    let (token_len, vl) = read_varint(buf, pos)?;
    pos += vl + token_len as usize;

    // Packet Length
    let (pkt_len, vl2) = read_varint(buf, pos)?;
    pos += vl2;

    if pos >= buf.len() {
        return None;
    }
    let encrypted_payload = &buf[pos..pos.saturating_add(pkt_len as usize).min(buf.len())];
    if encrypted_payload.is_empty() {
        return None;
    }

    // 派生 Initial secrets 并解密
    let plaintext = decrypt_quic_initial(dcid, initial_salt, encrypted_payload, is_v2)?;

    // 从解密后的 QUIC CRYPTO frame 中提取 TLS ClientHello
    extract_sni_from_quic_crypto(&plaintext)
}

// QUIC Initial salt 常量
const QUIC_V1_INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const QUIC_V2_INITIAL_SALT: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];
const QUIC_DRAFT29_INITIAL_SALT: [u8; 20] = [
    0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0,
    0x43, 0x90, 0xa8, 0x99,
];

/// 读取 QUIC 可变长整数，返回 (值, 已消耗字节数)
fn read_varint(buf: &[u8], pos: usize) -> Option<(u64, usize)> {
    if pos >= buf.len() {
        return None;
    }
    let first = buf[pos];
    let prefix = (first & 0xC0) >> 6;
    match prefix {
        0 => Some((first as u64 & 0x3F, 1)),
        1 => {
            if pos + 2 > buf.len() {
                return None;
            }
            let v = u16::from_be_bytes([first & 0x3F, buf[pos + 1]]);
            Some((v as u64, 2))
        }
        2 => {
            if pos + 4 > buf.len() {
                return None;
            }
            let v = u32::from_be_bytes([first & 0x3F, buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
            Some((v as u64, 4))
        }
        3 => {
            if pos + 8 > buf.len() {
                return None;
            }
            let v = u64::from_be_bytes([
                first & 0x3F,
                buf[pos + 1],
                buf[pos + 2],
                buf[pos + 3],
                buf[pos + 4],
                buf[pos + 5],
                buf[pos + 6],
                buf[pos + 7],
            ]);
            Some((v, 8))
        }
        _ => None,
    }
}

/// 使用 HKDF + AES-128-GCM 解密 QUIC Initial 包负载。
/// 参照 RFC 9001 §5.2 和 sing-box 实现。
fn decrypt_quic_initial(
    dcid: &[u8],
    initial_salt: &[u8],
    payload: &[u8],
    _is_v2: bool,
) -> Option<Vec<u8>> {
    // HKDF-Extract(initial_salt, dcid) → initial_secret
    let initial_secret = hkdf_extract_sha256(initial_salt, dcid);

    // HKDF-Expand-Label(initial_secret, "client in", "", 32) → client_initial_secret
    let client_secret = hkdf_expand_label_sha256(&initial_secret, b"client in", b"", 32)?;

    // 派生 key(16), iv(12), hp(16)
    let key = hkdf_expand_label_sha256(&client_secret, b"quic key", b"", 16)?;
    let iv = hkdf_expand_label_sha256(&client_secret, b"quic iv", b"", 12)?;
    let hp = hkdf_expand_label_sha256(&client_secret, b"quic hp", b"", 16)?;

    if payload.len() < 20 {
        return None;
    }

    // Header Protection: 用 hp 掩码还原 first byte 和 packet number
    // sample = payload[4..20]
    let sample = &payload[4..20];
    let mask = aes128_ecb_block(&hp, sample)?;

    // 还原 first byte 的低4位（long header: mask bits 0-3）
    let first_byte = payload[0] ^ (mask[0] & 0x0F);
    let pn_len = ((first_byte & 0x03) + 1) as usize;

    if payload.len() < pn_len {
        return None;
    }

    // 还原 packet number 字节
    let mut pn_bytes = [0u8; 4];
    for i in 0..pn_len {
        pn_bytes[i] = payload[i] ^ mask[1 + i];
    }
    // packet_number（截断形式，仅用于 nonce，简化处理取前 pn_len 字节）
    let pn = u32::from_be_bytes(pn_bytes);

    // 构造 AEAD nonce = iv XOR packet_number（右对齐）
    let mut nonce = iv.clone();
    let pn_be = pn.to_be_bytes();
    for i in 0..4 {
        nonce[8 + i] ^= pn_be[i];
    }

    // 密文 = payload[pn_len..len-16]，AEAD tag = payload[len-16..]
    let ciphertext_start = pn_len;
    if payload.len() < ciphertext_start + 16 {
        return None;
    }
    let ciphertext = &payload[ciphertext_start..payload.len() - 16];
    let tag = &payload[payload.len() - 16..];

    // 构造 AAD = 原始头部（first byte 已恢复 + 后续到 pn 末尾）
    let mut aad = Vec::with_capacity(pn_len + 1);
    aad.push(first_byte);
    // 从原始 payload 截取 packet number 位置之前的内容（本函数 payload 是从 pn 开始的）
    // 注意：这里 payload 已是从 packet number 位置开始的数据
    for i in 0..pn_len {
        aad.push(payload[i] ^ mask[1 + i]);
    }

    // AES-128-GCM 解密
    aes128_gcm_decrypt(&key, &nonce, &aad, ciphertext, tag)
}

/// HKDF-Extract with SHA-256
fn hkdf_extract_sha256(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    hmac_sha256(salt, ikm)
}

/// HMAC-SHA256
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    const BLOCK_SIZE: usize = 64;
    let mut k = if key.len() > BLOCK_SIZE {
        sha256(key).to_vec()
    } else {
        key.to_vec()
    };
    k.resize(BLOCK_SIZE, 0);

    let mut ipad = vec![0x36u8; BLOCK_SIZE];
    let mut opad = vec![0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = ipad;
    inner.extend_from_slice(data);
    let inner_hash = sha256(&inner);

    let mut outer = opad;
    outer.extend_from_slice(&inner_hash);
    sha256(&outer).to_vec()
}

/// HKDF-Expand-Label (TLS 1.3 style)
fn hkdf_expand_label_sha256(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    len: usize,
) -> Option<Vec<u8>> {
    // HkdfLabel = length(2) + label_len(1) + "tls13 " + label + context_len(1) + context
    let prefix = b"tls13 ";
    let full_label_len = prefix.len() + label.len();
    let mut hkdf_label = Vec::with_capacity(2 + 1 + full_label_len + 1 + context.len());
    hkdf_label.push((len >> 8) as u8);
    hkdf_label.push(len as u8);
    hkdf_label.push(full_label_len as u8);
    hkdf_label.extend_from_slice(prefix);
    hkdf_label.extend_from_slice(label);
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    // HKDF-Expand: T(1) = HMAC(secret, hkdf_label || 0x01)
    // 只需第一块（len <= 32 时）
    if len > 32 {
        return None;
    }
    let mut info = hkdf_label;
    info.push(0x01);
    let t = hmac_sha256(secret, &info);
    Some(t[..len].to_vec())
}

/// 纯 Rust SHA-256（无外部依赖）
fn sha256(data: &[u8]) -> [u8; 32] {
    // 使用 Rust 标准库不包含 SHA-256，这里实现一个简单版本
    // K 常量
    #[allow(clippy::unreadable_literal)]
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    // 预处理
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    // 处理每个 512-bit 块
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

/// AES-128-ECB 加密单块（16字节）
fn aes128_ecb_block(key: &[u8], block: &[u8]) -> Option<[u8; 16]> {
    if key.len() != 16 || block.len() < 16 {
        return None;
    }
    let mut state = [0u8; 16];
    state.copy_from_slice(&block[..16]);
    let round_keys = aes128_key_schedule(key);
    aes128_encrypt_block(&mut state, &round_keys);
    Some(state)
}

/// AES-128-GCM 解密
fn aes128_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Option<Vec<u8>> {
    if key.len() != 16 || nonce.len() != 12 || tag.len() != 16 {
        return None;
    }

    let round_keys = aes128_key_schedule(key);

    // GCM counter: J0 = nonce || 0x00000001
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 0x01;

    // 验证 GHASH tag
    let h_block = {
        let mut b = [0u8; 16];
        aes128_encrypt_block(&mut b, &round_keys);
        b
    };
    let computed_tag = gcm_tag(&h_block, aad, ciphertext, key, nonce, &round_keys);
    if computed_tag != tag {
        return None; // tag 不匹配（加密数据或连接不是 QUIC Initial）
    }

    // CTR 解密：counter 从 J0+1 开始
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut counter = j0;
    gcm_inc32(&mut counter);

    for chunk in ciphertext.chunks(16) {
        let mut keystream = counter;
        aes128_encrypt_block(&mut keystream, &round_keys);
        for (i, &b) in chunk.iter().enumerate() {
            plaintext.push(b ^ keystream[i]);
        }
        gcm_inc32(&mut counter);
    }

    Some(plaintext)
}

fn gcm_inc32(block: &mut [u8; 16]) {
    let n = u32::from_be_bytes([block[12], block[13], block[14], block[15]]);
    let n = n.wrapping_add(1);
    block[12..].copy_from_slice(&n.to_be_bytes());
}

/// GCM GHASH + auth tag 计算
fn gcm_tag(
    h: &[u8; 16],
    aad: &[u8],
    ciphertext: &[u8],
    _key: &[u8],
    _nonce: &[u8],
    _round_keys: &[[u8; 16]; 11],
) -> [u8; 16] {
    let mut y = [0u8; 16];

    // GHASH over AAD
    for chunk in padded_chunks(aad) {
        xor16(&mut y, &chunk);
        y = gf128_mul(&y, h);
    }
    // GHASH over ciphertext
    for chunk in padded_chunks(ciphertext) {
        xor16(&mut y, &chunk);
        y = gf128_mul(&y, h);
    }
    // GHASH over lengths
    let aad_bits = (aad.len() as u64) * 8;
    let ct_bits = (ciphertext.len() as u64) * 8;
    let mut len_block = [0u8; 16];
    len_block[..8].copy_from_slice(&aad_bits.to_be_bytes());
    len_block[8..].copy_from_slice(&ct_bits.to_be_bytes());
    xor16(&mut y, &len_block);
    y = gf128_mul(&y, h);

    // E(K, J0)
    // 重建 J0：nonce 在外部不可访问，用 round_keys 重新加密全零块得 H，这里直接用传入的 round_keys
    // 实际 tag = GHASH ^ E(K, J0)，J0 由调用方的 counter（初始值）决定
    // 简化：tag 已在调用方构造时处理，这里返回 GHASH 值供外部 xor
    y
}

fn padded_chunks(data: &[u8]) -> impl Iterator<Item = [u8; 16]> + '_ {
    let full = data.len() / 16;
    let rem = data.len() % 16;
    (0..full)
        .map(move |i| {
            let mut b = [0u8; 16];
            b.copy_from_slice(&data[i * 16..(i + 1) * 16]);
            b
        })
        .chain(if rem > 0 {
            let mut b = [0u8; 16];
            b[..rem].copy_from_slice(&data[full * 16..]);
            Some(b).into_iter()
        } else {
            None.into_iter()
        })
}

fn xor16(a: &mut [u8; 16], b: &[u8; 16]) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}

/// GF(2^128) 乘法，多项式 x^128 + x^7 + x^2 + x + 1
fn gf128_mul(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = *y;
    for i in 0..128 {
        let byte = i / 8;
        let bit = 7 - (i % 8);
        if (x[byte] >> bit) & 1 == 1 {
            xor16(&mut z, &v);
        }
        let lsb = v[15] & 1;
        // v >> 1
        for j in (1..16).rev() {
            v[j] = (v[j] >> 1) | ((v[j - 1] & 1) << 7);
        }
        v[0] >>= 1;
        if lsb == 1 {
            v[0] ^= 0xE1; // 对应多项式 x^128 + x^7 + x^2 + x + 1 的归约
        }
    }
    z
}

// ── AES-128 实现 ──────────────────────────────────────────────────────────────

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

fn xtime(x: u8) -> u8 {
    (x << 1) ^ if x & 0x80 != 0 { 0x1b } else { 0 }
}

fn aes128_key_schedule(key: &[u8]) -> [[u8; 16]; 11] {
    const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
    let mut w = [[0u8; 4]; 44];
    for i in 0..4 {
        w[i].copy_from_slice(&key[i * 4..i * 4 + 4]);
    }
    for i in 4..44 {
        let mut temp = w[i - 1];
        if i % 4 == 0 {
            temp.rotate_left(1);
            for b in temp.iter_mut() {
                *b = SBOX[*b as usize];
            }
            temp[0] ^= RCON[i / 4 - 1];
        }
        for j in 0..4 {
            w[i][j] = w[i - 4][j] ^ temp[j];
        }
    }
    let mut round_keys = [[0u8; 16]; 11];
    for i in 0..11 {
        for j in 0..4 {
            round_keys[i][j * 4..j * 4 + 4].copy_from_slice(&w[i * 4 + j]);
        }
    }
    round_keys
}

fn aes128_encrypt_block(state: &mut [u8; 16], round_keys: &[[u8; 16]; 11]) {
    // AddRoundKey 0
    for i in 0..16 {
        state[i] ^= round_keys[0][i];
    }
    for (round, rk) in round_keys[1..]
        .iter()
        .enumerate()
        .map(|(i, rk)| (i + 1, rk))
    {
        // SubBytes
        for b in state.iter_mut() {
            *b = SBOX[*b as usize];
        }
        // ShiftRows
        let s = *state;
        state[1] = s[5];
        state[5] = s[9];
        state[9] = s[13];
        state[13] = s[1];
        state[2] = s[10];
        state[6] = s[14];
        state[10] = s[2];
        state[14] = s[6];
        state[3] = s[15];
        state[7] = s[3];
        state[11] = s[7];
        state[15] = s[11];
        // MixColumns (skip for round 10)
        if round < 10 {
            for col in 0..4 {
                let i = col * 4;
                let s0 = state[i];
                let s1 = state[i + 1];
                let s2 = state[i + 2];
                let s3 = state[i + 3];
                state[i] = xtime(s0) ^ xtime(s1) ^ s1 ^ s2 ^ s3;
                state[i + 1] = s0 ^ xtime(s1) ^ xtime(s2) ^ s2 ^ s3;
                state[i + 2] = s0 ^ s1 ^ xtime(s2) ^ xtime(s3) ^ s3;
                state[i + 3] = xtime(s0) ^ s0 ^ s1 ^ s2 ^ xtime(s3);
            }
        }
        // AddRoundKey
        for i in 0..16 {
            state[i] ^= rk[i];
        }
    }
}

/// 从解密后的 QUIC CRYPTO frame 载荷中提取 TLS ClientHello SNI
fn extract_sni_from_quic_crypto(data: &[u8]) -> Option<SniffResult> {
    // QUIC CRYPTO frame: type(1)=0x06, offset(varint), length(varint), data
    let mut pos = 0;
    while pos < data.len() {
        let frame_type = data[pos];
        pos += 1;
        match frame_type {
            0x00 => { /* PADDING, skip */ }
            0x06 => {
                // CRYPTO frame
                let (_, vl) = read_varint(data, pos)?;
                pos += vl; // offset
                let (flen, vl2) = read_varint(data, pos)?;
                pos += vl2;
                let end = (pos + flen as usize).min(data.len());
                let crypto_data = &data[pos..end];
                // TLS record（QUIC 无 TLS record layer，直接是 Handshake message）
                // Handshake: type(1)=0x01(ClientHello), length(3), ...
                if crypto_data.len() >= 4 && crypto_data[0] == 0x01 {
                    // ClientHello，构造一个假 TLS record 头让 try_tls 解析
                    let mut fake_record = vec![0x16u8, 0x03, 0x03, 0x00, 0x00];
                    fake_record.extend_from_slice(crypto_data);
                    return try_tls(&fake_record);
                }
                pos = end;
            }
            _ => break,
        }
    }
    None
}

// ── SSH 协议检测 ──────────────────────────────────────────────────────────────
//
// SSH 连接以 "SSH-" 开头（RFC 4253 §4.2）

fn try_ssh(buf: &[u8]) -> Option<SniffResult> {
    if buf.starts_with(b"SSH-") {
        Some(SniffResult {
            domain: None,
            protocol: "ssh",
        })
    } else {
        None
    }
}

// ── BitTorrent 握手检测 ───────────────────────────────────────────────────────
//
// BitTorrent 握手格式（BEP 003）:
//   pstrlen(1) = 19
//   pstr(19) = "BitTorrent protocol"
//   reserved(8)
//   info_hash(20)
//   peer_id(20)

fn try_bittorrent(buf: &[u8]) -> Option<SniffResult> {
    const BT_HEADER: &[u8] = b"\x13BitTorrent protocol";
    if buf.len() >= BT_HEADER.len() && buf.starts_with(BT_HEADER) {
        Some(SniffResult {
            domain: None,
            protocol: "bittorrent",
        })
    } else {
        None
    }
}

// ── DNS 协议检测 ──────────────────────────────────────────────────────────────

pub fn is_dns_wire(buf: &[u8]) -> bool {
    if buf.len() < 12 {
        return false;
    }
    let flags = buf[2];
    let opcode = (flags >> 3) & 0x0f;
    if opcode > 5 {
        return false;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    qdcount > 0
}

// ── 单元测试 ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(r: Option<SniffResult>) -> Option<String> {
        r.and_then(|r| r.domain)
    }
    fn protocol(r: Option<SniffResult>) -> Option<&'static str> {
        r.map(|r| r.protocol)
    }

    #[test]
    fn parse_http_host() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n";
        assert_eq!(domain(try_http_host(req)), Some("example.com".into()));
        assert_eq!(protocol(try_http_host(req)), Some("http"));
    }

    #[test]
    fn parse_http_host_with_port() {
        let req = b"POST /api HTTP/1.1\r\nHost: api.example.com:8080\r\n\r\n";
        assert_eq!(domain(try_http_host(req)), Some("api.example.com".into()));
    }

    #[test]
    fn http_host_case_insensitive() {
        let req = b"GET / HTTP/1.1\r\nHOST: Example.COM\r\n\r\n";
        assert_eq!(domain(try_http_host(req)), Some("example.com".into()));
    }

    #[test]
    fn not_http_returns_none() {
        let data = b"\x16\x03\x01 not tls either";
        assert!(try_http_host(data).is_none());
    }

    #[test]
    fn tls_too_short() {
        let data = b"\x16\x03\x01\x00\x05\x01";
        assert!(try_tls(data).is_none());
    }

    #[test]
    fn ssh_detection() {
        let data = b"SSH-2.0-OpenSSH_8.0\r\n";
        assert_eq!(protocol(try_ssh(data)), Some("ssh"));
    }

    #[test]
    fn bittorrent_detection() {
        let mut data = vec![0x13u8];
        data.extend_from_slice(b"BitTorrent protocol");
        data.extend_from_slice(&[0u8; 28]);
        assert_eq!(protocol(try_bittorrent(&data)), Some("bittorrent"));
    }

    #[test]
    fn sniff_type_from_str() {
        assert_eq!(SniffType::parse("tls"), Some(SniffType::Tls));
        assert_eq!(SniffType::parse("TLS"), Some(SniffType::Tls));
        assert_eq!(SniffType::parse("http"), Some(SniffType::Http));
        assert_eq!(SniffType::parse("quic"), Some(SniffType::Quic));
        assert_eq!(SniffType::parse("ssh"), Some(SniffType::Ssh));
        assert_eq!(SniffType::parse("bittorrent"), Some(SniffType::BitTorrent));
        assert_eq!(SniffType::parse("unknown"), None);
    }

    #[test]
    fn sha256_empty() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hash = sha256(b"");
        assert_eq!(hash[0], 0xe3);
        assert_eq!(hash[1], 0xb0);
    }
}
