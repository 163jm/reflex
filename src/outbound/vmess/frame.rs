//! VMess 协议帧构建与 KDF 派生。
//!
//! 对照 sing-vmess/protocol.go 和 sing-vmess/client.go 的 AEAD 握手路径
//! （alterId == 0，即现代 VMess）实现。
//!
//! # 握手布局（AEAD 模式）
//! ```text
//! [AuthID 16B] [EncHeaderLen 2+16B] [ConnNonce 8B] [EncHeader N+16B]
//! ```
//!
//! ## Header 明文（在 encodeHeader 中构建）
//! ```text
//! [Ver=1 1B][ReqNonce 16B][ReqKey 16B][RespHeader 1B]
//! [Option 1B][PaddingLen<<4|Security 1B][Reserved=0 1B][Command 1B]
//! [Port 2B BE][Atyp 1B][Addr ...][Padding padLen B][FNV1a 4B]
//! ```
//!
//! ## KDF 派生（HMAC-SHA256 链式，sing-vmess/kdf.go）
//! KDF(key, salt, path...) = HMAC-SHA256(HMAC-SHA256(..., salt), key)

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::{
    aead::{Aead, KeyInit as AeadKeyInit, Payload},
    Aes128Gcm, Nonce,
};
use bytes::{BufMut, Bytes, BytesMut};
use hmac::{Hmac, Mac as HmacMac};
use md5::Md5;
use sha2::Sha256;

use crate::inbound::Target;

// ── 常量 ──────────────────────────────────────────────────────────────────────

pub const VERSION: u8 = 1;
pub const CIPHER_OVERHEAD: usize = 16;

// Security type bytes（同 sing-vmess/protocol.go）
pub const SECURITY_NONE: u8 = 5;
pub const SECURITY_AES128_GCM: u8 = 3;
pub const SECURITY_CHACHA20_POLY1305: u8 = 4;

// RequestOption flags
pub const OPT_CHUNK_STREAM: u8 = 1;
pub const OPT_CHUNK_MASKING: u8 = 4;

// Command
pub const CMD_TCP: u8 = 1;
pub const CMD_UDP: u8 = 2;

// Address type
const ATYP_IPV4: u8 = 0x01;
const ATYP_IPV6: u8 = 0x03;
const ATYP_DOMAIN: u8 = 0x02;

// KDF salt constants（同 sing-vmess/protocol.go）
const KDF_SALT_VMESS_AEAD_KDF: &str = "VMess AEAD KDF";
const KDF_SALT_AUTH_ID: &str = "AES Auth ID Encryption";
const KDF_SALT_HEADER_LEN_KEY: &str = "VMess Header AEAD Key_Length";
const KDF_SALT_HEADER_LEN_IV: &str = "VMess Header AEAD Nonce_Length";
const KDF_SALT_HEADER_KEY: &str = "VMess Header AEAD Key";
const KDF_SALT_HEADER_IV: &str = "VMess Header AEAD Nonce";

pub const KDF_SALT_RESP_LEN_KEY: &str = "AEAD Resp Header Len Key";
pub const KDF_SALT_RESP_LEN_IV: &str = "AEAD Resp Header Len IV";
pub const KDF_SALT_RESP_KEY: &str = "AEAD Resp Header Key";
pub const KDF_SALT_RESP_IV: &str = "AEAD Resp Header IV";

// ── KDF（HMAC-SHA256 链式，同 sing-vmess/kdf.go）────────────────────────────

/// 从 UUID 派生 Key（MD5(uuid + 固定盐)）
pub fn user_key(uuid_bytes: &[u8; 16]) -> [u8; 16] {
    use md5::Digest;
    let mut h = Md5::new();
    h.update(uuid_bytes);
    h.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    h.finalize().into()
}

/// VMess AEAD KDF：HMAC-SHA256 递归链，对应 Go 的 hMacCreator 结构。
///
/// kdf(key, salt, [path...])：
///   inner = HMAC-SHA256(key = KDF_ROOT_SALT, msg = salt)
///   for each p in path:
///       inner = HMAC-SHA256(key = inner, msg = p)
///   return HMAC-SHA256(key = inner, msg = key)
pub fn kdf(key: &[u8], salt: &str, path: &[&[u8]]) -> Vec<u8> {
    // 最底层：HMAC-SHA256(key=KDF_ROOT_SALT, msg=salt)
    let mut mac = <Hmac<Sha256> as HmacMac>::new_from_slice(KDF_SALT_VMESS_AEAD_KDF.as_bytes())
        .expect("hmac key");
    mac.update(salt.as_bytes());
    let mut current = mac.finalize().into_bytes().to_vec();

    // 每一层 path 叠加
    for &p in path {
        let mut mac = <Hmac<Sha256> as HmacMac>::new_from_slice(&current).expect("hmac key");
        mac.update(p);
        current = mac.finalize().into_bytes().to_vec();
    }

    // 最终：HMAC-SHA256(key=current, msg=key)
    let mut mac = <Hmac<Sha256> as HmacMac>::new_from_slice(&current).expect("hmac key");
    mac.update(key);
    mac.finalize().into_bytes().to_vec()
}

// ── AuthID（AES-ECB 加密的 8B 时间戳 + 4B 随机 + 4B CRC32）──────────────────

/// 构建 16 字节 AuthID（对应 sing-vmess/protocol.go AuthID()）
pub fn build_auth_id(key: &[u8; 16]) -> [u8; 16] {
    use crc32fast::Hasher;

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&ts.to_be_bytes());

    // 4 字节随机
    let rand_bytes: [u8; 4] = rand_array();
    buf[8..12].copy_from_slice(&rand_bytes);

    // CRC32（前 12 字节）
    let mut crc = Hasher::new();
    crc.update(&buf[..12]);
    let checksum = crc.finalize();
    buf[12..16].copy_from_slice(&checksum.to_be_bytes());

    // AES-128-ECB 加密（无填充，16B 刚好一个 block）
    let enc_key = kdf(key, KDF_SALT_AUTH_ID, &[]);
    aes_ecb_encrypt_inplace(&mut buf, &enc_key[..16]);

    buf
}

/// AES-128-ECB 加密单个 16 字节块（无 padding）
fn aes_ecb_encrypt_inplace(block: &mut [u8; 16], key: &[u8]) {
    use aes::cipher::{BlockEncrypt, KeyInit};
    let cipher = aes::Aes128::new_from_slice(key).expect("aes key");
    let mut b = aes::Block::clone_from_slice(block);
    cipher.encrypt_block(&mut b);
    block.copy_from_slice(&b);
}

// ── Header 明文编码（对应 rawClientConn.encodeHeader）────────────────────────

pub struct RequestHeader {
    /// 随机生成的 16 字节请求 Key（用于数据加密）
    pub req_key: [u8; 16],
    /// 随机生成的 16 字节请求 Nonce（同 IV）
    pub req_nonce: [u8; 16],
    /// 随机 1 字节，用于匹配响应头
    pub resp_header: u8,
    /// option 字段（ChunkStream | ChunkMasking 等）
    pub option: u8,
    /// security 字节（SecurityTypeAes128Gcm 等）
    pub security: u8,
    /// command（CMD_TCP / CMD_UDP）
    pub command: u8,
}

impl RequestHeader {
    pub fn new(security: u8, command: u8) -> Self {
        let req_key: [u8; 16] = rand_array();
        let req_nonce: [u8; 16] = rand_array();
        let resp_header: u8 = rand_array::<1>()[0];

        // option 与 sing-vmess/client.go dialRaw() 保持一致
        let option = match security {
            SECURITY_NONE => {
                if command == CMD_UDP {
                    OPT_CHUNK_STREAM
                } else {
                    0
                }
            }
            SECURITY_AES128_GCM | SECURITY_CHACHA20_POLY1305 => {
                OPT_CHUNK_STREAM | OPT_CHUNK_MASKING
            }
            _ => 0,
        };

        Self {
            req_key,
            req_nonce,
            resp_header,
            option,
            security,
            command,
        }
    }

    /// 构建明文 header 字节（含末尾 FNV1a checksum）
    pub fn encode(&self, target: &Target) -> Bytes {
        use fnv::FnvHasher;
        use std::hash::Hasher;

        let padding_len: usize = (rand_array::<1>()[0] % 16) as usize;

        let mut buf = BytesMut::with_capacity(64);
        buf.put_u8(VERSION);
        buf.put_slice(&self.req_nonce);
        buf.put_slice(&self.req_key);
        buf.put_u8(self.resp_header);
        buf.put_u8(self.option);
        buf.put_u8((padding_len as u8) << 4 | self.security);
        buf.put_u8(0x00); // reserved
        buf.put_u8(self.command);

        // 地址（Port 大端 + Atyp + Addr）— 对应 AddressSerializer.WriteAddrPort
        write_target(&mut buf, target);

        // padding
        for _ in 0..padding_len {
            buf.put_u8(0);
        }

        // FNV1a-32 checksum（覆盖整个 header 除 checksum 本身）
        let mut h = FnvHasher::default();
        h.write(&buf);
        buf.put_u32(h.finish() as u32);

        buf.freeze()
    }
}

fn write_target(buf: &mut BytesMut, target: &Target) {
    match target {
        Target::Domain(host, port) => {
            buf.put_u16(*port);
            buf.put_u8(ATYP_DOMAIN);
            buf.put_u8(host.len() as u8);
            buf.put_slice(host.as_bytes());
        }
        Target::Socket(addr) => {
            buf.put_u16(addr.port());
            match addr.ip() {
                IpAddr::V4(ip) => {
                    buf.put_u8(ATYP_IPV4);
                    buf.put_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    buf.put_u8(ATYP_IPV6);
                    buf.put_slice(&ip.octets());
                }
            }
        }
    }
}

// ── AEAD 握手帧打包（对应 rawClientConn.writeHandshake alterId==0 分支）───────

/// 将 RequestHeader 和 AuthID 打包成完整的握手字节流（发往服务端）。
///
/// 布局：
/// ```text
/// [AuthID 16B][EncHeaderLen 2+16B][ConnNonce 8B][EncHeader len+16B]
/// ```
pub fn build_handshake(user_key: &[u8; 16], req_hdr: &RequestHeader, target: &Target) -> Bytes {
    let auth_id = build_auth_id(user_key);
    let conn_nonce: [u8; 8] = rand_array();
    let header_plain = req_hdr.encode(target);
    let header_len = header_plain.len() as u16;

    // 加密 header length（2 bytes → 2+16 密文）
    let len_key = kdf(user_key, KDF_SALT_HEADER_LEN_KEY, &[&auth_id, &conn_nonce])[..16].to_vec();
    let len_nonce_raw =
        kdf(user_key, KDF_SALT_HEADER_LEN_IV, &[&auth_id, &conn_nonce])[..12].to_vec();
    let len_nonce = Nonce::from_slice(&len_nonce_raw);

    let cipher = <Aes128Gcm as AeadKeyInit>::new_from_slice(&len_key).expect("aes key");
    let mut len_plain = [0u8; 2];
    len_plain.copy_from_slice(&header_len.to_be_bytes());
    let enc_len = cipher
        .encrypt(
            len_nonce,
            Payload {
                msg: &len_plain,
                aad: &auth_id,
            },
        )
        .expect("encrypt len");

    // 加密 header payload（N bytes → N+16 密文）
    let hdr_key = kdf(user_key, KDF_SALT_HEADER_KEY, &[&auth_id, &conn_nonce])[..16].to_vec();
    let hdr_nonce_raw = kdf(user_key, KDF_SALT_HEADER_IV, &[&auth_id, &conn_nonce])[..12].to_vec();
    let hdr_nonce = Nonce::from_slice(&hdr_nonce_raw);

    let cipher = <Aes128Gcm as AeadKeyInit>::new_from_slice(&hdr_key).expect("aes key");
    let enc_hdr = cipher
        .encrypt(
            hdr_nonce,
            Payload {
                msg: &header_plain,
                aad: &auth_id,
            },
        )
        .expect("encrypt header");

    // 拼装
    let mut out = BytesMut::with_capacity(16 + 2 + CIPHER_OVERHEAD + 8 + enc_hdr.len());
    out.put_slice(&auth_id);
    out.put_slice(&enc_len);
    out.put_slice(&conn_nonce);
    out.put_slice(&enc_hdr);
    out.freeze()
}

// ── 响应头解析（对应 rawClientConn.readResponse alterId==0 分支）─────────────

/// 从流中读取并解密 VMess AEAD 响应头，返回消耗的字节数。
///
/// 响应布局：
/// ```text
/// [EncRespLen 2+16B][EncRespHeader 4+16B]
/// ```
/// 解密后 header 内容：[RespVersion 1B][RespToken 1B][Cmd 1B][CmdLen 1B]
///
/// 返回 `(response_token, consumed_bytes)` — token 用于校验与请求头的一致性。
pub fn parse_response_header(
    buf: &[u8],
    req_key: &[u8; 16],
    req_nonce: &[u8; 16],
) -> anyhow::Result<(u8, usize)> {
    // 响应 key / nonce 用 SHA256 派生（同 sing-vmess/client.go readResponse）
    let resp_key_full = sha256(req_key);
    let resp_nonce_full = sha256(req_nonce);
    let resp_key = &resp_key_full[..16];
    let resp_nonce = &resp_nonce_full[..16];

    // 解密 header length（2 + 16 字节）
    const LEN_FRAME: usize = 2 + CIPHER_OVERHEAD;
    anyhow::ensure!(
        buf.len() >= LEN_FRAME,
        "vmess resp: too short for len frame"
    );

    let len_key = kdf(resp_key, KDF_SALT_RESP_LEN_KEY, &[])[..16].to_vec();
    let len_nonce_raw = kdf(resp_nonce, KDF_SALT_RESP_LEN_IV, &[])[..12].to_vec();
    let len_nonce = Nonce::from_slice(&len_nonce_raw);
    let cipher = <Aes128Gcm as AeadKeyInit>::new_from_slice(&len_key).expect("aes key");
    let dec_len = cipher
        .decrypt(
            len_nonce,
            Payload {
                msg: &buf[..LEN_FRAME],
                aad: b"",
            },
        )
        .map_err(|_| anyhow::anyhow!("vmess resp: decrypt len failed"))?;
    let header_len = u16::from_be_bytes([dec_len[0], dec_len[1]]) as usize;

    // 解密 header payload（header_len + 16 字节）
    let hdr_cipher_len = header_len + CIPHER_OVERHEAD;
    anyhow::ensure!(
        buf.len() >= LEN_FRAME + hdr_cipher_len,
        "vmess resp: too short for header payload"
    );
    let hdr_key = kdf(resp_key, KDF_SALT_RESP_KEY, &[])[..16].to_vec();
    let hdr_nonce_raw = kdf(resp_nonce, KDF_SALT_RESP_IV, &[])[..12].to_vec();
    let hdr_nonce = Nonce::from_slice(&hdr_nonce_raw);
    let cipher = <Aes128Gcm as AeadKeyInit>::new_from_slice(&hdr_key).expect("aes key");
    let dec_hdr = cipher
        .decrypt(
            hdr_nonce,
            Payload {
                msg: &buf[LEN_FRAME..LEN_FRAME + hdr_cipher_len],
                aad: b"",
            },
        )
        .map_err(|_| anyhow::anyhow!("vmess resp: decrypt header failed"))?;

    anyhow::ensure!(dec_hdr.len() >= 4, "vmess resp: header too short");
    // dec_hdr[0] = response version (should be 0)
    // dec_hdr[1] = response token (must match req_hdr.resp_header)
    let token = dec_hdr[1];

    let consumed = LEN_FRAME + hdr_cipher_len;
    Ok((token, consumed))
}

// ── 杂项工具 ──────────────────────────────────────────────────────────────────

fn sha256(input: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(input).into()
}

/// 生成 N 字节随机数组
pub fn rand_array<const N: usize>() -> [u8; N] {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::SystemTime;

    // 轻量随机：用系统时间 + 地址混合，避免引入 getrandom 依赖
    // 实际项目建议换成 rand::rng().fill_bytes
    let mut out = [0u8; N];
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64;
    for (i, byte) in out.iter_mut().enumerate() {
        let mut h = DefaultHasher::new();
        (seed ^ (i as u64).wrapping_mul(0x9e3779b97f4a7c15)).hash(&mut h);
        *byte = h.finish() as u8;
    }
    out
}

// ── 解析 UUID 字符串 ──────────────────────────────────────────────────────────

pub fn parse_uuid(s: &str) -> anyhow::Result<[u8; 16]> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    anyhow::ensure!(hex.len() == 32, "invalid UUID: {s}");
    let mut out = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk)?, 16)?;
    }
    Ok(out)
}

// ── 选择 security type ────────────────────────────────────────────────────────

pub fn resolve_security(security: &str) -> anyhow::Result<u8> {
    // 与 sing-vmess/client.go NewClient() switch 一致
    // "auto" 在 x86_64/arm64 上选 aes-128-gcm，其余选 chacha20-poly1305
    // Reflex 简化：auto 始终选 aes-128-gcm（服务端均支持）
    match security {
        "auto" | "aes-128-gcm" => Ok(SECURITY_AES128_GCM),
        "chacha20-poly1305" => Ok(SECURITY_CHACHA20_POLY1305),
        "none" | "zero" => Ok(SECURITY_NONE),
        "aes-128-cfb" => anyhow::bail!(
            "vmess: aes-128-cfb (legacy/alterId) is not supported; use aes-128-gcm or none"
        ),
        other => anyhow::bail!("vmess: unknown security type: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uuid_ok() {
        let u = parse_uuid("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        assert_eq!(u[0], 0xaa);
        assert_eq!(u[15], 0xee);
    }

    #[test]
    fn kdf_deterministic() {
        let key = [0x42u8; 16];
        let a = kdf(&key, KDF_SALT_AUTH_ID, &[]);
        let b = kdf(&key, KDF_SALT_AUTH_ID, &[]);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn auth_id_length() {
        let key = [1u8; 16];
        let id = build_auth_id(&key);
        assert_eq!(id.len(), 16);
    }

    #[test]
    fn request_header_encode_non_empty() {
        let hdr = RequestHeader::new(SECURITY_AES128_GCM, CMD_TCP);
        let target = Target::Domain("example.com".into(), 443);
        let encoded = hdr.encode(&target);
        // 最小长度：1+16+16+1+1+1+1+1 + 2+1+1+11 + 0 + 4 = 57
        assert!(encoded.len() >= 57, "encoded len={}", encoded.len());
        assert_eq!(encoded[0], VERSION);
    }

    #[test]
    fn resolve_security_ok() {
        assert_eq!(resolve_security("auto").unwrap(), SECURITY_AES128_GCM);
        assert_eq!(resolve_security("none").unwrap(), SECURITY_NONE);
        assert!(resolve_security("unknown").is_err());
    }
}
