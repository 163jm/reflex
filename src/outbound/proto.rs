//! 协议帧构建与解析（纯计算，无网络依赖）

use crate::inbound::Target;
use bytes::{BufMut, Bytes, BytesMut};
use std::net::IpAddr;

// ── VLESS ─────────────────────────────────────────────────────────────────────

pub fn vless_parse_uuid(s: &str) -> anyhow::Result<[u8; 16]> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    anyhow::ensure!(hex.len() == 32, "invalid UUID: {s}");
    let mut out = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk)?, 16)?;
    }
    Ok(out)
}

pub fn vless_build_request(uuid: &[u8; 16], target: &Target) -> anyhow::Result<Bytes> {
    let mut buf = BytesMut::with_capacity(64);
    buf.put_u8(0x00); // Version
    buf.put_slice(uuid); // UUID
    buf.put_u8(0x00); // Addon len
    buf.put_u8(0x01); // Command: TCP
    buf.put_u16(target.port());
    match target {
        Target::Domain(host, _) => {
            buf.put_u8(0x02);
            buf.put_u8(host.len() as u8);
            buf.put_slice(host.as_bytes());
        }
        Target::Socket(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                buf.put_u8(0x01);
                buf.put_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                buf.put_u8(0x03);
                buf.put_slice(&ip.octets());
            }
        },
    }
    Ok(buf.freeze())
}

pub fn vless_parse_response(buf: &[u8]) -> anyhow::Result<usize> {
    anyhow::ensure!(buf.len() >= 2, "vless response too short");
    anyhow::ensure!(buf[0] == 0x00, "unsupported vless version: {}", buf[0]);
    let addon_len = buf[1] as usize;
    anyhow::ensure!(buf.len() >= 2 + addon_len, "vless response truncated");
    Ok(2 + addon_len)
}

// ── Hysteria2 ─────────────────────────────────────────────────────────────────

const HY2_ATYP_IPV4: u8 = 0x00;
const HY2_ATYP_IPV6: u8 = 0x01;
const HY2_ATYP_DOMAIN: u8 = 0x02;

pub fn hy2_build_tcp_request(target: &Target) -> Bytes {
    let mut buf = BytesMut::new();
    hy2_write_addr(&mut buf, target);
    buf.put_u16(0u16); // padding_len = 0
    buf.freeze()
}

pub fn hy2_build_udp_datagram(data: &[u8], target: &Target, session_id: u32) -> Bytes {
    let mut buf = BytesMut::new();
    buf.put_u32_le(session_id);
    buf.put_u16_le(0u16); // packet_id
    buf.put_u8(0x00); // frag_id
    buf.put_u8(0x01); // frag_count
    hy2_write_addr(&mut buf, target);
    buf.put_slice(data);
    buf.freeze()
}

fn hy2_write_addr(buf: &mut BytesMut, target: &Target) {
    match target {
        Target::Domain(host, port) => {
            buf.put_u8(HY2_ATYP_DOMAIN);
            buf.put_u8(host.len() as u8);
            buf.put_slice(host.as_bytes());
            buf.put_u16(*port);
        }
        Target::Socket(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                buf.put_u8(HY2_ATYP_IPV4);
                buf.put_slice(&ip.octets());
                buf.put_u16(addr.port());
            }
            IpAddr::V6(ip) => {
                buf.put_u8(HY2_ATYP_IPV6);
                buf.put_slice(&ip.octets());
                buf.put_u16(addr.port());
            }
        },
    }
}

pub fn hy2_parse_udp_datagram(buf: &[u8]) -> anyhow::Result<(u32, Bytes, Target)> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    anyhow::ensure!(buf.len() >= 8, "hy2 udp datagram too short");
    let session_id = u32::from_le_bytes(buf[0..4].try_into()?);
    let mut cur = 8usize; // skip session_id(4) + packet_id(2) + frag(2)

    anyhow::ensure!(buf.len() > cur, "hy2 udp: missing addr type");
    let atyp = buf[cur];
    cur += 1;

    let src_target = match atyp {
        HY2_ATYP_IPV4 => {
            anyhow::ensure!(buf.len() >= cur + 6);
            let ip = Ipv4Addr::new(buf[cur], buf[cur + 1], buf[cur + 2], buf[cur + 3]);
            cur += 4;
            let port = u16::from_be_bytes([buf[cur], buf[cur + 1]]);
            cur += 2;
            Target::Socket(SocketAddr::new(IpAddr::V4(ip), port))
        }
        HY2_ATYP_IPV6 => {
            anyhow::ensure!(buf.len() >= cur + 18);
            let ip: [u8; 16] = buf[cur..cur + 16].try_into()?;
            cur += 16;
            let port = u16::from_be_bytes([buf[cur], buf[cur + 1]]);
            cur += 2;
            Target::Socket(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port))
        }
        HY2_ATYP_DOMAIN => {
            anyhow::ensure!(buf.len() > cur);
            let dlen = buf[cur] as usize;
            cur += 1;
            anyhow::ensure!(buf.len() >= cur + dlen + 2);
            let domain = String::from_utf8(buf[cur..cur + dlen].to_vec())?;
            cur += dlen;
            let port = u16::from_be_bytes([buf[cur], buf[cur + 1]]);
            cur += 2;
            Target::Domain(domain, port)
        }
        other => anyhow::bail!("unknown atyp 0x{other:02x}"),
    };

    let payload = Bytes::copy_from_slice(&buf[cur..]);
    Ok((session_id, payload, src_target))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vless_uuid() {
        let u = vless_parse_uuid("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        assert_eq!(u[0], 0xaa);
        assert_eq!(u[15], 0xee);
    }

    #[test]
    fn vless_request_domain() {
        let uuid = [0xau8; 16];
        let t = Target::Domain("example.com".into(), 443);
        let h = vless_build_request(&uuid, &t).unwrap();
        assert_eq!(h[0], 0x00);
        assert_eq!(&h[1..17], &uuid);
        assert_eq!(h[18], 0x01); // cmd TCP
        assert_eq!(u16::from_be_bytes([h[19], h[20]]), 443);
        assert_eq!(h[21], 0x02);
        assert_eq!(h[22], 11);
        assert_eq!(&h[23..34], b"example.com");
    }

    #[test]
    fn vless_request_ipv4() {
        let uuid = [0u8; 16];
        let t = Target::Socket("1.2.3.4:80".parse().unwrap());
        let h = vless_build_request(&uuid, &t).unwrap();
        assert_eq!(h[21], 0x01);
        assert_eq!(&h[22..26], &[1, 2, 3, 4]);
    }

    #[test]
    fn vless_response_ok() {
        assert_eq!(vless_parse_response(&[0x00, 0x00]).unwrap(), 2);
        assert_eq!(vless_parse_response(&[0x00, 0x03, 0, 0, 0]).unwrap(), 5);
        assert!(vless_parse_response(&[0x01, 0x00]).is_err());
    }

    #[test]
    fn hy2_tcp_domain() {
        let t = Target::Domain("example.com".into(), 443);
        let b = hy2_build_tcp_request(&t);
        assert_eq!(b[0], HY2_ATYP_DOMAIN);
        assert_eq!(b[1], 11);
        assert_eq!(&b[2..13], b"example.com");
        assert_eq!(u16::from_be_bytes([b[13], b[14]]), 443);
    }

    #[test]
    fn hy2_tcp_ipv4() {
        let t = Target::Socket("1.2.3.4:80".parse().unwrap());
        let b = hy2_build_tcp_request(&t);
        assert_eq!(b[0], HY2_ATYP_IPV4);
        assert_eq!(&b[1..5], &[1, 2, 3, 4]);
        assert_eq!(u16::from_be_bytes([b[5], b[6]]), 80);
    }

    #[test]
    fn hy2_udp_roundtrip_ipv4() {
        let data = b"hello";
        let t = Target::Socket("9.9.9.9:53".parse().unwrap());
        let d = hy2_build_udp_datagram(data, &t, 42);
        let (sid, payload, src) = hy2_parse_udp_datagram(&d).unwrap();
        assert_eq!(sid, 42);
        assert_eq!(&payload[..], data);
        assert!(matches!(src, Target::Socket(a) if a.port() == 53));
    }

    #[test]
    fn hy2_udp_roundtrip_domain() {
        let data = b"dns";
        let t = Target::Domain("dns.google".into(), 53);
        let d = hy2_build_udp_datagram(data, &t, 1);
        let (_, payload, src) = hy2_parse_udp_datagram(&d).unwrap();
        assert_eq!(&payload[..], data);
        assert!(matches!(src, Target::Domain(ref h, 53) if h == "dns.google"));
    }
}

// ── VLESS UDP over WebSocket 分帧 ─────────────────────────────────────────────
//
// 每个 UDP 包在 WebSocket/TCP 流上用 2 字节大端长度前缀分帧：
//   [DATA_LEN 2B BE][DATA ...]
//
// 与 TCP 的区别：TCP 是纯透明转发；UDP 需要分帧以保持包边界。
// 发往服务端的第一帧同样包含 VLESS 请求头（Command=0x02 UDP）。

pub fn vless_build_udp_request(uuid: &[u8; 16], target: &Target) -> anyhow::Result<Bytes> {
    let mut buf = BytesMut::with_capacity(64);
    buf.put_u8(0x00); // Version
    buf.put_slice(uuid); // UUID
    buf.put_u8(0x00); // Addon len
    buf.put_u8(0x02); // Command: UDP
    buf.put_u16(target.port());
    match target {
        Target::Domain(host, _) => {
            buf.put_u8(0x02);
            buf.put_u8(host.len() as u8);
            buf.put_slice(host.as_bytes());
        }
        Target::Socket(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                buf.put_u8(0x01);
                buf.put_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                buf.put_u8(0x03);
                buf.put_slice(&ip.octets());
            }
        },
    }
    Ok(buf.freeze())
}

/// 将 UDP payload 封装为带长度前缀的帧
pub fn vless_encode_udp_frame(payload: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(2 + payload.len());
    buf.put_u16(payload.len() as u16);
    buf.put_slice(payload);
    buf.freeze()
}

/// 从字节流中解析出一个 UDP 帧的载荷长度，返回 (帧头占用字节数=2, 数据长度)
pub fn vless_decode_udp_frame_len(buf: &[u8]) -> anyhow::Result<(usize, usize)> {
    anyhow::ensure!(
        buf.len() >= 2,
        "vless udp frame: need at least 2 bytes for length"
    );
    let data_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    Ok((2, data_len))
}

#[cfg(test)]
mod udp_tests {
    use super::*;

    #[test]
    fn vless_udp_request_cmd_byte() {
        let uuid = [0xau8; 16];
        let t = Target::Socket("8.8.8.8:53".parse().unwrap());
        let h = vless_build_udp_request(&uuid, &t).unwrap();
        assert_eq!(h[18], 0x02); // Command = UDP
    }

    #[test]
    fn vless_udp_frame_roundtrip() {
        let data = b"hello dns";
        let frame = vless_encode_udp_frame(data);
        assert_eq!(frame.len(), 2 + data.len());
        let (hdr, dlen) = vless_decode_udp_frame_len(&frame).unwrap();
        assert_eq!(hdr, 2);
        assert_eq!(dlen, data.len());
        assert_eq!(&frame[hdr..hdr + dlen], data);
    }

    #[test]
    fn vless_udp_frame_empty() {
        let frame = vless_encode_udp_frame(b"");
        assert_eq!(&frame[..2], &[0, 0]);
        let (_, dlen) = vless_decode_udp_frame_len(&frame).unwrap();
        assert_eq!(dlen, 0);
    }

    #[test]
    fn vless_udp_frame_too_short() {
        assert!(vless_decode_udp_frame_len(&[0x00]).is_err());
    }
}
