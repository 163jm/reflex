//! 从二进制格式加载规则集，反序列化为 [`LoadedRuleSet`]。

use std::{
    io::Read,
    net::{Ipv4Addr, Ipv6Addr},
};

use super::{
    error::{Result, RuleSetError},
    format::*,
};

/// 从二进制流加载的原始数据，尚未建立索引结构。
/// 通常不直接使用，而是传给 [`crate::matcher::RuleSet::from_loaded`] 建立匹配引擎。
#[derive(Debug, Default)]
pub struct LoadedRuleSet {
    /// v1 旧版精确域名列表（字符串）
    pub domains: Vec<String>,
    /// v1 旧版后缀域名列表（字符串）
    pub domain_suffixes: Vec<String>,
    /// v2 精确域名 FST 字节（可直接传给 fst::Set::new）
    pub domain_fst: Vec<u8>,
    /// v2 后缀域名 FST 字节
    pub domain_suffix_fst: Vec<u8>,
    pub domain_keywords: Vec<String>,
    pub domain_regexes: Vec<String>,
    pub ipv4_cidrs: Vec<(Ipv4Addr, u8)>,
    pub ipv6_cidrs: Vec<(Ipv6Addr, u8)>,
    pub ports: Vec<(u16, u16)>,
}

impl LoadedRuleSet {
    /// 从任意 `Read` 加载二进制规则集，同时兼容 v1 和 v2。
    pub fn from_reader<R: Read>(mut r: R) -> Result<Self> {
        // ── 文件头 ────────────────────────────────────────────
        let mut header = [0u8; HEADER_LEN];
        r.read_exact(&mut header)
            .map_err(|_| RuleSetError::BadMagic)?;

        if header[0..4] != MAGIC {
            return Err(RuleSetError::BadMagic);
        }
        let ver = header[4];
        if ver != VERSION && ver != VERSION_V1 {
            return Err(RuleSetError::UnsupportedVersion(ver));
        }
        let section_count = u32::from_le_bytes(header[6..10].try_into().unwrap()) as usize;

        // ── Sections ──────────────────────────────────────────
        let mut out = Self::default();

        let mut sec_header = [0u8; SECTION_HEADER_LEN];
        for _ in 0..section_count {
            r.read_exact(&mut sec_header)?;

            let sec_type_byte = sec_header[0];
            let entry_count = u32::from_le_bytes(sec_header[1..5].try_into().unwrap()) as usize;
            let byte_len = u32::from_le_bytes(sec_header[5..9].try_into().unwrap()) as usize;

            let sec_type =
                SectionType::try_from(sec_type_byte).map_err(RuleSetError::UnknownSection)?;

            let mut data = vec![0u8; byte_len];
            r.read_exact(&mut data)
                .map_err(|_| RuleSetError::Truncated {
                    expected: byte_len,
                    got: 0,
                })?;

            match sec_type {
                // v1 旧版字符串格式（向后兼容）
                SectionType::Domain => out.domains = decode_strings(&data, entry_count)?,
                SectionType::DomainSuffix => {
                    out.domain_suffixes = decode_strings(&data, entry_count)?
                }
                // v2 FST 格式：直接保存原始字节，由 matcher 用 fst::Set 加载
                SectionType::DomainFst => out.domain_fst = data,
                SectionType::DomainSuffixFst => out.domain_suffix_fst = data,
                SectionType::DomainKeyword => {
                    out.domain_keywords = decode_strings(&data, entry_count)?
                }
                SectionType::DomainRegex => {
                    out.domain_regexes = decode_strings(&data, entry_count)?
                }
                SectionType::IpCidrV4 => out.ipv4_cidrs = decode_ipv4_cidrs(&data, entry_count)?,
                SectionType::IpCidrV6 => out.ipv6_cidrs = decode_ipv6_cidrs(&data, entry_count)?,
                SectionType::Port => out.ports = decode_ports(&data, entry_count)?,
            }
        }

        Ok(out)
    }

    /// 从字节切片加载（适合内存中已有数据的场景）
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        Self::from_reader(data)
    }
}

// ── 解码辅助 ─────────────────────────────────────────────────────────────────

fn decode_strings(data: &[u8], expected: usize) -> Result<Vec<String>> {
    let mut result = Vec::with_capacity(expected);
    let mut i = 0;
    while i < data.len() {
        if i + 1 > data.len() {
            return Err(RuleSetError::Truncated {
                expected: i + 1,
                got: data.len(),
            });
        }
        let len = data[i] as usize;
        i += 1;
        if i + len > data.len() {
            return Err(RuleSetError::Truncated {
                expected: i + len,
                got: data.len(),
            });
        }
        let s = std::str::from_utf8(&data[i..i + len])
            .map_err(|_| RuleSetError::InvalidUtf8)?
            .to_string();
        result.push(s);
        i += len;
    }
    Ok(result)
}

fn decode_ipv4_cidrs(data: &[u8], expected: usize) -> Result<Vec<(Ipv4Addr, u8)>> {
    if data.len() != expected * IPV4_ENTRY_LEN {
        return Err(RuleSetError::Truncated {
            expected: expected * IPV4_ENTRY_LEN,
            got: data.len(),
        });
    }
    Ok(data
        .chunks_exact(IPV4_ENTRY_LEN)
        .map(|c| {
            let addr = Ipv4Addr::new(c[0], c[1], c[2], c[3]);
            let prefix = c[4];
            (addr, prefix)
        })
        .collect())
}

fn decode_ipv6_cidrs(data: &[u8], expected: usize) -> Result<Vec<(Ipv6Addr, u8)>> {
    if data.len() != expected * IPV6_ENTRY_LEN {
        return Err(RuleSetError::Truncated {
            expected: expected * IPV6_ENTRY_LEN,
            got: data.len(),
        });
    }
    Ok(data
        .chunks_exact(IPV6_ENTRY_LEN)
        .map(|c| {
            let octets: [u8; 16] = c[..16].try_into().unwrap();
            let addr = Ipv6Addr::from(octets);
            let prefix = c[16];
            (addr, prefix)
        })
        .collect())
}

fn decode_ports(data: &[u8], expected: usize) -> Result<Vec<(u16, u16)>> {
    if data.len() != expected * PORT_ENTRY_LEN {
        return Err(RuleSetError::Truncated {
            expected: expected * PORT_ENTRY_LEN,
            got: data.len(),
        });
    }
    Ok(data
        .chunks_exact(PORT_ENTRY_LEN)
        .map(|c| {
            let start = u16::from_le_bytes([c[0], c[1]]);
            let end = u16::from_le_bytes([c[2], c[3]]);
            (start, end)
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ruleset::compiler::CompiledRuleSet;

    fn compile_and_load(src: &str) -> LoadedRuleSet {
        let compiled = CompiledRuleSet::from_text(src).unwrap();
        let mut buf = Vec::new();
        compiled.serialize(&mut buf).unwrap();
        LoadedRuleSet::from_bytes(&buf).unwrap()
    }

    #[test]
    fn roundtrip_domains() {
        let loaded =
            compile_and_load("domain: example.com\ndomain-suffix: google.com\ndomain-keyword: ads");
        // v2 格式：domains/domain_suffixes 为空，FST 有内容
        assert!(loaded.domains.is_empty());
        assert!(loaded.domain_suffixes.is_empty());
        assert!(!loaded.domain_fst.is_empty());
        assert!(!loaded.domain_suffix_fst.is_empty());
        assert_eq!(loaded.domain_keywords, vec!["ads"]);
    }

    #[test]
    fn roundtrip_cidrs() {
        let loaded = compile_and_load("ip-cidr: 10.0.0.0/8\nip-cidr6: 2001:db8::/32");
        assert_eq!(loaded.ipv4_cidrs, vec![(Ipv4Addr::new(10, 0, 0, 0), 8)]);
        assert_eq!(
            loaded.ipv6_cidrs,
            vec![("2001:db8::".parse::<Ipv6Addr>().unwrap(), 32)]
        );
    }

    #[test]
    fn roundtrip_ports() {
        let loaded = compile_and_load("port: 80\nport: 8000-9000");
        assert_eq!(loaded.ports, vec![(80, 80), (8000, 9000)]);
    }

    #[test]
    fn bad_magic() {
        let err = LoadedRuleSet::from_bytes(b"BADD\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00");
        assert!(matches!(err, Err(RuleSetError::BadMagic)));
    }

    #[test]
    fn bad_version() {
        let buf = b"RRST\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec();
        let err = LoadedRuleSet::from_bytes(&buf);
        assert!(matches!(err, Err(RuleSetError::UnsupportedVersion(0xff))));
    }
}
