/// 文件魔数：b"RRST"
pub const MAGIC: [u8; 4] = *b"RRST";

/// 当前格式版本（v2 新增 DomainFst / DomainSuffixFst section）
pub const VERSION: u8 = 0x02;

/// v1 格式版本号，加载时向后兼容
pub const VERSION_V1: u8 = 0x01;

/// 文件头总长度（字节）
/// [magic 4][version 1][flags 1][section_count 4][reserved 4]
pub const HEADER_LEN: usize = 14;

/// Section 头长度（字节）
/// [type 1][entry_count 4][byte_len 4]
pub const SECTION_HEADER_LEN: usize = 9;

/// Section 类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SectionType {
    /// 精确域名匹配（v1 旧版，len-prefixed 字符串列表）
    Domain = 0x01,
    /// 域名后缀匹配（v1 旧版，len-prefixed 字符串列表）
    DomainSuffix = 0x02,
    /// 域名关键词匹配
    DomainKeyword = 0x03,
    /// 域名正则匹配
    DomainRegex = 0x04,
    /// 精确域名匹配（v2 FST，key 为倒序 label 拼接，如 "com.google"）
    DomainFst = 0x05,
    /// 域名后缀匹配（v2 FST，key 为倒序 label + 尾部点，如 "com.google."）
    DomainSuffixFst = 0x06,
    /// IPv4 CIDR
    IpCidrV4 = 0x10,
    /// IPv6 CIDR
    IpCidrV6 = 0x11,
    /// 端口或端口范围
    Port = 0x20,
}

impl TryFrom<u8> for SectionType {
    type Error = u8;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x01 => Ok(Self::Domain),
            0x02 => Ok(Self::DomainSuffix),
            0x03 => Ok(Self::DomainKeyword),
            0x04 => Ok(Self::DomainRegex),
            0x05 => Ok(Self::DomainFst),
            0x06 => Ok(Self::DomainSuffixFst),
            0x10 => Ok(Self::IpCidrV4),
            0x11 => Ok(Self::IpCidrV6),
            0x20 => Ok(Self::Port),
            other => Err(other),
        }
    }
}

/// IPv4 CIDR entry 固定长度：4（地址）+ 1（前缀）
pub const IPV4_ENTRY_LEN: usize = 5;

/// IPv6 CIDR entry 固定长度：16（地址）+ 1（前缀）
pub const IPV6_ENTRY_LEN: usize = 17;

/// Port entry 固定长度：2（起始）+ 2（结束）
pub const PORT_ENTRY_LEN: usize = 4;
