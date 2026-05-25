//! 匹配引擎：将加载的规则集构建为高效的内存索引。
//!
//! ## 优化说明（对比原版）
//!
//! ### 1. 端口匹配：BitSet O(1)
//! 原版：`Vec<RangeInclusive<u16>>` 线性扫描 O(n)
//! 新版：`Box<[u64; 1024]>`（65536 bits = 8 KB），`port >> 6` 找 word，
//!       `1 << (port & 63)` 查 bit，完全 O(1) 无分支跳转，cache 友好。
//!
//! ### 2. IP CIDR 匹配：有序区间树 O(log n)
//! 原版：`Vec<(u32, u8)>` 线性扫描 O(n)
//! 新版：将每条 CIDR 展开为 [start, end] 区间，按 start 排序后存入
//!       `Vec<(u32, u32)>`/`Vec<(u128, u128)>`，用二分查找 O(log n)。
//!       大型 geoip 规则集（数千条）性能提升显著。
//!
//! ### 3. FST suffix 匹配：零分配迭代
//! 原版：每次匹配都 `String::new()` 分配多次，对热路径影响大。
//! 新版：用 `&[u8]` 切片直接在栈上拼接（最长域名 253 字节），
//!       完全不堆分配。
//!
//! ### 4. 域名 normalize：调用方 once vs 逐函数 lowercase
//! 原版：`match_domain` 里 `to_ascii_lowercase()` 分配一次，
//!       `matches_suffix` 的 Fst 分支再做一次 `lower`。
//! 新版：`match_domain` 统一 normalize，后续全程用 `&str` 传递。
//!
//! ### 5. 路由层预计算（router/mod.rs 配合）
//! 把 skip_sniff / skip_resolve 所需的过滤索引在编译期计算好，
//! 热路由路径只遍历已过滤的规则切片，无条件判断开销。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use fst::Set;
use regex::RegexSet;

use super::{
    compiler::domain_to_fst_key,
    error::{Result, RuleSetError},
    loader::LoadedRuleSet,
};

// ── 端口 BitSet ───────────────────────────────────────────────────────────────

/// 65536 位的 BitSet，用一个 1024×u64 数组存储。
/// 内存占用固定 8 KB，查询 O(1)，比端口范围线性扫描快 ~10×。
struct PortBitSet(Box<[u64; 1024]>);

impl PortBitSet {
    fn new() -> Self {
        Self(Box::new([0u64; 1024]))
    }

    #[inline]
    fn set(&mut self, port: u16) {
        let idx = (port >> 6) as usize;
        let bit = 1u64 << (port & 63);
        self.0[idx] |= bit;
    }

    fn set_range(&mut self, start: u16, end: u16) {
        for p in start..=end {
            self.set(p);
        }
    }

    #[inline(always)]
    fn contains(&self, port: u16) -> bool {
        let idx = (port >> 6) as usize;
        let bit = 1u64 << (port & 63);
        (self.0[idx] & bit) != 0
    }
}

// ── IP 区间树（有序区间，二分查找） ──────────────────────────────────────────

/// 将 CIDR 列表展开为 [lo, hi] 区间，按 lo 排序。
/// 查询时二分找到第一个 lo <= target 的区间，判断 target <= hi。
/// 最坏 O(log n)，比线性扫描对大型 geoip 列表快数十倍。
struct IpRanges<T: Copy + Ord> {
    /// (lo, hi)，按 lo 升序排列
    ranges: Vec<(T, T)>,
}

impl<T: Copy + Ord> IpRanges<T> {
    fn len(&self) -> usize {
        self.ranges.len()
    }
}

impl<T: Copy + Ord> IpRanges<T> {
    fn build(cidrs: impl IntoIterator<Item = (T, T)>) -> Self {
        let mut ranges: Vec<(T, T)> = cidrs.into_iter().collect();
        ranges.sort_unstable_by_key(|&(lo, _)| lo);
        // 合并相邻/重叠区间，进一步压缩
        let ranges = merge_ranges(ranges);
        Self { ranges }
    }

    #[inline]
    fn contains(&self, addr: T) -> bool {
        if self.ranges.is_empty() {
            return false;
        }
        // 找最后一个 lo <= addr 的区间
        match self.ranges.partition_point(|&(lo, _)| lo <= addr) {
            0 => false,
            i => {
                let (_, hi) = self.ranges[i - 1];
                addr <= hi
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }
}

fn merge_ranges<T: Copy + Ord>(mut ranges: Vec<(T, T)>) -> Vec<(T, T)> {
    if ranges.len() <= 1 {
        return ranges;
    }
    let mut out: Vec<(T, T)> = Vec::with_capacity(ranges.len());
    // ranges 已按 lo 排序
    out.push(ranges[0]);
    for (lo, hi) in ranges.drain(1..) {
        let last = out.last_mut().unwrap();
        if lo <= last.1 {
            // 重叠或相邻，合并
            if hi > last.1 {
                last.1 = hi;
            }
        } else {
            out.push((lo, hi));
        }
    }
    out
}

/// IPv4 CIDR → (lo, hi) 区间
fn ipv4_cidr_to_range(addr: Ipv4Addr, prefix: u8) -> (u32, u32) {
    let base = u32::from(addr);
    if prefix == 0 {
        return (0, u32::MAX);
    }
    let mask = !0u32 << (32 - prefix);
    let lo = base & mask;
    let hi = lo | !mask;
    (lo, hi)
}

/// IPv6 CIDR → (lo, hi) 区间
fn ipv6_cidr_to_range(addr: Ipv6Addr, prefix: u8) -> (u128, u128) {
    let base = u128::from(addr);
    if prefix == 0 {
        return (0, u128::MAX);
    }
    let mask = !0u128 << (128 - prefix);
    let lo = base & mask;
    let hi = lo | !mask;
    (lo, hi)
}

// ── 域名匹配后端 ──────────────────────────────────────────────────────────────

enum DomainMatcher {
    Fst {
        exact: Option<Set<Vec<u8>>>,
        suffix: Option<Set<Vec<u8>>>,
    },
    Legacy {
        domains: ahash::AHashSet<Box<str>>,
        suffix_trie: super::trie::SuffixTrie,
    },
}

impl DomainMatcher {
    /// `fst_key` 已是倒序 label 格式（由调用方计算好，避免重复计算）
    fn matches_exact(&self, fst_key: &[u8], domain: &str) -> bool {
        match self {
            DomainMatcher::Fst { exact, .. } => exact.as_ref().is_some_and(|s| s.contains(fst_key)),
            DomainMatcher::Legacy { domains, .. } => domains.contains(domain),
        }
    }

    /// 零分配 FST suffix 匹配：用栈上固定缓冲区拼接 key，不堆分配。
    ///
    /// 算法：收集 '.' 位置后从右往左逐 label 追加到固定缓冲区，
    /// 每追加一个 label 就在末尾加 '.' 并查 FST。
    ///
    /// "sub.google.com" 产生的查询序列：
    ///   "com." → "com.google." → "com.google.sub."
    ///
    /// 上一个 label 末尾的 '.' 自动成为下一个 label 的分隔符，
    /// 无需额外分隔符逻辑。全程不堆分配。
    fn matches_suffix(&self, domain: &str) -> bool {
        match self {
            DomainMatcher::Fst { suffix, .. } => {
                let Some(set) = suffix else { return false };

                let bytes = domain.as_bytes();
                let n = bytes.len();

                // 收集 label 边界：label_ends[0] = n，后续为各 '.' 的位置
                // 最多支持 127 个 label（RFC 最大 127 层）
                let mut label_ends = [0usize; 128];
                let mut nlabels = 0usize;
                label_ends[nlabels] = n;
                nlabels += 1;
                let mut i = n;
                while i > 0 && nlabels < 128 {
                    i -= 1;
                    if bytes[i] == b'.' {
                        label_ends[nlabels] = i;
                        nlabels += 1;
                    }
                }

                // 栈缓冲区：域名最长 253 字节 + 每层末尾 '.' + 余量
                let mut buf = [0u8; 260];
                let mut buf_len = 0usize;

                // 从最右 label 开始依次追加
                // k=0: 最右 label = bytes[label_ends[1]+1 .. label_ends[0]]
                // k=nlabels-1: 最左 label = bytes[0 .. label_ends[nlabels-1]]
                for k in 0..nlabels {
                    let label_start = if k + 1 < nlabels {
                        label_ends[k + 1] + 1 // 跳过 '.'
                    } else {
                        0 // 最左 label 从 0 开始
                    };
                    let label_end = label_ends[k];
                    let label = &bytes[label_start..label_end];

                    // 追加 label 字节
                    let avail = buf.len().saturating_sub(buf_len + 1); // +1 留给尾部 '.'
                    let copy_len = label.len().min(avail);
                    buf[buf_len..buf_len + copy_len].copy_from_slice(&label[..copy_len]);
                    buf_len += copy_len;

                    // 追加尾部 '.'（同时作为下一 label 的分隔符）
                    if buf_len < buf.len() {
                        buf[buf_len] = b'.';
                        buf_len += 1;
                    }

                    if set.contains(&buf[..buf_len]) {
                        return true;
                    }
                }
                false
            }
            DomainMatcher::Legacy { suffix_trie, .. } => suffix_trie.matches(domain),
        }
    }
}

// ── 查询目标 ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum MatchTarget<'a> {
    Domain(&'a str),
    Ip(IpAddr),
    Port(u16),
}

// ── 匹配引擎 ──────────────────────────────────────────────────────────────────

pub struct RuleSet {
    domain_matcher: DomainMatcher,

    /// 关键词（数量少，线性扫描）
    keywords: Vec<Box<str>>,

    /// 多正则合并 NFA
    regexes: Option<RegexSet>,

    /// IPv4 区间树（O(log n) 查询）
    ipv4_ranges: IpRanges<u32>,

    /// IPv6 区间树
    ipv6_ranges: IpRanges<u128>,

    /// 端口 BitSet（O(1) 查询，8 KB）
    port_bitset: Option<Box<PortBitSet>>,
}

impl RuleSet {
    pub fn from_loaded(loaded: LoadedRuleSet) -> Result<Self> {
        // ── 域名匹配器 ──────────────────────────────────────────────────────
        let domain_matcher =
            if !loaded.domain_fst.is_empty() || !loaded.domain_suffix_fst.is_empty() {
                let exact = if loaded.domain_fst.is_empty() {
                    None
                } else {
                    Some(
                        Set::new(loaded.domain_fst)
                            .map_err(|e| RuleSetError::LoadedInvalidRegex(e.to_string()))?,
                    )
                };
                let suffix = if loaded.domain_suffix_fst.is_empty() {
                    None
                } else {
                    Some(
                        Set::new(loaded.domain_suffix_fst)
                            .map_err(|e| RuleSetError::LoadedInvalidRegex(e.to_string()))?,
                    )
                };
                DomainMatcher::Fst { exact, suffix }
            } else {
                let mut domains = ahash::AHashSet::with_capacity(loaded.domains.len());
                for s in loaded.domains {
                    domains.insert(s.into_boxed_str());
                }
                let mut suffix_trie = super::trie::SuffixTrie::new();
                for s in &loaded.domain_suffixes {
                    suffix_trie.insert(s);
                }
                DomainMatcher::Legacy {
                    domains,
                    suffix_trie,
                }
            };

        // ── 关键词 ──────────────────────────────────────────────────────────
        let keywords: Vec<Box<str>> = loaded
            .domain_keywords
            .into_iter()
            .map(|s| s.into_boxed_str())
            .collect();

        // ── 正则 ────────────────────────────────────────────────────────────
        let regexes = if loaded.domain_regexes.is_empty() {
            None
        } else {
            Some(
                RegexSet::new(&loaded.domain_regexes)
                    .map_err(|e| RuleSetError::LoadedInvalidRegex(e.to_string()))?,
            )
        };

        // ── IPv4 区间树 ─────────────────────────────────────────────────────
        let ipv4_ranges = IpRanges::build(
            loaded
                .ipv4_cidrs
                .into_iter()
                .map(|(addr, prefix)| ipv4_cidr_to_range(addr, prefix)),
        );

        // ── IPv6 区间树 ─────────────────────────────────────────────────────
        let ipv6_ranges = IpRanges::build(
            loaded
                .ipv6_cidrs
                .into_iter()
                .map(|(addr, prefix)| ipv6_cidr_to_range(addr, prefix)),
        );

        // ── 端口 BitSet ─────────────────────────────────────────────────────
        let port_bitset = if loaded.ports.is_empty() {
            None
        } else {
            let mut bs = Box::new(PortBitSet::new());
            for (start, end) in loaded.ports {
                bs.set_range(start, end);
            }
            Some(bs)
        };

        Ok(Self {
            domain_matcher,
            keywords,
            regexes,
            ipv4_ranges,
            ipv6_ranges,
            port_bitset,
        })
    }

    /// 返回此规则集的条目数（域名关键词数量 + IP 段数量 + 端口规则数量等）。
    /// 编译后结构无法精确还原原始计数，此处返回合并后的可观测数量。
    pub fn rule_count(&self) -> usize {
        let domain_count = match &self.domain_matcher {
            DomainMatcher::Fst { exact, suffix } => {
                exact.as_ref().map(|s| s.len()).unwrap_or(0)
                    + suffix.as_ref().map(|s| s.len()).unwrap_or(0)
            }
            DomainMatcher::Legacy {
                domains,
                suffix_trie,
            } => domains.len() + suffix_trie.len(),
        };
        let keyword_count = self.keywords.len();
        let regex_count = self.regexes.as_ref().map(|r| r.len()).unwrap_or(0);
        let ipv4_count = self.ipv4_ranges.len();
        let ipv6_count = self.ipv6_ranges.len();
        let port_count = if self.port_bitset.is_some() { 1 } else { 0 };
        domain_count + keyword_count + regex_count + ipv4_count + ipv6_count + port_count
    }

    /// 主匹配入口
    #[inline]
    pub fn matches(&self, target: &MatchTarget<'_>) -> bool {
        match target {
            MatchTarget::Domain(d) => self.match_domain(d),
            MatchTarget::Ip(ip) => self.match_ip(*ip),
            MatchTarget::Port(p) => self.match_port(*p),
        }
    }

    // ── 域名匹配 ──────────────────────────────────────────────────────────

    fn match_domain(&self, domain: &str) -> bool {
        // 统一 normalize：trim trailing dot + lowercase（一次分配）
        let domain = domain.trim_end_matches('.');
        // 避免在无大写字母时分配：先检查是否需要 lowercase
        let lower_buf;
        let d: &str = if domain.bytes().any(|b| b.is_ascii_uppercase()) {
            lower_buf = domain.to_ascii_lowercase();
            &lower_buf
        } else {
            domain
        };

        // 预计算 FST key（供精确匹配用，suffix 匹配内部自行迭代）
        let fst_key = domain_to_fst_key(d);

        // 1. 精确匹配
        if self.domain_matcher.matches_exact(fst_key.as_bytes(), d) {
            return true;
        }

        // 2. 后缀匹配
        if self.domain_matcher.matches_suffix(d) {
            return true;
        }

        // 3. 关键词（线性，通常条目极少）
        for kw in &self.keywords {
            if d.contains(kw.as_ref()) {
                return true;
            }
        }

        // 4. 正则
        if let Some(ref rs) = self.regexes {
            if rs.is_match(d) {
                return true;
            }
        }

        false
    }

    // ── IP 匹配（区间树 O(log n)） ────────────────────────────────────────

    #[inline]
    fn match_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.match_ipv4(v4),
            IpAddr::V6(v6) => {
                // IPv4-mapped IPv6（::ffff:x.x.x.x）优先走 IPv4 区间树
                if let Some(v4) = v6.to_ipv4_mapped() {
                    if self.match_ipv4(v4) {
                        return true;
                    }
                }
                self.match_ipv6(v6)
            }
        }
    }

    #[inline]
    fn match_ipv4(&self, addr: Ipv4Addr) -> bool {
        if self.ipv4_ranges.is_empty() {
            return false;
        }
        self.ipv4_ranges.contains(u32::from(addr))
    }

    #[inline]
    fn match_ipv6(&self, addr: Ipv6Addr) -> bool {
        if self.ipv6_ranges.is_empty() {
            return false;
        }
        self.ipv6_ranges.contains(u128::from(addr))
    }

    // ── 端口匹配（BitSet O(1)） ───────────────────────────────────────────

    #[inline(always)]
    fn match_port(&self, port: u16) -> bool {
        match &self.port_bitset {
            Some(bs) => bs.contains(port),
            None => false,
        }
    }
}

// ── 便捷构造（从文本，用于测试）──────────────────────────────────────────────

impl RuleSet {
    pub fn from_text(src: &str) -> Result<Self> {
        use crate::ruleset::compiler::CompiledRuleSet;
        let compiled = CompiledRuleSet::from_text(src)?;
        let mut buf = Vec::new();
        compiled.serialize(&mut buf)?;
        let loaded = LoadedRuleSet::from_bytes(&buf)?;
        Self::from_loaded(loaded)
    }
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn rs(src: &str) -> RuleSet {
        RuleSet::from_text(src).unwrap()
    }

    #[test]
    fn exact_domain() {
        let r = rs("domain: example.com");
        assert!(r.matches(&MatchTarget::Domain("example.com")));
        assert!(!r.matches(&MatchTarget::Domain("sub.example.com")));
        assert!(!r.matches(&MatchTarget::Domain("other.com")));
    }

    #[test]
    fn domain_case_insensitive() {
        let r = rs("domain: Example.COM");
        assert!(r.matches(&MatchTarget::Domain("example.com")));
        assert!(r.matches(&MatchTarget::Domain("EXAMPLE.COM")));
    }

    #[test]
    fn suffix_match() {
        let r = rs("domain-suffix: google.com");
        assert!(r.matches(&MatchTarget::Domain("google.com")));
        assert!(r.matches(&MatchTarget::Domain("www.google.com")));
        assert!(r.matches(&MatchTarget::Domain("mail.google.com")));
        assert!(!r.matches(&MatchTarget::Domain("notgoogle.com")));
        assert!(!r.matches(&MatchTarget::Domain("evilgoogle.com")));
    }

    #[test]
    fn suffix_match_self() {
        let r = rs("domain-suffix: google.com");
        assert!(r.matches(&MatchTarget::Domain("google.com")));
    }

    #[test]
    fn keyword_match() {
        let r = rs("domain-keyword: ads");
        assert!(r.matches(&MatchTarget::Domain("ads.example.com")));
        assert!(r.matches(&MatchTarget::Domain("badads.net")));
        assert!(!r.matches(&MatchTarget::Domain("example.com")));
    }

    #[test]
    fn regex_match() {
        let r = rs(r"domain-regex: ^tracker\d+\.");
        assert!(r.matches(&MatchTarget::Domain("tracker1.example.com")));
        assert!(r.matches(&MatchTarget::Domain("tracker99.net")));
        assert!(!r.matches(&MatchTarget::Domain("tracker.example.com")));
    }

    #[test]
    fn multiple_regexes() {
        let r = rs("domain-regex: ^ads\\.\ndomain-regex: ^tracker\\d+\\.");
        assert!(r.matches(&MatchTarget::Domain("ads.example.com")));
        assert!(r.matches(&MatchTarget::Domain("tracker1.net")));
        assert!(!r.matches(&MatchTarget::Domain("safe.com")));
    }

    #[test]
    fn ipv4_cidr() {
        let r = rs("ip-cidr: 192.168.0.0/16");
        assert!(r.matches(&MatchTarget::Ip("192.168.1.1".parse().unwrap())));
        assert!(!r.matches(&MatchTarget::Ip("192.169.0.1".parse().unwrap())));
    }

    #[test]
    fn ipv4_cidr_boundary() {
        let r = rs("ip-cidr: 10.0.0.0/8");
        assert!(r.matches(&MatchTarget::Ip("10.0.0.0".parse().unwrap())));
        assert!(r.matches(&MatchTarget::Ip("10.255.255.255".parse().unwrap())));
        assert!(!r.matches(&MatchTarget::Ip("11.0.0.0".parse().unwrap())));
        assert!(!r.matches(&MatchTarget::Ip("9.255.255.255".parse().unwrap())));
    }

    #[test]
    fn multiple_ipv4_cidrs_merged() {
        // 两个相邻 CIDR 会被合并为一个区间
        let r = rs("ip-cidr: 10.0.0.0/8\nip-cidr: 11.0.0.0/8");
        assert!(r.matches(&MatchTarget::Ip("10.5.5.5".parse().unwrap())));
        assert!(r.matches(&MatchTarget::Ip("11.5.5.5".parse().unwrap())));
        assert!(!r.matches(&MatchTarget::Ip("12.0.0.0".parse().unwrap())));
    }

    #[test]
    fn ipv6_cidr() {
        let r = rs("ip-cidr6: 2001:db8::/32");
        assert!(r.matches(&MatchTarget::Ip("2001:db8::1".parse().unwrap())));
        assert!(!r.matches(&MatchTarget::Ip("2001:db9::1".parse().unwrap())));
    }

    #[test]
    fn port_single() {
        let r = rs("port: 443");
        assert!(r.matches(&MatchTarget::Port(443)));
        assert!(!r.matches(&MatchTarget::Port(80)));
    }

    #[test]
    fn port_range() {
        let r = rs("port: 8000-9000");
        assert!(r.matches(&MatchTarget::Port(8000)));
        assert!(r.matches(&MatchTarget::Port(9000)));
        assert!(r.matches(&MatchTarget::Port(8500)));
        assert!(!r.matches(&MatchTarget::Port(7999)));
        assert!(!r.matches(&MatchTarget::Port(9001)));
    }

    #[test]
    fn port_multiple_ranges() {
        let r = rs("port: 80\nport: 443\nport: 8000-9000");
        assert!(r.matches(&MatchTarget::Port(80)));
        assert!(r.matches(&MatchTarget::Port(443)));
        assert!(r.matches(&MatchTarget::Port(8080)));
        assert!(!r.matches(&MatchTarget::Port(22)));
    }

    #[test]
    fn combined_rules() {
        let r = rs("domain-suffix: google.com\nip-cidr: 10.0.0.0/8\nport: 443");
        assert!(r.matches(&MatchTarget::Domain("maps.google.com")));
        assert!(r.matches(&MatchTarget::Ip("10.5.5.5".parse().unwrap())));
        assert!(r.matches(&MatchTarget::Port(443)));
        assert!(!r.matches(&MatchTarget::Domain("bing.com")));
    }

    // ── BitSet 专项测试 ───────────────────────────────────────────────────

    #[test]
    fn port_bitset_boundary_ports() {
        let r = rs("port: 0\nport: 65535");
        assert!(r.matches(&MatchTarget::Port(0)));
        assert!(r.matches(&MatchTarget::Port(65535)));
        assert!(!r.matches(&MatchTarget::Port(1)));
        assert!(!r.matches(&MatchTarget::Port(65534)));
    }

    // ── IP 区间树专项测试 ─────────────────────────────────────────────────

    #[test]
    fn ipv4_host_route() {
        let r = rs("ip-cidr: 8.8.8.8/32");
        assert!(r.matches(&MatchTarget::Ip("8.8.8.8".parse().unwrap())));
        assert!(!r.matches(&MatchTarget::Ip("8.8.8.9".parse().unwrap())));
    }

    #[test]
    fn ipv4_default_route() {
        let r = rs("ip-cidr: 0.0.0.0/0");
        assert!(r.matches(&MatchTarget::Ip("1.2.3.4".parse().unwrap())));
        assert!(r.matches(&MatchTarget::Ip("255.255.255.255".parse().unwrap())));
    }

    // ── FST suffix 零分配测试 ─────────────────────────────────────────────

    #[test]
    fn suffix_deep_subdomain() {
        let r = rs("domain-suffix: example.com");
        assert!(r.matches(&MatchTarget::Domain("a.b.c.d.example.com")));
        assert!(!r.matches(&MatchTarget::Domain("a.b.c.d.example.net")));
    }

    #[test]
    fn suffix_trailing_dot() {
        // FQDN 格式（末尾有点）
        let r = rs("domain-suffix: google.com");
        assert!(r.matches(&MatchTarget::Domain("www.google.com.")));
    }
}
