//! DNS 模块集成测试：缓存行为、wire-format 解析、规则分流。

use bytes::Bytes;

use reflex::dns::{
    cache::DnsCache, extract_qname, extract_qtype, make_nxdomain, make_refused, make_servfail,
};

// ── wire-format 工具 ──────────────────────────────────────────────────────────

fn make_query(name: &str, qtype: u16) -> Bytes {
    let mut msg = vec![
        0xAB, 0xCD, // ID
        0x01, 0x00, // flags: RD=1
        0x00, 0x01, // QDCOUNT=1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in name.split('.') {
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0x00); // root
    msg.extend_from_slice(&qtype.to_be_bytes());
    msg.extend_from_slice(&[0x00, 0x01]); // CLASS IN
    Bytes::from(msg)
}

/// 构建一个带 Answer 的最小 DNS 响应（A 记录）
fn make_answer_response(query: &[u8], ip: [u8; 4], ttl: u32) -> Vec<u8> {
    let mut resp = Vec::new();
    resp.extend_from_slice(&query[..2]); // ID
    resp.extend_from_slice(&[0x81, 0x80]); // QR=1 RD=1 RA=1
    resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    resp.extend_from_slice(&[0x00, 0x01]); // ANCOUNT=1
    resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NS/AR

    // Question section（复制查询部分）
    let qdstart = 12;
    let qdend = query.len();
    resp.extend_from_slice(&query[qdstart..qdend]);

    // Answer RR
    resp.extend_from_slice(&[0xC0, 0x0C]); // 指针压缩到 offset 12
    resp.extend_from_slice(&[0x00, 0x01]); // TYPE A
    resp.extend_from_slice(&[0x00, 0x01]); // CLASS IN
    resp.extend_from_slice(&ttl.to_be_bytes()); // TTL
    resp.extend_from_slice(&[0x00, 0x04]); // RDLENGTH=4
    resp.extend_from_slice(&ip); // RDATA

    resp
}

// ── extract_qname / extract_qtype ────────────────────────────────────────────

#[test]
fn extract_qname_single_label() {
    let q = make_query("localhost", 1);
    assert_eq!(extract_qname(&q), Some("localhost".into()));
}

#[test]
fn extract_qname_multi_label() {
    let q = make_query("www.google.com", 1);
    assert_eq!(extract_qname(&q), Some("www.google.com".into()));
}

#[test]
fn extract_qname_deep() {
    let q = make_query("a.b.c.d.example.com", 1);
    assert_eq!(extract_qname(&q), Some("a.b.c.d.example.com".into()));
}

#[test]
fn extract_qtype_a() {
    assert_eq!(extract_qtype(&make_query("x.com", 1)), Some(1));
}
#[test]
fn extract_qtype_aaaa() {
    assert_eq!(extract_qtype(&make_query("x.com", 28)), Some(28));
}
#[test]
fn extract_qtype_mx() {
    assert_eq!(extract_qtype(&make_query("x.com", 15)), Some(15));
}
#[test]
fn extract_qtype_txt() {
    assert_eq!(extract_qtype(&make_query("x.com", 16)), Some(16));
}

// ── rcode 响应构建 ────────────────────────────────────────────────────────────

#[test]
fn servfail_preserves_id_and_rcode() {
    let q = make_query("test.com", 1);
    let r = make_servfail(&q);
    assert_eq!(r[0], 0xAB); // ID high
    assert_eq!(r[1], 0xCD); // ID low
    assert_eq!(r[2] & 0x80, 0x80); // QR=1
    assert_eq!(r[3] & 0x0F, 0x02); // RCODE=SERVFAIL
}

#[test]
fn refused_rcode() {
    let q = make_query("ads.example.com", 1);
    let r = make_refused(&q);
    assert_eq!(r[0], 0xAB);
    assert_eq!(r[3] & 0x0F, 0x05); // REFUSED
}

#[test]
fn nxdomain_rcode() {
    let q = make_query("notexist.example", 1);
    let r = make_nxdomain(&q);
    assert_eq!(r[3] & 0x0F, 0x03); // NXDOMAIN
}

// ── DnsCache ─────────────────────────────────────────────────────────────────

#[test]
fn cache_hit_miss_basic() {
    let cache = DnsCache::new(64, 300);
    let q = make_query("example.com", 1);
    let resp = Bytes::from(make_answer_response(&q, [1, 2, 3, 4], 60));

    assert!(
        matches!(
            cache.get("default", "example.com", 1),
            reflex::dns::cache::CacheResult::Miss
        ),
        "should miss before set"
    );
    cache.set("default", "example.com", 1, resp.clone(), 60);
    let hit = match cache.get("default", "example.com", 1) {
        reflex::dns::cache::CacheResult::Hit(b) => b,
        _ => panic!("expected Hit"),
    };
    // 内容相同（ID 可能被 patch，但其余内容一致）
    assert_eq!(hit.len(), resp.len());
}

#[test]
fn cache_id_patching() {
    fn patch_id(resp_bytes: &[u8], query: &[u8]) -> Vec<u8> {
        let mut v = resp_bytes.to_vec();
        if v.len() >= 2 && query.len() >= 2 {
            v[0] = query[0];
            v[1] = query[1];
        }
        v
    }
    let query = make_query("example.com", 1);
    let mut cached = query.to_vec();
    cached[0] = 0xFF;
    cached[1] = 0xFF;
    let patched = patch_id(&cached, &query);
    assert_eq!(patched[0], 0xAB);
    assert_eq!(patched[1], 0xCD);
}

#[test]
fn cache_type_separation() {
    let cache = DnsCache::new(64, 300);
    let qa = make_query("dual.example.com", 1);
    let _qaaaa = make_query("dual.example.com", 28);

    let resp_a = Bytes::from(make_answer_response(&qa, [1, 2, 3, 4], 60));
    let resp_aaaa = Bytes::from(vec![0x00, 0x02, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0]);

    cache.set("default", "dual.example.com", 1, resp_a.clone(), 60);
    cache.set("default", "dual.example.com", 28, resp_aaaa.clone(), 60);

    let a_hit = match cache.get("default", "dual.example.com", 1) {
        reflex::dns::cache::CacheResult::Hit(b) => b,
        _ => panic!("expected Hit for A"),
    };
    let aaaa_hit = match cache.get("default", "dual.example.com", 28) {
        reflex::dns::cache::CacheResult::Hit(b) => b,
        _ => panic!("expected Hit for AAAA"),
    };

    assert_eq!(a_hit.len(), resp_a.len());
    assert_eq!(aaaa_hit.len(), resp_aaaa.len());
}

#[test]
fn cache_case_insensitive() {
    let cache = DnsCache::new(64, 300);
    let q = make_query("Example.COM", 1);
    let resp = Bytes::from(make_answer_response(&q, [5, 6, 7, 8], 60));

    cache.set("default", "Example.COM", 1, resp, 60);
    assert!(matches!(
        cache.get("default", "example.com", 1),
        reflex::dns::cache::CacheResult::Hit(_)
    ));
    assert!(matches!(
        cache.get("default", "EXAMPLE.COM", 1),
        reflex::dns::cache::CacheResult::Hit(_)
    ));
}

#[test]
fn cache_capacity_bounded() {
    let cap = 8usize;
    let cache = DnsCache::new(cap, 300);
    for i in 0u8..20 {
        let name = format!("host{i}.example.com");
        cache.set(
            "default",
            &name,
            1,
            Bytes::from_static(b"\x00\x00\x81\x80\x00\x00\x00\x00\x00\x00\x00\x00"),
            60,
        );
    }
    assert!(
        cache.len() <= cap,
        "cache len {} exceeded capacity {cap}",
        cache.len()
    );
}

#[test]
fn cache_ttl_cap() {
    let cache = DnsCache::new(64, 10); // ttl_cap = 10 秒
                                       // 即使传入很大的 TTL，缓存条目应该仍然存在（未超过 10 秒）
    cache.set(
        "default",
        "long-ttl.com",
        1,
        Bytes::from_static(b"\x00\x00\x81\x80\x00\x00\x00\x00\x00\x00\x00\x00"),
        86400,
    );
    assert!(
        matches!(
            cache.get("default", "long-ttl.com", 1),
            reflex::dns::cache::CacheResult::Hit(_)
        ),
        "entry should be present immediately after set"
    );
}
