//! DNS 缓存：LRU + TTL 内存缓存，支持 transport 隔离和 optimistic（stale-while-revalidate）模式。
//!
//! 优化（参照 sing-box dns/client.go）：
//! - **两级缓存**：内存 LRU（热路径）+ 持久化后端（跨重启恢复，可选）
//! - **transport 隔离**：key = (transport_tag, qname_lower, qtype)，不同上游的缓存互不干扰
//! - **Optimistic 模式**：缓存过期后继续返回 stale 值（TTL 归一为 1s），同时在后台异步刷新
//! - **持久化回写**：命中内存缓存后不再写持久层；仅在查询上游后异步回写
//! - **并发请求去重**（新增）：同一 (transport, qname, qtype) 的并发请求，只发出一次上游查询，
//!   其余等待者复用同一结果，消除 DNS 请求风暴（对应 sing-box 的 cacheLock）。
//!
//! 内存 LRU 使用 `lru` crate（标准双向链表 + HashMap），O(1) get/set/evict，
//! 彻底消除原实现 Vec::remove + rebuild_order_idx 的 O(n) 热路径开销。

use std::{
    collections::HashMap,
    num::NonZeroUsize,
    sync::Arc,
    sync::Mutex,
    time::{Duration, Instant},
};

use bytes::Bytes;
use lru::LruCache;
use tokio::sync::broadcast;

use crate::experimental::{unix_now, CacheFile, CacheFileReader};

// ── 公共接口 ──────────────────────────────────────────────────────────────────

pub struct DnsCache {
    inner: Mutex<LruCache<CacheKey, CacheEntry>>,
    ttl_cap: u32,
    /// Optimistic stale 容忍时长（None = 禁用 optimistic 模式）
    optimistic_ttl: Option<Duration>,
    /// 持久化读句柄（None = 仅内存）
    persist_reader: Option<Arc<CacheFileReader>>,
    /// 持久化写句柄（None = 仅内存）
    persist_writer: Option<Arc<CacheFile>>,
    /// 并发请求去重：同一 key 的飞行中请求只有一个，其余等待广播结果。
    /// 参照 sing-box 的 cacheLock：Map<CacheKey, broadcast::Sender<Bytes>>
    inflight: Mutex<HashMap<CacheKey, broadcast::Sender<Bytes>>>,
}

/// get() 的返回值，区分三种状态
pub enum CacheResult {
    /// 完全命中且未过期
    Hit(Bytes),
    /// 已过期但在 optimistic 窗口内：返回 stale 值，调用方应后台刷新
    Stale(Bytes),
    /// 未命中
    Miss,
}

/// 并发去重的结果：调用方是这次请求的「发起者」还是「等待者」
pub enum InflightResult {
    /// 本请求是 leader（第一个到达），需要真正查询上游，查完后调用 complete_inflight
    Leader,
    /// 本请求是 waiter（已有 leader 在飞），等待 Receiver，收到结果即可直接返回
    Waiter(broadcast::Receiver<Bytes>),
}

impl DnsCache {
    /// 创建纯内存缓存（不持久化）
    pub fn new(capacity: usize, ttl_cap: u32) -> Self {
        Self::with_options(capacity, ttl_cap, None, None, None)
    }

    /// 完整构造：可注入持久化句柄和 optimistic 时长
    pub fn with_options(
        capacity: usize,
        ttl_cap: u32,
        optimistic_ttl: Option<Duration>,
        persist_reader: Option<Arc<CacheFileReader>>,
        persist_writer: Option<Arc<CacheFile>>,
    ) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap();
        Self {
            inner: Mutex::new(LruCache::new(cap)),
            ttl_cap,
            optimistic_ttl,
            persist_reader,
            persist_writer,
            inflight: Mutex::new(HashMap::new()),
        }
    }

    /// 查询缓存。
    /// - `transport`：DNS 上游标签，用于隔离不同上游的缓存
    /// - 返回 `CacheResult`，由调用方决定是否触发后台刷新
    pub fn get(&self, transport: &str, qname: &str, qtype: u16) -> CacheResult {
        let key = CacheKey::new(transport, qname, qtype);
        let now = Instant::now();

        // ── 1. 查内存 LRU（O(1) get，自动更新访问顺序）─────────────────────
        {
            let mut inner = self.inner.lock().unwrap();
            if let Some(entry) = inner.get(&key) {
                if now < entry.expires {
                    return CacheResult::Hit(entry.resp.clone());
                }
                // 过期：检查 optimistic 窗口
                if let Some(opt_dur) = self.optimistic_ttl {
                    if now < entry.expires + opt_dur {
                        return CacheResult::Stale(entry.resp.clone());
                    }
                }
                // 完全过期，从内存移除
                drop(inner); // 释放锁再 remove，避免二次借用
                self.inner.lock().unwrap().pop(&key);
            }
        }

        // ── 2. 查持久层 ────────────────────────────────────────────────────
        if let Some(reader) = &self.persist_reader {
            let qname_lower = qname.to_ascii_lowercase();
            if let Some((raw, expire_at_secs)) =
                reader.load_dns_cache(transport, &qname_lower, qtype)
            {
                let now_secs = unix_now();

                if expire_at_secs > now_secs {
                    // 未过期：写回内存 LRU
                    let remaining_secs =
                        (expire_at_secs - now_secs).min(self.ttl_cap as u64) as u32;
                    self.insert_memory(key, raw.clone(), remaining_secs);
                    return CacheResult::Hit(raw);
                }
                // 过期：检查 optimistic 窗口
                if let Some(opt_dur) = self.optimistic_ttl {
                    let stale_secs = now_secs.saturating_sub(expire_at_secs);
                    if Duration::from_secs(stale_secs) < opt_dur {
                        return CacheResult::Stale(raw);
                    }
                }
            }
        }

        CacheResult::Miss
    }

    /// 写入缓存（内存 + 持久化）
    pub fn set(&self, transport: &str, qname: &str, qtype: u16, resp: Bytes, ttl: u32) {
        let ttl = ttl.min(self.ttl_cap).max(1);
        let key = CacheKey::new(transport, qname, qtype);
        self.insert_memory(key, resp.clone(), ttl);

        // 异步写持久层
        if let Some(writer) = &self.persist_writer {
            let expire_at = unix_now() + ttl as u64;
            writer.save_dns_cache_async(transport, qname, qtype, resp, expire_at);
        }
    }

    // ── 并发请求去重 API ──────────────────────────────────────────────────────

    /// 尝试成为「飞行中」请求的 leader。
    ///
    /// - 若此 key 尚无 leader：注册 broadcast sender，返回 `Leader`。
    ///   调用方查询完上游后**必须**调用 `complete_inflight` 广播结果并清理。
    /// - 若此 key 已有 leader：返回 `Waiter(rx)`，调用方 await rx 即可。
    pub fn try_lead_inflight(&self, transport: &str, qname: &str, qtype: u16) -> InflightResult {
        let key = CacheKey::new(transport, qname, qtype);
        let mut inflight = self.inflight.lock().unwrap();
        if let Some(sender) = inflight.get(&key) {
            InflightResult::Waiter(sender.subscribe())
        } else {
            // capacity=1：每条查询只需一个结果值，waiter 数量不限
            let (tx, _rx) = broadcast::channel(1);
            inflight.insert(key, tx);
            InflightResult::Leader
        }
    }

    /// Leader 查询完成后调用：广播结果给所有等待者，并从 inflight 表移除。
    /// `resp` 为 None 表示查询失败（waiter 收到 RecvError，自行决定重试或报错）。
    pub fn complete_inflight(
        &self,
        transport: &str,
        qname: &str,
        qtype: u16,
        resp: Option<&Bytes>,
    ) {
        let key = CacheKey::new(transport, qname, qtype);
        let sender = {
            let mut inflight = self.inflight.lock().unwrap();
            inflight.remove(&key)
        };
        if let Some(tx) = sender {
            if let Some(r) = resp {
                // 忽略「无 waiter」的错误（正常情况）
                let _ = tx.send(r.clone());
            }
            // resp=None 时 tx 直接 drop，waiter 会收到 RecvError，自行处理
        }
    }

    /// 当前 inflight 去重表中的条目数，正常情况应趋近于 0。
    /// 若持续增长说明 complete_inflight 没有被配对调用（leader task 被 cancel）。
    pub fn inflight_len(&self) -> usize {
        self.inflight.lock().unwrap().len()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn insert_memory(&self, key: CacheKey, resp: Bytes, ttl_secs: u32) {
        let expires = Instant::now() + Duration::from_secs(ttl_secs as u64);
        let mut inner = self.inner.lock().unwrap();
        // lru::LruCache::put 自动处理容量淘汰（O(1)）
        inner.put(key, CacheEntry { resp, expires });
    }
}

// ── 内部结构 ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CacheKey {
    transport: String,
    qname: String,
    qtype: u16,
}

impl CacheKey {
    fn new(transport: &str, qname: &str, qtype: u16) -> Self {
        Self {
            transport: transport.to_string(),
            qname: qname.to_ascii_lowercase(),
            qtype,
        }
    }
}

struct CacheEntry {
    resp: Bytes,
    expires: Instant,
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(id: u8) -> Bytes {
        Bytes::from(vec![id, 0, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0])
    }

    #[test]
    fn basic_hit() {
        let c = DnsCache::new(16, 300);
        c.set("t", "example.com", 1, resp(1), 60);
        assert!(matches!(c.get("t", "example.com", 1), CacheResult::Hit(_)));
        assert!(matches!(c.get("t", "other.com", 1), CacheResult::Miss));
    }

    #[test]
    fn transport_isolation() {
        let c = DnsCache::new(16, 300);
        c.set("ta", "x.com", 1, resp(1), 60);
        c.set("tb", "x.com", 1, resp(2), 60);
        let CacheResult::Hit(r1) = c.get("ta", "x.com", 1) else {
            panic!()
        };
        let CacheResult::Hit(r2) = c.get("tb", "x.com", 1) else {
            panic!()
        };
        assert_eq!(r1[0], 1);
        assert_eq!(r2[0], 2);
        assert!(matches!(c.get("ta", "x.com", 28), CacheResult::Miss));
    }

    #[test]
    fn qtype_separation() {
        let c = DnsCache::new(16, 300);
        c.set("t", "x.com", 1, resp(1), 60);
        c.set("t", "x.com", 28, resp(2), 60);
        let CacheResult::Hit(a) = c.get("t", "x.com", 1) else {
            panic!()
        };
        let CacheResult::Hit(aaaa) = c.get("t", "x.com", 28) else {
            panic!()
        };
        assert_eq!(a[0], 1);
        assert_eq!(aaaa[0], 2);
    }

    #[test]
    fn case_insensitive() {
        let c = DnsCache::new(16, 300);
        c.set("t", "Example.COM", 1, resp(1), 60);
        assert!(matches!(c.get("t", "example.com", 1), CacheResult::Hit(_)));
        assert!(matches!(c.get("t", "EXAMPLE.COM", 1), CacheResult::Hit(_)));
    }

    #[test]
    fn ttl_cap() {
        let c = DnsCache::new(16, 10);
        c.set("t", "capped.com", 1, resp(1), 9999);
        assert!(matches!(c.get("t", "capped.com", 1), CacheResult::Hit(_)));
    }

    #[test]
    fn expired_miss() {
        let c = DnsCache::new(16, 300);
        // 手动插入一个已过期的条目
        let key = CacheKey::new("t", "expire.com", 1);
        {
            let mut inner = c.inner.lock().unwrap();
            inner.put(
                key,
                CacheEntry {
                    resp: resp(5),
                    expires: Instant::now() - Duration::from_secs(1),
                },
            );
        }
        assert!(matches!(c.get("t", "expire.com", 1), CacheResult::Miss));
    }

    #[test]
    fn optimistic_stale() {
        let c = DnsCache::with_options(16, 300, Some(Duration::from_secs(60)), None, None);
        let key = CacheKey::new("t", "stale.com", 1);
        {
            let mut inner = c.inner.lock().unwrap();
            inner.put(
                key,
                CacheEntry {
                    resp: resp(7),
                    expires: Instant::now() - Duration::from_secs(5),
                },
            );
        }
        assert!(matches!(c.get("t", "stale.com", 1), CacheResult::Stale(_)));
    }

    #[test]
    fn optimistic_expired_beyond_window() {
        let c = DnsCache::with_options(16, 300, Some(Duration::from_secs(10)), None, None);
        let key = CacheKey::new("t", "old.com", 1);
        {
            let mut inner = c.inner.lock().unwrap();
            inner.put(
                key,
                CacheEntry {
                    resp: resp(8),
                    expires: Instant::now() - Duration::from_secs(30),
                },
            );
        }
        assert!(matches!(c.get("t", "old.com", 1), CacheResult::Miss));
    }

    #[test]
    fn capacity_eviction() {
        let c = DnsCache::new(4, 300);
        for i in 0u8..6 {
            c.set("t", &format!("host{i}.com"), 1, resp(i), 60);
        }
        assert!(c.len() <= 4);
    }

    #[tokio::test]
    async fn inflight_dedup_basic() {
        let c = Arc::new(DnsCache::new(16, 300));
        // 第一次 → Leader
        assert!(matches!(
            c.try_lead_inflight("t", "dedup.com", 1),
            InflightResult::Leader
        ));
        // 第二次 → Waiter
        let mut rx = match c.try_lead_inflight("t", "dedup.com", 1) {
            InflightResult::Waiter(r) => r,
            InflightResult::Leader => panic!("expected Waiter"),
        };
        let c2 = c.clone();
        let fake_resp = Bytes::from_static(b"\x00\x01\x81\x80\x00\x00\x00\x01\x00\x00\x00\x00");
        // Leader 完成，广播结果
        tokio::spawn(async move {
            c2.complete_inflight("t", "dedup.com", 1, Some(&fake_resp));
        });
        let got = rx.recv().await.expect("should receive result");
        assert!(!got.is_empty());
    }
}
