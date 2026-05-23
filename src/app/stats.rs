//! 连接统计：原子计数器，零锁开销。
//!
//! 每个 Outbound tag 维护独立计数，全局也有汇总。
//!
//! 在 32 位平台（如 mips32）上 `AtomicU64` 不存在，
//! 通过条件编译退化为 `AtomicU32`；对外接口统一使用 `u64`。

use std::{
    collections::HashMap,
    sync::{atomic::Ordering, Arc, RwLock},
};

// ── 平台适配：32 位用 AtomicU32，64 位用 AtomicU64 ────────────────────────────

#[cfg(target_pointer_width = "64")]
use std::sync::atomic::AtomicU64 as AtomicCounter;

#[cfg(not(target_pointer_width = "64"))]
use std::sync::atomic::AtomicU32 as AtomicCounter;

/// 将原子计数器的值读出并扩展为 u64
#[inline]
#[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
fn load_u64(c: &AtomicCounter) -> u64 {
    c.load(Ordering::Relaxed) as u64
}

// ── 单个 tag 的统计 ────────────────────────────────────────────────────────────

#[derive(Default, Debug)]
pub struct TagStats {
    /// 当前活跃 TCP 连接数
    pub tcp_active: AtomicCounter,
    /// 当前活跃 UDP 会话数
    pub udp_active: AtomicCounter,
    /// 累计 TCP 连接总数
    pub tcp_total: AtomicCounter,
    /// 累计 UDP 包总数
    pub udp_total: AtomicCounter,
    /// 累计上行字节（入站→出站）
    pub bytes_up: AtomicCounter,
    /// 累计下行字节（出站→入站）
    pub bytes_down: AtomicCounter,
    /// 累计错误次数
    pub errors: AtomicCounter,
}

impl TagStats {
    pub fn snapshot(&self) -> TagSnapshot {
        TagSnapshot {
            tcp_active: load_u64(&self.tcp_active),
            udp_active: load_u64(&self.udp_active),
            tcp_total: load_u64(&self.tcp_total),
            udp_total: load_u64(&self.udp_total),
            bytes_up: load_u64(&self.bytes_up),
            bytes_down: load_u64(&self.bytes_down),
            errors: load_u64(&self.errors),
        }
    }
}

/// 某一时刻的统计快照（可序列化）
#[derive(Debug, Clone)]
pub struct TagSnapshot {
    pub tcp_active: u64,
    pub udp_active: u64,
    pub tcp_total: u64,
    pub udp_total: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub errors: u64,
}

// ── 全局统计注册表 ─────────────────────────────────────────────────────────────

pub struct Stats {
    tags: RwLock<HashMap<String, Arc<TagStats>>>,
}

impl Stats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            tags: RwLock::new(HashMap::new()),
        })
    }

    /// 获取或创建某个 tag 的统计对象
    pub fn tag(&self, tag: &str) -> Arc<TagStats> {
        {
            let r = self.tags.read().unwrap();
            if let Some(s) = r.get(tag) {
                return s.clone();
            }
        }
        let mut w = self.tags.write().unwrap();
        w.entry(tag.to_string())
            .or_insert_with(|| Arc::new(TagStats::default()))
            .clone()
    }

    /// 所有 tag 的快照
    pub fn snapshot_all(&self) -> HashMap<String, TagSnapshot> {
        self.tags
            .read()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.snapshot()))
            .collect()
    }

    /// 全局汇总
    pub fn global_snapshot(&self) -> TagSnapshot {
        self.tags
            .read()
            .unwrap()
            .values()
            .fold(TagSnapshot::zero(), |mut acc, s| {
                let snap = s.snapshot();
                acc.tcp_active += snap.tcp_active;
                acc.udp_active += snap.udp_active;
                acc.tcp_total += snap.tcp_total;
                acc.udp_total += snap.udp_total;
                acc.bytes_up += snap.bytes_up;
                acc.bytes_down += snap.bytes_down;
                acc.errors += snap.errors;
                acc
            })
    }
}

impl TagSnapshot {
    pub fn zero() -> Self {
        Self {
            tcp_active: 0,
            udp_active: 0,
            tcp_total: 0,
            udp_total: 0,
            bytes_up: 0,
            bytes_down: 0,
            errors: 0,
        }
    }
}

// ── RAII 守卫：连接结束时自动减计数 ──────────────────────────────────────────

pub struct TcpGuard(Arc<TagStats>);

impl TcpGuard {
    pub fn new(stats: Arc<TagStats>) -> Self {
        stats.tcp_active.fetch_add(1, Ordering::Relaxed);
        stats.tcp_total.fetch_add(1, Ordering::Relaxed);
        Self(stats)
    }

    pub fn add_bytes(&self, up: u64, down: u64) {
        // 32 位平台截断为 u32：单次传输不会超过 4 GB
        self.0.bytes_up.fetch_add(up as _, Ordering::Relaxed);
        self.0.bytes_down.fetch_add(down as _, Ordering::Relaxed);
    }

    pub fn record_error(&self) {
        self.0.errors.fetch_add(1, Ordering::Relaxed);
    }
}

impl Drop for TcpGuard {
    fn drop(&mut self) {
        self.0.tcp_active.fetch_sub(1, Ordering::Relaxed);
    }
}

pub struct UdpGuard(Arc<TagStats>);

impl UdpGuard {
    pub fn new(stats: Arc<TagStats>) -> Self {
        stats.udp_active.fetch_add(1, Ordering::Relaxed);
        stats.udp_total.fetch_add(1, Ordering::Relaxed);
        Self(stats)
    }

    pub fn add_bytes(&self, up: u64, down: u64) {
        self.0.bytes_up.fetch_add(up as _, Ordering::Relaxed);
        self.0.bytes_down.fetch_add(down as _, Ordering::Relaxed);
    }
}

impl Drop for UdpGuard {
    fn drop(&mut self) {
        self.0.udp_active.fetch_sub(1, Ordering::Relaxed);
    }
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_guard_counts() {
        let stats = Stats::new();
        let tag = stats.tag("proxy");

        assert_eq!(tag.snapshot().tcp_active, 0);
        assert_eq!(tag.snapshot().tcp_total, 0);

        let g1 = TcpGuard::new(stats.tag("proxy"));
        assert_eq!(tag.snapshot().tcp_active, 1);
        assert_eq!(tag.snapshot().tcp_total, 1);

        let g2 = TcpGuard::new(stats.tag("proxy"));
        assert_eq!(tag.snapshot().tcp_active, 2);
        assert_eq!(tag.snapshot().tcp_total, 2);

        g1.add_bytes(100, 200);
        assert_eq!(tag.snapshot().bytes_up, 100);
        assert_eq!(tag.snapshot().bytes_down, 200);

        drop(g1);
        assert_eq!(tag.snapshot().tcp_active, 1);
        assert_eq!(tag.snapshot().tcp_total, 2);

        drop(g2);
        assert_eq!(tag.snapshot().tcp_active, 0);
    }

    #[test]
    fn udp_guard_counts() {
        let stats = Stats::new();
        let g = UdpGuard::new(stats.tag("direct"));
        assert_eq!(stats.tag("direct").snapshot().udp_active, 1);
        drop(g);
        assert_eq!(stats.tag("direct").snapshot().udp_active, 0);
    }

    #[test]
    fn global_snapshot_aggregates() {
        let stats = Stats::new();
        let _g1 = TcpGuard::new(stats.tag("proxy"));
        let _g2 = TcpGuard::new(stats.tag("direct"));
        let global = stats.global_snapshot();
        assert_eq!(global.tcp_active, 2);
        assert_eq!(global.tcp_total, 2);
    }

    #[test]
    fn multiple_tags() {
        let stats = Stats::new();
        let _g = TcpGuard::new(stats.tag("proxy"));
        let _g2 = TcpGuard::new(stats.tag("proxy"));
        let _g3 = UdpGuard::new(stats.tag("direct"));
        let snap = stats.snapshot_all();
        assert_eq!(snap["proxy"].tcp_active, 2);
        assert_eq!(snap["direct"].udp_active, 1);
    }

    #[test]
    fn error_recording() {
        let stats = Stats::new();
        let g = TcpGuard::new(stats.tag("hy2"));
        g.record_error();
        g.record_error();
        assert_eq!(stats.tag("hy2").snapshot().errors, 2);
    }
}
