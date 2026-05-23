//! 持久化缓存：基于 redb 嵌入式 KV 数据库。
//!
//! 表（Table）设计：
//! - `fakeip`         : key = IP 字符串, value = (last_seen_unix_secs, domain)
//! - `dns_cache`      : key = encode_dns_key(transport, qname_lower, qtype)
//!   value = (expire_at_unix_secs, raw_dns_response_bytes)
//! - `ruleset_cache`  : key = ruleset tag (String), value = 原始规则集字节
//!   用于缓存 type=remote 且未配置 path 的规则集，避免每次重启重新下载
//!
//! 特性：
//! - redb 原生 MVCC，读写互不阻塞，无 SQLite WAL 开销
//! - DNS 缓存写入通过 tokio mpsc channel 串行化，不阻塞查询路径
//! - 启动时自动清理过期条目；后台定时任务周期性清理

use std::{
    net::IpAddr,
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use bytes::Bytes;
use redb::{Database, ReadableTable, TableDefinition};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

// ── redb 表定义 ───────────────────────────────────────────────────────────────

const FAKEIP_TABLE: TableDefinition<&str, (u64, &str)> = TableDefinition::new("fakeip");
const DNS_TABLE: TableDefinition<&[u8], (u64, &[u8])> = TableDefinition::new("dns_cache");
/// key = selector tag，value = 上次选中的 outbound tag
const SELECTED_TABLE: TableDefinition<&str, &str> = TableDefinition::new("selected");
/// key = ruleset tag，value = 原始规则集字节（type=remote 且无 path 时使用）
const RULESET_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("ruleset_cache");

// ── 写操作消息 ────────────────────────────────────────────────────────────────

#[allow(dead_code)]
enum WriteOp {
    StoreFakeip {
        ip: String,
        domain: String,
        last_seen: u64,
    },
    TouchFakeip {
        ip: String,
        last_seen: u64,
    },
    SaveDns {
        key: Vec<u8>,
        expire_at: u64,
        raw: Vec<u8>,
    },
    /// 持久化 selector 选中记录：group_tag → selected_tag
    StoreSelected {
        group: String,
        selected: String,
    },
    /// 持久化远程规则集字节（type=remote 且无 path 时）
    StoreRuleset {
        tag: String,
        data: Vec<u8>,
    },
    Cleanup,
    Shutdown,
}

// ── 写句柄（跨 task 共享） ────────────────────────────────────────────────────

pub struct CacheFile {
    write_tx: mpsc::UnboundedSender<WriteOp>,
    pub store_fakeip: bool,
    pub store_dns: bool,
}

impl CacheFile {
    pub fn store_fakeip_entry(&self, ip: IpAddr, domain: &str) {
        if !self.store_fakeip {
            return;
        }
        let _ = self.write_tx.send(WriteOp::StoreFakeip {
            ip: ip.to_string(),
            domain: domain.to_string(),
            last_seen: unix_now(),
        });
    }

    pub fn touch_fakeip_entry(&self, ip: IpAddr) {
        if !self.store_fakeip {
            return;
        }
        let _ = self.write_tx.send(WriteOp::TouchFakeip {
            ip: ip.to_string(),
            last_seen: unix_now(),
        });
    }

    /// 持久化 Selector 选中节点（非阻塞）
    pub fn store_selected(&self, group: &str, selected: &str) {
        let _ = self.write_tx.send(WriteOp::StoreSelected {
            group: group.to_string(),
            selected: selected.to_string(),
        });
    }

    /// 持久化远程规则集字节（非阻塞，type=remote 且无 path 时调用）
    pub fn store_ruleset_entry(&self, tag: &str, data: Vec<u8>) {
        let _ = self.write_tx.send(WriteOp::StoreRuleset {
            tag: tag.to_string(),
            data,
        });
    }

    /// 异步写入 DNS 缓存（非阻塞）
    pub fn save_dns_cache_async(
        &self,
        transport: &str,
        qname: &str,
        qtype: u16,
        raw: Bytes,
        expire_at_secs: u64,
    ) {
        if !self.store_dns {
            return;
        }
        let _ = self.write_tx.send(WriteOp::SaveDns {
            key: encode_dns_key(transport, qname, qtype),
            expire_at: expire_at_secs,
            raw: raw.to_vec(),
        });
    }
}

// ── 读句柄（持有 Arc<Database>，可并发只读） ──────────────────────────────────

pub struct CacheFileReader {
    db: Arc<Database>,
    pub store_dns: bool,
}

impl CacheFileReader {
    /// 读取 Selector 上次选中的 outbound tag；未找到时返回 None。
    pub fn load_selected(&self, group: &str) -> Option<String> {
        let rtx = self.db.begin_read().ok()?;
        let table = rtx.open_table(SELECTED_TABLE).ok()?;
        let guard = table.get(group).ok()??;
        Some(guard.value().to_string())
    }

    /// 读取已缓存的远程规则集原始字节；未找到时返回 None。
    pub fn load_ruleset_cache(&self, tag: &str) -> Option<Vec<u8>> {
        let rtx = self.db.begin_read().ok()?;
        let table = rtx.open_table(RULESET_TABLE).ok()?;
        let guard = table.get(tag).ok()??;
        Some(guard.value().to_vec())
    }

    /// 读取 DNS 缓存，返回 (raw_response, expire_at_unix_secs)。
    /// 不检查是否过期，由调用方（DnsCache）决策。
    pub fn load_dns_cache(&self, transport: &str, qname: &str, qtype: u16) -> Option<(Bytes, u64)> {
        if !self.store_dns {
            return None;
        }
        let key = encode_dns_key(transport, qname, qtype);
        let rtx = self.db.begin_read().ok()?;
        let table = rtx.open_table(DNS_TABLE).ok()?;
        let guard = table.get(key.as_slice()).ok()??;
        let (expire_at, raw_bytes) = guard.value();
        let raw = Bytes::copy_from_slice(raw_bytes);
        Some((raw, expire_at))
    }

    /// 启动时恢复内存 fakeip 映射
    pub fn load_all_fakeip(&self) -> anyhow::Result<Vec<(IpAddr, String)>> {
        let rtx = self.db.begin_read()?;
        let table = rtx.open_table(FAKEIP_TABLE)?;
        let mut result = Vec::new();
        for item in table.iter()? {
            let (k, v) = item?;
            let ip_str = k.value();
            let (_, domain) = v.value();
            match ip_str.parse::<IpAddr>() {
                Ok(ip) => result.push((ip, domain.to_string())),
                Err(e) => warn!(ip=%ip_str, err=%e, "invalid ip in fakeip table, skipping"),
            }
        }
        Ok(result)
    }
}

// ── 工厂函数：同时返回写句柄和读句柄 ─────────────────────────────────────────

pub fn open_cache_file(
    path: impl AsRef<Path>,
    store_fakeip: bool,
    fakeip_ttl_days: u32,
    store_dns: bool,
    dns_cleanup_secs: u64,
) -> anyhow::Result<(Arc<CacheFile>, Arc<CacheFileReader>)> {
    let db = Arc::new(
        Database::create(path.as_ref())
            .with_context(|| format!("failed to open redb: {}", path.as_ref().display()))?,
    );

    // 建表（幂等）
    {
        let wtx = db.begin_write()?;
        wtx.open_table(FAKEIP_TABLE)?;
        wtx.open_table(DNS_TABLE)?;
        wtx.open_table(SELECTED_TABLE)?;
        wtx.open_table(RULESET_TABLE)?;
        wtx.commit()?;
    }

    // 启动时清理
    if store_fakeip && fakeip_ttl_days > 0 {
        let cutoff = unix_now().saturating_sub(fakeip_ttl_days as u64 * 86400);
        match purge_stale_fakeip(&db, cutoff) {
            Ok(n) if n > 0 => info!(count = n, "purged stale fakeip on startup"),
            Err(e) => warn!(err=%e, "purge stale fakeip failed"),
            _ => {}
        }
    }
    if store_dns {
        match purge_expired_dns(&db, unix_now()) {
            Ok(n) if n > 0 => info!(count = n, "purged expired dns cache on startup"),
            Err(e) => warn!(err=%e, "purge expired dns failed"),
            _ => {}
        }
    }

    let (write_tx, write_rx) = mpsc::unbounded_channel::<WriteOp>();
    let interval = if dns_cleanup_secs > 0 {
        dns_cleanup_secs
    } else {
        3600
    };
    let db_write = db.clone();
    tokio::spawn(write_loop(db_write, write_rx, interval, fakeip_ttl_days));

    let writer = Arc::new(CacheFile {
        write_tx,
        store_fakeip,
        store_dns,
    });
    let reader = Arc::new(CacheFileReader { db, store_dns });
    Ok((writer, reader))
}

// ── 后台写循环 ────────────────────────────────────────────────────────────────

async fn write_loop(
    db: Arc<Database>,
    mut rx: mpsc::UnboundedReceiver<WriteOp>,
    cleanup_interval_secs: u64,
    fakeip_ttl_days: u32,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(cleanup_interval_secs));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            Some(op) = rx.recv() => {
                match op {
                    WriteOp::Shutdown => break,
                    WriteOp::Cleanup => do_cleanup(&db, fakeip_ttl_days),
                    op => {
                        if let Err(e) = apply_op(&db, op) {
                            warn!(err=%e, "cache write failed");
                        }
                    }
                }
            }
            _ = ticker.tick() => {
                do_cleanup(&db, fakeip_ttl_days);
            }
        }
    }
}

fn do_cleanup(db: &Arc<Database>, fakeip_ttl_days: u32) {
    let now = unix_now();
    match purge_expired_dns(db, now) {
        Ok(n) if n > 0 => debug!(count = n, "dns cache cleanup"),
        Err(e) => warn!(err=%e, "dns cleanup error"),
        _ => {}
    }
    if fakeip_ttl_days > 0 {
        let cutoff = now.saturating_sub(fakeip_ttl_days as u64 * 86400);
        match purge_stale_fakeip(db, cutoff) {
            Ok(n) if n > 0 => debug!(count = n, "fakeip cleanup"),
            Err(e) => warn!(err=%e, "fakeip cleanup error"),
            _ => {}
        }
    }
}

fn apply_op(db: &Database, op: WriteOp) -> anyhow::Result<()> {
    match op {
        WriteOp::StoreFakeip {
            ip,
            domain,
            last_seen,
        } => {
            let wtx = db.begin_write()?;
            {
                wtx.open_table(FAKEIP_TABLE)?
                    .insert(ip.as_str(), (last_seen, domain.as_str()))?;
            }
            wtx.commit()?;
        }
        WriteOp::TouchFakeip { ip, last_seen } => {
            let wtx = db.begin_write()?;
            {
                let mut table = wtx.open_table(FAKEIP_TABLE)?;
                let existing_domain: Option<String> = {
                    let result = table.get(ip.as_str())?;
                    result.map(|g| {
                        let (_, domain) = g.value();
                        domain.to_string()
                    })
                };
                if let Some(domain) = existing_domain {
                    table.insert(ip.as_str(), (last_seen, domain.as_str()))?;
                }
            }
            wtx.commit()?;
        }
        WriteOp::SaveDns {
            key,
            expire_at,
            raw,
        } => {
            let wtx = db.begin_write()?;
            {
                wtx.open_table(DNS_TABLE)?
                    .insert(key.as_slice(), (expire_at, raw.as_slice()))?;
            }
            wtx.commit()?;
        }
        WriteOp::StoreSelected { group, selected } => {
            let wtx = db.begin_write()?;
            {
                wtx.open_table(SELECTED_TABLE)?
                    .insert(group.as_str(), selected.as_str())?;
            }
            wtx.commit()?;
        }
        WriteOp::StoreRuleset { tag, data } => {
            let wtx = db.begin_write()?;
            {
                wtx.open_table(RULESET_TABLE)?
                    .insert(tag.as_str(), data.as_slice())?;
            }
            wtx.commit()?;
        }
        WriteOp::Cleanup | WriteOp::Shutdown => {}
    }
    Ok(())
}

// ── 清理辅助 ──────────────────────────────────────────────────────────────────

fn purge_expired_dns(db: &Database, now_secs: u64) -> anyhow::Result<usize> {
    let rtx = db.begin_read()?;
    let expired: Vec<Vec<u8>> = {
        let table = rtx.open_table(DNS_TABLE)?;
        table
            .iter()?
            .filter_map(|item| {
                let (k, v) = item.ok()?;
                let (expire_at, _) = v.value();
                if expire_at <= now_secs {
                    Some(k.value().to_vec())
                } else {
                    None
                }
            })
            .collect()
    };
    drop(rtx);
    if expired.is_empty() {
        return Ok(0);
    }
    let count = expired.len();
    let wtx = db.begin_write()?;
    {
        let mut t = wtx.open_table(DNS_TABLE)?;
        for k in &expired {
            t.remove(k.as_slice())?;
        }
    }
    wtx.commit()?;
    Ok(count)
}

fn purge_stale_fakeip(db: &Database, cutoff_secs: u64) -> anyhow::Result<usize> {
    let rtx = db.begin_read()?;
    let stale: Vec<String> = {
        let table = rtx.open_table(FAKEIP_TABLE)?;
        table
            .iter()?
            .filter_map(|item| {
                let (k, v) = item.ok()?;
                let (last_seen, _) = v.value();
                if last_seen < cutoff_secs {
                    Some(k.value().to_string())
                } else {
                    None
                }
            })
            .collect()
    };
    drop(rtx);
    if stale.is_empty() {
        return Ok(0);
    }
    let count = stale.len();
    let wtx = db.begin_write()?;
    {
        let mut t = wtx.open_table(FAKEIP_TABLE)?;
        for k in &stale {
            t.remove(k.as_str())?;
        }
    }
    wtx.commit()?;
    Ok(count)
}

// ── 编码辅助 ──────────────────────────────────────────────────────────────────

/// key 格式：[transport_len(2 BE) | transport_bytes | qname_lower | 0x00 | qtype(2 BE)]
fn encode_dns_key(transport: &str, qname: &str, qtype: u16) -> Vec<u8> {
    let t = transport.as_bytes();
    let q = qname.to_ascii_lowercase();
    let qb = q.as_bytes();
    let mut key = Vec::with_capacity(2 + t.len() + qb.len() + 3);
    key.extend_from_slice(&(t.len() as u16).to_be_bytes());
    key.extend_from_slice(t);
    key.extend_from_slice(qb);
    key.push(0x00);
    key.extend_from_slice(&qtype.to_be_bytes());
    key
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tempfile::NamedTempFile;

    async fn open_temp(
        sf: bool,
        sd: bool,
    ) -> (Arc<CacheFile>, Arc<CacheFileReader>, NamedTempFile) {
        let f = NamedTempFile::new().unwrap();
        let (cf, rd) = open_cache_file(f.path(), sf, 7, sd, 3600).unwrap();
        (cf, rd, f)
    }

    #[tokio::test]
    async fn fakeip_store_and_load() {
        let (cf, rd, _f) = open_temp(true, false).await;
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1));
        cf.store_fakeip_entry(ip, "example.com");
        tokio::time::sleep(Duration::from_millis(60)).await;
        let records = rd.load_all_fakeip().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].1, "example.com");
    }

    #[tokio::test]
    async fn dns_cache_roundtrip() {
        let (cf, rd, _f) = open_temp(false, true).await;
        let raw = Bytes::from(vec![0xAB, 0xCD, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0]);
        let expire_at = unix_now() + 300;
        cf.save_dns_cache_async("up1", "example.com", 1, raw.clone(), expire_at);
        tokio::time::sleep(Duration::from_millis(60)).await;
        let (loaded, exp) = rd.load_dns_cache("up1", "example.com", 1).unwrap();
        assert_eq!(loaded, raw);
        assert_eq!(exp, expire_at);
    }

    #[tokio::test]
    async fn dns_transport_isolation() {
        let (cf, rd, _f) = open_temp(false, true).await;
        let r1 = Bytes::from(vec![0x01; 12]);
        let r2 = Bytes::from(vec![0x02; 12]);
        let exp = unix_now() + 300;
        cf.save_dns_cache_async("ta", "x.com", 1, r1.clone(), exp);
        cf.save_dns_cache_async("tb", "x.com", 1, r2.clone(), exp);
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(rd.load_dns_cache("ta", "x.com", 1).unwrap().0, r1);
        assert_eq!(rd.load_dns_cache("tb", "x.com", 1).unwrap().0, r2);
    }

    #[tokio::test]
    async fn dns_key_case_insensitive() {
        let (cf, rd, _f) = open_temp(false, true).await;
        let raw = Bytes::from(vec![0xAA; 12]);
        cf.save_dns_cache_async("t", "Example.COM", 1, raw.clone(), unix_now() + 300);
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(rd.load_dns_cache("t", "example.com", 1).is_some());
    }
}
