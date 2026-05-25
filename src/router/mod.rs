//! 路由层：根据规则集决定每条连接走哪个出站。
//!
//! 匹配顺序：rules 数组从上到下，第一条命中生效；全未命中则走 `final`。
//! 单条 rule 内多个条件是 AND，同一条件内多个值是 OR。
//!
//! ## 端口条件的特殊处理
//! ruleset crate 的 `RuleSet` 同时支持 IP/Domain/Port 匹配，但
//! `target_to_match` 只能传一种类型。端口规则被单独拆出，用
//! `MatchTarget::Port(target.port())` 查询，与地址规则通过 OR 合并。
//!
//! ## 优化：预计算过滤索引（避免热路由路径上的分支判断）
//! 原版的 `route_skip_sniff` / `route_skip_resolve` 每次都遍历全部规则
//! 并在循环内 `matches!(action, ...)` 跳过，有额外分支开销。
//!
//! 新版在构建时额外记录：
//! - `rules_no_sniff`：去掉所有 `Sniff` 动作规则后的索引切片
//! - `rules_no_sniff_resolve`：去掉所有 `Sniff`/`Resolve` 动作规则的索引切片
//!
//! 热路由只遍历预过滤后的索引，完全无分支判断。

use std::{collections::HashMap, sync::Arc};

use tracing::{debug, trace};

use crate::ruleset::{LoadedRuleSet, MatchTarget, RuleSet};

use crate::{
    config::route::{NetworkFilter, RouteConfig, RouteRuleConfig, RuleSetType},
    experimental::{CacheFile, CacheFileReader},
    inbound::{InboundTcpStream, InboundUdpPacket, Target},
};

// ── 路由决策 ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteAction {
    Outbound(String),
    DnsOut,
    /// 先做协议嗅探，用嗅探结果更新目标域名后重新路由。
    /// - `timeout_ms`：嗅探超时毫秒数（0 = 使用默认值 300 ms）
    /// - `override_destination`：是否用嗅探结果覆盖连接目标地址（默认 false）
    /// - `sniff_types`：启用的嗅探协议列表（空 = 全部默认）
    Sniff {
        timeout_ms: u64,
        override_destination: bool,
        sniff_types: Vec<crate::app::sniff::SniffType>,
    },
    /// 将域名目标解析为 IP 后继续向后匹配（跳过所有 Resolve 规则，防止循环）。
    /// - `server`：可选，指定使用的 DNS server tag；None 表示使用默认服务器。
    Resolve {
        server: Option<String>,
    },
}

// ── 规则集元数据（规则数量 + 加载时间）────────────────────────────────────────

#[derive(Clone)]
pub struct RuleSetMeta {
    /// 规则条目总数
    pub rule_count: usize,
    /// 最后加载/更新的 Unix 毫秒时间戳
    pub updated_at_ms: u64,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ── 路由器 ────────────────────────────────────────────────────────────────────

pub struct Router {
    rules: Vec<CompiledRule>,
    /// 预计算：去掉 Sniff 动作的规则索引列表（供 route_skip_sniff 使用）
    idx_no_sniff: Vec<usize>,
    /// 预计算：去掉 Sniff+Resolve 动作的规则索引列表（供 route_skip_resolve 使用）
    idx_no_sniff_resolve: Vec<usize>,
    default: RouteAction,
    /// 已加载的规则集，供 DNS 模块共享
    pub rulesets: std::collections::HashMap<String, std::sync::Arc<RuleSet>>,
    /// 每个规则集的元数据（数量、更新时间）
    pub ruleset_meta: std::collections::HashMap<String, RuleSetMeta>,
    /// 原始配置，供刷新 remote 规则集时使用
    route_config: RouteConfig,
}

impl Router {
    /// 从配置构建路由器。
    pub fn from_config(
        config: &RouteConfig,
        cache_reader: Option<&CacheFileReader>,
        cache_writer: Option<&CacheFile>,
    ) -> anyhow::Result<Self> {
        let mut rulesets: HashMap<String, Arc<RuleSet>> = HashMap::new();
        let mut ruleset_meta: HashMap<String, RuleSetMeta> = HashMap::new();
        for rs_ref in &config.rule_set {
            let rs = load_ruleset_ref(rs_ref, cache_reader, cache_writer)?;
            let rc = rs.rule_count();
            ruleset_meta.insert(
                rs_ref.tag.clone(),
                RuleSetMeta {
                    rule_count: rc,
                    updated_at_ms: now_ms(),
                },
            );
            rulesets.insert(rs_ref.tag.clone(), Arc::new(rs));
        }

        // 验证：hijack_dns=true 必须配合至少一个匹配条件
        for (i, r) in config.rules.iter().enumerate() {
            if r.hijack_dns && !r.has_conditions() {
                anyhow::bail!(
                    "route rule[{i}]: `hijack_dns: true` must be used with at least one \
                     matching condition (e.g. `protocol`, `inbound`, `network`, `port`). \
                     A bare `hijack_dns: true` with no conditions is not allowed."
                );
            }
        }

        let rules = config
            .rules
            .iter()
            .map(|r| CompiledRule::compile(r, &rulesets))
            .collect::<anyhow::Result<Vec<_>>>()?;

        // ── 预计算过滤索引 ──────────────────────────────────────────────────
        let idx_no_sniff: Vec<usize> = rules
            .iter()
            .enumerate()
            .filter_map(|(i, r)| {
                if matches!(r.action, RouteAction::Sniff { .. }) {
                    None
                } else {
                    Some(i)
                }
            })
            .collect();

        let idx_no_sniff_resolve: Vec<usize> = rules
            .iter()
            .enumerate()
            .filter_map(|(i, r)| {
                if matches!(
                    r.action,
                    RouteAction::Sniff { .. } | RouteAction::Resolve { .. }
                ) {
                    None
                } else {
                    Some(i)
                }
            })
            .collect();

        let default = to_action(&config.r#final);
        Ok(Self {
            rules,
            idx_no_sniff,
            idx_no_sniff_resolve,
            default,
            rulesets,
            ruleset_meta,
            route_config: config.clone(),
        })
    }

    /// 返回默认路由动作（用于 UDP 嗅探降级）
    pub fn default_action(&self) -> &RouteAction {
        &self.default
    }

    /// 重新下载并替换指定 remote 规则集。仅对 type=remote 的规则集有效。
    /// 成功后更新 rulesets 和 ruleset_meta。
    /// 注意：此方法会阻塞当前线程做网络下载，应在 tokio::task::spawn_blocking 里调用。
    pub fn reload_remote_ruleset(&mut self, tag: &str) -> anyhow::Result<()> {
        let rs_ref = self
            .route_config
            .rule_set
            .iter()
            .find(|r| r.tag == tag)
            .ok_or_else(|| anyhow::anyhow!("rule_set '{tag}' not found"))?
            .clone();

        use crate::config::route::RuleSetType;
        if rs_ref.r#type != RuleSetType::Remote {
            anyhow::bail!("rule_set '{tag}' is not remote, cannot update");
        }

        let url = rs_ref
            .url
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("rule_set '{tag}': missing url"))?;

        // 强制从网络重新下载（忽略磁盘缓存）
        let data = download_bytes(url, tag)?;

        // 覆盖磁盘缓存
        if let Some(path) = &rs_ref.path {
            if let Some(parent) = std::path::Path::new(path).parent() {
                std::fs::create_dir_all(parent).ok();
            }
            std::fs::write(path, &data).ok();
            tracing::debug!(tag, path, "rule_set: refreshed disk cache");
        }

        let loaded = crate::ruleset::LoadedRuleSet::from_bytes(&data)
            .map_err(|e| anyhow::anyhow!("rule_set '{tag}': parse error: {e}"))?;
        let rs = RuleSet::from_loaded(loaded)?;
        let rc = rs.rule_count();
        self.rulesets.insert(tag.to_string(), Arc::new(rs));
        self.ruleset_meta.insert(
            tag.to_string(),
            RuleSetMeta {
                rule_count: rc,
                updated_at_ms: now_ms(),
            },
        );
        tracing::info!(tag, rule_count = rc, "rule_set: refreshed");
        Ok(())
    }

    pub fn route_tcp(&self, conn: &InboundTcpStream) -> (&RouteAction, &str, &str) {
        self.route(
            &conn.inbound_tag,
            Some(NetworkKind::Tcp),
            &conn.target,
            conn.sniffed_protocol.as_deref(),
        )
    }

    pub fn route_tcp_after_sniff(
        &self,
        conn: &InboundTcpStream,
        target: &Target,
    ) -> (&RouteAction, &str, &str) {
        self.route_indexed(
            &self.idx_no_sniff,
            &conn.inbound_tag,
            Some(NetworkKind::Tcp),
            target,
            conn.sniffed_protocol.as_deref(),
            "post-sniff",
        )
    }

    pub fn route_tcp_after_resolve(
        &self,
        conn: &InboundTcpStream,
        target: &Target,
    ) -> (&RouteAction, &str, &str) {
        self.route_indexed(
            &self.idx_no_sniff_resolve,
            &conn.inbound_tag,
            Some(NetworkKind::Tcp),
            target,
            conn.sniffed_protocol.as_deref(),
            "post-resolve",
        )
    }

    pub fn route_udp_after_resolve(
        &self,
        packet: &InboundUdpPacket,
        target: &Target,
    ) -> (&RouteAction, &str, &str) {
        self.route_indexed(
            &self.idx_no_sniff_resolve,
            &packet.inbound_tag,
            Some(NetworkKind::Udp),
            target,
            packet.sniffed_protocol.as_deref(),
            "post-resolve",
        )
    }

    /// UDP 命中 Sniff 规则后重新路由：跳过所有 Sniff 规则，继续匹配后续规则。
    /// 与 TCP 的 route_tcp_after_sniff 对称，修复 UDP Sniff 降级直接跳到 final 的问题。
    pub fn route_udp_after_sniff(&self, packet: &InboundUdpPacket) -> (&RouteAction, &str, &str) {
        self.route_indexed(
            &self.idx_no_sniff,
            &packet.inbound_tag,
            Some(NetworkKind::Udp),
            &packet.target,
            packet.sniffed_protocol.as_deref(),
            "post-sniff(udp)",
        )
    }

    pub fn route_udp(&self, packet: &InboundUdpPacket) -> (&RouteAction, &str, &str) {
        self.route(
            &packet.inbound_tag,
            Some(NetworkKind::Udp),
            &packet.target,
            packet.sniffed_protocol.as_deref(),
        )
    }

    /// 全量规则遍历（普通路由）
    fn route(
        &self,
        inbound_tag: &str,
        network: Option<NetworkKind>,
        target: &Target,
        sniffed_protocol: Option<&str>,
    ) -> (&RouteAction, &str, &str) {
        for rule in &self.rules {
            if rule.matches(inbound_tag, network, target, sniffed_protocol) {
                trace!(inbound=%inbound_tag, target=%target, action=?rule.action, "route hit");
                return (&rule.action, &rule.rule_display.0, &rule.rule_display.1);
            }
        }
        debug!(inbound=%inbound_tag, target=%target, action=?self.default, "route default");
        (&self.default, "final", "")
    }

    /// 按预计算索引遍历（跳过特定 action 规则，零分支判断）
    fn route_indexed(
        &self,
        indices: &[usize],
        inbound_tag: &str,
        network: Option<NetworkKind>,
        target: &Target,
        sniffed_protocol: Option<&str>,
        label: &str,
    ) -> (&RouteAction, &str, &str) {
        for &i in indices {
            let rule = &self.rules[i];
            if rule.matches(inbound_tag, network, target, sniffed_protocol) {
                trace!(inbound=%inbound_tag, target=%target, action=?rule.action, label, "route hit");
                return (&rule.action, &rule.rule_display.0, &rule.rule_display.1);
            }
        }
        debug!(inbound=%inbound_tag, target=%target, action=?self.default, label, "route default");
        (&self.default, "final", "")
    }
}

// ── 编译后的单条规则 ──────────────────────────────────────────────────────────

struct CompiledRule {
    inbound_tags: Vec<String>,
    network: Option<NetworkFilter>,
    protocols: Vec<String>,
    rulesets: Vec<Arc<RuleSet>>,
    addr_rs: Option<Arc<RuleSet>>,
    port_rs: Option<Arc<RuleSet>>,
    action: RouteAction,
    rule_display: (String, String),
}

impl CompiledRule {
    fn compile(
        rule: &RouteRuleConfig,
        rulesets: &HashMap<String, Arc<RuleSet>>,
    ) -> anyhow::Result<Self> {
        let mut compiled_rulesets = Vec::new();
        for tag in &rule.ruleset {
            let rs = rulesets
                .get(tag)
                .ok_or_else(|| anyhow::anyhow!("ruleset '{tag}' not found"))?;
            compiled_rulesets.push(rs.clone());
        }

        // 地址类内联规则
        let addr_rs = {
            let mut lines = Vec::new();
            for d in &rule.domain {
                lines.push(format!("domain: {d}"));
            }
            for d in &rule.domain_suffix {
                lines.push(format!("domain-suffix: {d}"));
            }
            for d in &rule.domain_keyword {
                lines.push(format!("domain-keyword: {d}"));
            }
            for c in &rule.ip_cidr {
                if c.contains(':') {
                    lines.push(format!("ip-cidr6: {c}"));
                } else {
                    lines.push(format!("ip-cidr: {c}"));
                }
            }
            if lines.is_empty() {
                None
            } else {
                Some(Arc::new(RuleSet::from_text(&lines.join("\n"))?))
            }
        };

        // 端口类内联规则
        let port_rs = {
            let mut lines = Vec::new();
            for p in &rule.port {
                if p.0 == p.1 {
                    lines.push(format!("port: {}", p.0));
                } else {
                    lines.push(format!("port: {}-{}", p.0, p.1));
                }
            }
            for p in &rule.port_range {
                lines.push(format!("port: {p}"));
            }
            if lines.is_empty() {
                None
            } else {
                Some(Arc::new(RuleSet::from_text(&lines.join("\n"))?))
            }
        };

        let action = if rule.sniff {
            let sniff_types = rule
                .sniff_type
                .iter()
                .filter_map(|s| crate::app::sniff::SniffType::parse(s))
                .collect();
            RouteAction::Sniff {
                timeout_ms: rule.sniff_timeout_ms,
                override_destination: rule.sniff_override_destination,
                sniff_types,
            }
        } else if rule.resolve {
            RouteAction::Resolve {
                server: rule.resolve_server.clone(),
            }
        } else if rule.hijack_dns {
            RouteAction::DnsOut
        } else {
            to_action(&rule.outbound)
        };

        let rule_display = if !rule.ruleset.is_empty() {
            ("rule-set".to_string(), rule.ruleset.join(","))
        } else if !rule.domain.is_empty() {
            ("DOMAIN".to_string(), rule.domain.join(","))
        } else if !rule.domain_suffix.is_empty() {
            ("DOMAIN-SUFFIX".to_string(), rule.domain_suffix.join(","))
        } else if !rule.domain_keyword.is_empty() {
            ("DOMAIN-KEYWORD".to_string(), rule.domain_keyword.join(","))
        } else if !rule.ip_cidr.is_empty() {
            ("IP-CIDR".to_string(), rule.ip_cidr.join(","))
        } else if rule.network.is_some() {
            (
                "NETWORK".to_string(),
                format!("{:?}", rule.network.unwrap()).to_ascii_lowercase(),
            )
        } else if !rule.protocol.is_empty() {
            ("PROTOCOL".to_string(), rule.protocol.join(","))
        } else if !rule.inbound.is_empty() {
            ("IN-NAME".to_string(), rule.inbound.join(","))
        } else if rule.sniff {
            ("SNIFF".to_string(), String::new())
        } else if rule.resolve {
            ("RESOLVE".to_string(), String::new())
        } else if rule.hijack_dns {
            ("HIJACK-DNS".to_string(), String::new())
        } else {
            ("MATCH".to_string(), String::new())
        };

        Ok(Self {
            inbound_tags: rule.inbound.clone(),
            network: rule.network,
            protocols: rule.protocol.iter().map(|s| s.to_lowercase()).collect(),
            rulesets: compiled_rulesets,
            addr_rs,
            port_rs,
            action,
            rule_display,
        })
    }

    #[inline]
    fn matches(
        &self,
        inbound_tag: &str,
        network: Option<NetworkKind>,
        target: &Target,
        sniffed_protocol: Option<&str>,
    ) -> bool {
        // 1. 入站 tag 过滤
        if !self.inbound_tags.is_empty() && !self.inbound_tags.iter().any(|t| t == inbound_tag) {
            return false;
        }

        // 2. 网络类型过滤
        if let Some(nf) = &self.network {
            match (nf, network) {
                (NetworkFilter::Tcp, Some(NetworkKind::Tcp)) => {}
                (NetworkFilter::Udp, Some(NetworkKind::Udp)) => {}
                _ => return false,
            }
        }

        // 3. 协议过滤
        if !self.protocols.is_empty() {
            match sniffed_protocol {
                Some(proto) => {
                    let proto_lc = proto.to_lowercase();
                    if !self.protocols.contains(&proto_lc) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        // 4. 目标条件
        let has_any = !self.rulesets.is_empty() || self.addr_rs.is_some() || self.port_rs.is_some();
        if has_any && !self.match_target(target) {
            return false;
        }

        true
    }

    fn match_target(&self, target: &Target) -> bool {
        let addr_mt = target_to_addr_match(target);
        let port_val = target.port();

        for rs in &self.rulesets {
            if rs.matches(&addr_mt) {
                return true;
            }
            if rs.matches(&MatchTarget::Port(port_val)) {
                return true;
            }
        }

        if let Some(rs) = &self.addr_rs {
            if rs.matches(&addr_mt) {
                return true;
            }
        }

        if let Some(rs) = &self.port_rs {
            if rs.matches(&MatchTarget::Port(port_val)) {
                return true;
            }
        }

        false
    }
}

// ── 辅助函数 ──────────────────────────────────────────────────────────────────

fn target_to_addr_match(target: &Target) -> MatchTarget<'_> {
    match target {
        Target::Domain(h, _) => MatchTarget::Domain(h),
        Target::Socket(addr) => MatchTarget::Ip(addr.ip()),
    }
}

fn to_action(outbound: &str) -> RouteAction {
    if outbound == "dns-out" {
        RouteAction::DnsOut
    } else {
        RouteAction::Outbound(outbound.to_string())
    }
}

fn load_ruleset_ref(
    rs_ref: &crate::config::route::RuleSetRef,
    cache_reader: Option<&CacheFileReader>,
    cache_writer: Option<&CacheFile>,
) -> anyhow::Result<RuleSet> {
    match rs_ref.r#type {
        RuleSetType::Local => {
            let path = rs_ref.path.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "rule_set '{}': `path` is required when type = \"local\"",
                    rs_ref.tag
                )
            })?;
            load_ruleset_from_path(path, &rs_ref.tag)
        }
        RuleSetType::Remote => {
            let url = rs_ref.url.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "rule_set '{}': `url` is required when type = \"remote\"",
                    rs_ref.tag
                )
            })?;
            load_ruleset_remote(
                url,
                rs_ref.path.as_deref(),
                rs_ref.download_detour.as_deref(),
                &rs_ref.tag,
                cache_reader,
                cache_writer,
            )
        }
    }
}

fn load_ruleset_from_path(path: &str, tag: &str) -> anyhow::Result<RuleSet> {
    let data = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("rule_set '{tag}': failed to read file '{path}': {e}"))?;
    let loaded = LoadedRuleSet::from_bytes(&data)?;
    Ok(RuleSet::from_loaded(loaded)?)
}

/// 加载远程规则集，按以下优先级依次尝试：
///
/// 1. **`path` 磁盘缓存**
/// 2. **cache_file 持久化缓存**
/// 3. **网络下载**
fn load_ruleset_remote(
    url: &str,
    cache_path: Option<&str>,
    download_detour: Option<&str>,
    tag: &str,
    cache_reader: Option<&CacheFileReader>,
    cache_writer: Option<&CacheFile>,
) -> anyhow::Result<RuleSet> {
    // ── 1. path 磁盘缓存 ──────────────────────────────────────────────────
    if let Some(path) = cache_path {
        if std::path::Path::new(path).exists() {
            tracing::debug!(tag, path, "rule_set: loading from disk cache (path)");
            return load_ruleset_from_path(path, tag);
        }
    }

    // ── 2. cache_file 持久化缓存 ──────────────────────────────────────────
    if cache_path.is_none() {
        if let Some(reader) = cache_reader {
            if let Some(data) = reader.load_ruleset_cache(tag) {
                tracing::debug!(tag, "rule_set: loading from cache_file (redb)");
                let loaded = LoadedRuleSet::from_bytes(&data).map_err(|e| {
                    anyhow::anyhow!(
                        "rule_set '{tag}': failed to parse cached data from cache_file: {e}"
                    )
                })?;
                return Ok(RuleSet::from_loaded(loaded)?);
            }
        }
    }

    // ── 3. 网络下载 ───────────────────────────────────────────────────────
    if let Some(detour) = download_detour {
        tracing::info!(tag, url, detour, "rule_set: downloading via detour");
    } else {
        tracing::info!(tag, url, "rule_set: downloading directly");
    }

    let data = download_bytes(url, tag)?;

    if let Some(path) = cache_path {
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                anyhow::anyhow!(
                    "rule_set '{tag}': failed to create cache dir '{}': {e}",
                    parent.display()
                )
            })?;
        }
        std::fs::write(path, &data).map_err(|e| {
            anyhow::anyhow!("rule_set '{tag}': failed to write disk cache to '{path}': {e}")
        })?;
        tracing::debug!(tag, path, "rule_set: saved to disk cache (path)");
    } else if let Some(writer) = cache_writer {
        writer.store_ruleset_entry(tag, data.clone());
        tracing::debug!(tag, "rule_set: saved to cache_file (redb)");
    } else {
        tracing::warn!(
            tag,
            url,
            "rule_set: no `path` and no cache_file configured; \
             ruleset is memory-only and will be re-downloaded on next startup"
        );
    }

    let loaded = LoadedRuleSet::from_bytes(&data)
        .map_err(|e| anyhow::anyhow!("rule_set '{tag}': failed to parse downloaded data: {e}"))?;
    Ok(RuleSet::from_loaded(loaded)?)
}

fn download_bytes(url: &str, tag: &str) -> anyhow::Result<Vec<u8>> {
    use std::io::Read;
    let resp = ureq::get(url)
        .call()
        .map_err(|e| anyhow::anyhow!("rule_set '{tag}': download failed from '{url}': {e}"))?;
    let mut buf = Vec::new();
    resp.into_reader().read_to_end(&mut buf).map_err(|e| {
        anyhow::anyhow!("rule_set '{tag}': failed to read response body from '{url}': {e}")
    })?;
    Ok(buf)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkKind {
    Tcp,
    Udp,
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::route::{PortFilter, RouteRuleConfig};

    fn make_router(rules: Vec<RouteRuleConfig>, default: &str) -> Router {
        let rules_compiled: Vec<CompiledRule> = rules
            .iter()
            .map(|r| CompiledRule::compile(r, &HashMap::new()).unwrap())
            .collect();

        let idx_no_sniff: Vec<usize> = rules_compiled
            .iter()
            .enumerate()
            .filter_map(|(i, r)| {
                if matches!(r.action, RouteAction::Sniff { .. }) {
                    None
                } else {
                    Some(i)
                }
            })
            .collect();
        let idx_no_sniff_resolve: Vec<usize> = rules_compiled
            .iter()
            .enumerate()
            .filter_map(|(i, r)| {
                if matches!(
                    r.action,
                    RouteAction::Sniff { .. } | RouteAction::Resolve { .. }
                ) {
                    None
                } else {
                    Some(i)
                }
            })
            .collect();

        Router {
            rules: rules_compiled,
            idx_no_sniff,
            idx_no_sniff_resolve,
            default: RouteAction::Outbound(default.into()),
            rulesets: HashMap::new(),
            ruleset_meta: HashMap::new(),
            route_config: crate::config::route::RouteConfig {
                rules: vec![],
                r#final: String::new(),
                rule_set: vec![],
                resolve_dns: false,
            },
        }
    }

    fn empty_rule(outbound: &str) -> RouteRuleConfig {
        RouteRuleConfig {
            inbound: vec![],
            network: None,
            protocol: vec![],
            ruleset: vec![],
            domain: vec![],
            domain_suffix: vec![],
            domain_keyword: vec![],
            ip_cidr: vec![],
            port: vec![],
            port_range: vec![],
            sniff: false,
            sniff_timeout_ms: 0,
            sniff_type: vec![],
            sniff_override_destination: false,
            resolve: false,
            resolve_server: None,
            hijack_dns: false,
            outbound: outbound.into(),
        }
    }

    #[test]
    fn default_route() {
        let r = make_router(vec![], "proxy");
        let t = Target::Domain("example.com".into(), 443);
        assert_eq!(
            r.route("in", Some(NetworkKind::Tcp), &t, None).0,
            &RouteAction::Outbound("proxy".into())
        );
    }

    #[test]
    fn inbound_tag_filter() {
        let mut rule = empty_rule("direct");
        rule.inbound = vec!["tproxy-in".into()];
        let r = make_router(vec![rule], "proxy");
        let t = Target::Domain("example.com".into(), 80);
        assert_eq!(
            r.route("tproxy-in", Some(NetworkKind::Tcp), &t, None).0,
            &RouteAction::Outbound("direct".into())
        );
        assert_eq!(
            r.route("mixed-in", Some(NetworkKind::Tcp), &t, None).0,
            &RouteAction::Outbound("proxy".into())
        );
    }

    #[test]
    fn network_filter() {
        let mut rule = empty_rule("direct");
        rule.network = Some(NetworkFilter::Udp);
        let r = make_router(vec![rule], "proxy");
        let t = Target::Socket("8.8.8.8:53".parse().unwrap());
        assert_eq!(
            r.route("in", Some(NetworkKind::Udp), &t, None).0,
            &RouteAction::Outbound("direct".into())
        );
        assert_eq!(
            r.route("in", Some(NetworkKind::Tcp), &t, None).0,
            &RouteAction::Outbound("proxy".into())
        );
    }

    #[test]
    fn inline_domain_suffix() {
        let mut rule = empty_rule("direct");
        rule.domain_suffix = vec!["cn".into()];
        let r = make_router(vec![rule], "proxy");
        assert_eq!(
            r.route(
                "in",
                Some(NetworkKind::Tcp),
                &Target::Domain("baidu.com.cn".into(), 80),
                None
            )
            .0,
            &RouteAction::Outbound("direct".into())
        );
        assert_eq!(
            r.route(
                "in",
                Some(NetworkKind::Tcp),
                &Target::Domain("google.com".into(), 443),
                None
            )
            .0,
            &RouteAction::Outbound("proxy".into())
        );
    }

    #[test]
    fn inline_domain_exact() {
        let mut rule = empty_rule("direct");
        rule.domain = vec!["example.com".into()];
        let r = make_router(vec![rule], "proxy");
        assert_eq!(
            r.route(
                "in",
                Some(NetworkKind::Tcp),
                &Target::Domain("example.com".into(), 80),
                None
            )
            .0,
            &RouteAction::Outbound("direct".into())
        );
        assert_eq!(
            r.route(
                "in",
                Some(NetworkKind::Tcp),
                &Target::Domain("sub.example.com".into(), 80),
                None
            )
            .0,
            &RouteAction::Outbound("proxy".into())
        );
    }

    #[test]
    fn inline_ip_cidr() {
        let mut rule = empty_rule("direct");
        rule.ip_cidr = vec!["192.168.0.0/16".into()];
        let r = make_router(vec![rule], "proxy");
        assert_eq!(
            r.route(
                "in",
                Some(NetworkKind::Tcp),
                &Target::Socket("192.168.1.1:80".parse().unwrap()),
                None
            )
            .0,
            &RouteAction::Outbound("direct".into())
        );
        assert_eq!(
            r.route(
                "in",
                Some(NetworkKind::Tcp),
                &Target::Socket("8.8.8.8:53".parse().unwrap()),
                None
            )
            .0,
            &RouteAction::Outbound("proxy".into())
        );
    }

    #[test]
    fn inline_port_only() {
        let mut rule = empty_rule("direct");
        rule.port = vec![PortFilter(80, 80), PortFilter(443, 443)];
        let r = make_router(vec![rule], "proxy");
        assert_eq!(
            r.route(
                "in",
                Some(NetworkKind::Tcp),
                &Target::Socket("1.1.1.1:80".parse().unwrap()),
                None
            )
            .0,
            &RouteAction::Outbound("direct".into())
        );
        assert_eq!(
            r.route(
                "in",
                Some(NetworkKind::Tcp),
                &Target::Socket("1.1.1.1:443".parse().unwrap()),
                None
            )
            .0,
            &RouteAction::Outbound("direct".into())
        );
        assert_eq!(
            r.route(
                "in",
                Some(NetworkKind::Tcp),
                &Target::Socket("1.1.1.1:22".parse().unwrap()),
                None
            )
            .0,
            &RouteAction::Outbound("proxy".into())
        );
        assert_eq!(
            r.route(
                "in",
                Some(NetworkKind::Tcp),
                &Target::Domain("example.com".into(), 443),
                None
            )
            .0,
            &RouteAction::Outbound("direct".into())
        );
        assert_eq!(
            r.route(
                "in",
                Some(NetworkKind::Tcp),
                &Target::Domain("example.com".into(), 22),
                None
            )
            .0,
            &RouteAction::Outbound("proxy".into())
        );
    }

    #[test]
    fn inline_port_range() {
        let mut rule = empty_rule("direct");
        rule.port = vec![PortFilter(8000, 9000)];
        let r = make_router(vec![rule], "proxy");
        assert_eq!(
            r.route(
                "in",
                Some(NetworkKind::Tcp),
                &Target::Socket("1.1.1.1:8500".parse().unwrap()),
                None
            )
            .0,
            &RouteAction::Outbound("direct".into())
        );
        assert_eq!(
            r.route(
                "in",
                Some(NetworkKind::Tcp),
                &Target::Socket("1.1.1.1:7999".parse().unwrap()),
                None
            )
            .0,
            &RouteAction::Outbound("proxy".into())
        );
    }

    #[test]
    fn port_and_domain_suffix_or() {
        let mut rule = empty_rule("direct");
        rule.port = vec![PortFilter(53, 53)];
        rule.domain_suffix = vec!["cn".into()];
        let r = make_router(vec![rule], "proxy");
        assert_eq!(
            r.route(
                "in",
                Some(NetworkKind::Udp),
                &Target::Socket("8.8.8.8:53".parse().unwrap()),
                None
            )
            .0,
            &RouteAction::Outbound("direct".into())
        );
        assert_eq!(
            r.route(
                "in",
                Some(NetworkKind::Tcp),
                &Target::Domain("baidu.cn".into(), 80),
                None
            )
            .0,
            &RouteAction::Outbound("direct".into())
        );
        assert_eq!(
            r.route(
                "in",
                Some(NetworkKind::Tcp),
                &Target::Domain("google.com".into(), 443),
                None
            )
            .0,
            &RouteAction::Outbound("proxy".into())
        );
    }

    #[test]
    fn dns_out_action() {
        let mut rule = empty_rule("dns-out");
        rule.inbound = vec!["dns-in".into()];
        let r = make_router(vec![rule], "proxy");
        let t = Target::Domain("example.com".into(), 53);
        assert_eq!(
            r.route("dns-in", Some(NetworkKind::Udp), &t, None).0,
            &RouteAction::DnsOut
        );
    }

    #[test]
    fn rule_order_first_wins() {
        let mut r1 = empty_rule("direct");
        r1.domain_suffix = vec!["google.com".into()];
        let mut r2 = empty_rule("block");
        r2.domain_suffix = vec!["google.com".into()];
        let r = make_router(vec![r1, r2], "proxy");
        let t = Target::Domain("www.google.com".into(), 443);
        assert_eq!(
            r.route("in", Some(NetworkKind::Tcp), &t, None).0,
            &RouteAction::Outbound("direct".into())
        );
    }

    #[test]
    fn no_condition_rule_matches_all() {
        let rule = empty_rule("direct");
        let r = make_router(vec![rule], "proxy");
        let t1 = Target::Domain("anything.example".into(), 1234);
        let t2 = Target::Socket("5.6.7.8:22".parse().unwrap());
        assert_eq!(
            r.route("any-in", Some(NetworkKind::Tcp), &t1, None).0,
            &RouteAction::Outbound("direct".into())
        );
        assert_eq!(
            r.route("any-in", Some(NetworkKind::Udp), &t2, None).0,
            &RouteAction::Outbound("direct".into())
        );
    }

    // ── 预计算索引测试 ────────────────────────────────────────────────────

    #[test]
    fn precomputed_idx_skips_sniff() {
        let sniff_rule = RouteRuleConfig {
            sniff: true,
            sniff_timeout_ms: 300,
            sniff_override_destination: true,
            inbound: vec!["mixed-in".into()],
            ..Default::default()
        };
        let mut direct_rule = empty_rule("direct");
        direct_rule.domain_suffix = vec!["cn".into()];

        let r = make_router(vec![sniff_rule, direct_rule], "proxy");
        // 全部规则：[Sniff, direct]
        assert_eq!(r.rules.len(), 2);
        // idx_no_sniff 应只含索引 1
        assert_eq!(r.idx_no_sniff, vec![1]);
        // route_indexed with idx_no_sniff：对 .cn 应命中 direct
        let t = Target::Domain("baidu.cn".into(), 80);
        let (action, _, _) = r.route_indexed(
            &r.idx_no_sniff,
            "mixed-in",
            Some(NetworkKind::Tcp),
            &t,
            None,
            "test",
        );
        assert_eq!(action, &RouteAction::Outbound("direct".into()));
    }
}

// ── hijack_dns + protocol 行为测试 ────────────────────────────────────────────

#[cfg(test)]
mod hijack_dns_tests {
    use super::*;
    use crate::config::route::{RouteConfig, RouteRuleConfig};

    fn make_config(rules: Vec<RouteRuleConfig>) -> RouteConfig {
        RouteConfig {
            rules,
            r#final: "proxy".to_string(),
            rule_set: vec![],
            resolve_dns: false,
        }
    }

    fn dns_protocol_rule() -> RouteRuleConfig {
        RouteRuleConfig {
            hijack_dns: true,
            protocol: vec!["dns".to_string()],
            ..Default::default()
        }
    }

    fn dns_inbound_rule() -> RouteRuleConfig {
        RouteRuleConfig {
            hijack_dns: true,
            inbound: vec!["dns-in".to_string()],
            ..Default::default()
        }
    }

    #[test]
    fn hijack_dns_with_protocol_dns_action() {
        let config = make_config(vec![dns_protocol_rule()]);
        let router = Router::from_config(&config, None, None).unwrap();
        let t = Target::Socket("8.8.8.8:53".parse().unwrap());
        assert_eq!(
            router
                .route("any-in", Some(NetworkKind::Udp), &t, Some("dns"))
                .0,
            &RouteAction::DnsOut
        );
    }

    #[test]
    fn hijack_dns_with_protocol_no_sniff_miss() {
        let config = make_config(vec![dns_protocol_rule()]);
        let router = Router::from_config(&config, None, None).unwrap();
        let t = Target::Socket("8.8.8.8:53".parse().unwrap());
        assert_eq!(
            router.route("any-in", Some(NetworkKind::Udp), &t, None).0,
            &RouteAction::Outbound("proxy".to_string())
        );
    }

    #[test]
    fn hijack_dns_with_inbound_action() {
        let config = make_config(vec![dns_inbound_rule()]);
        let router = Router::from_config(&config, None, None).unwrap();
        let t = Target::Domain("example.com".into(), 53);
        assert_eq!(
            router.route("dns-in", Some(NetworkKind::Udp), &t, None).0,
            &RouteAction::DnsOut
        );
    }

    #[test]
    fn hijack_dns_with_inbound_wrong_inbound_miss() {
        let config = make_config(vec![dns_inbound_rule()]);
        let router = Router::from_config(&config, None, None).unwrap();
        let t = Target::Domain("example.com".into(), 53);
        assert_eq!(
            router
                .route("tproxy-in", Some(NetworkKind::Udp), &t, None)
                .0,
            &RouteAction::Outbound("proxy".to_string())
        );
    }

    #[test]
    fn bare_hijack_dns_is_error() {
        let rule = RouteRuleConfig {
            hijack_dns: true,
            ..Default::default()
        };
        let config = make_config(vec![rule]);
        let result = Router::from_config(&config, None, None);
        assert!(result.is_err(), "bare hijack_dns should be an error");
        let msg = result.err().unwrap().to_string();
        assert!(
            msg.contains("hijack_dns"),
            "error message should mention hijack_dns"
        );
    }

    #[test]
    fn protocol_case_insensitive() {
        let rule = RouteRuleConfig {
            hijack_dns: true,
            protocol: vec!["DNS".to_string()],
            ..Default::default()
        };
        let config = make_config(vec![rule]);
        let router = Router::from_config(&config, None, None).unwrap();
        let t = Target::Socket("8.8.8.8:53".parse().unwrap());
        assert_eq!(
            router
                .route("any-in", Some(NetworkKind::Udp), &t, Some("dns"))
                .0,
            &RouteAction::DnsOut
        );
    }
}
