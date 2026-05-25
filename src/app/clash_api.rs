//! Clash API 兼容控制器。
//!
//! 支持常用 Clash Dashboard 需要的接口：
//! - GET /version
//! - GET/PATCH /configs
//! - GET /traffic  （HTTP 轮询 & WebSocket 实时推送）
//! - GET /logs     （HTTP 流式 & WebSocket 实时推送）
//! - GET /rules
//! - GET/PUT /proxies, GET /proxies/:name, GET /proxies/:name/delay
//! - GET/DELETE /connections
//! - GET /providers/proxies, /providers/rules
//! - 静态 external_ui 文件服务
//! - Bearer 密钥鉴权（secret 非空时启用）

use std::{
    collections::HashMap,
    path::{Component, Path, PathBuf},
    sync::{atomic::Ordering, Arc, RwLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

// 64-bit atomics are unavailable on 32-bit targets (e.g. MIPS).
// Use 32-bit variants there; traffic counters will wrap but that is
// acceptable on embedded/router targets.
#[cfg(not(target_pointer_width = "64"))]
use std::sync::atomic::{AtomicI32 as AtomicI64, AtomicU32 as AtomicU64};
#[cfg(target_pointer_width = "64")]
use std::sync::atomic::{AtomicI64, AtomicU64};

use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::broadcast,
};
use tracing::{debug, info};

use crate::{
    app::{outbound_mgr::OutboundManager, ruleset_registry::RuleSetRegistry, stats::Stats},
    config::{
        experimental::ClashApiConfig, inbound::InboundConfig, log::LogLevel, route::RouteConfig,
    },
};

// ── 全局日志转发器（供 tracing subscriber 写入 Clash API 日志流）───────────────

static GLOBAL_LOG_TX: std::sync::OnceLock<broadcast::Sender<LogEntry>> = std::sync::OnceLock::new();

/// 由 tracing subscriber 调用：向 Clash API 推送日志条目。
pub fn broadcast_log(level: &str, message: String) {
    if let Some(tx) = GLOBAL_LOG_TX.get() {
        let _ = tx.send(LogEntry {
            level: level.to_string(),
            message,
        });
    }
}

// ── URLTest 延迟历史 ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DelayRecord {
    pub time_ms: u64,
    pub delay: u64,
}

#[derive(Default)]
pub struct DelayHistory {
    inner: RwLock<HashMap<String, DelayRecord>>,
}

impl DelayHistory {
    pub fn store(&self, tag: &str, delay: u64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.inner.write().unwrap().insert(
            tag.to_string(),
            DelayRecord {
                time_ms: now,
                delay,
            },
        );
    }

    pub fn load(&self, tag: &str) -> Option<DelayRecord> {
        self.inner.read().unwrap().get(tag).cloned()
    }

    pub fn delete(&self, tag: &str) {
        self.inner.write().unwrap().remove(tag);
    }
}

// ── 连接追踪 ──────────────────────────────────────────────────────────────────

/// 命中规则信息，打包传递以规避 clippy::too_many_arguments
#[derive(Clone, Default)]
pub struct RuleInfo {
    pub rule_type: String,
    pub rule_payload: String,
}

/// 连接基本信息，打包传递以规避 clippy::too_many_arguments
pub struct ConnInfo<'a> {
    pub network: &'a str,
    pub host: &'a str,
    pub source: std::net::SocketAddr,
    pub dest_port: u16,
    pub inbound: &'a str,
    pub outbound: &'a str,
}

#[derive(Clone)]
pub struct ConnMeta {
    pub id: u64,
    pub network: String,
    pub host: String,
    pub source_ip: String,
    pub source_port: u16,
    pub dest_port: u16,
    pub inbound: String,
    pub outbound: String,
    pub rule: String,
    pub rule_payload: String,
    pub started_ms: u64,
    pub upload: Arc<AtomicI64>,
    pub download: Arc<AtomicI64>,
}

pub struct ConnGuard {
    id: u64,
    tracker: Arc<ConnectionTracker>,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.tracker.remove(self.id);
    }
}

impl ConnGuard {
    pub fn add_bytes(&self, up: i64, down: i64) {
        if let Some(meta) = self.tracker.get(self.id) {
            meta.upload.fetch_add(up as _, Ordering::Relaxed);
            meta.download.fetch_add(down as _, Ordering::Relaxed);
        }
    }

    /// 返回实时上传/下载计数器的 Arc 引用，供 relay_tracked 实时更新。
    pub fn live_counters(&self) -> Option<(Arc<AtomicI64>, Arc<AtomicI64>)> {
        self.tracker
            .get(self.id)
            .map(|meta| (meta.upload.clone(), meta.download.clone()))
    }
}

pub struct ConnectionTracker {
    next_id: AtomicU64,
    conns: RwLock<HashMap<u64, ConnMeta>>,
}

impl ConnectionTracker {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            next_id: AtomicU64::new(1),
            conns: RwLock::new(HashMap::new()),
        })
    }

    pub fn register(self: &Arc<Self>, info: ConnInfo<'_>, rule_info: &RuleInfo) -> ConnGuard {
        #[allow(clippy::unnecessary_cast)]
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) as u64;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let meta = ConnMeta {
            id,
            network: info.network.to_string(),
            host: info.host.to_string(),
            source_ip: info.source.ip().to_string(),
            source_port: info.source.port(),
            dest_port: info.dest_port,
            inbound: info.inbound.to_string(),
            outbound: info.outbound.to_string(),
            rule: rule_info.rule_type.clone(),
            rule_payload: rule_info.rule_payload.clone(),
            started_ms: now,
            upload: Arc::new(AtomicI64::new(0)),
            download: Arc::new(AtomicI64::new(0)),
        };
        self.conns.write().unwrap().insert(id, meta);
        ConnGuard {
            id,
            tracker: self.clone(),
        }
    }

    fn remove(&self, id: u64) {
        self.conns.write().unwrap().remove(&id);
    }

    fn get(&self, id: u64) -> Option<ConnMeta> {
        self.conns.read().unwrap().get(&id).cloned()
    }

    fn snapshot(&self) -> Vec<ConnMeta> {
        self.conns.read().unwrap().values().cloned().collect()
    }

    /// 按 id 删除单条连接（供 DELETE /connections/:id 使用）
    pub fn len(&self) -> usize {
        self.conns.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.conns.read().unwrap().is_empty()
    }

    pub fn remove_by_id(&self, id: u64) {
        self.conns.write().unwrap().remove(&id);
    }
}

// ── 日志广播 ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct LogEntry {
    pub level: String,
    pub message: String,
}

// ── ClashApi 主体 ─────────────────────────────────────────────────────────────

pub struct ClashApi {
    config: ClashApiConfig,
    outbound_mgr: Arc<OutboundManager>,
    stats: Arc<Stats>,
    route_config: Arc<RouteConfig>,
    mode: Arc<RwLock<String>>,
    mode_list: Vec<String>,
    delay_history: Arc<DelayHistory>,
    conn_tracker: Arc<ConnectionTracker>,
    log_tx: broadcast::Sender<LogEntry>,
    /// 实际 inbound 列表，用于在 /configs 返回真实端口和 allow-lan
    inbound_configs: Vec<InboundConfig>,
    /// 当前日志级别，用于在 /configs 返回
    log_level: LogLevel,
    /// 规则集注册表，用于查询元数据和触发 remote 规则集刷新
    rs_registry: Arc<RuleSetRegistry>,
}

impl ClashApi {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: ClashApiConfig,
        outbound_mgr: Arc<OutboundManager>,
        stats: Arc<Stats>,
        route_config: Arc<RouteConfig>,
        inbound_configs: Vec<InboundConfig>,
        log_level: LogLevel,
        conn_tracker: Arc<ConnectionTracker>,
        rs_registry: Arc<RuleSetRegistry>,
    ) -> Self {
        let mode = Arc::new(RwLock::new(config.default_mode.clone()));

        let mut mode_list = config.mode_list.clone();
        if mode_list.is_empty() {
            mode_list = vec![
                "rule".to_string(),
                "global".to_string(),
                "direct".to_string(),
            ];
        }
        if !mode_list.contains(&config.default_mode) {
            mode_list.insert(0, config.default_mode.clone());
        }

        let (log_tx, _) = broadcast::channel(256);

        // 注册全局转发器（首次调用生效；多次调用时已有的保持不变）
        let _ = GLOBAL_LOG_TX.set(log_tx.clone());

        Self {
            config,
            outbound_mgr,
            stats,
            route_config,
            mode,
            mode_list,
            delay_history: Arc::new(DelayHistory::default()),
            conn_tracker,
            log_tx,
            inbound_configs,
            log_level,
            rs_registry,
        }
    }

    pub fn conn_tracker(&self) -> Arc<ConnectionTracker> {
        self.conn_tracker.clone()
    }

    pub fn log_tx(&self) -> broadcast::Sender<LogEntry> {
        self.log_tx.clone()
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let listener = TcpListener::bind(&self.config.external_controller).await?;
        info!(listen=%self.config.external_controller, "clash api listening");

        let shared = Arc::new(self);
        loop {
            let (stream, peer) = listener.accept().await?;
            let api = shared.clone();
            tokio::spawn(async move {
                if let Err(e) = api.handle_connection(stream).await {
                    debug!(peer=%peer, err=%e, "clash api connection error");
                }
            });
        }
    }

    async fn handle_connection(self: Arc<Self>, mut stream: TcpStream) -> anyhow::Result<()> {
        let request = read_request(&mut stream).await?;
        self.handle_request(request, stream).await;
        Ok(())
    }

    async fn handle_request(self: Arc<Self>, request: HttpRequest, mut stream: TcpStream) {
        // CORS 预检
        if request.method == "OPTIONS" {
            let resp = HttpResponse::new(204, "No Content")
                .header(
                    "Access-Control-Allow-Methods",
                    "GET, POST, PUT, PATCH, DELETE, OPTIONS",
                )
                .header(
                    "Access-Control-Allow-Headers",
                    "Content-Type, Authorization",
                )
                .body(Vec::new(), "text/plain; charset=utf-8");
            let _ = stream.write_all(&resp.to_bytes()).await;
            return;
        }

        let full_path = &request.path;
        let path = full_path.split('?').next().unwrap_or(full_path);
        let query = full_path
            .find('?')
            .map(|i| &full_path[i + 1..])
            .unwrap_or("");

        // Bearer 鉴权
        if !self.config.secret.is_empty() {
            let token_ok = if request.is_websocket() {
                query.split('&').any(|kv| {
                    kv.strip_prefix("token=")
                        .map(|t| t == self.config.secret)
                        .unwrap_or(false)
                })
            } else {
                request
                    .header("authorization")
                    .and_then(|v| v.strip_prefix("Bearer "))
                    .map(|t| t == self.config.secret)
                    .unwrap_or(false)
            };

            if !token_ok {
                let resp = HttpResponse::new(401, "Unauthorized").body(
                    serde_json::to_vec(&json!({"message": "Unauthorized"})).unwrap(),
                    "application/json; charset=utf-8",
                );
                let _ = stream.write_all(&resp.to_bytes()).await;
                return;
            }
        }

        // WebSocket 路由
        if request.is_websocket() {
            match path {
                "/traffic" => {
                    self.ws_traffic(request, stream).await;
                    return;
                }
                "/logs" => {
                    self.ws_logs(request, stream).await;
                    return;
                }
                "/connections" => {
                    self.ws_connections(request, stream).await;
                    return;
                }
                "/memory" => {
                    self.ws_memory(request, stream).await;
                    return;
                }
                _ => {}
            }
        }

        // 普通 HTTP 路由
        let response = match (request.method.as_str(), path) {
            ("GET", "/") => self.redirect_to_ui(),
            ("GET", "/version") => json_response(json!({
                "premium": false,
                "version": concat!("reflex ", env!("CARGO_PKG_VERSION")),
                "meta": true,
            })),
            ("GET", "/configs") => self.get_configs(),
            ("PATCH", "/configs") => self.patch_configs(&request.body),
            ("PUT", "/configs") => empty_response(204, "No Content"),
            ("GET", "/traffic") => self.get_traffic_once(),
            ("GET", "/logs") => {
                self.get_logs_stream(&mut stream).await;
                return;
            }
            ("GET", "/rules") => self.get_rules(),
            ("GET", "/connections") => self.get_connections(),
            ("DELETE", "/connections") => self.delete_connections(),
            ("GET", "/proxies") => self.get_proxies(),
            ("GET", "/providers/proxies") => json_response(json!({"providers": {}})),
            ("GET", "/providers/rules") => self.get_rule_providers().await,
            ("GET", "/script") => json_response(json!({"code": ""})),
            ("GET", "/cache") => empty_response(204, "No Content"),
            ("GET", "/profile") => json_response(json!({"payload": ""})),
            ("GET", "/dns/query") => json_response(json!({"Answer": []})),
            ("GET", "/memory") => self.get_memory_once(),
            ("GET", "/group") => self.get_groups(),
            _ if request.method == "GET" && path.starts_with("/group/") => {
                let rest = path.trim_start_matches("/group/");
                if let Some(name_enc) = rest.strip_suffix("/delay") {
                    self.get_group_delay(name_enc, query).await
                } else {
                    self.get_group(rest)
                }
            }
            _ if request.method == "PUT" && path.starts_with("/group/") => {
                self.put_proxy(path.trim_start_matches("/group/"), &request.body)
            }
            _ if request.method == "DELETE" && path.starts_with("/connections/") => {
                self.delete_connection(path.trim_start_matches("/connections/"))
            }
            _ if request.method == "GET" && path.starts_with("/proxies/") => {
                let rest = path.trim_start_matches("/proxies/");
                if let Some(name_enc) = rest.strip_suffix("/delay") {
                    self.get_proxy_delay(name_enc, query).await
                } else {
                    self.get_proxy(rest)
                }
            }
            _ if request.method == "PUT" && path.starts_with("/proxies/") => {
                self.put_proxy(path.trim_start_matches("/proxies/"), &request.body)
            }
            _ if request.method == "GET" && path.starts_with("/providers/proxies/") => {
                empty_response(204, "No Content")
            }
            _ if request.method == "PUT" && path.starts_with("/providers/rules/") => {
                let name_enc = path.trim_start_matches("/providers/rules/");
                let name = percent_decode(name_enc);
                self.update_rule_provider(&name).await
            }
            _ if request.method == "GET" => self.serve_ui(path).await,
            _ => text_response(404, "Not Found", "not found"),
        };

        let _ = stream.write_all(&response.to_bytes()).await;
    }

    // ── /configs ──────────────────────────────────────────────────────────────

    fn get_configs(&self) -> HttpResponse {
        use crate::config::inbound::InboundConfig as IB;
        let mode = self.mode.read().unwrap().clone();

        // 从 inbound 配置中提取各协议端口
        let mut mixed_port: u16 = 0;
        let socks_port: u16 = 0;
        let mut redir_port: u16 = 0;
        let mut tproxy_port: u16 = 0;
        let http_port: u16 = 0;
        let mut allow_lan = false;

        for ib in &self.inbound_configs {
            let (listen, port) = match ib {
                IB::Mixed(c) => {
                    if mixed_port == 0 {
                        mixed_port = c.listen_port;
                    }
                    (&c.listen, c.listen_port)
                }
                IB::Redir(c) => {
                    if redir_port == 0 {
                        redir_port = c.listen_port;
                    }
                    (&c.listen, c.listen_port)
                }
                IB::TProxy(c) => {
                    if tproxy_port == 0 {
                        tproxy_port = c.listen_port;
                    }
                    (&c.listen, c.listen_port)
                }
                IB::Dns(_) | IB::Tun(_) => continue,
            };
            let _ = port;
            // 绑定 0.0.0.0 或 :: 意味着允许局域网
            if listen == "0.0.0.0" || listen == "::" || listen == "0" {
                allow_lan = true;
            }
        }

        let log_level_str = match self.log_level {
            LogLevel::Trace | LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warning",
            LogLevel::Error => "error",
            LogLevel::Off => "silent",
        };

        json_response(json!({
            "port": http_port,
            "socks-port": socks_port,
            "redir-port": redir_port,
            "tproxy-port": tproxy_port,
            "mixed-port": mixed_port,
            "allow-lan": allow_lan,
            "bind-address": "*",
            "mode": mode,
            "mode-list": self.mode_list,
            "log-level": log_level_str,
            "ipv6": true,
        }))
    }

    fn patch_configs(&self, body: &[u8]) -> HttpResponse {
        let value: serde_json::Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(e) => return text_response(400, "Bad Request", &format!("invalid json: {e}")),
        };
        if let Some(mode) = value.get("mode").and_then(|v| v.as_str()) {
            let mode_str = mode.to_string();
            let valid = self
                .mode_list
                .iter()
                .any(|m| m.eq_ignore_ascii_case(&mode_str));
            if valid {
                *self.mode.write().unwrap() = mode_str;
            }
        }
        empty_response(204, "No Content")
    }

    // ── /traffic ──────────────────────────────────────────────────────────────

    fn get_traffic_once(&self) -> HttpResponse {
        let snap = self.stats.global_snapshot();
        json_response(json!({
            "up": snap.bytes_up,
            "down": snap.bytes_down,
            "uploadTotal": snap.bytes_up,
            "downloadTotal": snap.bytes_down,
        }))
    }

    async fn ws_traffic(self: Arc<Self>, request: HttpRequest, mut stream: TcpStream) {
        let key = match request.header("sec-websocket-key") {
            Some(k) => k.to_string(),
            None => return,
        };
        let handshake = ws_upgrade_response(&key);
        if stream.write_all(handshake.as_bytes()).await.is_err() {
            return;
        }

        let mut prev_up = self.stats.global_snapshot().bytes_up;
        let mut prev_down = self.stats.global_snapshot().bytes_down;

        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let snap = self.stats.global_snapshot();
            let up_delta = snap.bytes_up.saturating_sub(prev_up);
            let down_delta = snap.bytes_down.saturating_sub(prev_down);
            prev_up = snap.bytes_up;
            prev_down = snap.bytes_down;
            let msg = serde_json::to_vec(&json!({"up": up_delta, "down": down_delta}))
                .unwrap_or_default();
            if ws_send_text(&mut stream, &msg).await.is_err() {
                break;
            }
        }
    }

    // ── /logs ─────────────────────────────────────────────────────────────────

    async fn get_logs_stream(self: Arc<Self>, stream: &mut TcpStream) {
        let header = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n";
        if stream.write_all(header).await.is_err() {
            return;
        }

        let mut rx = self.log_tx.subscribe();
        loop {
            match tokio::time::timeout(Duration::from_secs(30), rx.recv()).await {
                Ok(Ok(entry)) => {
                    let line = serde_json::to_vec(&json!({
                        "type": entry.level,
                        "payload": entry.message,
                    }))
                    .unwrap_or_default();
                    let chunk_hdr = format!("{:x}\r\n", line.len() + 1);
                    if stream.write_all(chunk_hdr.as_bytes()).await.is_err() {
                        break;
                    }
                    if stream.write_all(&line).await.is_err() {
                        break;
                    }
                    if stream.write_all(b"\n\r\n").await.is_err() {
                        break;
                    }
                }
                Ok(Err(_)) => break,
                Err(_) => {
                    // keepalive: send a tiny comment chunk so connection stays open
                    // "1\r\n \r\n" is a valid 1-byte chunk (a space character)
                    if stream.write_all(b"1\r\n \r\n").await.is_err() {
                        break;
                    }
                }
            }
        }
    }

    async fn ws_logs(self: Arc<Self>, request: HttpRequest, mut stream: TcpStream) {
        let key = match request.header("sec-websocket-key") {
            Some(k) => k.to_string(),
            None => return,
        };
        let handshake = ws_upgrade_response(&key);
        if stream.write_all(handshake.as_bytes()).await.is_err() {
            return;
        }
        // 解析 query 里的 level 参数，决定最低推送级别
        // Clash API 约定：error > warning > info > debug，silent 表示全部屏蔽
        let full_path = &request.path;
        let query = full_path
            .find('?')
            .map(|i| &full_path[i + 1..])
            .unwrap_or("");
        let min_level = query
            .split('&')
            .find_map(|kv| kv.strip_prefix("level="))
            .unwrap_or("info");

        // 返回 level 数值，越大越高；silent = usize::MAX 全屏蔽
        fn level_rank(l: &str) -> usize {
            match l {
                "debug" => 0,
                "info" => 1,
                "warning" | "warn" => 2,
                "error" => 3,
                _ => usize::MAX, // silent 或未知
            }
        }
        let min_rank = level_rank(min_level);

        let mut rx = self.log_tx.subscribe();
        while let Ok(entry) = rx.recv().await {
            if level_rank(&entry.level) < min_rank {
                continue;
            }
            let msg = serde_json::to_vec(&json!({
                "type": entry.level,
                "payload": entry.message,
            }))
            .unwrap_or_default();
            if ws_send_text(&mut stream, &msg).await.is_err() {
                break;
            }
        }
    }

    // ── /connections ──────────────────────────────────────────────────────────

    fn get_connections(&self) -> HttpResponse {
        let snap = self.stats.global_snapshot();
        let conns = self.conn_tracker.snapshot();
        let conn_json: Vec<serde_json::Value> = conns.iter().map(conn_to_json).collect();
        json_response(json!({
            "downloadTotal": snap.bytes_down,
            "uploadTotal": snap.bytes_up,
            "connections": conn_json,
        }))
    }

    fn delete_connections(&self) -> HttpResponse {
        empty_response(204, "No Content")
    }

    async fn ws_connections(self: Arc<Self>, request: HttpRequest, mut stream: TcpStream) {
        let key = match request.header("sec-websocket-key") {
            Some(k) => k.to_string(),
            None => return,
        };
        let handshake = ws_upgrade_response(&key);
        if stream.write_all(handshake.as_bytes()).await.is_err() {
            return;
        }
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let snap = self.stats.global_snapshot();
            let conns = self.conn_tracker.snapshot();
            let conn_json: Vec<serde_json::Value> = conns.iter().map(conn_to_json).collect();
            let msg = serde_json::to_vec(&json!({
                "downloadTotal": snap.bytes_down,
                "uploadTotal": snap.bytes_up,
                "connections": conn_json,
            }))
            .unwrap_or_default();
            if ws_send_text(&mut stream, &msg).await.is_err() {
                break;
            }
        }
    }

    // ── /memory ──────────────────────────────────────────────────────────────

    fn get_memory_once(&self) -> HttpResponse {
        let inuse = read_process_rss_kb().unwrap_or(0) * 1024;
        json_response(json!({"inuse": inuse, "oslimit": 0}))
    }

    async fn ws_memory(self: Arc<Self>, request: HttpRequest, mut stream: TcpStream) {
        let key = match request.header("sec-websocket-key") {
            Some(k) => k.to_string(),
            None => return,
        };
        let handshake = ws_upgrade_response(&key);
        if stream.write_all(handshake.as_bytes()).await.is_err() {
            return;
        }
        let mut first = true;
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let inuse = if first {
                first = false;
                0
            } else {
                read_process_rss_kb().unwrap_or(0) * 1024
            };
            let msg =
                serde_json::to_vec(&json!({"inuse": inuse, "oslimit": 0})).unwrap_or_default();
            if ws_send_text(&mut stream, &msg).await.is_err() {
                break;
            }
        }
    }

    // ── /connections/:id ──────────────────────────────────────────────────────

    fn delete_connection(&self, id_str: &str) -> HttpResponse {
        match id_str.parse::<u64>() {
            Ok(id) => {
                self.conn_tracker.remove_by_id(id);
                empty_response(204, "No Content")
            }
            Err(_) => text_response(400, "Bad Request", "invalid connection id"),
        }
    }

    // ── /group (Clash.Meta 扩展，Dashboard 分组视图) ───────────────────────────

    fn get_groups(&self) -> HttpResponse {
        let statuses = self.outbound_mgr.statuses();
        let groups: Vec<serde_json::Value> = statuses
            .iter()
            .filter(|s| {
                s.type_name == "Selector" || s.type_name == "URLTest" || s.type_name == "UrlTest"
            })
            .map(|s| self.build_group_entry(s))
            .collect();
        json_response(json!({"proxies": groups}))
    }

    fn get_group(&self, encoded_name: &str) -> HttpResponse {
        let name = percent_decode(encoded_name);
        let statuses = self.outbound_mgr.statuses();
        if let Some(status) = statuses.iter().find(|s| s.name == name) {
            if status.type_name == "Selector"
                || status.type_name == "URLTest"
                || status.type_name == "UrlTest"
            {
                return json_response(self.build_group_entry(status));
            }
        }
        text_response(404, "Not Found", "group not found")
    }

    async fn get_group_delay(&self, encoded_name: &str, query: &str) -> HttpResponse {
        // 对组内所有节点并发测速，返回 {tag: delay_ms} map
        let name = percent_decode(encoded_name);
        let statuses = self.outbound_mgr.statuses();
        let group = match statuses.iter().find(|s| s.name == name) {
            Some(s) => s.clone(),
            None => return text_response(404, "Not Found", "group not found"),
        };
        if group.all.is_empty() {
            return json_response(json!({}));
        }

        let mut probe_url = "https://www.gstatic.com/generate_204".to_string();
        let mut timeout_ms: u64 = 5000;
        for kv in query.split('&') {
            if let Some(v) = kv.strip_prefix("url=") {
                probe_url = percent_decode(v);
            } else if let Some(v) = kv.strip_prefix("timeout=") {
                if let Ok(n) = v.parse::<u64>() {
                    timeout_ms = n;
                }
            }
        }

        let (host, port) = {
            let (default_port, rest) = if let Some(r) = probe_url.strip_prefix("https://") {
                (443u16, r)
            } else if let Some(r) = probe_url.strip_prefix("http://") {
                (80u16, r)
            } else {
                return text_response(400, "Bad Request", "invalid probe url scheme");
            };
            let authority = rest.split('/').next().unwrap_or(rest);
            if let Some((h, p)) = authority.rsplit_once(':') {
                match p.parse::<u16>() {
                    Ok(port) => (h.to_string(), port),
                    Err(_) => return text_response(400, "Bad Request", "invalid port"),
                }
            } else {
                (authority.to_string(), default_port)
            }
        };

        let timeout = Duration::from_millis(timeout_ms);
        let delay_history = self.delay_history.clone();
        let mut futs = Vec::new();
        for tag in &group.all {
            let tag = tag.clone();
            let host = host.clone();
            let ob = self.outbound_mgr.get(&tag);
            let dh = delay_history.clone();
            futs.push(async move {
                let ob = match ob {
                    Some(o) => o,
                    None => return (tag, None),
                };
                let started = Instant::now();
                match tokio::time::timeout(timeout, ob.connect_tcp(&host, port)).await {
                    Ok(Ok(_)) => {
                        let delay = started.elapsed().as_millis() as u64;
                        dh.store(&tag, delay);
                        (tag, Some(delay))
                    }
                    _ => {
                        dh.delete(&tag);
                        (tag, None)
                    }
                }
            });
        }
        let results = futures_util::future::join_all(futs).await;
        let mut map = serde_json::Map::new();
        for (tag, delay) in results {
            map.insert(tag, delay.map(|d| json!(d)).unwrap_or(json!(null)));
        }
        json_response(serde_json::Value::Object(map))
    }

    fn build_group_entry(&self, status: &crate::outbound::OutboundStatus) -> serde_json::Value {
        let history = self
            .delay_history
            .load(&status.name)
            .map(|r| {
                vec![json!({"time": ms_to_iso(r.time_ms), "delay": r.delay, "meanDelay": r.delay})]
            })
            .unwrap_or_default();
        let member_proxies: Vec<serde_json::Value> = status.all.iter().map(|tag| {
            let h = self.delay_history.load(tag)
                .map(|r| vec![json!({"time": ms_to_iso(r.time_ms), "delay": r.delay, "meanDelay": r.delay})])
                .unwrap_or_default();
            let s = self.outbound_mgr.status(tag);
            let type_name = s.as_ref().map(|s| s.type_name.as_str()).unwrap_or("Unknown");
            json!({
                "name": tag,
                "type": type_name,
                "udp": true,
                "history": h,
            })
        }).collect();
        let mut entry = json!({
            "type": status.type_name,
            "name": status.name,
            "udp": true,
            "history": history,
            "all": member_proxies,
        });
        if let Some(now) = &status.now {
            entry["now"] = json!(now);
        }
        entry
    }

    // ── /providers/rules ─────────────────────────────────────────────────────

    async fn get_rule_providers(&self) -> HttpResponse {
        use crate::config::route::RuleSetType;
        let meta_map = self.rs_registry.snapshot().await;
        let providers: serde_json::Map<String, serde_json::Value> = self
            .route_config
            .rule_set
            .iter()
            .map(|rs| {
                let vehicle_type = match rs.r#type {
                    RuleSetType::Local => "File",
                    RuleSetType::Remote => "HTTP",
                };
                let name = rs.tag.clone();
                let (rule_count, updated_at) = meta_map
                    .get(&name)
                    .map(|m| (m.rule_count, ms_to_iso(m.updated_at_ms)))
                    .unwrap_or((0, String::new()));
                let val = json!({
                    "behavior": "domain",
                    "format": "binary",
                    "name": name,
                    "ruleCount": rule_count,
                    "type": "Rule",
                    "updatedAt": updated_at,
                    "vehicleType": vehicle_type,
                });
                (name, val)
            })
            .collect();
        json_response(json!({ "providers": providers }))
    }

    /// PUT /providers/rules/:name — 触发远程规则集重新下载
    async fn update_rule_provider(&self, name: &str) -> HttpResponse {
        use crate::config::route::RuleSetType;
        // 检查是否存在且为 remote
        let is_remote = self
            .route_config
            .rule_set
            .iter()
            .find(|r| r.tag == name)
            .map(|r| r.r#type == RuleSetType::Remote)
            .unwrap_or(false);

        if !is_remote {
            return text_response(
                400,
                "Bad Request",
                "rule_set is not remote or does not exist",
            );
        }

        match self.rs_registry.reload_remote(name).await {
            Ok(()) => empty_response(204, "No Content"),
            Err(e) => text_response(500, "Internal Server Error", &e.to_string()),
        }
    }

    // ── /rules ────────────────────────────────────────────────────────────────

    fn get_rules(&self) -> HttpResponse {
        let mut rules: Vec<serde_json::Value> = self
            .route_config
            .rules
            .iter()
            .map(|r| {
                let (rule_type, payload) = if !r.ruleset.is_empty() {
                    ("rule-set", r.ruleset.join(","))
                } else if !r.domain.is_empty() {
                    ("DOMAIN", r.domain.join(","))
                } else if !r.domain_suffix.is_empty() {
                    ("DOMAIN-SUFFIX", r.domain_suffix.join(","))
                } else if !r.domain_keyword.is_empty() {
                    ("DOMAIN-KEYWORD", r.domain_keyword.join(","))
                } else if !r.ip_cidr.is_empty() {
                    ("IP-CIDR", r.ip_cidr.join(","))
                } else if r.network.is_some() {
                    (
                        "NETWORK",
                        format!("{:?}", r.network.unwrap()).to_ascii_lowercase(),
                    )
                } else if !r.protocol.is_empty() {
                    ("PROTOCOL", r.protocol.join(","))
                } else if !r.inbound.is_empty() {
                    ("IN-NAME", r.inbound.join(","))
                } else if r.sniff {
                    ("SNIFF", String::new())
                } else {
                    ("MATCH", String::new())
                };
                let proxy = if r.hijack_dns {
                    "dns-out".to_string()
                } else {
                    r.outbound.clone()
                };
                json!({
                    "type": rule_type,
                    "payload": payload,
                    "proxy": proxy,
                    "size": -1,
                })
            })
            .collect();

        rules.push(json!({
            "type": "MATCH",
            "payload": "",
            "proxy": self.route_config.r#final,
            "size": -1,
        }));

        json_response(json!({ "rules": rules }))
    }

    // ── /proxies ──────────────────────────────────────────────────────────────

    fn get_proxies(&self) -> HttpResponse {
        let statuses = self.outbound_mgr.statuses();

        // 所有非特殊出站 tag 列表，供 GLOBAL 引用
        let all_proxy_tags: Vec<String> = statuses
            .iter()
            .filter(|s| s.type_name != "Direct" && s.type_name != "Block")
            .map(|s| s.name.clone())
            .collect();

        let global_now = all_proxy_tags.first().cloned().unwrap_or_default();

        let mut proxies = serde_json::Map::new();
        proxies.insert(
            "GLOBAL".to_string(),
            json!({
                "type": "Selector",
                "name": "GLOBAL",
                "udp": true,
                "history": [],
                "all": all_proxy_tags,
                "now": global_now,
            }),
        );

        for status in &statuses {
            let history = self
                .delay_history
                .load(&status.name)
                .map(|r| {
                    vec![json!({
                        "time": ms_to_iso(r.time_ms),
                        "delay": r.delay,
                        "meanDelay": r.delay,
                    })]
                })
                .unwrap_or_default();

            let mut entry = json!({
                "type": status.type_name,
                "name": status.name,
                "udp": true,
                "history": history,
            });
            if let Some(now) = &status.now {
                entry["now"] = json!(now);
            }
            if !status.all.is_empty() {
                entry["all"] = json!(status.all);
            }

            proxies.insert(status.name.clone(), entry);
        }

        json_response(json!({ "proxies": proxies }))
    }

    fn get_proxy(&self, encoded_name: &str) -> HttpResponse {
        let name = percent_decode(encoded_name);
        if name == "GLOBAL" {
            return self.global_proxy_entry();
        }
        match self.outbound_mgr.status(&name) {
            Some(status) => {
                let history = self
                    .delay_history
                    .load(&status.name)
                    .map(|r| {
                        vec![json!({
                            "time": ms_to_iso(r.time_ms),
                            "delay": r.delay,
                            "meanDelay": r.delay,
                        })]
                    })
                    .unwrap_or_default();
                let mut entry = json!({
                    "type": status.type_name,
                    "name": status.name,
                    "udp": true,
                    "history": history,
                });
                if let Some(now) = &status.now {
                    entry["now"] = json!(now);
                }
                if !status.all.is_empty() {
                    entry["all"] = json!(status.all);
                }
                json_response(entry)
            }
            None => text_response(404, "Not Found", "proxy not found"),
        }
    }

    fn global_proxy_entry(&self) -> HttpResponse {
        let statuses = self.outbound_mgr.statuses();
        let all: Vec<String> = statuses
            .iter()
            .filter(|s| s.type_name != "Direct" && s.type_name != "Block")
            .map(|s| s.name.clone())
            .collect();
        let now = all.first().cloned().unwrap_or_default();
        json_response(json!({
            "type": "Selector", "name": "GLOBAL",
            "udp": true, "history": [], "all": all, "now": now,
        }))
    }

    fn put_proxy(&self, encoded_name: &str, body: &[u8]) -> HttpResponse {
        let name = percent_decode(encoded_name);
        let value: serde_json::Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(e) => return text_response(400, "Bad Request", &format!("invalid json: {e}")),
        };
        let Some(child) = value.get("name").and_then(|v| v.as_str()) else {
            return text_response(400, "Bad Request", "missing proxy name");
        };
        match self.outbound_mgr.select(&name, child) {
            Ok(()) => empty_response(204, "No Content"),
            Err(e) => text_response(400, "Bad Request", &e.to_string()),
        }
    }

    async fn get_proxy_delay(&self, encoded_name: &str, query: &str) -> HttpResponse {
        let name = percent_decode(encoded_name);

        let mut probe_url = "https://www.gstatic.com/generate_204".to_string();
        let mut timeout_ms: u64 = 5000;
        for kv in query.split('&') {
            if let Some(v) = kv.strip_prefix("url=") {
                probe_url = percent_decode(v);
            } else if let Some(v) = kv.strip_prefix("timeout=") {
                if let Ok(n) = v.parse::<u64>() {
                    timeout_ms = n;
                }
            }
        }

        let (host, port) = {
            let (default_port, rest) = if let Some(r) = probe_url.strip_prefix("https://") {
                (443u16, r)
            } else if let Some(r) = probe_url.strip_prefix("http://") {
                (80u16, r)
            } else {
                return text_response(400, "Bad Request", "invalid probe url scheme");
            };
            let authority = rest.split('/').next().unwrap_or(rest);
            if let Some((h, p)) = authority.rsplit_once(':') {
                match p.parse::<u16>() {
                    Ok(port) => (h.to_string(), port),
                    Err(_) => return text_response(400, "Bad Request", "invalid port in url"),
                }
            } else {
                (authority.to_string(), default_port)
            }
        };

        let outbound = match self.outbound_mgr.get(&name) {
            Some(ob) => ob,
            None => return text_response(404, "Not Found", "proxy not found"),
        };

        let timeout = Duration::from_millis(timeout_ms);
        let started = Instant::now();
        match tokio::time::timeout(timeout, outbound.connect_tcp(&host, port)).await {
            Ok(Ok(_)) => {
                let delay = started.elapsed().as_millis() as u64;
                self.delay_history.store(&name, delay);
                json_response(json!({ "delay": delay, "meanDelay": delay }))
            }
            Ok(Err(e)) => {
                self.delay_history.delete(&name);
                HttpResponse::new(500, "Internal Server Error").body(
                    serde_json::to_vec(&json!({ "message": e.to_string() })).unwrap(),
                    "application/json; charset=utf-8",
                )
            }
            Err(_) => {
                self.delay_history.delete(&name);
                HttpResponse::new(500, "Internal Server Error").body(
                    serde_json::to_vec(&json!({ "message": "timeout" })).unwrap(),
                    "application/json; charset=utf-8",
                )
            }
        }
    }

    // ── UI 文件服务 ───────────────────────────────────────────────────────────

    fn redirect_to_ui(&self) -> HttpResponse {
        if self.config.external_ui.is_some() {
            HttpResponse::new(302, "Found")
                .header("Location", "/ui/")
                .body(Vec::new(), "text/plain; charset=utf-8")
        } else {
            json_response(json!({ "hello": "clash" }))
        }
    }

    async fn serve_ui(&self, path: &str) -> HttpResponse {
        let Some(ui_dir) = &self.config.external_ui else {
            return text_response(404, "Not Found", "not found");
        };
        let Some(relative) = path.strip_prefix("/ui") else {
            return text_response(404, "Not Found", "not found");
        };
        let relative = relative.trim_start_matches('/');
        let file = match safe_join(Path::new(ui_dir), relative) {
            Some(p) if p.is_dir() => p.join("index.html"),
            Some(p) => p,
            None => return text_response(403, "Forbidden", "forbidden"),
        };
        match tokio::fs::read(&file).await {
            Ok(bytes) => HttpResponse::new(200, "OK").body(bytes, content_type(&file)),
            Err(_) => {
                // SPA fallback
                let index = Path::new(ui_dir).join("index.html");
                match tokio::fs::read(&index).await {
                    Ok(bytes) => {
                        HttpResponse::new(200, "OK").body(bytes, "text/html; charset=utf-8")
                    }
                    Err(_) => text_response(404, "Not Found", "not found"),
                }
            }
        }
    }
}

// ── WebSocket 工具 ─────────────────────────────────────────────────────────────

fn ws_upgrade_response(client_key: &str) -> String {
    let accept = ws_accept_key(client_key);
    format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nAccess-Control-Allow-Origin: *\r\n\r\n"
    )
}

fn ws_accept_key(client_key: &str) -> String {
    const MAGIC: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let combined = format!("{client_key}{MAGIC}");
    let digest = sha1_bytes(combined.as_bytes());
    base64_encode(&digest)
}

fn sha1_bytes(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        #[allow(clippy::needless_range_loop)]
        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (i, &v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = match chunk.len() {
            3 => [chunk[0], chunk[1], chunk[2]],
            2 => [chunk[0], chunk[1], 0],
            _ => [chunk[0], 0, 0],
        };
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(CHARS[((n >> 18) & 63) as usize] as char);
        out.push(CHARS[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            CHARS[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            CHARS[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

async fn ws_send_text(stream: &mut TcpStream, data: &[u8]) -> anyhow::Result<()> {
    let len = data.len();
    let mut frame = Vec::with_capacity(len + 10);
    frame.push(0x81); // FIN + text opcode
    if len <= 125 {
        frame.push(len as u8);
    } else if len <= 65535 {
        frame.push(126);
        frame.push((len >> 8) as u8);
        frame.push((len & 0xFF) as u8);
    } else {
        frame.push(127);
        frame.extend_from_slice(&(len as u64).to_be_bytes());
    }
    frame.extend_from_slice(data);
    stream.write_all(&frame).await?;
    Ok(())
}

// ── HTTP 解析 / 序列化 ────────────────────────────────────────────────────────

struct HttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl HttpRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(|s| s.as_str())
    }
    fn is_websocket(&self) -> bool {
        self.header("upgrade")
            .map(|v| v.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false)
    }
}

async fn read_request(stream: &mut TcpStream) -> anyhow::Result<HttpRequest> {
    let mut buf = Vec::new();
    let header_end = loop {
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await?;
        anyhow::ensure!(n > 0, "connection closed before request");
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_header_end(&buf) {
            break pos;
        }
        anyhow::ensure!(buf.len() <= 64 * 1024, "request headers too large");
    };

    let headers_str = std::str::from_utf8(&buf[..header_end])?;
    let mut lines = headers_str.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing request line"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing method"))?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing path"))?
        .to_string();

    let headers: HashMap<String, String> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();

    let content_len = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let body_start = header_end + 4;
    while buf.len() < body_start + content_len {
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await?;
        anyhow::ensure!(n > 0, "connection closed before body");
        buf.extend_from_slice(&chunk[..n]);
        anyhow::ensure!(buf.len() <= 2 * 1024 * 1024, "request body too large");
    }

    Ok(HttpRequest {
        method,
        path,
        headers,
        body: buf[body_start..body_start + content_len].to_vec(),
    })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

struct HttpResponse {
    status: u16,
    reason: &'static str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpResponse {
    fn new(status: u16, reason: &'static str) -> Self {
        Self {
            status,
            reason,
            headers: vec![],
            body: vec![],
        }
    }
    fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }
    fn body(mut self, body: Vec<u8>, content_type: &str) -> Self {
        self.headers
            .push(("Content-Type".to_string(), content_type.to_string()));
        self.body = body;
        self
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n",
            self.status, self.reason, self.body.len()
        ).into_bytes();
        for (name, value) in &self.headers {
            response.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        response.extend_from_slice(b"\r\n");
        response.extend_from_slice(&self.body);
        response
    }
}

fn json_response(value: serde_json::Value) -> HttpResponse {
    HttpResponse::new(200, "OK").body(
        serde_json::to_vec(&value).expect("json serialization should not fail"),
        "application/json; charset=utf-8",
    )
}
fn text_response(status: u16, reason: &'static str, text: &str) -> HttpResponse {
    HttpResponse::new(status, reason).body(text.as_bytes().to_vec(), "text/plain; charset=utf-8")
}
fn empty_response(status: u16, reason: &'static str) -> HttpResponse {
    HttpResponse::new(status, reason).body(Vec::new(), "text/plain; charset=utf-8")
}

// ── 杂项工具 ──────────────────────────────────────────────────────────────────

fn conn_to_json(c: &ConnMeta) -> serde_json::Value {
    // host 字段可能是域名也可能是 IP 直连
    // UI 需要：host = 域名（或空），destinationIP = IP（域名连接时留空）
    let (host, destination_ip) = if c.host.parse::<std::net::IpAddr>().is_ok() {
        ("".to_string(), c.host.clone())
    } else {
        (c.host.clone(), "".to_string())
    };

    json!({
        "id": c.id.to_string(),
        "metadata": {
            "network": c.network,
            "type": c.inbound,
            "host": host,
            "sniffHost": "",
            "destinationIP": destination_ip,
            "destinationPort": c.dest_port.to_string(),
            "sourceIP": c.source_ip,
            "sourcePort": c.source_port.to_string(),
            "inboundName": c.inbound,
            "inboundPort": "",
            "inboundUser": "",
            "process": "",
            "processPath": "",
            "dnsMode": "normal",
        },
        "upload":   c.upload.load(Ordering::Relaxed),
        "download": c.download.load(Ordering::Relaxed),
        "start": ms_to_iso(c.started_ms),
        "chains": [c.outbound.clone()],
        "rule": c.rule.clone(),
        "rulePayload": c.rule_payload.clone(),
    })
}

fn percent_decode(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(hex);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn safe_join(root: &Path, relative: &str) -> Option<PathBuf> {
    let mut out = root.to_path_buf();
    for component in Path::new(relative).components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            _ => return None,
        }
    }
    Some(out)
}

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") | Some("mjs") => "application/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}

/// 毫秒 Unix 时间戳 → ISO 8601 UTC 字符串（不依赖 chrono）
fn ms_to_iso(ms: u64) -> String {
    let secs = ms / 1000;
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;
    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}.000000000Z")
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut year = 1970u64;
    loop {
        let diy = if is_leap(year) { 366 } else { 365 };
        if days < diy {
            break;
        }
        days -= diy;
        year += 1;
    }
    let month_days = [
        31u64,
        if is_leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 0u64;
    for &md in &month_days {
        if days < md {
            break;
        }
        days -= md;
        month += 1;
    }
    (year, month + 1, days + 1)
}

fn is_leap(y: u64) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

// ── 内存读取工具（跨平台）──────────────────────────────────────────────────────

/// 读取当前进程 RSS（常驻内存），单位 kB。
/// Linux 读 /proc/self/status；其他平台返回 None。
pub(crate) fn read_process_rss_kb() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                let kb = rest
                    .trim()
                    .trim_end_matches(" kB")
                    .trim()
                    .parse::<u64>()
                    .ok()?;
                return Some(kb);
            }
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decode_utf8() {
        assert_eq!(percent_decode("%E8%87%AA%E5%8A%A8"), "自动");
    }

    #[test]
    fn safe_join_rejects_parent() {
        assert!(safe_join(Path::new("ui"), "../secret").is_none());
        assert_eq!(
            safe_join(Path::new("ui"), "index.html").unwrap(),
            PathBuf::from("ui/index.html")
        );
    }

    #[test]
    fn ws_accept_key_rfc_example() {
        // RFC 6455 §1.3 example
        let accept = ws_accept_key("dGhlIHNhbXBsZSBub25jZQ==");
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn ms_to_iso_epoch() {
        let s = ms_to_iso(0);
        assert!(s.starts_with("1970-01-01T00:00:00"), "got: {s}");
    }

    #[test]
    fn ms_to_iso_known_date() {
        // 2024-01-01 00:00:00 UTC = 1704067200 seconds
        let s = ms_to_iso(1704067200_000);
        assert!(s.starts_with("2024-01-01T00:00:00"), "got: {s}");
    }

    #[test]
    fn delay_history_roundtrip() {
        let h = DelayHistory::default();
        h.store("proxy1", 123);
        let r = h.load("proxy1").unwrap();
        assert_eq!(r.delay, 123);
        h.delete("proxy1");
        assert!(h.load("proxy1").is_none());
    }
}
