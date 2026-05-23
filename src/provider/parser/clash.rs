//! Clash YAML 订阅格式解析器。
//!
//! 解析 `proxies:` 字段，将 Clash proxy 对象转换为 Reflex `OutboundConfig`。
//! 支持：ss、vmess、vless、trojan、hysteria2、tuic。

use std::collections::HashMap;

use serde::Deserialize;

use crate::config::outbound::{
    Hysteria2OutboundConfig, OutboundConfig, RealityConfig, TlsConfig, TrojanOutboundConfig,
    TrojanTransportConfig, TuicOutboundConfig, VlessOutboundConfig, VlessTlsConfig,
    VlessTransportConfig, VmessOutboundConfig, VmessTransportConfig, WsTransportConfig,
};

/// 解析 Clash YAML 文本，返回 (节点名, OutboundConfig) 列表。
/// 节点名单独返回，调用方负责去重命名。
pub fn parse_clash_yaml(text: &str) -> anyhow::Result<Vec<(String, OutboundConfig)>> {
    let doc: ClashDoc =
        serde_yaml::from_str(text).map_err(|e| anyhow::anyhow!("clash yaml parse error: {e}"))?;

    let mut result = Vec::new();
    for (i, proxy) in doc.proxies.into_iter().enumerate() {
        let name = proxy.name.clone();
        match build_outbound(proxy) {
            Ok(ob) => result.push((name, ob)),
            Err(e) => {
                tracing::warn!(index = i, node = %name, err = %e, "skip unsupported proxy");
            }
        }
    }
    Ok(result)
}

// ── 内部 Clash 数据结构 ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct ClashDoc {
    #[serde(default)]
    proxies: Vec<ClashProxy>,
}

#[derive(Debug, Deserialize)]
struct ClashProxy {
    name: String,
    #[serde(rename = "type")]
    proxy_type: String,
    // 通用字段
    #[serde(default)]
    server: String,
    #[serde(default)]
    port: u16,
    // ss
    #[serde(default)]
    cipher: Option<String>,
    #[serde(default)]
    password: Option<String>,
    // vmess
    #[serde(default)]
    uuid: Option<String>,
    #[serde(rename = "alterId", default)]
    #[allow(dead_code)]
    alter_id: Option<u32>,
    // vmess cipher 字段名也叫 cipher
    // vless
    #[serde(default)]
    #[allow(dead_code)]
    flow: Option<String>,
    // trojan
    // password 同上
    // tls 相关
    #[serde(default)]
    tls: Option<bool>,
    #[serde(rename = "skip-cert-verify", default)]
    skip_cert_verify: bool,
    #[serde(default)]
    sni: Option<String>,
    #[serde(default)]
    alpn: Option<Vec<String>>,
    // network / ws-opts
    #[serde(default)]
    network: Option<String>,
    #[serde(rename = "ws-opts", default)]
    ws_opts: Option<ClashWsOpts>,
    // hysteria2
    #[serde(default)]
    up: Option<String>,
    #[serde(default)]
    down: Option<String>,
    // tuic
    #[serde(rename = "congestion-controller", default)]
    congestion_controller: Option<String>,
    #[serde(rename = "udp-relay-mode", default)]
    udp_relay_mode: Option<String>,
    // reality
    #[serde(rename = "reality-opts", default)]
    reality_opts: Option<ClashRealityOpts>,
    // 其余字段忽略
    #[serde(flatten)]
    _extra: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Deserialize, Default)]
struct ClashWsOpts {
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    headers: Option<HashMap<String, String>>,
    #[serde(rename = "early-data-header-name", default)]
    early_data_header_name: Option<String>,
    #[serde(rename = "max-early-data", default)]
    max_early_data: Option<u32>,
}

#[derive(Debug, Deserialize, Default)]
struct ClashRealityOpts {
    #[serde(rename = "public-key", default)]
    public_key: String,
    #[serde(rename = "short-id", default)]
    short_id: String,
}

// ── 构建 OutboundConfig ───────────────────────────────────────────────────────

fn build_outbound(p: ClashProxy) -> anyhow::Result<OutboundConfig> {
    // tag 先用占位符，调用方会用去重后的名字替换
    let tag = p.name.clone();

    match p.proxy_type.as_str() {
        "ss" | "shadowsocks" => build_ss(tag, p),
        "vmess" => build_vmess(tag, p),
        "vless" => build_vless(tag, p),
        "trojan" => build_trojan(tag, p),
        "hysteria2" | "hy2" => build_hysteria2(tag, p),
        "tuic" => build_tuic(tag, p),
        other => anyhow::bail!("unsupported proxy type: '{other}'"),
    }
}

/// Shadowsocks → Hysteria2（借用 ss 隧道思路，Reflex 暂无原生 SS outbound，跳过）
fn build_ss(_tag: String, p: ClashProxy) -> anyhow::Result<OutboundConfig> {
    // Reflex 目前没有 SS outbound，跳过
    anyhow::bail!(
        "shadowsocks is not yet supported in Reflex (node: {})",
        p.name
    )
}

fn build_vmess(tag: String, p: ClashProxy) -> anyhow::Result<OutboundConfig> {
    let uuid = p
        .uuid
        .ok_or_else(|| anyhow::anyhow!("vmess: missing uuid"))?;
    let tls_enabled = p.tls.unwrap_or(false);
    let tls = build_tls(
        tls_enabled,
        p.skip_cert_verify,
        p.sni.clone(),
        p.alpn.clone(),
    );

    let transport = match p.network.as_deref() {
        Some("ws") => VmessTransportConfig::Ws(build_ws_transport(p.ws_opts)),
        _ => VmessTransportConfig::Tcp,
    };

    Ok(OutboundConfig::Vmess(VmessOutboundConfig {
        tag,
        server: p.server,
        server_port: p.port,
        uuid,
        security: p.cipher.unwrap_or_else(|| "auto".to_string()),
        transport,
        tls,
        detour: None,
    }))
}

fn build_vless(tag: String, p: ClashProxy) -> anyhow::Result<OutboundConfig> {
    let uuid = p
        .uuid
        .ok_or_else(|| anyhow::anyhow!("vless: missing uuid"))?;

    let transport = match p.network.as_deref() {
        Some("ws") => Some(VlessTransportConfig::Ws(build_ws_transport(p.ws_opts))),
        _ => None,
    };

    let tls_enabled = p.tls.unwrap_or(false);
    let tls = if tls_enabled {
        let reality = p.reality_opts.as_ref().map(|ro| RealityConfig {
            enabled: true,
            public_key: ro.public_key.clone(),
            short_id: ro.short_id.clone(),
        });
        Some(VlessTlsConfig {
            enabled: true,
            server_name: p.sni.clone(),
            insecure: p.skip_cert_verify,
            ca_path: None,
            alpn: p.alpn.clone().unwrap_or_default(),
            reality,
        })
    } else {
        None
    };

    Ok(OutboundConfig::Vless(VlessOutboundConfig {
        tag,
        server: p.server,
        server_port: p.port,
        uuid,
        transport,
        tls,
        detour: None,
    }))
}

fn build_trojan(tag: String, p: ClashProxy) -> anyhow::Result<OutboundConfig> {
    let password = p
        .password
        .ok_or_else(|| anyhow::anyhow!("trojan: missing password"))?;

    let tls_enabled = p.tls.unwrap_or(true);
    let tls = build_tls(
        tls_enabled,
        p.skip_cert_verify,
        p.sni.clone(),
        p.alpn.clone(),
    );

    let transport = match p.network.as_deref() {
        Some("ws") => Some(TrojanTransportConfig::Ws(build_ws_transport(p.ws_opts))),
        _ => None,
    };

    Ok(OutboundConfig::Trojan(TrojanOutboundConfig {
        tag,
        server: p.server,
        server_port: p.port,
        password,
        transport,
        tls,
        detour: None,
    }))
}

fn build_hysteria2(tag: String, p: ClashProxy) -> anyhow::Result<OutboundConfig> {
    let password = p
        .password
        .ok_or_else(|| anyhow::anyhow!("hysteria2: missing password"))?;
    let tls = build_tls(true, p.skip_cert_verify, p.sni.clone(), p.alpn.clone());

    let up_mbps = p.up.as_deref().and_then(parse_mbps).unwrap_or(0);
    let down_mbps = p.down.as_deref().and_then(parse_mbps).unwrap_or(0);

    Ok(OutboundConfig::Hysteria2(Hysteria2OutboundConfig {
        tag,
        server: p.server,
        server_port: p.port,
        password,
        tls,
        up_mbps,
        down_mbps,
        detour: None,
    }))
}

/// 将 "100 mbps" / "100" 解析为 Mbps 整数
fn parse_mbps(s: &str) -> Option<u64> {
    s.split_whitespace().next()?.parse().ok()
}

fn build_tuic(tag: String, p: ClashProxy) -> anyhow::Result<OutboundConfig> {
    let uuid = p
        .uuid
        .ok_or_else(|| anyhow::anyhow!("tuic: missing uuid"))?;
    let password = p
        .password
        .ok_or_else(|| anyhow::anyhow!("tuic: missing password"))?;
    let tls = build_tls(true, p.skip_cert_verify, p.sni.clone(), p.alpn.clone());

    Ok(OutboundConfig::Tuic(TuicOutboundConfig {
        tag,
        server: p.server,
        server_port: p.port,
        uuid,
        password,
        congestion_control: p
            .congestion_controller
            .unwrap_or_else(|| "cubic".to_string()),
        udp_relay_mode: p.udp_relay_mode.unwrap_or_else(|| "native".to_string()),
        tls,
        heartbeat: None,
        zero_rtt_handshake: false,
        detour: None,
    }))
}

// ── 工具函数 ──────────────────────────────────────────────────────────────────

fn build_tls(
    enabled: bool,
    insecure: bool,
    sni: Option<String>,
    alpn: Option<Vec<String>>,
) -> TlsConfig {
    TlsConfig {
        enabled,
        server_name: sni,
        insecure,
        ca_path: None,
        alpn: alpn.unwrap_or_default(),
        min_version: None,
        max_version: None,
    }
}

fn build_ws_transport(opts: Option<ClashWsOpts>) -> WsTransportConfig {
    let opts = opts.unwrap_or_default();
    WsTransportConfig {
        path: opts.path.unwrap_or_else(|| "/".to_string()),
        headers: opts.headers.unwrap_or_default(),
        early_data_header_name: opts.early_data_header_name,
        max_early_data: opts.max_early_data.unwrap_or(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_vmess_ws() {
        let yaml = r#"
proxies:
  - name: "日本 WS"
    type: vmess
    server: jp.example.com
    port: 443
    uuid: "12345678-1234-1234-1234-123456789abc"
    cipher: auto
    tls: true
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: jp.example.com
    skip-cert-verify: false
"#;
        let nodes = parse_clash_yaml(yaml).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].0, "日本 WS");
        assert!(matches!(nodes[0].1, OutboundConfig::Vmess(_)));
    }

    #[test]
    fn parse_hy2() {
        let yaml = r#"
proxies:
  - name: "HK HY2"
    type: hysteria2
    server: hk.example.com
    port: 443
    password: mypassword
    up: "50 mbps"
    down: "100 mbps"
    skip-cert-verify: true
"#;
        let nodes = parse_clash_yaml(yaml).unwrap();
        assert_eq!(nodes.len(), 1);
        assert!(matches!(nodes[0].1, OutboundConfig::Hysteria2(_)));
    }

    #[test]
    fn skip_unsupported_type() {
        let yaml = r#"
proxies:
  - name: "SS节点"
    type: ss
    server: s.example.com
    port: 1234
    cipher: aes-256-gcm
    password: pass
  - name: "HK HY2"
    type: hy2
    server: hk.example.com
    port: 443
    password: mypassword
"#;
        // ss 被跳过，hy2 保留
        let nodes = parse_clash_yaml(yaml).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].0, "HK HY2");
    }

    #[test]
    fn parse_trojan_tcp_tls() {
        let yaml = r#"
proxies:
  - name: "JP Trojan"
    type: trojan
    server: jp.example.com
    port: 443
    password: mypassword
    sni: jp.example.com
    skip-cert-verify: false
"#;
        let nodes = parse_clash_yaml(yaml).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].0, "JP Trojan");
        if let OutboundConfig::Trojan(ref c) = nodes[0].1 {
            assert_eq!(c.server, "jp.example.com");
            assert_eq!(c.server_port, 443);
            assert_eq!(c.password, "mypassword");
            assert!(c.tls.enabled);
            assert_eq!(c.tls.server_name.as_deref(), Some("jp.example.com"));
            assert!(matches!(
                c.transport,
                None | Some(TrojanTransportConfig::Tcp(_))
            ));
        } else {
            panic!("expected Trojan outbound");
        }
    }

    #[test]
    fn parse_trojan_ws_tls() {
        let yaml = r#"
proxies:
  - name: "SG Trojan WS"
    type: trojan
    server: sg.example.com
    port: 443
    password: wspassword
    tls: true
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /trojan
      headers:
        Host: sg.example.com
"#;
        let nodes = parse_clash_yaml(yaml).unwrap();
        assert_eq!(nodes.len(), 1);
        if let OutboundConfig::Trojan(ref c) = nodes[0].1 {
            assert!(c.tls.enabled);
            assert!(c.tls.insecure);
            if let Some(TrojanTransportConfig::Ws(ref ws)) = c.transport {
                assert_eq!(ws.path, "/trojan");
                assert_eq!(
                    ws.headers.get("Host").map(|s| s.as_str()),
                    Some("sg.example.com")
                );
            } else {
                panic!("expected WS transport");
            }
        } else {
            panic!("expected Trojan outbound");
        }
    }

    #[test]
    fn parse_trojan_missing_password() {
        let yaml = r#"
proxies:
  - name: "Bad Trojan"
    type: trojan
    server: x.example.com
    port: 443
"#;
        // password 缺失，节点被跳过（warn 日志），结果为空
        let nodes = parse_clash_yaml(yaml).unwrap();
        assert_eq!(nodes.len(), 0);
    }
}
