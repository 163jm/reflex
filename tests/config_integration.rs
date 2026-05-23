//! 配置解析与校验的集成测试。
//!
//! 覆盖：完整配置文件解析、各字段默认值、错误情况。

use reflex::config::{validate_uuid, Config};

// ── 完整配置解析 ──────────────────────────────────────────────────────────────

static FULL_CONFIG: &str = r#"{
    "log": { "level": "debug", "output": "stderr", "timestamp": true },

    "dns": {
        "servers": [
            { "tag": "local",  "address": "223.5.5.5",                  "detour": "direct" },
            { "tag": "remote", "address": "https://1.1.1.1/dns-query",   "detour": "proxy"  },
            { "tag": "block",  "address": "rcode://refused" }
        ],
        "rules": [
            { "domain_suffix": [".cn"],  "server": "local"  },
            { "domain_suffix": [".gov"], "server": "local"  }
        ],
        "final": "remote",
        "strategy": "prefer_ipv4",
        "disable_cache": false,
        "cache_ttl_max": 600
    },

    "inbounds": [
        {
            "type": "tproxy",
            "tag":  "tproxy-in",
            "listen": "0.0.0.0",
            "listen_port": 7893,
            "network": "tcp+udp"
        },
        {
            "type": "mixed",
            "tag":  "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": 7890
        },
        {
            "type": "dns",
            "tag":  "dns-in",
            "listen": "127.0.0.1",
            "listen_port": 5353,
            "network": "udp"
        }
    ],

    "outbounds": [
        {
            "type": "vless",
            "tag":  "proxy",
            "server": "example.com",
            "server_port": 443,
            "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "transport": {
                "type": "ws",
                "path": "/ws",
                "headers": { "Host": "example.com" }
            },
            "tls": { "enabled": true, "server_name": "example.com", "insecure": false }
        },
        {
            "type": "hysteria2",
            "tag":  "hy2",
            "server": "example.com",
            "server_port": 443,
            "password": "secret",
            "up_mbps": 50,
            "down_mbps": 200
        },
        { "type": "direct", "tag": "direct" },
        { "type": "block",  "tag": "block"  }
    ],

    "route": {
        "rules": [
            { "inbound": ["dns-in"], "outbound": "dns-out" },
            { "network": "udp", "port": [53], "outbound": "dns-out" },
            { "ruleset": ["geosite-ads"], "outbound": "block" },
            { "ip_cidr": ["192.168.0.0/16", "10.0.0.0/8"], "outbound": "direct" },
            { "ruleset": ["geosite-cn", "geoip-cn"], "outbound": "direct" }
        ],
        "final": "proxy",
        "rule_set": [
            { "tag": "geosite-cn",  "type": "local", "path": "/tmp/geosite-cn.bin"  },
            { "tag": "geosite-ads", "type": "local", "path": "/tmp/geosite-ads.bin" },
            { "tag": "geoip-cn",    "type": "local", "path": "/tmp/geoip-cn.bin"    }
        ]
    }
}"#;

#[test]
fn parse_full_config() {
    let cfg = Config::from_text(FULL_CONFIG).unwrap();

    // log
    assert!(matches!(
        cfg.log.level,
        reflex::config::log::LogLevel::Debug
    ));

    // dns
    assert_eq!(cfg.dns.servers.len(), 3);
    assert_eq!(cfg.dns.r#final, "remote");
    assert!(!cfg.dns.disable_cache);
    assert_eq!(cfg.dns.cache_ttl_max, 600);

    // inbounds
    assert_eq!(cfg.inbounds.len(), 3);

    // outbounds
    assert_eq!(cfg.outbounds.len(), 4);

    // route
    assert_eq!(cfg.route.rules.len(), 5);
    assert_eq!(cfg.route.r#final, "proxy");
    assert_eq!(cfg.route.rule_set.len(), 3);
}

#[test]
fn inbound_defaults() {
    let cfg = Config::from_text(FULL_CONFIG).unwrap();
    use reflex::config::inbound::InboundConfig;

    // mixed 默认 udp=true, listen=127.0.0.1
    let mixed = cfg.inbounds.iter().find(|i| i.tag() == "mixed-in").unwrap();
    if let InboundConfig::Mixed(c) = mixed {
        assert!(c.network.udp());
        assert_eq!(c.listen, "127.0.0.1");
    }

    // dns-in 默认 network=udp（按配置）
    let dns = cfg.inbounds.iter().find(|i| i.tag() == "dns-in").unwrap();
    if let InboundConfig::Dns(c) = dns {
        assert!(c.network.udp());
        assert!(!c.network.tcp());
    }
}

#[test]
fn outbound_vless_fields() {
    let cfg = Config::from_text(FULL_CONFIG).unwrap();
    use reflex::config::outbound::{OutboundConfig, VlessTransportConfig};

    let vless = cfg.outbounds.iter().find(|o| o.tag() == "proxy").unwrap();
    if let OutboundConfig::Vless(c) = vless {
        assert_eq!(c.server, "example.com");
        assert_eq!(c.server_port, 443);
        assert_eq!(c.uuid, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        // TLS 配置（sing-box 格式）
        let tls = c.tls.as_ref().expect("expected tls");
        assert!(tls.enabled);
        assert!(!tls.insecure);
        assert_eq!(tls.server_name.as_deref(), Some("example.com"));
        // transport 为 Some(Ws(...))
        let Some(VlessTransportConfig::Ws(ref ws)) = c.transport else {
            panic!("expected Ws transport")
        };
        assert_eq!(ws.path, "/ws");
        assert_eq!(ws.headers.get("Host").unwrap(), "example.com");
    } else {
        panic!("expected vless outbound");
    }
}

#[test]
fn outbound_hy2_bandwidth() {
    use reflex::config::outbound::OutboundConfig;
    let cfg = Config::from_text(FULL_CONFIG).unwrap();
    let hy2 = cfg.outbounds.iter().find(|o| o.tag() == "hy2").unwrap();
    if let OutboundConfig::Hysteria2(c) = hy2 {
        // sing-box 格式：整数 Mbps
        assert_eq!(c.up_mbps, 50);
        assert_eq!(c.down_mbps, 200);
    }
}

// ── 错误情况 ──────────────────────────────────────────────────────────────────

#[test]
fn missing_route_final() {
    let s = r#"{
        "outbounds": [{"type":"direct","tag":"direct"}],
        "route": {"final":"nonexistent","rules":[],"rule_set":[]}
    }"#;
    assert!(Config::from_text(s).is_err());
}

#[test]
fn duplicate_outbound_tags() {
    let s = r#"{
        "outbounds": [
            {"type":"direct","tag":"direct"},
            {"type":"direct","tag":"direct"}
        ],
        "route": {"final":"direct","rules":[],"rule_set":[]}
    }"#;
    let err = Config::from_text(s).unwrap_err();
    assert!(err.to_string().contains("duplicate outbound tag"));
}

#[test]
fn invalid_vless_uuid() {
    let s = r#"{
        "inbounds": [{"type":"mixed","tag":"in","listen_port":7890}],
        "outbounds": [{
            "type": "vless", "tag": "proxy",
            "server": "x.com", "server_port": 443,
            "uuid": "not-a-valid-uuid",
            "transport": {"type":"ws","path":"/"}
        }],
        "route": {"final":"proxy","rules":[],"rule_set":[]}
    }"#;
    let err = Config::from_text(s).unwrap_err();
    assert!(err.to_string().contains("UUID") || err.to_string().contains("uuid"));
}

#[test]
fn route_rule_unknown_inbound_tag() {
    let s = r#"{
        "inbounds": [{"type":"mixed","tag":"in","listen_port":7890}],
        "outbounds": [{"type":"direct","tag":"direct"}],
        "route": {
            "final": "direct",
            "rules": [{"inbound":["ghost"],"outbound":"direct"}],
            "rule_set": []
        }
    }"#;
    let err = Config::from_text(s).unwrap_err();
    assert!(err.to_string().contains("ghost"));
}

#[test]
fn dns_unknown_server_in_rule() {
    let s = r#"{
        "inbounds": [{"type":"mixed","tag":"in","listen_port":7890}],
        "dns": {
            "servers": [{"tag":"local","address":"1.1.1.1"}],
            "rules": [{"domain_suffix":[".cn"],"server":"nonexistent"}],
            "final": "local"
        },
        "outbounds": [{"type":"direct","tag":"direct"}],
        "route": {"final":"direct","rules":[],"rule_set":[]}
    }"#;
    let err = Config::from_text(s).unwrap_err();
    assert!(err.to_string().contains("nonexistent"));
}

#[test]
fn comment_stripping() {
    let s = r#"{
        // this is a comment
        "outbounds": [{"type":"direct","tag":"direct"}], // inline
        # hash comment
        "route": {"final":"direct","rules":[],"rule_set":[]}
    }"#;
    Config::from_text(s).unwrap();
}

// ── UUID 校验 ─────────────────────────────────────────────────────────────────

#[test]
fn uuid_valid_forms() {
    // 标准带连字符
    validate_uuid("550e8400-e29b-41d4-a716-446655440000").unwrap();
    // 不带连字符
    validate_uuid("550e8400e29b41d4a716446655440000").unwrap();
    // 全零
    validate_uuid("00000000-0000-0000-0000-000000000000").unwrap();
}

#[test]
fn uuid_invalid_forms() {
    // 太短
    assert!(validate_uuid("550e8400-e29b").is_err());
    // 非十六进制
    assert!(validate_uuid("gggggggg-gggg-gggg-gggg-gggggggggggg").is_err());
    // 连字符位置错误
    assert!(validate_uuid("550e8400e29b-41d4-a716-446655440000").is_err());
    // 空字符串
    assert!(validate_uuid("").is_err());
}
