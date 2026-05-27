//! 路由层集成测试：从真实规则集文件构建 Router，验证分流逻辑。

use bytes::Bytes;
use reflex::{
    config::route::{NetworkFilter, PortFilter, RouteConfig, RouteRuleConfig, RuleSetRef},
    inbound::{InboundTcpStream, InboundUdpPacket, Target, UdpSession},
    router::{RouteAction, Router},
};
use tokio::sync::mpsc;

// ── 辅助函数 ──────────────────────────────────────────────────────────────────

fn compile_ruleset_to_file(src: &str) -> tempfile::NamedTempFile {
    let compiled = reflex::ruleset::CompiledRuleSet::from_text(src).unwrap();
    let mut f = tempfile::NamedTempFile::new().unwrap();
    compiled.serialize(f.as_file_mut()).unwrap();
    f
}

fn empty_rule(outbound: &str) -> RouteRuleConfig {
    RouteRuleConfig {
        inbound: vec![],
        network: None,
        ruleset: vec![],
        domain: vec![],
        domain_suffix: vec![],
        domain_keyword: vec![],
        ip_cidr: vec![],
        port: vec![],
        port_range: vec![],
        protocol: vec![],
        outbound: outbound.into(),
        sniff: false,
        sniff_timeout_ms: 0,
        sniff_type: vec![],
        sniff_override_destination: false,
        resolve: false,
        resolve_server: None,
        hijack_dns: false,
    }
}

async fn make_conn(target: Target, inbound_tag: &str) -> InboundTcpStream {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    InboundTcpStream {
        stream: reflex::inbound::SniffedStream::new(stream),
        target,
        inbound_tag: inbound_tag.into(),
        sniffed_protocol: None,
        sniffed_domain: None,
    }
}

fn make_udp_packet(target: Target, inbound_tag: &str) -> InboundUdpPacket {
    let (tx, _rx) = mpsc::channel(1);
    InboundUdpPacket {
        data: Bytes::new(),
        src: "127.0.0.1:12345".parse().unwrap(),
        target,
        inbound_tag: inbound_tag.into(),
        sniffed_protocol: None,
        sniffed_domain: None,
        session: UdpSession { reply_tx: tx },
        upstream_rx: None,
                    lifetime_guards: vec![],
    }
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn router_loads_ruleset_file() {
    let rs_file = compile_ruleset_to_file(
        "domain-suffix: google.com\ndomain-suffix: youtube.com\nip-cidr: 8.8.8.0/24",
    );

    let mut proxy_rule = empty_rule("proxy");
    proxy_rule.ruleset = vec!["foreign".into()];

    let config = RouteConfig {
        rules: vec![proxy_rule],
        r#final: "direct".into(),
        rule_set: vec![RuleSetRef {
            tag: "foreign".into(),
            r#type: reflex::config::route::RuleSetType::Local,
            path: Some(rs_file.path().to_str().unwrap().into()),
            url: None,
            download_detour: None,
        }],
        resolve_dns: false,
    };

    let router = Router::from_config(&config, None, None).unwrap();

    let google = make_conn(Target::Domain("www.google.com".into(), 443), "in").await;
    let baidu = make_conn(Target::Domain("www.baidu.com".into(), 443), "in").await;
    let dns = make_conn(Target::Socket("8.8.8.8:53".parse().unwrap()), "in").await;
    let cn_ip = make_conn(Target::Socket("114.114.114.114:53".parse().unwrap()), "in").await;

    assert_eq!(
        router.route_tcp(&google).0,
        &RouteAction::Outbound("proxy".into())
    );
    assert_eq!(
        router.route_tcp(&baidu).0,
        &RouteAction::Outbound("direct".into())
    );
    assert_eq!(
        router.route_tcp(&dns).0,
        &RouteAction::Outbound("proxy".into())
    );
    assert_eq!(
        router.route_tcp(&cn_ip).0,
        &RouteAction::Outbound("direct".into())
    );
}

#[tokio::test]
async fn router_multiple_rulesets_or_logic() {
    let cn_domain = compile_ruleset_to_file("domain-suffix: baidu.com\ndomain-suffix: qq.com");
    let cn_ip = compile_ruleset_to_file("ip-cidr: 114.0.0.0/8\nip-cidr: 163.0.0.0/8");

    let mut r1 = empty_rule("direct");
    r1.ruleset = vec!["cn-domain".into()];
    let mut r2 = empty_rule("direct");
    r2.ruleset = vec!["cn-ip".into()];

    let config = RouteConfig {
        rules: vec![r1, r2],
        r#final: "proxy".into(),
        rule_set: vec![
            RuleSetRef {
                tag: "cn-domain".into(),
                r#type: reflex::config::route::RuleSetType::Local,
                path: Some(cn_domain.path().to_str().unwrap().into()),
                url: None,
                download_detour: None,
            },
            RuleSetRef {
                tag: "cn-ip".into(),
                r#type: reflex::config::route::RuleSetType::Local,
                path: Some(cn_ip.path().to_str().unwrap().into()),
                url: None,
                download_detour: None,
            },
        ],
        resolve_dns: false,
    };
    let router = Router::from_config(&config, None, None).unwrap();

    let baidu = make_conn(Target::Domain("www.baidu.com".into(), 80), "in").await;
    let cn_ip = make_conn(Target::Socket("114.5.5.5:80".parse().unwrap()), "in").await;
    let google = make_conn(Target::Domain("google.com".into(), 443), "in").await;

    assert_eq!(
        router.route_tcp(&baidu).0,
        &RouteAction::Outbound("direct".into())
    );
    assert_eq!(
        router.route_tcp(&cn_ip).0,
        &RouteAction::Outbound("direct".into())
    );
    assert_eq!(
        router.route_tcp(&google).0,
        &RouteAction::Outbound("proxy".into())
    );
}

#[tokio::test]
async fn router_dns_out_routing() {
    let mut dns_rule = empty_rule("dns-out");
    dns_rule.inbound = vec!["dns-in".into()];

    let mut cn_rule = empty_rule("direct");
    cn_rule.domain_suffix = vec!["cn".into()];

    let config = RouteConfig {
        rules: vec![dns_rule, cn_rule],
        r#final: "proxy".into(),
        rule_set: vec![],
        resolve_dns: false,
    };
    let router = Router::from_config(&config, None, None).unwrap();

    let dns_q = make_conn(Target::Domain("example.com".into(), 53), "dns-in").await;
    let cn = make_conn(Target::Domain("example.cn".into(), 80), "tproxy-in").await;
    let foreign = make_conn(Target::Domain("google.com".into(), 443), "tproxy-in").await;

    assert_eq!(router.route_tcp(&dns_q).0, &RouteAction::DnsOut);
    assert_eq!(
        router.route_tcp(&cn).0,
        &RouteAction::Outbound("direct".into())
    );
    assert_eq!(
        router.route_tcp(&foreign).0,
        &RouteAction::Outbound("proxy".into())
    );
}

#[tokio::test]
async fn router_network_filter_separates_tcp_udp() {
    let mut udp_dns = empty_rule("dns-out");
    udp_dns.network = Some(NetworkFilter::Udp);
    udp_dns.port = vec![PortFilter(53, 53)];

    let config = RouteConfig {
        rules: vec![udp_dns],
        r#final: "proxy".into(),
        rule_set: vec![],
        resolve_dns: false,
    };
    let router = Router::from_config(&config, None, None).unwrap();

    // UDP port 53 → dns-out
    let udp_pkt = make_udp_packet(Target::Socket("8.8.8.8:53".parse().unwrap()), "tproxy-in");
    assert_eq!(router.route_udp(&udp_pkt).0, &RouteAction::DnsOut);

    // TCP port 53 同样目标 → proxy（因为规则只匹配 UDP）
    let tcp_53 = make_conn(Target::Socket("8.8.8.8:53".parse().unwrap()), "tproxy-in").await;
    assert_eq!(
        router.route_tcp(&tcp_53).0,
        &RouteAction::Outbound("proxy".into())
    );
}

#[tokio::test]
async fn router_private_ip_direct() {
    let mut private = empty_rule("direct");
    private.ip_cidr = vec![
        "127.0.0.0/8".into(),
        "10.0.0.0/8".into(),
        "172.16.0.0/12".into(),
        "192.168.0.0/16".into(),
    ];

    let config = RouteConfig {
        rules: vec![private],
        r#final: "proxy".into(),
        rule_set: vec![],
        resolve_dns: false,
    };
    let router = Router::from_config(&config, None, None).unwrap();

    for ip in ["127.0.0.1", "10.0.0.1", "172.16.1.1", "192.168.1.100"] {
        let conn = make_conn(Target::Socket(format!("{ip}:80").parse().unwrap()), "in").await;
        assert_eq!(
            router.route_tcp(&conn).0,
            &RouteAction::Outbound("direct".into()),
            "ip={ip}"
        );
    }

    let pub_ip = make_conn(Target::Socket("1.2.3.4:80".parse().unwrap()), "in").await;
    assert_eq!(
        router.route_tcp(&pub_ip).0,
        &RouteAction::Outbound("proxy".into())
    );
}

#[tokio::test]
async fn router_port_range_rule() {
    let mut rule = empty_rule("block");
    rule.port = vec![PortFilter(0, 1023)]; // well-known ports → block

    let config = RouteConfig {
        rules: vec![rule],
        r#final: "proxy".into(),
        rule_set: vec![],
        resolve_dns: false,
    };
    let router = Router::from_config(&config, None, None).unwrap();

    let p80 = make_conn(Target::Socket("1.2.3.4:80".parse().unwrap()), "in").await;
    let p443 = make_conn(Target::Socket("1.2.3.4:443".parse().unwrap()), "in").await;
    let p8080 = make_conn(Target::Socket("1.2.3.4:8080".parse().unwrap()), "in").await;

    assert_eq!(
        router.route_tcp(&p80).0,
        &RouteAction::Outbound("block".into())
    );
    assert_eq!(
        router.route_tcp(&p443).0,
        &RouteAction::Outbound("block".into())
    );
    assert_eq!(
        router.route_tcp(&p8080).0,
        &RouteAction::Outbound("proxy".into())
    );
}
