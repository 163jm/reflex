# Reflex

用 Rust 实现的轻量代理，支持 VLESS over WebSocket+TLS 和 Hysteria2 出站，TProxy/Mixed/DNS 入站，以及二进制规则集分流。

## 功能

| 类别 | 支持内容 |
|---|---|
| **入站** | TProxy（TCP+UDP）、Mixed（SOCKS5+HTTP CONNECT，含 UDP ASSOCIATE）、DNS-in |
| **出站** | VLESS over WS+TLS、Hysteria2（QUIC）、Direct、Block |
| **路由** | 按入站 tag / 网络类型 / 域名 / IP CIDR / 端口分流，支持二进制规则集文件 |
| **DNS** | UDP / TCP / DoH 上游，内置 rcode（refused/nxdomain/success），LRU+TTL 缓存，按规则分流 |
| **规则集** | 自定义 `.rrs` 二进制格式，支持 domain/suffix/keyword/regex/IPv4 CIDR/IPv6 CIDR/端口；可直接从 sing-box JSON 规则集转换 |

## 项目结构

```
crates/
├── ruleset/               # 规则集 crate（独立，无网络依赖）
│   └── src/
│       ├── compiler.rs    # 文本 .rrs → 二进制序列化
│       ├── loader.rs      # 二进制反序列化
│       ├── matcher.rs     # 匹配引擎（HashSet + Trie + CIDR + 端口）
│       ├── trie.rs        # 域名后缀 Trie
│       └── bin/rsc.rs     # CLI 工具
└── proxy/                 # 主程序
    ├── src/
    │   ├── lib.rs
    │   ├── main.rs
    │   ├── config/        # JSON 配置解析与校验
    │   ├── inbound/       # tproxy / mixed / dns-in
    │   ├── outbound/      # vless / hy2 / direct / block / proto
    │   ├── router/        # 路由引擎
    │   ├── dns/           # DNS 解析器 + 上游 + LRU 缓存
    │   └── app/           # 启动编排 + dispatcher + 统计
    └── tests/             # 集成测试
```

## 构建

### 依赖

- Rust 1.75+
- Linux（TProxy 入站需要 Linux 内核，Mixed/DNS-in 跨平台）

### 编译

```bash
# 仅核心逻辑（不含网络出站，可在任意平台编译测试）
cargo build

# 含 VLESS/Hy2 网络出站（需要 rustls + quinn 等依赖）
cargo build --features outbound-net

# Release 构建
cargo build --release --features outbound-net
```

### 测试

```bash
cargo test               # 运行所有单元测试 + 集成测试
cargo test -p ruleset    # 仅规则集测试
cargo test -p proxy      # 仅主程序测试
```

## 规则集工具（rsc）

```bash
# 编译文本规则集为二进制 .rrs
cargo run -p ruleset --bin rsc -- compile rules/cn.rrs rules/cn.rrs

# 直接从 sing-box JSON 规则集转换（推荐）
cargo run -p ruleset --bin rsc -- from-singbox geosite-cn.json rules/geosite-cn.rrs
cargo run -p ruleset --bin rsc -- from-singbox geoip-cn.json   rules/geoip-cn.rrs

# 查看规则集统计
cargo run -p ruleset --bin rsc -- inspect rules/geosite-cn.rrs

# 测试匹配
cargo run -p ruleset --bin rsc -- test rules/geosite-cn.rrs www.baidu.com
cargo run -p ruleset --bin rsc -- test rules/geoip-cn.rrs   114.114.114.114
cargo run -p ruleset --bin rsc -- test rules/cn.rrs         443
```

### sing-box JSON 规则集转换

`from-singbox` 命令直接读取 sing-box Source Rule Set 的 JSON 文件（`.json` 或 `.srs` 未编译格式），
转换为 Reflex 的二进制 `.rrs` 格式，无需中间步骤：

```bash
# 下载 sing-box 社区规则集后直接转换
rsc from-singbox geosite-cn.json rules/geosite-cn.rrs
rsc from-singbox geoip-cn.json   rules/geoip-cn.rrs
```

字段映射：

| sing-box 字段    | Reflex 规则类型 |
|-----------------|----------------|
| `domain`        | domain（精确）  |
| `domain_suffix` | domain-suffix  |
| `domain_keyword`| domain-keyword |
| `domain_regex`  | domain-regex   |
| `ip_cidr`       | ip-cidr / ip-cidr6（自动识别 v4/v6）|
| `port`          | port（整数）    |
| `port_range`    | port（"start:end"）|

### 文本规则集格式（.rrs）

```
# 注释行
domain:         example.com          # 精确域名
domain-suffix:  google.com           # 域名后缀（含子域名）
domain-keyword: ads                  # 关键词
domain-regex:   ^tracker\d+\.        # 正则
ip-cidr:        192.168.0.0/16       # IPv4 CIDR
ip-cidr6:       2001:db8::/32        # IPv6 CIDR
port:           443                  # 单端口
port:           8000-9000            # 端口范围
```

## 配置文件

参考 `config.example.json`，主要字段：

```jsonc
{
  "log":       { "level": "info" },
  "dns":       { "servers": [...], "rules": [...], "final": "remote" },
  "inbounds":  [...],
  "outbounds": [...],
  "route":     { "rules": [...], "final": "proxy", "rulesets": [...] }
}
```

支持 `//` 和 `#` 行注释。

### 典型 iptables 规则（TProxy）

```bash
# 创建策略路由
ip rule add fwmark 0x1 table 100
ip route add local 0.0.0.0/0 dev lo table 100

# TCP 透明代理
iptables -t mangle -N RS_PROXY
iptables -t mangle -A RS_PROXY -d 127.0.0.0/8 -j RETURN
iptables -t mangle -A RS_PROXY -d 10.0.0.0/8 -j RETURN
iptables -t mangle -A RS_PROXY -d 172.16.0.0/12 -j RETURN
iptables -t mangle -A RS_PROXY -d 192.168.0.0/16 -j RETURN
iptables -t mangle -A RS_PROXY -p tcp -j TPROXY \
    --tproxy-mark 0x1 --on-ip 0.0.0.0 --on-port 7893
iptables -t mangle -A RS_PROXY -p udp -j TPROXY \
    --tproxy-mark 0x1 --on-ip 0.0.0.0 --on-port 7893
iptables -t mangle -A PREROUTING -j RS_PROXY
```

## 运行

```bash
# 基本启动
./proxy --config /etc/rs-proxy/config.json

# 验证配置
./proxy --config config.json --check

# 调试模式
./proxy --config config.json --log debug
```

## 架构说明

### 数据流

```
入站（tproxy/mixed/dns-in）
    ↓ InboundTcpStream / InboundUdpPacket
Dispatcher
    ↓ Router::route_tcp / route_udp
    ├─→ dns-out → DnsResolver → 上游 DNS
    └─→ Outbound tag → VlessOutbound / Hy2Outbound / DirectOutbound / BlockOutbound
```

### 路由匹配语义

- **规则顺序**：从上到下，第一条命中生效
- **规则内部**：多个条件是 AND（入站 tag AND 网络类型 AND 目标条件）
- **目标条件内部**：多个值是 OR（命中任意 ruleset 或内联规则即满足）
- **端口规则**：独立于地址规则，OR 合并

### DNS 缓存

- key = `(qname_lowercase, qtype)`，A 和 AAAA 独立存储
- 命中时用查询的事务 ID 替换缓存响应的 ID
- TTL 上限可通过 `dns.cache_ttl_max` 配置
- 容量满时优先淘汰过期条目，其次淘汰 LRU 队尾

### 统计

通过 `App::stats` 可获取每个 outbound tag 的实时统计：

```rust
let global = app.stats.global_snapshot();
println!("active tcp: {}", global.tcp_active);
println!("total bytes up: {}", global.bytes_up);
```

## Feature Flags

| Flag | 内容 |
|---|---|
| `outbound-net`（默认关闭）| 启用 VLESS/Hy2 网络出站，引入 rustls/quinn/tokio-tungstenite |

不带 `outbound-net` 时，VLESS/Hy2 出站自动降级为 Block 并打日志警告。这允许在受限环境中编译和测试核心逻辑（路由、DNS、规则集）。
