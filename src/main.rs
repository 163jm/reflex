// main.rs — reflex 主入口（含内置 ruleset 编译器，原 rsc 功能）
use anyhow::Context as _;
use reflex::app::App;
use reflex::config::log::LogLevel;
use std::{env, fs, net::IpAddr, process};
use tracing::info;

use reflex::ruleset::{CompiledRuleSet, LoadedRuleSet, MatchTarget, RuleSet};

#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(unix)]
fn raise_nofile_limit() {
    unsafe {
        let mut rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) == 0 {
            let target = rl.rlim_max.min(1 << 20);
            if rl.rlim_cur < target {
                rl.rlim_cur = target;
                if libc::setrlimit(libc::RLIMIT_NOFILE, &rl) != 0 {
                    let e = std::io::Error::last_os_error();
                    eprintln!("[warn] setrlimit RLIMIT_NOFILE failed: {e}");
                } else {
                    eprintln!("[info] raised RLIMIT_NOFILE to {target}");
                }
            }
        }
    }
}

// ── ruleset 子命令 ─────────────────────────────────────────────────────────────

/// 从参数列表中找到 `-o <value>`，返回输出路径。
fn parse_output_flag(args: &[String]) -> anyhow::Result<String> {
    let mut iter = args.iter().peekable();
    while let Some(a) = iter.next() {
        if a == "-o" {
            return iter
                .next()
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("'-o' requires an argument"));
        }
        if let Some(val) = a.strip_prefix("-o=") {
            return Ok(val.to_string());
        }
    }
    Err(anyhow::anyhow!("missing required flag: -o <output.rrs>"))
}

/// `reflex ruleset <input.json> -o <output.rrs>`
/// 支持 sing-box JSON 格式（rule-set）和文本格式（.txt）
fn cmd_ruleset(args: &[String]) -> anyhow::Result<()> {
    // args[0] == "ruleset", args[1] == input, rest contains -o
    if args.len() < 4 {
        eprintln!("usage: reflex ruleset <input.json|input.txt> -o <output.rrs>");
        process::exit(1);
    }
    let input = &args[1];
    let output = parse_output_flag(&args[2..])?;

    let src =
        fs::read_to_string(input).map_err(|e| anyhow::anyhow!("cannot read '{}': {}", input, e))?;

    // 自动判断格式：JSON → sing-box rule-set，其他 → 文本规则集
    let compiled = if input.ends_with(".json") || src.trim_start().starts_with('{') {
        CompiledRuleSet::from_singbox_json(&src)?
    } else {
        CompiledRuleSet::from_text(&src)?
    };

    let total = compiled.total_entries();
    let mut buf = Vec::new();
    compiled.serialize(&mut buf)?;
    fs::write(&output, &buf)?;

    println!(
        "compiled {} entries → {} ({} bytes)",
        total,
        output,
        buf.len()
    );
    Ok(())
}

/// `reflex inspect <input.rrs>` — 查看二进制规则集统计
fn cmd_inspect(args: &[String]) -> anyhow::Result<()> {
    if args.len() < 2 {
        eprintln!("usage: reflex inspect <input.rrs>");
        process::exit(1);
    }
    let path = &args[1];
    let data = fs::read(path)?;
    let loaded = LoadedRuleSet::from_bytes(&data)?;

    println!("file:            {}", path);
    println!("domains:         {}", loaded.domains.len());
    println!("domain-suffixes: {}", loaded.domain_suffixes.len());
    println!("domain-keywords: {}", loaded.domain_keywords.len());
    println!("domain-regexes:  {}", loaded.domain_regexes.len());
    println!("ipv4-cidrs:      {}", loaded.ipv4_cidrs.len());
    println!("ipv6-cidrs:      {}", loaded.ipv6_cidrs.len());
    println!("ports:           {}", loaded.ports.len());

    let total = loaded.domains.len()
        + loaded.domain_suffixes.len()
        + loaded.domain_keywords.len()
        + loaded.domain_regexes.len()
        + loaded.ipv4_cidrs.len()
        + loaded.ipv6_cidrs.len()
        + loaded.ports.len();
    println!("total:           {}", total);
    Ok(())
}

/// `reflex test-rule <input.rrs> <domain|ip|port>` — 测试规则集匹配
fn cmd_test_rule(args: &[String]) -> anyhow::Result<()> {
    if args.len() < 3 {
        eprintln!("usage: reflex test-rule <input.rrs> <domain|ip|port>");
        process::exit(1);
    }
    let path = &args[1];
    let query = &args[2];

    let data = fs::read(path)?;
    let loaded = LoadedRuleSet::from_bytes(&data)?;
    let rs = RuleSet::from_loaded(loaded)?;

    let target = parse_match_target(query)?;
    let hit = rs.matches(&target);

    if hit {
        println!("MATCH    {}", query);
    } else {
        println!("NO MATCH {}", query);
    }
    process::exit(if hit { 0 } else { 1 });
}

fn parse_match_target(s: &str) -> anyhow::Result<MatchTarget<'static>> {
    if let Ok(port) = s.parse::<u16>() {
        return Ok(MatchTarget::Port(port));
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(MatchTarget::Ip(ip));
    }
    let leaked: &'static str = Box::leak(s.to_string().into_boxed_str());
    Ok(MatchTarget::Domain(leaked))
}

// ── main ───────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();

    // 首个参数若为子命令则分发，否则走代理运行模式
    if args.len() >= 2 {
        match args[1].as_str() {
            // ── ruleset 编译器子命令 ──────────────────────────────────────
            "ruleset" => {
                return cmd_ruleset(&args[1..]);
            }
            "inspect" => {
                return cmd_inspect(&args[1..]);
            }
            "test-rule" => {
                return cmd_test_rule(&args[1..]);
            }
            // ── config 检测子命令 ─────────────────────────────────────────
            "check" => {
                // `reflex check <config.json>`
                // `reflex check -d /etc/reflex`
                let config_path = args.get(2).map(|s| s.as_str()).unwrap_or("config.json");
                return cmd_check(config_path);
            }
            _ => {}
        }
    }

    // ── 代理运行模式（原有逻辑） ───────────────────────────────────────────────
    run_proxy(args).await
}

fn cmd_check(config_path: &str) -> anyhow::Result<()> {
    use std::path::Path;
    let path = Path::new(config_path);
    let base_dir = path.parent().unwrap_or(Path::new("."));
    let mut config = reflex::config::Config::from_file(path)?;
    config.resolve_paths(base_dir);
    println!("config OK: {}", config_path);
    Ok(())
}

/// 根据 -d / -c 参数组合解析出最终的 (config_path, base_dir)。
///
/// 规则：
/// - 只给了 -c：config 文件路径即为入参，base_dir = config 所在目录
/// - 只给了 -d：在目录里找 config.json；没有则找唯一 .json 文件；否则报错
/// - 都给了：base_dir = -d 指定的目录，config = -d 目录下的 -c 路径（-c 已是绝对路径则直接用）
/// - 都没给：当前工作目录 + config.json
fn resolve_config_and_base(
    config_arg: Option<String>,
    dir_arg: Option<std::path::PathBuf>,
) -> anyhow::Result<(String, std::path::PathBuf)> {
    use std::path::{Path, PathBuf};

    match (config_arg, dir_arg) {
        // -d 指定了目录，自动在目录里找 config
        (None, Some(dir)) => {
            let config_path = find_config_in_dir(&dir)?;
            Ok((config_path.to_string_lossy().into_owned(), dir))
        }
        // 只有 -c，base_dir = config 所在目录
        (Some(cfg), None) => {
            let p = PathBuf::from(&cfg);
            let base = p
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."));
            Ok((cfg, base))
        }
        // -d 和 -c 都给了：config 路径相对于 base_dir 解析（已是绝对路径则直接用）
        (Some(cfg), Some(dir)) => {
            let p = Path::new(&cfg);
            let resolved = if p.is_absolute() {
                p.to_path_buf()
            } else {
                dir.join(p)
            };
            Ok((resolved.to_string_lossy().into_owned(), dir))
        }
        // 什么都没给：cwd + config.json
        (None, None) => {
            let cwd = std::env::current_dir()?;
            let p = cwd.join("config.json");
            Ok((p.to_string_lossy().into_owned(), cwd))
        }
    }
}

/// 在目录里找 config 文件：
/// 1. config.json 存在 → 返回它
/// 2. 没有 config.json，但只有一个 .json 文件 → 返回它
/// 3. 其他情况报错
fn find_config_in_dir(dir: &std::path::Path) -> anyhow::Result<std::path::PathBuf> {
    let config_json = dir.join("config.json");
    if config_json.is_file() {
        return Ok(config_json);
    }

    let json_files: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("cannot read directory '{}'", dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();

    match json_files.len() {
        1 => Ok(json_files.into_iter().next().unwrap()),
        0 => anyhow::bail!(
            "no JSON config file found in '{}'",
            dir.display()
        ),
        _ => anyhow::bail!(
            "multiple JSON files found in '{}' and no config.json;              please specify the file explicitly with -c",
            dir.display()
        ),
    }
}

async fn run_proxy(args: Vec<String>) -> anyhow::Result<()> {
    use std::path::PathBuf;

    #[cfg(unix)]
    raise_nofile_limit();

    #[cfg(feature = "outbound-net")]
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    let mut config_path: Option<String> = None;
    let mut base_dir: Option<PathBuf> = None;
    let mut log_level = None::<String>;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-c" => {
                i += 1;
                config_path = args.get(i).cloned();
            }
            "--dir" | "-d" => {
                i += 1;
                let dir = args
                    .get(i)
                    .map(PathBuf::from)
                    .ok_or_else(|| anyhow::anyhow!("'-d' requires a directory path"))?;
                if !dir.is_dir() {
                    anyhow::bail!("'{}' is not a directory", dir.display());
                }
                base_dir = Some(dir);
            }
            "--log" | "-l" => {
                i += 1;
                log_level = args.get(i).cloned();
            }
            "--help" | "-h" => {
                print_usage();
                return Ok(());
            }
            "--version" | "-v" => {
                println!("reflex {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            other => {
                eprintln!("unknown argument: {other}");
                print_usage();
                process::exit(1);
            }
        }
        i += 1;
    }

    // 解析最终的 base_dir 和 config_path
    let (resolved_config, resolved_base) = resolve_config_and_base(config_path, base_dir)?;

    let mut config = reflex::config::Config::from_file(&resolved_config)?;
    config.resolve_paths(&resolved_base);

    let level = if let Some(ref l) = log_level {
        l.as_str()
    } else {
        match config.log.level {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
            LogLevel::Off => "off",
        }
    };
    init_tracing(level);

    info!(version=env!("CARGO_PKG_VERSION"), config=%resolved_config, "reflex starting");

    let app = App::start_with_config(config).await?;
    tokio::select! {
        _ = signal_shutdown() => { info!("shutdown signal received"); }
        _ = app.wait()        => { info!("all tasks exited"); }
    }
    Ok(())
}

fn init_tracing(level: &str) {
    use std::sync::OnceLock;
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let max = match level {
            "trace" => tracing::Level::TRACE,
            "debug" => tracing::Level::DEBUG,
            "warn" => tracing::Level::WARN,
            "error" => tracing::Level::ERROR,
            "off" => {
                tracing::subscriber::set_global_default(
                    tracing::subscriber::NoSubscriber::default(),
                )
                .ok();
                return;
            }
            _ => tracing::Level::INFO,
        };
        tracing::subscriber::set_global_default(SimpleSubscriber { max_level: max }).ok();
    });
}

struct SimpleSubscriber {
    max_level: tracing::Level,
}
impl tracing::Subscriber for SimpleSubscriber {
    fn enabled(&self, m: &tracing::Metadata<'_>) -> bool {
        m.level() <= &self.max_level
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let meta = event.metadata();
        let mut msg = String::new();
        event.record(&mut SV(&mut msg));
        eprintln!("[{:<5}] {}: {msg}", meta.level(), meta.target());
        let level_str = match *meta.level() {
            tracing::Level::ERROR => "error",
            tracing::Level::WARN => "warning",
            tracing::Level::INFO => "info",
            tracing::Level::DEBUG => "debug",
            tracing::Level::TRACE => "debug",
        };
        reflex::app::clash_api::broadcast_log(level_str, msg);
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}
struct SV<'a>(&'a mut String);
impl tracing::field::Visit for SV<'_> {
    fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
        if f.name() == "message" {
            self.0.push_str(&format!("{v:?}"));
        } else {
            self.0.push_str(&format!(" {}={v:?}", f.name()));
        }
    }
    fn record_str(&mut self, f: &tracing::field::Field, v: &str) {
        if f.name() == "message" {
            self.0.push_str(v);
        } else {
            self.0.push_str(&format!(" {}={v}", f.name()));
        }
    }
}

async fn signal_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut st = signal(SignalKind::terminate()).expect("SIGTERM");
        let mut si = signal(SignalKind::interrupt()).expect("SIGINT");
        tokio::select! { _ = st.recv() => {} _ = si.recv() => {} }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.expect("ctrl-c");
    }
}

fn print_usage() {
    eprintln!(
        r#"reflex {ver}

PROXY MODE:
  reflex [OPTIONS]
    -d, --dir <DIR>       working directory; config and relative paths are resolved here
                            auto-finds config.json, or the sole .json file in the directory
    -c, --config <PATH>   config file path (relative to -d if given) [default: config.json]
    -l, --log <LEVEL>     log level (trace/debug/info/warn/error/off)
    -v, --version
    -h, --help

RULESET COMMANDS:
  reflex ruleset <input.json|input.txt> -o <output.rrs>
        Compile a sing-box JSON rule-set or text rule-set to binary .rrs

  reflex check <config.json>
        Validate config file without starting the proxy

  reflex inspect <input.rrs>
        Show statistics of a compiled .rrs binary

  reflex test-rule <input.rrs> <domain|ip|port>
        Test whether a query matches a compiled rule set

EXAMPLES:
  reflex -d /etc/reflex                   # auto-find config in /etc/reflex/
  reflex -d /etc/reflex -c myconf.json    # use /etc/reflex/myconf.json
  reflex -c /etc/reflex/config.json       # absolute config path
  reflex ruleset geosite-cn.json -o rules/geosite-cn.rrs
  reflex ruleset rules/cn.txt    -o rules/cn.rrs
  reflex check   config.json
  reflex inspect rules/geosite-cn.rrs
  reflex test-rule rules/geosite-cn.rrs www.baidu.com
"#,
        ver = env!("CARGO_PKG_VERSION")
    );
}
