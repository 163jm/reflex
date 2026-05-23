use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    /// 日志级别
    #[serde(default = "default_level")]
    pub level: LogLevel,

    /// 输出目标：stderr | stdout | /path/to/file
    #[serde(default = "default_output")]
    pub output: String,

    /// 是否在每行前添加时间戳
    #[serde(default = "default_true")]
    pub timestamp: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            output: "stderr".into(),
            timestamp: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Off,
}

fn default_level() -> LogLevel {
    LogLevel::Info
}
fn default_output() -> String {
    "stderr".into()
}
fn default_true() -> bool {
    true
}
