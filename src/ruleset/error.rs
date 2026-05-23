use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuleSetError {
    // ── 编译期错误 ────────────────────────────────────────────
    #[error("line {line}: {msg}")]
    ParseError { line: usize, msg: String },

    #[error("invalid CIDR '{0}': {1}")]
    InvalidCidr(String, String),

    #[error("invalid port range '{0}'")]
    InvalidPort(String),

    #[error("invalid regex '{0}': {1}")]
    InvalidRegex(String, String),

    #[error("domain too long (max 255): '{0}'")]
    DomainTooLong(String),

    // ── 加载期错误 ────────────────────────────────────────────
    #[error("bad magic bytes, not a ruleset file")]
    BadMagic,

    #[error("unsupported version {0}")]
    UnsupportedVersion(u8),

    #[error("unknown section type 0x{0:02x}")]
    UnknownSection(u8),

    #[error("section data truncated (expected {expected} bytes, got {got})")]
    Truncated { expected: usize, got: usize },

    #[error("invalid UTF-8 in domain entry")]
    InvalidUtf8,

    #[error("invalid regex in loaded ruleset: {0}")]
    LoadedInvalidRegex(String),

    // ── IO ────────────────────────────────────────────────────
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, RuleSetError>;
