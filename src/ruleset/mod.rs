pub mod compiler;
pub mod error;
pub mod format;
pub mod loader;
pub mod matcher;
pub mod trie;

// 顶层重导出，方便使用方不用知道内部模块结构
pub use compiler::CompiledRuleSet;
pub use error::{Result, RuleSetError};
pub use loader::LoadedRuleSet;
pub use matcher::{MatchTarget, RuleSet};
