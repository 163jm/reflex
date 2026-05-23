/// 后缀 Trie，按域名 label 倒序存储。
///
/// 插入 "google.com" → 路径 root(0) → "com"(1) → "google"(2, terminal)
/// 查询 "www.google.com" → 0 → 1 → 2(terminal=true) → 命中
/// 查询 "evil.com"       → 0 → 1 → 无 "evil" → 未命中
///
/// # 内存与性能布局
///
/// 所有节点平铺在一个 `Vec<TrieNode>` 中（arena），子节点用 `u32` 索引寻址。
/// 子节点映射使用 `HashMap<Box<str>, u32>`：
/// - 大型规则集（如 geosite-cn）中，`com` 等热门 TLD 节点下可能有数万个子节点，
///   `Vec` 线性扫描会退化为 O(N)，导致高频路由时 CPU 暴涨；
/// - `HashMap` 保证 O(1) 查找，无论子节点数量多少。
use std::collections::HashMap;

pub struct SuffixTrie {
    /// 节点池，下标即节点 ID；`nodes[0]` 永远是 root
    nodes: Vec<TrieNode>,
}

struct TrieNode {
    /// 子节点映射：label → node_index
    /// 用 HashMap 保证 O(1) 查找，避免大型 TLD 节点下线性扫描退化
    children: HashMap<Box<str>, u32>,
    /// 此节点是否是某条规则的终点
    is_terminal: bool,
}

impl TrieNode {
    fn new() -> Self {
        Self {
            children: HashMap::new(),
            is_terminal: false,
        }
    }
}

impl SuffixTrie {
    pub fn new() -> Self {
        Self {
            nodes: vec![TrieNode::new()],
        }
    }

    /// 插入一条后缀规则，如 "google.com"
    pub fn insert(&mut self, domain: &str) {
        let domain = domain.trim_start_matches('.');
        let mut cur: u32 = 0;

        for label in domain.rsplit('.') {
            cur = if let Some(&idx) = self.nodes[cur as usize].children.get(label) {
                idx
            } else {
                let new_idx = self.nodes.len() as u32;
                self.nodes.push(TrieNode::new());
                self.nodes[cur as usize]
                    .children
                    .insert(label.into(), new_idx);
                new_idx
            };
        }

        self.nodes[cur as usize].is_terminal = true;
    }

    /// 判断 domain 是否被任意已插入的后缀规则覆盖。
    ///
    /// 匹配规则：逐 label 从右往左走，一旦走到 terminal 节点即命中。
    /// 例：规则 "google.com" 匹配 "google.com" 及其所有子域名。
    pub fn matches(&self, domain: &str) -> bool {
        let domain = domain.trim_end_matches('.');
        let mut cur: u32 = 0;

        for label in domain.rsplit('.') {
            match self.nodes[cur as usize].children.get(label) {
                Some(&idx) => {
                    cur = idx;
                    if self.nodes[cur as usize].is_terminal {
                        return true;
                    }
                }
                None => return false,
            }
        }
        // 走完所有 label 仍在树上：domain 与某条规则精确相等
        self.nodes[cur as usize].is_terminal
    }

    /// 当前存储的规则数量（terminal 节点数）
    pub fn len(&self) -> usize {
        self.nodes.iter().filter(|n| n.is_terminal).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 节点总数（含 root），用于内存分析
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

impl Default for SuffixTrie {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_suffix() {
        let mut t = SuffixTrie::new();
        t.insert("google.com");

        assert!(t.matches("google.com"));
        assert!(t.matches("www.google.com"));
        assert!(t.matches("mail.google.com"));
        assert!(t.matches("a.b.google.com"));
        assert!(!t.matches("evil.com"));
        assert!(!t.matches("notgoogle.com"));
        assert!(!t.matches("com"));
    }

    #[test]
    fn multiple_rules() {
        let mut t = SuffixTrie::new();
        t.insert("google.com");
        t.insert("github.com");

        assert!(t.matches("api.github.com"));
        assert!(!t.matches("gitlab.com"));
    }

    #[test]
    fn nested_rules() {
        let mut t = SuffixTrie::new();
        t.insert("com");
        t.insert("github.com");

        assert!(t.matches("anything.com"));
        assert!(t.matches("github.com"));
        assert!(t.matches("api.github.com"));
    }

    #[test]
    fn leading_dot() {
        let mut t = SuffixTrie::new();
        t.insert(".google.com");
        assert!(t.matches("www.google.com"));
    }

    #[test]
    fn len() {
        let mut t = SuffixTrie::new();
        assert_eq!(t.len(), 0);
        t.insert("a.com");
        t.insert("b.com");
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn node_count_shared_prefix() {
        // "google.com" 和 "github.com" 共享 "com" 节点
        // root(1) + com(1) + google(1) + github(1) = 4 节点
        let mut t = SuffixTrie::new();
        t.insert("google.com");
        t.insert("github.com");
        assert_eq!(t.node_count(), 4);
    }

    #[test]
    fn duplicate_insert_idempotent() {
        let mut t = SuffixTrie::new();
        t.insert("example.com");
        t.insert("example.com");
        assert_eq!(t.len(), 1);
        assert!(t.matches("example.com"));
    }

    #[test]
    fn large_tld_no_false_positive() {
        // 模拟 com 下挂载大量子域，确保不相关域名不命中
        let mut t = SuffixTrie::new();
        for i in 0..1000 {
            t.insert(&format!("site{i}.com"));
        }
        assert!(t.matches("site0.com"));
        assert!(t.matches("www.site999.com"));
        assert!(!t.matches("evil.com"));
        assert!(!t.matches("site1000.com"));
    }

    #[test]
    fn no_partial_label_match() {
        // "google.com" 不应该匹配 "notgoogle.com"
        let mut t = SuffixTrie::new();
        t.insert("google.com");
        assert!(!t.matches("notgoogle.com"));
        assert!(!t.matches("xgoogle.com"));
    }
}
