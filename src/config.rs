/// Severity level for a rule violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

/// Parsed rule configuration from `guardrails.toml`.
#[derive(Debug, Clone)]
pub struct RuleConfig {
    pub id: String,
    pub severity: Severity,
    pub message: String,
    pub suggest: Option<String>,
    pub glob: Option<String>,
    /// Classes exempt from enforcement.
    pub allowed_classes: Vec<String>,
    /// User-provided token mappings (`"raw-class=semantic-class"`).
    pub token_map: Vec<String>,
    /// Literal pattern to search for (used by ratchet and banned-pattern rules).
    pub pattern: Option<String>,
    /// Maximum allowed occurrences (used by ratchet rules).
    pub max_count: Option<usize>,
    /// Banned package names (used by banned-import and banned-dependency rules).
    pub packages: Vec<String>,
    /// Whether `pattern` should be interpreted as a regex (default: false).
    pub regex: bool,
    /// Manifest filename to check (used by banned-dependency, defaults to `package.json`).
    pub manifest: Option<String>,
    /// Glob patterns for files to exclude from this rule.
    pub exclude_glob: Vec<String>,
    /// Only run rule if file contains this string.
    pub file_contains: Option<String>,
    /// Only run rule if file does NOT contain this string.
    pub file_not_contains: Option<String>,
    /// Required files that must exist (used by file-presence rule).
    pub required_files: Vec<String>,
    /// Forbidden files that must NOT exist (used by file-presence rule).
    pub forbidden_files: Vec<String>,
    /// Condition pattern: only enforce required-pattern if this pattern is present.
    pub condition_pattern: Option<String>,
}

impl Default for RuleConfig {
    fn default() -> Self {
        Self {
            id: String::new(),
            severity: Severity::Warning,
            message: String::new(),
            suggest: None,
            glob: None,
            allowed_classes: Vec::new(),
            token_map: Vec::new(),
            pattern: None,
            max_count: None,
            packages: Vec::new(),
            regex: false,
            manifest: None,
            exclude_glob: Vec::new(),
            file_contains: None,
            file_not_contains: None,
            required_files: Vec::new(),
            forbidden_files: Vec::new(),
            condition_pattern: None,
        }
    }
}
