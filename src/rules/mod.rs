pub mod ast;
pub mod banned_dependency;
pub mod banned_import;
pub mod banned_pattern;
pub mod factory;
pub mod file_presence;
pub mod ratchet;
pub mod required_pattern;
pub mod tailwind_dark_mode;
pub mod tailwind_theme_tokens;
pub mod window_pattern;

use crate::config::Severity;
use std::path::{Path, PathBuf};

/// A lint rule that checks source files for violations.
pub trait Rule: Send + Sync {
    /// Unique identifier for this rule (e.g. `"tailwind-dark-mode"`).
    fn id(&self) -> &str;

    /// Severity level reported when the rule fires.
    fn severity(&self) -> Severity;

    /// Optional glob pattern restricting which files are scanned.
    fn file_glob(&self) -> Option<&str>;

    /// Scan a single file and return any violations found.
    fn check_file(&self, ctx: &ScanContext) -> Vec<Violation>;
}

/// The file currently being scanned.
pub struct ScanContext<'a> {
    pub file_path: &'a Path,
    pub content: &'a str,
}

/// Machine-actionable fix data for a violation.
#[derive(Debug, Clone)]
pub struct Fix {
    pub old: String,
    pub new: String,
}

/// A single violation emitted by a rule.
#[derive(Debug, Clone)]
pub struct Violation {
    pub rule_id: String,
    pub severity: Severity,
    pub file: PathBuf,
    pub line: Option<usize>,
    pub column: Option<usize>,
    pub message: String,
    pub suggest: Option<String>,
    pub source_line: Option<String>,
    pub fix: Option<Fix>,
}

/// Errors that can occur when constructing a rule from config.
#[derive(Debug)]
pub enum RuleBuildError {
    InvalidRegex(String, regex::Error),
    MissingField(String, &'static str),
}

impl std::fmt::Display for RuleBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleBuildError::InvalidRegex(id, err) => {
                write!(f, "rule '{}': invalid regex: {}", id, err)
            }
            RuleBuildError::MissingField(id, field) => {
                write!(f, "rule '{}': missing required field '{}'", id, field)
            }
        }
    }
}

impl std::error::Error for RuleBuildError {}
