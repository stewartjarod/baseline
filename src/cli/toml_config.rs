use crate::config::{RuleConfig, Severity};
use serde::Deserialize;

/// Top-level TOML config file structure.
#[derive(Debug, Deserialize)]
pub struct TomlConfig {
    pub baseline: BaselineSection,
    #[serde(default)]
    pub rule: Vec<TomlRule>,
}

/// A `[[baseline.scoped]]` entry that applies a preset to a specific directory.
#[derive(Debug, Clone, Deserialize)]
pub struct ScopedPreset {
    pub preset: String,
    pub path: String,
}

/// The `[baseline]` section.
#[derive(Debug, Deserialize)]
pub struct BaselineSection {
    #[allow(dead_code)]
    pub name: Option<String>,
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub extends: Vec<String>,
    /// Paths to plugin TOML files containing additional rules
    #[serde(default)]
    pub plugins: Vec<String>,
    /// Scoped presets: apply a preset only to files under a specific path
    #[serde(default)]
    pub scoped: Vec<ScopedPreset>,
}

/// A single `[[rule]]` entry.
#[derive(Debug, Clone, Deserialize)]
pub struct TomlRule {
    pub id: String,
    #[serde(rename = "type")]
    pub rule_type: String,
    #[serde(default = "default_severity")]
    pub severity: String,
    pub glob: Option<String>,
    #[serde(default)]
    pub message: String,
    pub suggest: Option<String>,
    #[serde(default)]
    pub allowed_classes: Vec<String>,
    #[serde(default)]
    pub token_map: Vec<String>,
    pub pattern: Option<String>,
    pub max_count: Option<usize>,
    #[serde(default)]
    pub packages: Vec<String>,
    #[serde(default)]
    pub regex: bool,
    pub manifest: Option<String>,
    #[serde(default)]
    pub exclude_glob: Vec<String>,
    pub file_contains: Option<String>,
    pub file_not_contains: Option<String>,
    #[serde(default)]
    pub required_files: Vec<String>,
    #[serde(default)]
    pub forbidden_files: Vec<String>,
    pub condition_pattern: Option<String>,
}

fn default_severity() -> String {
    "warning".into()
}

impl Default for TomlRule {
    fn default() -> Self {
        Self {
            id: String::new(),
            rule_type: String::new(),
            severity: default_severity(),
            glob: None,
            message: String::new(),
            suggest: None,
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

impl TomlRule {
    /// Convert to the core `RuleConfig` type.
    pub fn to_rule_config(&self) -> RuleConfig {
        let severity = match self.severity.to_lowercase().as_str() {
            "error" => Severity::Error,
            _ => Severity::Warning,
        };

        RuleConfig {
            id: self.id.clone(),
            severity,
            message: self.message.clone(),
            suggest: self.suggest.clone(),
            glob: self.glob.clone(),
            allowed_classes: self.allowed_classes.clone(),
            token_map: self.token_map.clone(),
            pattern: self.pattern.clone(),
            max_count: self.max_count,
            packages: self.packages.clone(),
            regex: self.regex,
            manifest: self.manifest.clone(),
            exclude_glob: self.exclude_glob.clone(),
            file_contains: self.file_contains.clone(),
            file_not_contains: self.file_not_contains.clone(),
            required_files: self.required_files.clone(),
            forbidden_files: self.forbidden_files.clone(),
            condition_pattern: self.condition_pattern.clone(),
        }
    }
}
