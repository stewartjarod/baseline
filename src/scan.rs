use crate::cli::toml_config::{TomlConfig, TomlRule};
use crate::presets::{self, PresetError};
use crate::rules::factory::{self, FactoryError};
use crate::rules::file_presence::FilePresenceRule;
use crate::rules::{Rule, ScanContext, Violation};
use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

/// A plugin config file containing additional rules.
#[derive(Debug, serde::Deserialize)]
struct PluginConfig {
    #[serde(default)]
    rule: Vec<crate::cli::toml_config::TomlRule>,
}

#[derive(Debug)]
pub enum ScanError {
    ConfigRead(std::io::Error),
    ConfigParse(toml::de::Error),
    GlobParse(globset::Error),
    RuleFactory(FactoryError),
    Preset(PresetError),
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::ConfigRead(e) => write!(f, "failed to read config: {}", e),
            ScanError::ConfigParse(e) => write!(f, "failed to parse config: {}", e),
            ScanError::GlobParse(e) => write!(f, "invalid glob pattern: {}", e),
            ScanError::RuleFactory(e) => write!(f, "failed to build rule: {}", e),
            ScanError::Preset(e) => write!(f, "preset error: {}", e),
        }
    }
}

impl std::error::Error for ScanError {}

pub struct ScanResult {
    pub violations: Vec<Violation>,
    pub files_scanned: usize,
    pub rules_loaded: usize,
    /// For each ratchet rule: (found_count, max_count).
    pub ratchet_counts: HashMap<String, (usize, usize)>,
}

#[derive(Debug, Serialize)]
pub struct BaselineEntry {
    pub rule_id: String,
    pub pattern: String,
    pub count: usize,
}

#[derive(Debug, Serialize)]
pub struct BaselineResult {
    pub entries: Vec<BaselineEntry>,
    pub files_scanned: usize,
}

/// A fully-built rule with all its compiled metadata.
/// This avoids index-mismatch bugs by keeping conditioning data
/// alongside the rule rather than looking it up by index.
struct BuiltRule {
    rule: Box<dyn Rule>,
    inclusion_glob: Option<GlobSet>,
    exclusion_glob: Option<GlobSet>,
    file_contains: Option<String>,
    file_not_contains: Option<String>,
}

/// Result of building rules from config.
struct BuiltRules {
    rules: Vec<BuiltRule>,
    ratchet_thresholds: HashMap<String, usize>,
    file_presence_rules: Vec<FilePresenceRule>,
}

/// Build rules from resolved TOML rules. Shared by run_scan and run_scan_stdin.
fn build_rules(resolved_rules: &[TomlRule]) -> Result<BuiltRules, ScanError> {
    let mut rules: Vec<BuiltRule> = Vec::new();
    let mut ratchet_thresholds: HashMap<String, usize> = HashMap::new();
    let mut file_presence_rules: Vec<FilePresenceRule> = Vec::new();

    for toml_rule in resolved_rules {
        let rule_config = toml_rule.to_rule_config();

        // File-presence rules are handled separately (they check existence, not content)
        if toml_rule.rule_type == "file-presence" {
            if let Ok(fp_rule) = FilePresenceRule::new(&rule_config) {
                file_presence_rules.push(fp_rule);
            }
            continue;
        }

        let rule = factory::build_rule(&toml_rule.rule_type, &rule_config)
            .map_err(ScanError::RuleFactory)?;

        if toml_rule.rule_type == "ratchet" {
            if let Some(max) = toml_rule.max_count {
                ratchet_thresholds.insert(rule.id().to_string(), max);
            }
        }

        // Build per-rule inclusion glob
        let inclusion_glob = if let Some(ref pattern) = rule.file_glob() {
            let gs = GlobSetBuilder::new()
                .add(Glob::new(pattern).map_err(ScanError::GlobParse)?)
                .build()
                .map_err(ScanError::GlobParse)?;
            Some(gs)
        } else {
            None
        };

        // Build per-rule exclusion glob
        let exclusion_glob = if !toml_rule.exclude_glob.is_empty() {
            Some(build_glob_set(&toml_rule.exclude_glob)?)
        } else {
            None
        };

        rules.push(BuiltRule {
            rule,
            inclusion_glob,
            exclusion_glob,
            file_contains: toml_rule.file_contains.clone(),
            file_not_contains: toml_rule.file_not_contains.clone(),
        });
    }

    Ok(BuiltRules {
        rules,
        ratchet_thresholds,
        file_presence_rules,
    })
}

/// Check if a rule matches a file path (inclusion + exclusion globs).
fn rule_matches_file(built: &BuiltRule, file_str: &str, file_name: &str) -> bool {
    let included = match &built.inclusion_glob {
        Some(gs) => gs.is_match(file_str) || gs.is_match(file_name),
        None => true,
    };
    if !included {
        return false;
    }
    if let Some(ref exc) = built.exclusion_glob {
        if exc.is_match(file_str) || exc.is_match(file_name) {
            return false;
        }
    }
    true
}

/// Check file-context conditioning (file_contains / file_not_contains).
fn passes_file_conditioning(built: &BuiltRule, content: &str) -> bool {
    if let Some(ref needle) = built.file_contains {
        if !content.contains(needle.as_str()) {
            return false;
        }
    }
    if let Some(ref needle) = built.file_not_contains {
        if content.contains(needle.as_str()) {
            return false;
        }
    }
    true
}

/// Run rules against content and collect violations, filtering escape-hatch comments.
fn run_rules_on_content(
    built_rules: &[BuiltRule],
    file_path: &Path,
    content: &str,
    file_str: &str,
    file_name: &str,
) -> Vec<Violation> {
    let mut violations = Vec::new();
    let content_lines: Vec<&str> = content.lines().collect();
    let ctx = ScanContext {
        file_path,
        content,
    };

    for built in built_rules {
        if !rule_matches_file(built, file_str, file_name) {
            continue;
        }
        if !passes_file_conditioning(built, content) {
            continue;
        }

        let file_violations = built.rule.check_file(&ctx);
        for v in file_violations {
            if let Some(line_num) = v.line {
                if is_suppressed(&content_lines, line_num, &v.rule_id) {
                    continue;
                }
            }
            violations.push(v);
        }
    }

    violations
}

/// Run a full scan: parse config, build rules, walk files, collect violations.
pub fn run_scan(config_path: &Path, target_paths: &[PathBuf]) -> Result<ScanResult, ScanError> {
    // 1. Read and parse TOML config
    let config_text = fs::read_to_string(config_path).map_err(ScanError::ConfigRead)?;
    let toml_config: TomlConfig = toml::from_str(&config_text).map_err(ScanError::ConfigParse)?;

    // 2. Load plugin rules from external TOML files
    let mut plugin_rules: Vec<crate::cli::toml_config::TomlRule> = Vec::new();
    for plugin_path in &toml_config.guardrails.plugins {
        let plugin_text = fs::read_to_string(plugin_path).map_err(ScanError::ConfigRead)?;
        let plugin_config: PluginConfig =
            toml::from_str(&plugin_text).map_err(ScanError::ConfigParse)?;
        plugin_rules.extend(plugin_config.rule);
    }

    // 3. Resolve presets and merge with user-defined rules + plugin rules
    let mut all_user_rules = toml_config.rule.clone();
    all_user_rules.extend(plugin_rules);

    let resolved_rules = presets::resolve_rules(
        &toml_config.guardrails.extends,
        &all_user_rules,
    )
    .map_err(ScanError::Preset)?;

    // 4. Build exclude glob set
    let exclude_set = build_glob_set(&toml_config.guardrails.exclude)?;

    // 5. Build rules via factory
    let built = build_rules(&resolved_rules)?;
    let rules_loaded = built.rules.len();

    // 6. Walk target paths and collect files
    let files = collect_files(target_paths, &exclude_set);

    // 7. Run rules on each file
    let mut violations: Vec<Violation> = Vec::new();
    let mut files_scanned = 0;

    for file_path in &files {
        let file_str = file_path.to_string_lossy();
        let file_name = file_path.file_name().unwrap_or_default().to_string_lossy();

        // Pre-check: does ANY rule match this file? If not, skip the read entirely.
        let any_match = built.rules.iter().any(|r| rule_matches_file(r, &file_str, &file_name));
        if !any_match {
            continue;
        }

        let content = match fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => continue, // skip binary/unreadable files
        };

        files_scanned += 1;
        let mut file_violations =
            run_rules_on_content(&built.rules, file_path, &content, &file_str, &file_name);
        violations.append(&mut file_violations);
    }

    // 8. Run file-presence checks
    for fp_rule in &built.file_presence_rules {
        let mut fp_violations = fp_rule.check_paths(target_paths);
        violations.append(&mut fp_violations);
    }

    // 9. Apply ratchet thresholds
    let ratchet_counts = apply_ratchet_thresholds(&mut violations, &built.ratchet_thresholds);

    Ok(ScanResult {
        violations,
        files_scanned,
        rules_loaded,
        ratchet_counts,
    })
}

/// Suppress ratchet violations that are within budget. Returns counts for display.
fn apply_ratchet_thresholds(
    violations: &mut Vec<Violation>,
    thresholds: &HashMap<String, usize>,
) -> HashMap<String, (usize, usize)> {
    if thresholds.is_empty() {
        return HashMap::new();
    }

    // Count violations per ratchet rule
    let mut counts: HashMap<String, usize> = HashMap::new();
    for v in violations.iter() {
        if thresholds.contains_key(&v.rule_id) {
            *counts.entry(v.rule_id.clone()).or_insert(0) += 1;
        }
    }

    // Build result map and determine which rules to suppress
    let mut result: HashMap<String, (usize, usize)> = HashMap::new();
    let mut suppress: std::collections::HashSet<String> = std::collections::HashSet::new();

    for (rule_id, &max) in thresholds {
        let found = counts.get(rule_id).copied().unwrap_or(0);
        result.insert(rule_id.clone(), (found, max));
        if found <= max {
            suppress.insert(rule_id.clone());
        }
    }

    // Remove suppressed violations
    if !suppress.is_empty() {
        violations.retain(|v| !suppress.contains(&v.rule_id));
    }

    result
}

/// Run a scan on stdin content with a virtual filename.
pub fn run_scan_stdin(
    config_path: &Path,
    content: &str,
    filename: &str,
) -> Result<ScanResult, ScanError> {
    let config_text = fs::read_to_string(config_path).map_err(ScanError::ConfigRead)?;
    let toml_config: TomlConfig = toml::from_str(&config_text).map_err(ScanError::ConfigParse)?;

    let resolved_rules = presets::resolve_rules(
        &toml_config.guardrails.extends,
        &toml_config.rule,
    )
    .map_err(ScanError::Preset)?;

    let built = build_rules(&resolved_rules)?;
    let rules_loaded = built.rules.len();

    let file_path = PathBuf::from(filename);
    let file_str = file_path.to_string_lossy();
    let file_name = file_path.file_name().unwrap_or_default().to_string_lossy();

    let violations =
        run_rules_on_content(&built.rules, &file_path, content, &file_str, &file_name);

    let mut violations = violations;
    let ratchet_counts = apply_ratchet_thresholds(&mut violations, &built.ratchet_thresholds);

    Ok(ScanResult {
        violations,
        files_scanned: 1,
        rules_loaded,
        ratchet_counts,
    })
}

/// Run baseline counting: parse config, build only ratchet rules, count matches.
pub fn run_baseline(
    config_path: &Path,
    target_paths: &[PathBuf],
) -> Result<BaselineResult, ScanError> {
    let config_text = fs::read_to_string(config_path).map_err(ScanError::ConfigRead)?;
    let toml_config: TomlConfig = toml::from_str(&config_text).map_err(ScanError::ConfigParse)?;

    // Resolve presets and merge with user-defined rules
    let resolved_rules = presets::resolve_rules(
        &toml_config.guardrails.extends,
        &toml_config.rule,
    )
    .map_err(ScanError::Preset)?;

    let exclude_set = build_glob_set(&toml_config.guardrails.exclude)?;

    // Build only ratchet rules
    let mut rules: Vec<(Box<dyn Rule>, Option<GlobSet>, String)> = Vec::new();
    for toml_rule in &resolved_rules {
        if toml_rule.rule_type != "ratchet" {
            continue;
        }
        let rule_config = toml_rule.to_rule_config();
        let rule = factory::build_rule(&toml_rule.rule_type, &rule_config)
            .map_err(ScanError::RuleFactory)?;

        let pattern = toml_rule.pattern.clone().unwrap_or_default();

        let rule_glob = if let Some(ref pat) = rule.file_glob() {
            let gs = GlobSetBuilder::new()
                .add(Glob::new(pat).map_err(ScanError::GlobParse)?)
                .build()
                .map_err(ScanError::GlobParse)?;
            Some(gs)
        } else {
            None
        };

        rules.push((rule, rule_glob, pattern));
    }

    let files = collect_files(target_paths, &exclude_set);

    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut files_scanned = 0;

    for file_path in &files {
        let content = match fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        files_scanned += 1;
        let ctx = ScanContext {
            file_path,
            content: &content,
        };

        for (rule, rule_glob, _) in &rules {
            if let Some(ref gs) = rule_glob {
                let file_str = file_path.to_string_lossy();
                let file_name = file_path.file_name().unwrap_or_default().to_string_lossy();
                if !gs.is_match(&*file_str) && !gs.is_match(&*file_name) {
                    continue;
                }
            }

            let violations = rule.check_file(&ctx);
            *counts.entry(rule.id().to_string()).or_insert(0) += violations.len();
        }
    }

    let entries: Vec<BaselineEntry> = rules
        .iter()
        .map(|(rule, _, pattern)| BaselineEntry {
            rule_id: rule.id().to_string(),
            pattern: pattern.clone(),
            count: counts.get(rule.id()).copied().unwrap_or(0),
        })
        .collect();

    Ok(BaselineResult {
        entries,
        files_scanned,
    })
}

/// Check if a violation is suppressed by an escape-hatch comment.
/// Looks for `guardrails:allow-{rule_id}` on the same line or the line before.
fn is_suppressed(lines: &[&str], line_num: usize, rule_id: &str) -> bool {
    let allow_marker = format!("guardrails:allow-{}", rule_id);
    let allow_all = "guardrails:allow-all";

    // Check current line (1-indexed)
    if line_num > 0 && line_num <= lines.len() {
        let line = lines[line_num - 1];
        if line.contains(&allow_marker) || line.contains(allow_all) {
            return true;
        }
    }

    // Check previous line (next-line style: `// guardrails:allow-next-line`)
    if line_num >= 2 && line_num <= lines.len() {
        let prev = lines[line_num - 2];
        let allow_next = format!("guardrails:allow-next-line {}", rule_id);
        if prev.contains(&allow_next)
            || prev.contains("guardrails:allow-next-line all")
        {
            return true;
        }
    }

    false
}

fn collect_files(target_paths: &[PathBuf], exclude_set: &GlobSet) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = Vec::new();
    for target in target_paths {
        if target.is_file() {
            files.push(target.clone());
        } else {
            // Use the `ignore` crate to automatically respect .gitignore,
            // .ignore, and skip hidden files/directories (.git, etc.).
            let walker = WalkBuilder::new(target)
                .hidden(true) // skip hidden files/dirs like .git
                .git_ignore(true) // respect .gitignore
                .git_global(true) // respect global gitignore
                .git_exclude(true) // respect .git/info/exclude
                .build();

            for entry in walker.into_iter().filter_map(|e| e.ok()) {
                if entry.file_type().map_or(false, |ft| ft.is_file()) {
                    let path = entry.into_path();
                    let rel = path.strip_prefix(target).unwrap_or(&path);
                    if exclude_set.is_match(rel.to_string_lossy().as_ref()) {
                        continue;
                    }
                    files.push(path);
                }
            }
        }
    }
    files
}

fn build_glob_set(patterns: &[String]) -> Result<GlobSet, ScanError> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(Glob::new(pattern).map_err(ScanError::GlobParse)?);
    }
    builder.build().map_err(ScanError::GlobParse)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Severity;

    fn make_violation(rule_id: &str) -> Violation {
        Violation {
            rule_id: rule_id.to_string(),
            severity: Severity::Error,
            file: PathBuf::from("test.ts"),
            line: Some(1),
            column: Some(1),
            message: "test".to_string(),
            suggest: None,
            source_line: None,
            fix: None,
        }
    }

    #[test]
    fn ratchet_under_budget_suppresses() {
        let mut violations = vec![
            make_violation("ratchet-legacy"),
            make_violation("ratchet-legacy"),
            make_violation("other-rule"),
        ];
        let mut thresholds = HashMap::new();
        thresholds.insert("ratchet-legacy".to_string(), 5);

        let counts = apply_ratchet_thresholds(&mut violations, &thresholds);

        assert_eq!(violations.len(), 1); // only "other-rule" remains
        assert_eq!(violations[0].rule_id, "other-rule");
        assert_eq!(counts["ratchet-legacy"], (2, 5));
    }

    #[test]
    fn ratchet_over_budget_keeps_all() {
        let mut violations = vec![
            make_violation("ratchet-legacy"),
            make_violation("ratchet-legacy"),
            make_violation("ratchet-legacy"),
            make_violation("other-rule"),
        ];
        let mut thresholds = HashMap::new();
        thresholds.insert("ratchet-legacy".to_string(), 2);

        let counts = apply_ratchet_thresholds(&mut violations, &thresholds);

        assert_eq!(violations.len(), 4); // all kept
        assert_eq!(counts["ratchet-legacy"], (3, 2));
    }

    #[test]
    fn ratchet_exactly_at_budget_suppresses() {
        let mut violations = vec![
            make_violation("ratchet-legacy"),
            make_violation("ratchet-legacy"),
        ];
        let mut thresholds = HashMap::new();
        thresholds.insert("ratchet-legacy".to_string(), 2);

        let counts = apply_ratchet_thresholds(&mut violations, &thresholds);

        assert_eq!(violations.len(), 0); // suppressed (at budget)
        assert_eq!(counts["ratchet-legacy"], (2, 2));
    }

    #[test]
    fn no_ratchet_rules_is_noop() {
        let mut violations = vec![make_violation("other-rule")];
        let thresholds = HashMap::new();

        let counts = apply_ratchet_thresholds(&mut violations, &thresholds);

        assert_eq!(violations.len(), 1);
        assert!(counts.is_empty());
    }

    #[test]
    fn ratchet_zero_with_matches_keeps_all() {
        let mut violations = vec![make_violation("ratchet-zero")];
        let mut thresholds = HashMap::new();
        thresholds.insert("ratchet-zero".to_string(), 0);

        let counts = apply_ratchet_thresholds(&mut violations, &thresholds);

        assert_eq!(violations.len(), 1);
        assert_eq!(counts["ratchet-zero"], (1, 0));
    }

    #[test]
    fn ratchet_zero_no_matches_suppresses() {
        let mut violations: Vec<Violation> = vec![];
        let mut thresholds = HashMap::new();
        thresholds.insert("ratchet-zero".to_string(), 0);

        let counts = apply_ratchet_thresholds(&mut violations, &thresholds);

        assert!(violations.is_empty());
        assert_eq!(counts["ratchet-zero"], (0, 0));
    }

    // ── is_suppressed tests ──

    #[test]
    fn suppressed_by_same_line_allow() {
        let lines = vec![
            "let x = style={{ color: 'red' }}; // guardrails:allow-no-inline-styles",
        ];
        assert!(is_suppressed(&lines, 1, "no-inline-styles"));
    }

    #[test]
    fn suppressed_by_allow_all() {
        let lines = vec![
            "let x = style={{ color: 'red' }}; // guardrails:allow-all",
        ];
        assert!(is_suppressed(&lines, 1, "no-inline-styles"));
        assert!(is_suppressed(&lines, 1, "any-other-rule"));
    }

    #[test]
    fn suppressed_by_allow_next_line() {
        let lines = vec![
            "// guardrails:allow-next-line no-inline-styles",
            "let x = style={{ color: 'red' }};",
        ];
        assert!(is_suppressed(&lines, 2, "no-inline-styles"));
    }

    #[test]
    fn suppressed_by_allow_next_line_all() {
        let lines = vec![
            "// guardrails:allow-next-line all",
            "let x = style={{ color: 'red' }};",
        ];
        assert!(is_suppressed(&lines, 2, "no-inline-styles"));
    }

    #[test]
    fn not_suppressed_wrong_rule_id() {
        let lines = vec![
            "let x = style={{ color: 'red' }}; // guardrails:allow-other-rule",
        ];
        assert!(!is_suppressed(&lines, 1, "no-inline-styles"));
    }

    #[test]
    fn not_suppressed_no_comment() {
        let lines = vec![
            "let x = style={{ color: 'red' }};",
        ];
        assert!(!is_suppressed(&lines, 1, "no-inline-styles"));
    }

    #[test]
    fn not_suppressed_next_line_wrong_rule() {
        let lines = vec![
            "// guardrails:allow-next-line other-rule",
            "let x = style={{ color: 'red' }};",
        ];
        assert!(!is_suppressed(&lines, 2, "no-inline-styles"));
    }

    #[test]
    fn suppressed_line_zero_is_safe() {
        let lines = vec!["some content"];
        // line_num 0 should not panic
        assert!(!is_suppressed(&lines, 0, "any-rule"));
    }

    #[test]
    fn suppressed_past_end_is_safe() {
        let lines = vec!["some content"];
        // line_num past end should not panic
        assert!(!is_suppressed(&lines, 5, "any-rule"));
    }
}
