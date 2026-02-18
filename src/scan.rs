use crate::cli::toml_config::{TomlConfig, TomlRule};
use crate::git_diff;
use crate::presets::{self, PresetError};
use crate::rules::factory::{self, FactoryError};
use crate::rules::file_presence::FilePresenceRule;
use crate::rules::{Rule, ScanContext, Violation};
use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;
use rayon::prelude::*;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

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
    GitDiff(String),
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::ConfigRead(e) => write!(f, "failed to read config: {}", e),
            ScanError::ConfigParse(e) => write!(f, "failed to parse config: {}", e),
            ScanError::GlobParse(e) => write!(f, "invalid glob pattern: {}", e),
            ScanError::RuleFactory(e) => write!(f, "failed to build rule: {}", e),
            ScanError::Preset(e) => write!(f, "preset error: {}", e),
            ScanError::GitDiff(e) => write!(f, "git diff failed: {}", e),
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
    /// Number of changed files when using --changed-only.
    pub changed_files_count: Option<usize>,
    /// Base ref used for diff when using --changed-only.
    pub base_ref: Option<String>,
}

#[derive(Debug, Serialize, serde::Deserialize)]
pub struct BaselineEntry {
    pub rule_id: String,
    pub pattern: String,
    pub count: usize,
}

#[derive(Debug, Serialize, serde::Deserialize)]
pub struct BaselineResult {
    pub entries: Vec<BaselineEntry>,
    pub files_scanned: usize,
}

/// A group of rules that share the same glob patterns.
/// Glob matching is done once per group, amortizing the cost when
/// multiple rules use the same inclusion/exclusion patterns.
struct RuleGroup {
    inclusion_glob: Option<GlobSet>,
    exclusion_glob: Option<GlobSet>,
    rules: Vec<RuleWithConditioning>,
}

/// A single rule with its conditioning data and pre-computed suppression strings.
struct RuleWithConditioning {
    rule: Box<dyn Rule>,
    file_contains: Option<String>,
    file_not_contains: Option<String>,
    /// Pre-computed `"baseline:allow-{rule_id}"` string.
    allow_marker: String,
    /// Pre-computed `"baseline:allow-next-line {rule_id}"` string.
    allow_next_line: String,
}

/// Result of building rules from config.
struct BuiltRules {
    rule_groups: Vec<RuleGroup>,
    ratchet_thresholds: HashMap<String, usize>,
    file_presence_rules: Vec<FilePresenceRule>,
}

/// Build rules from resolved TOML rules. Shared by run_scan and run_scan_stdin.
fn build_rules(resolved_rules: &[TomlRule]) -> Result<BuiltRules, ScanError> {
    let mut ratchet_thresholds: HashMap<String, usize> = HashMap::new();
    let mut file_presence_rules: Vec<FilePresenceRule> = Vec::new();

    // Intermediate representation before grouping
    struct IntermediateRule {
        rule: Box<dyn Rule>,
        inclusion_pattern: Option<String>,
        exclusion_patterns: Vec<String>,
        file_contains: Option<String>,
        file_not_contains: Option<String>,
    }

    let mut intermediates: Vec<IntermediateRule> = Vec::new();

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

        let inclusion_pattern = rule.file_glob().map(|s| s.to_string());
        let exclusion_patterns = toml_rule.exclude_glob.clone();

        intermediates.push(IntermediateRule {
            rule,
            inclusion_pattern,
            exclusion_patterns,
            file_contains: toml_rule.file_contains.clone(),
            file_not_contains: toml_rule.file_not_contains.clone(),
        });
    }

    // Group rules by (inclusion_pattern, exclusion_patterns) to avoid redundant glob matching.
    let mut groups: Vec<((Option<String>, Vec<String>), Vec<IntermediateRule>)> = Vec::new();

    for ir in intermediates {
        let key = (ir.inclusion_pattern.clone(), ir.exclusion_patterns.clone());
        if let Some(group) = groups.iter_mut().find(|(k, _)| *k == key) {
            group.1.push(ir);
        } else {
            groups.push((key, vec![ir]));
        }
    }

    // Build RuleGroups with compiled GlobSets (once per unique pattern)
    let mut rule_groups: Vec<RuleGroup> = Vec::new();
    for ((inc_pattern, exc_patterns), intermediates) in groups {
        let inclusion_glob = if let Some(ref pattern) = inc_pattern {
            Some(build_glob_set_from_pattern(pattern)?)
        } else {
            None
        };

        let exclusion_glob = if !exc_patterns.is_empty() {
            Some(build_glob_set(&exc_patterns)?)
        } else {
            None
        };

        let rules = intermediates
            .into_iter()
            .map(|ir| {
                let id = ir.rule.id().to_string();
                RuleWithConditioning {
                    rule: ir.rule,
                    file_contains: ir.file_contains,
                    file_not_contains: ir.file_not_contains,
                    allow_marker: format!("baseline:allow-{}", id),
                    allow_next_line: format!("baseline:allow-next-line {}", id),
                }
            })
            .collect();

        rule_groups.push(RuleGroup {
            inclusion_glob,
            exclusion_glob,
            rules,
        });
    }

    Ok(BuiltRules {
        rule_groups,
        ratchet_thresholds,
        file_presence_rules,
    })
}

/// Check if a rule group matches a file path (inclusion + exclusion globs).
fn group_matches_file(group: &RuleGroup, file_str: &str, file_name: &str) -> bool {
    let included = match &group.inclusion_glob {
        Some(gs) => gs.is_match(file_str) || gs.is_match(file_name),
        None => true,
    };
    if !included {
        return false;
    }
    if let Some(ref exc) = group.exclusion_glob {
        if exc.is_match(file_str) || exc.is_match(file_name) {
            return false;
        }
    }
    true
}

/// Check file-context conditioning (file_contains / file_not_contains) with caching.
fn passes_file_conditioning_cached<'a>(
    rule: &'a RuleWithConditioning,
    content: &str,
    cache: &mut HashMap<&'a str, bool>,
) -> bool {
    if let Some(ref needle) = rule.file_contains {
        let &mut result = cache
            .entry(needle.as_str())
            .or_insert_with(|| content.contains(needle.as_str()));
        if !result {
            return false;
        }
    }
    if let Some(ref needle) = rule.file_not_contains {
        let &mut result = cache
            .entry(needle.as_str())
            .or_insert_with(|| content.contains(needle.as_str()));
        if result {
            return false;
        }
    }
    true
}

/// Run rules against content and collect violations, filtering escape-hatch comments.
fn run_rules_on_content(
    rule_groups: &[RuleGroup],
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
    let mut conditioning_cache: HashMap<&str, bool> = HashMap::new();

    for group in rule_groups {
        if !group_matches_file(group, file_str, file_name) {
            continue;
        }

        for rule_cond in &group.rules {
            if !passes_file_conditioning_cached(rule_cond, content, &mut conditioning_cache) {
                continue;
            }

            let file_violations = rule_cond.rule.check_file(&ctx);
            for v in file_violations {
                if let Some(line_num) = v.line {
                    if is_suppressed(
                        &content_lines,
                        line_num,
                        &rule_cond.allow_marker,
                        &rule_cond.allow_next_line,
                    ) {
                        continue;
                    }
                }
                violations.push(v);
            }
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
    for plugin_path in &toml_config.baseline.plugins {
        let plugin_text = fs::read_to_string(plugin_path).map_err(ScanError::ConfigRead)?;
        let plugin_config: PluginConfig =
            toml::from_str(&plugin_text).map_err(ScanError::ConfigParse)?;
        plugin_rules.extend(plugin_config.rule);
    }

    // 3. Resolve presets and merge with user-defined rules + plugin rules
    let mut all_user_rules = toml_config.rule.clone();
    all_user_rules.extend(plugin_rules);

    let mut resolved_rules = presets::resolve_rules(
        &toml_config.baseline.extends,
        &all_user_rules,
    )
    .map_err(ScanError::Preset)?;

    // 3b. Resolve scoped presets and append
    let scoped_rules = presets::resolve_scoped_rules(
        &toml_config.baseline.scoped,
        &all_user_rules,
    )
    .map_err(ScanError::Preset)?;
    resolved_rules.extend(scoped_rules);

    // 4. Build exclude glob set
    let exclude_set = build_glob_set(&toml_config.baseline.exclude)?;

    // 5. Build rules via factory
    let built = build_rules(&resolved_rules)?;
    let rules_loaded: usize = built.rule_groups.iter().map(|g| g.rules.len()).sum();

    // 6. Walk target paths and collect files
    let files = collect_files(target_paths, &exclude_set);

    // 7. Run rules on each file (parallel)
    let files_scanned = AtomicUsize::new(0);

    let mut violations: Vec<Violation> = files
        .par_iter()
        .filter_map(|file_path| {
            let file_str = file_path.to_string_lossy();
            let file_name = file_path.file_name().unwrap_or_default().to_string_lossy();

            // Pre-check: does ANY rule group match this file? If not, skip the read entirely.
            let any_match = built
                .rule_groups
                .iter()
                .any(|g| group_matches_file(g, &file_str, &file_name));
            if !any_match {
                return None;
            }

            let content = fs::read_to_string(file_path).ok()?;

            files_scanned.fetch_add(1, Ordering::Relaxed);
            let file_violations = run_rules_on_content(
                &built.rule_groups,
                file_path,
                &content,
                &file_str,
                &file_name,
            );
            if file_violations.is_empty() {
                None
            } else {
                Some(file_violations)
            }
        })
        .flatten()
        .collect();

    // 8. Run file-presence checks
    for fp_rule in &built.file_presence_rules {
        let mut fp_violations = fp_rule.check_paths(target_paths);
        violations.append(&mut fp_violations);
    }

    // 9. Apply ratchet thresholds
    let ratchet_counts = apply_ratchet_thresholds(&mut violations, &built.ratchet_thresholds);

    Ok(ScanResult {
        violations,
        files_scanned: files_scanned.load(Ordering::Relaxed),
        rules_loaded,
        ratchet_counts,
        changed_files_count: None,
        base_ref: None,
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

    let mut resolved_rules = presets::resolve_rules(
        &toml_config.baseline.extends,
        &toml_config.rule,
    )
    .map_err(ScanError::Preset)?;

    let scoped_rules = presets::resolve_scoped_rules(
        &toml_config.baseline.scoped,
        &toml_config.rule,
    )
    .map_err(ScanError::Preset)?;
    resolved_rules.extend(scoped_rules);

    let built = build_rules(&resolved_rules)?;
    let rules_loaded: usize = built.rule_groups.iter().map(|g| g.rules.len()).sum();

    let file_path = PathBuf::from(filename);
    let file_str = file_path.to_string_lossy();
    let file_name = file_path.file_name().unwrap_or_default().to_string_lossy();

    let violations =
        run_rules_on_content(&built.rule_groups, &file_path, content, &file_str, &file_name);

    let mut violations = violations;
    let ratchet_counts = apply_ratchet_thresholds(&mut violations, &built.ratchet_thresholds);

    Ok(ScanResult {
        violations,
        files_scanned: 1,
        rules_loaded,
        ratchet_counts,
        changed_files_count: None,
        base_ref: None,
    })
}

/// Run a scan filtered to only files/lines changed relative to a base branch.
pub fn run_scan_changed(
    config_path: &Path,
    target_paths: &[PathBuf],
    base_ref: &str,
) -> Result<ScanResult, ScanError> {
    // Get diff info from git
    let diff = git_diff::diff_info(base_ref).map_err(|e| ScanError::GitDiff(e.to_string()))?;
    let repo_root = git_diff::repo_root().map_err(|e| ScanError::GitDiff(e.to_string()))?;

    let changed_files_count = diff.changed_lines.len();

    // Run normal scan
    let mut result = run_scan(config_path, target_paths)?;

    // Post-filter violations to only those in changed files/lines
    result.violations.retain(|v| {
        // Compute relative path from repo root for matching against diff
        let rel_path = if v.file.is_absolute() {
            v.file.strip_prefix(&repo_root).unwrap_or(&v.file).to_path_buf()
        } else {
            v.file.clone()
        };

        if !diff.has_file(&rel_path) {
            return false;
        }

        // File-level violations (no line number) pass if file is changed
        match v.line {
            Some(line) => diff.has_line(&rel_path, line),
            None => true,
        }
    });

    result.changed_files_count = Some(changed_files_count);
    result.base_ref = Some(base_ref.to_string());

    Ok(result)
}

/// Run baseline counting: parse config, build only ratchet rules, count matches.
pub fn run_baseline(
    config_path: &Path,
    target_paths: &[PathBuf],
) -> Result<BaselineResult, ScanError> {
    let config_text = fs::read_to_string(config_path).map_err(ScanError::ConfigRead)?;
    let toml_config: TomlConfig = toml::from_str(&config_text).map_err(ScanError::ConfigParse)?;

    // Resolve presets and merge with user-defined rules
    let mut resolved_rules = presets::resolve_rules(
        &toml_config.baseline.extends,
        &toml_config.rule,
    )
    .map_err(ScanError::Preset)?;

    let scoped_rules = presets::resolve_scoped_rules(
        &toml_config.baseline.scoped,
        &toml_config.rule,
    )
    .map_err(ScanError::Preset)?;
    resolved_rules.extend(scoped_rules);

    let exclude_set = build_glob_set(&toml_config.baseline.exclude)?;

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
            Some(build_glob_set_from_pattern(pat)?)
        } else {
            None
        };

        rules.push((rule, rule_glob, pattern));
    }

    let files = collect_files(target_paths, &exclude_set);

    let files_scanned = AtomicUsize::new(0);

    let counts: HashMap<String, usize> = files
        .par_iter()
        .filter_map(|file_path| {
            let content = fs::read_to_string(file_path).ok()?;

            files_scanned.fetch_add(1, Ordering::Relaxed);
            let ctx = ScanContext {
                file_path,
                content: &content,
            };

            let mut local_counts: HashMap<String, usize> = HashMap::new();
            for (rule, rule_glob, _) in &rules {
                if let Some(ref gs) = rule_glob {
                    let file_str = file_path.to_string_lossy();
                    let file_name = file_path.file_name().unwrap_or_default().to_string_lossy();
                    if !gs.is_match(&*file_str) && !gs.is_match(&*file_name) {
                        continue;
                    }
                }

                let violations = rule.check_file(&ctx);
                if !violations.is_empty() {
                    *local_counts.entry(rule.id().to_string()).or_insert(0) += violations.len();
                }
            }

            if local_counts.is_empty() {
                None
            } else {
                Some(local_counts)
            }
        })
        .reduce(
            || HashMap::new(),
            |mut acc, local| {
                for (k, v) in local {
                    *acc.entry(k).or_insert(0) += v;
                }
                acc
            },
        );

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
        files_scanned: files_scanned.load(Ordering::Relaxed),
    })
}

/// Check if a violation is suppressed by an escape-hatch comment.
/// Uses pre-computed marker strings to avoid per-call allocations.
fn is_suppressed(lines: &[&str], line_num: usize, allow_marker: &str, allow_next_line: &str) -> bool {
    let allow_all = "baseline:allow-all";

    // Check current line (1-indexed)
    if line_num > 0 && line_num <= lines.len() {
        let line = lines[line_num - 1];
        if line.contains(allow_marker) || line.contains(allow_all) {
            return true;
        }
    }

    // Check previous line (next-line style: `// baseline:allow-next-line`)
    if line_num >= 2 && line_num <= lines.len() {
        let prev = lines[line_num - 2];
        if prev.contains(allow_next_line)
            || prev.contains("baseline:allow-next-line all")
        {
            return true;
        }
    }

    false
}

pub(crate) fn collect_files(target_paths: &[PathBuf], exclude_set: &GlobSet) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = Vec::new();
    for target in target_paths {
        if target.is_file() {
            files.push(target.clone());
        } else {
            // Use the `ignore` crate's parallel walker for multi-threaded directory traversal.
            let walker = WalkBuilder::new(target)
                .hidden(true) // skip hidden files/dirs like .git
                .git_ignore(true) // respect .gitignore
                .git_global(true) // respect global gitignore
                .git_exclude(true) // respect .git/info/exclude
                .build_parallel();

            let collected: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

            walker.run(|| {
                Box::new(|entry| {
                    if let Ok(entry) = entry {
                        if entry.file_type().map_or(false, |ft| ft.is_file()) {
                            let path = entry.into_path();
                            let rel = path.strip_prefix(target).unwrap_or(&path);
                            if !exclude_set.is_match(rel.to_string_lossy().as_ref()) {
                                collected.lock().unwrap().push(path);
                            }
                        }
                    }
                    ignore::WalkState::Continue
                })
            });

            files.extend(collected.into_inner().unwrap());
        }
    }
    files
}

/// Normalize a glob pattern:
/// 1. Expand brace syntax (`{a,b}`) into multiple patterns (globset doesn't support it).
/// 2. Auto-prefix path-based globs with `**/` so they match against absolute paths.
///    e.g. `apps/web/src/**/*.tsx` → `**/apps/web/src/**/*.tsx`
fn expand_glob(pattern: &str) -> Vec<String> {
    // First, expand brace syntax
    if let Some(open) = pattern.find('{') {
        if let Some(close) = pattern[open..].find('}') {
            let close = open + close;
            let prefix = &pattern[..open];
            let suffix = &pattern[close + 1..];
            let alternatives = &pattern[open + 1..close];

            // Only expand if there are commas (otherwise it's a glob char class)
            if alternatives.contains(',') {
                let mut result = Vec::new();
                for alt in alternatives.split(',') {
                    let expanded = format!("{prefix}{alt}{suffix}");
                    // Recursively expand in case there are nested braces
                    result.extend(expand_glob(&expanded));
                }
                return result;
            }
        }
    }

    // Auto-prefix path-based globs that don't already start with ** or /
    // e.g. "apps/web/src/**/*.tsx" → "**/apps/web/src/**/*.tsx"
    // This ensures they match against absolute file paths.
    let normalized = if pattern.contains('/')
        && !pattern.starts_with("**/")
        && !pattern.starts_with('/')
    {
        format!("**/{pattern}")
    } else {
        pattern.to_string()
    };

    vec![normalized]
}

/// Build a GlobSet from a single pattern string, expanding brace syntax.
pub(crate) fn build_glob_set_from_pattern(pattern: &str) -> Result<GlobSet, ScanError> {
    let expanded = expand_glob(pattern);
    let mut builder = GlobSetBuilder::new();
    for pat in &expanded {
        builder.add(Glob::new(pat).map_err(ScanError::GlobParse)?);
    }
    builder.build().map_err(ScanError::GlobParse)
}

pub(crate) fn build_glob_set(patterns: &[String]) -> Result<GlobSet, ScanError> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        for pat in &expand_glob(pattern) {
            builder.add(Glob::new(pat).map_err(ScanError::GlobParse)?);
        }
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

    /// Count total rules across all groups.
    fn total_rules(groups: &[RuleGroup]) -> usize {
        groups.iter().map(|g| g.rules.len()).sum()
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
            "let x = style={{ color: 'red' }}; // baseline:allow-no-inline-styles",
        ];
        assert!(is_suppressed(
            &lines,
            1,
            "baseline:allow-no-inline-styles",
            "baseline:allow-next-line no-inline-styles",
        ));
    }

    #[test]
    fn suppressed_by_allow_all() {
        let lines = vec![
            "let x = style={{ color: 'red' }}; // baseline:allow-all",
        ];
        assert!(is_suppressed(
            &lines,
            1,
            "baseline:allow-no-inline-styles",
            "baseline:allow-next-line no-inline-styles",
        ));
        assert!(is_suppressed(
            &lines,
            1,
            "baseline:allow-any-other-rule",
            "baseline:allow-next-line any-other-rule",
        ));
    }

    #[test]
    fn suppressed_by_allow_next_line() {
        let lines = vec![
            "// baseline:allow-next-line no-inline-styles",
            "let x = style={{ color: 'red' }};",
        ];
        assert!(is_suppressed(
            &lines,
            2,
            "baseline:allow-no-inline-styles",
            "baseline:allow-next-line no-inline-styles",
        ));
    }

    #[test]
    fn suppressed_by_allow_next_line_all() {
        let lines = vec![
            "// baseline:allow-next-line all",
            "let x = style={{ color: 'red' }};",
        ];
        assert!(is_suppressed(
            &lines,
            2,
            "baseline:allow-no-inline-styles",
            "baseline:allow-next-line no-inline-styles",
        ));
    }

    #[test]
    fn not_suppressed_wrong_rule_id() {
        let lines = vec![
            "let x = style={{ color: 'red' }}; // baseline:allow-other-rule",
        ];
        assert!(!is_suppressed(
            &lines,
            1,
            "baseline:allow-no-inline-styles",
            "baseline:allow-next-line no-inline-styles",
        ));
    }

    #[test]
    fn not_suppressed_no_comment() {
        let lines = vec![
            "let x = style={{ color: 'red' }};",
        ];
        assert!(!is_suppressed(
            &lines,
            1,
            "baseline:allow-no-inline-styles",
            "baseline:allow-next-line no-inline-styles",
        ));
    }

    #[test]
    fn not_suppressed_next_line_wrong_rule() {
        let lines = vec![
            "// baseline:allow-next-line other-rule",
            "let x = style={{ color: 'red' }};",
        ];
        assert!(!is_suppressed(
            &lines,
            2,
            "baseline:allow-no-inline-styles",
            "baseline:allow-next-line no-inline-styles",
        ));
    }

    #[test]
    fn suppressed_line_zero_is_safe() {
        let lines = vec!["some content"];
        // line_num 0 should not panic
        assert!(!is_suppressed(
            &lines,
            0,
            "baseline:allow-any-rule",
            "baseline:allow-next-line any-rule",
        ));
    }

    #[test]
    fn suppressed_past_end_is_safe() {
        let lines = vec!["some content"];
        // line_num past end should not panic
        assert!(!is_suppressed(
            &lines,
            5,
            "baseline:allow-any-rule",
            "baseline:allow-next-line any-rule",
        ));
    }

    // ── ScanError Display tests ──

    #[test]
    fn scan_error_display_config_read() {
        let err = ScanError::ConfigRead(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "not found",
        ));
        assert!(err.to_string().contains("failed to read config"));
    }

    #[test]
    fn scan_error_display_config_parse() {
        let toml_err = toml::from_str::<TomlConfig>("not valid toml [[[").unwrap_err();
        let err = ScanError::ConfigParse(toml_err);
        assert!(err.to_string().contains("failed to parse config"));
    }

    #[test]
    fn scan_error_display_glob_parse() {
        let glob_err = Glob::new("[invalid").unwrap_err();
        let err = ScanError::GlobParse(glob_err);
        assert!(err.to_string().contains("invalid glob pattern"));
    }

    #[test]
    fn scan_error_display_rule_factory() {
        let err = ScanError::RuleFactory(FactoryError::UnknownRuleType("nope".into()));
        assert!(err.to_string().contains("failed to build rule"));
    }

    #[test]
    fn scan_error_display_preset() {
        let err = ScanError::Preset(PresetError::UnknownPreset {
            name: "bad".into(),
            available: vec!["shadcn-strict"],
        });
        assert!(err.to_string().contains("preset error"));
    }

    #[test]
    fn scan_error_display_git_diff() {
        let err = ScanError::GitDiff("diff broke".into());
        assert_eq!(err.to_string(), "git diff failed: diff broke");
    }

    // ── build_rules tests ──

    #[test]
    fn build_rules_banned_pattern_rule() {
        let rules = vec![TomlRule {
            id: "no-console".into(),
            rule_type: "banned-pattern".into(),
            pattern: Some("console\\.log".into()),
            message: "no console.log".into(),
            glob: Some("**/*.ts".into()),
            ..Default::default()
        }];

        let built = build_rules(&rules).unwrap();
        assert_eq!(total_rules(&built.rule_groups), 1);
        assert!(built.ratchet_thresholds.is_empty());
        assert!(built.file_presence_rules.is_empty());
    }

    #[test]
    fn build_rules_ratchet_records_threshold() {
        let rules = vec![TomlRule {
            id: "legacy-api".into(),
            rule_type: "ratchet".into(),
            pattern: Some("legacyCall".into()),
            max_count: Some(10),
            glob: Some("**/*.ts".into()),
            message: "legacy".into(),
            ..Default::default()
        }];

        let built = build_rules(&rules).unwrap();
        assert_eq!(total_rules(&built.rule_groups), 1);
        assert_eq!(built.ratchet_thresholds["legacy-api"], 10);
    }

    #[test]
    fn build_rules_file_presence_separated() {
        let rules = vec![
            TomlRule {
                id: "has-readme".into(),
                rule_type: "file-presence".into(),
                required_files: vec!["README.md".into()],
                message: "need readme".into(),
                ..Default::default()
            },
            TomlRule {
                id: "no-console".into(),
                rule_type: "banned-pattern".into(),
                pattern: Some("console\\.log".into()),
                message: "no console".into(),
                ..Default::default()
            },
        ];

        let built = build_rules(&rules).unwrap();
        assert_eq!(total_rules(&built.rule_groups), 1); // only banned-pattern
        assert_eq!(built.file_presence_rules.len(), 1);
    }

    #[test]
    fn build_rules_unknown_type_errors() {
        let rules = vec![TomlRule {
            id: "bad".into(),
            rule_type: "nonexistent-rule-type".into(),
            message: "x".into(),
            ..Default::default()
        }];

        let result = build_rules(&rules);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(matches!(err, ScanError::RuleFactory(_)));
    }

    #[test]
    fn build_rules_with_exclude_glob() {
        let rules = vec![TomlRule {
            id: "no-console".into(),
            rule_type: "banned-pattern".into(),
            pattern: Some("console\\.log".into()),
            message: "no console".into(),
            exclude_glob: vec!["**/test/**".into()],
            ..Default::default()
        }];

        let built = build_rules(&rules).unwrap();
        assert_eq!(built.rule_groups.len(), 1);
        assert!(built.rule_groups[0].exclusion_glob.is_some());
    }

    #[test]
    fn build_rules_with_file_conditioning() {
        let rules = vec![TomlRule {
            id: "no-console".into(),
            rule_type: "banned-pattern".into(),
            pattern: Some("console\\.log".into()),
            message: "no console".into(),
            file_contains: Some("import React".into()),
            file_not_contains: Some("// @generated".into()),
            ..Default::default()
        }];

        let built = build_rules(&rules).unwrap();
        assert_eq!(built.rule_groups.len(), 1);
        assert!(built.rule_groups[0].rules[0].file_contains.is_some());
        assert!(built.rule_groups[0].rules[0].file_not_contains.is_some());
    }

    // ── group_matches_file tests ──

    #[test]
    fn group_matches_file_no_glob_matches_all() {
        let rules = vec![TomlRule {
            id: "r".into(),
            rule_type: "banned-pattern".into(),
            pattern: Some("x".into()),
            message: "m".into(),
            ..Default::default()
        }];
        let built = build_rules(&rules).unwrap();
        assert!(group_matches_file(&built.rule_groups[0], "anything.rs", "anything.rs"));
    }

    #[test]
    fn group_matches_file_inclusion_glob_filters() {
        let rules = vec![TomlRule {
            id: "r".into(),
            rule_type: "banned-pattern".into(),
            pattern: Some("x".into()),
            message: "m".into(),
            glob: Some("**/*.tsx".into()),
            ..Default::default()
        }];
        let built = build_rules(&rules).unwrap();
        assert!(group_matches_file(&built.rule_groups[0], "src/Foo.tsx", "Foo.tsx"));
        assert!(!group_matches_file(&built.rule_groups[0], "src/Foo.rs", "Foo.rs"));
    }

    #[test]
    fn group_matches_file_exclusion_glob_rejects() {
        let rules = vec![TomlRule {
            id: "r".into(),
            rule_type: "banned-pattern".into(),
            pattern: Some("x".into()),
            message: "m".into(),
            exclude_glob: vec!["**/test/**".into()],
            ..Default::default()
        }];
        let built = build_rules(&rules).unwrap();
        assert!(group_matches_file(&built.rule_groups[0], "src/app.ts", "app.ts"));
        assert!(!group_matches_file(&built.rule_groups[0], "src/test/app.ts", "app.ts"));
    }

    // ── passes_file_conditioning tests ──

    #[test]
    fn passes_conditioning_no_conditions() {
        let rules = vec![TomlRule {
            id: "r".into(),
            rule_type: "banned-pattern".into(),
            pattern: Some("x".into()),
            message: "m".into(),
            ..Default::default()
        }];
        let built = build_rules(&rules).unwrap();
        let mut cache = HashMap::new();
        assert!(passes_file_conditioning_cached(&built.rule_groups[0].rules[0], "anything", &mut cache));
    }

    #[test]
    fn passes_conditioning_file_contains_present() {
        let rules = vec![TomlRule {
            id: "r".into(),
            rule_type: "banned-pattern".into(),
            pattern: Some("x".into()),
            message: "m".into(),
            file_contains: Some("import React".into()),
            ..Default::default()
        }];
        let built = build_rules(&rules).unwrap();
        let mut cache = HashMap::new();
        assert!(passes_file_conditioning_cached(&built.rule_groups[0].rules[0], "import React from 'react';", &mut cache));
        let mut cache = HashMap::new();
        assert!(!passes_file_conditioning_cached(&built.rule_groups[0].rules[0], "import Vue from 'vue';", &mut cache));
    }

    #[test]
    fn passes_conditioning_file_not_contains() {
        let rules = vec![TomlRule {
            id: "r".into(),
            rule_type: "banned-pattern".into(),
            pattern: Some("x".into()),
            message: "m".into(),
            file_not_contains: Some("// @generated".into()),
            ..Default::default()
        }];
        let built = build_rules(&rules).unwrap();
        let mut cache = HashMap::new();
        assert!(passes_file_conditioning_cached(&built.rule_groups[0].rules[0], "normal code", &mut cache));
        let mut cache = HashMap::new();
        assert!(!passes_file_conditioning_cached(&built.rule_groups[0].rules[0], "// @generated\nnormal code", &mut cache));
    }

    #[test]
    fn passes_conditioning_both_conditions() {
        let rules = vec![TomlRule {
            id: "r".into(),
            rule_type: "banned-pattern".into(),
            pattern: Some("x".into()),
            message: "m".into(),
            file_contains: Some("import React".into()),
            file_not_contains: Some("// @generated".into()),
            ..Default::default()
        }];
        let built = build_rules(&rules).unwrap();
        // Has required, missing excluded -> pass
        let mut cache = HashMap::new();
        assert!(passes_file_conditioning_cached(&built.rule_groups[0].rules[0], "import React", &mut cache));
        // Missing required -> fail
        let mut cache = HashMap::new();
        assert!(!passes_file_conditioning_cached(&built.rule_groups[0].rules[0], "import Vue", &mut cache));
        // Has both -> fail (file_not_contains blocks it)
        let mut cache = HashMap::new();
        assert!(!passes_file_conditioning_cached(&built.rule_groups[0].rules[0], "import React // @generated", &mut cache));
    }

    // ── run_rules_on_content tests ──

    #[test]
    fn run_rules_on_content_finds_violations() {
        let rules = vec![TomlRule {
            id: "no-console".into(),
            rule_type: "banned-pattern".into(),
            pattern: Some("console\\.log".into()),
            message: "no console.log".into(),
            regex: true,
            ..Default::default()
        }];
        let built = build_rules(&rules).unwrap();
        let path = PathBuf::from("test.ts");
        let content = "console.log('hello');\nfoo();\n";

        let violations = run_rules_on_content(&built.rule_groups, &path, content, "test.ts", "test.ts");
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule_id, "no-console");
    }

    #[test]
    fn run_rules_on_content_respects_suppression() {
        let rules = vec![TomlRule {
            id: "no-console".into(),
            rule_type: "banned-pattern".into(),
            pattern: Some("console\\.log".into()),
            message: "no console.log".into(),
            regex: true,
            ..Default::default()
        }];
        let built = build_rules(&rules).unwrap();
        let path = PathBuf::from("test.ts");
        let content = "console.log('hello'); // baseline:allow-no-console\n";

        let violations = run_rules_on_content(&built.rule_groups, &path, content, "test.ts", "test.ts");
        assert_eq!(violations.len(), 0);
    }

    #[test]
    fn run_rules_on_content_skips_non_matching_glob() {
        let rules = vec![TomlRule {
            id: "no-console".into(),
            rule_type: "banned-pattern".into(),
            pattern: Some("console\\.log".into()),
            message: "no console.log".into(),
            regex: true,
            glob: Some("**/*.tsx".into()),
            ..Default::default()
        }];
        let built = build_rules(&rules).unwrap();
        let path = PathBuf::from("test.rs");
        let content = "console.log('hello');\n";

        let violations = run_rules_on_content(&built.rule_groups, &path, content, "test.rs", "test.rs");
        assert_eq!(violations.len(), 0);
    }

    #[test]
    fn run_rules_on_content_skips_file_conditioning() {
        let rules = vec![TomlRule {
            id: "no-console".into(),
            rule_type: "banned-pattern".into(),
            pattern: Some("console\\.log".into()),
            message: "no console.log".into(),
            regex: true,
            file_contains: Some("import React".into()),
            ..Default::default()
        }];
        let built = build_rules(&rules).unwrap();
        let path = PathBuf::from("test.ts");
        let content = "console.log('hello');\n"; // no "import React"

        let violations = run_rules_on_content(&built.rule_groups, &path, content, "test.ts", "test.ts");
        assert_eq!(violations.len(), 0);
    }

    // ── build_glob_set tests ──

    #[test]
    fn build_glob_set_empty() {
        let gs = build_glob_set(&[]).unwrap();
        assert!(!gs.is_match("anything"));
    }

    #[test]
    fn build_glob_set_matches() {
        let gs = build_glob_set(&["**/*.ts".into(), "**/*.tsx".into()]).unwrap();
        assert!(gs.is_match("src/foo.ts"));
        assert!(gs.is_match("src/foo.tsx"));
        assert!(!gs.is_match("src/foo.rs"));
    }

    #[test]
    fn build_glob_set_invalid_pattern() {
        let err = build_glob_set(&["[invalid".into()]).unwrap_err();
        assert!(matches!(err, ScanError::GlobParse(_)));
    }

    // ── expand_glob / brace expansion tests ──

    #[test]
    fn expand_glob_no_braces() {
        assert_eq!(expand_glob("**/*.ts"), vec!["**/*.ts"]);
    }

    #[test]
    fn expand_glob_single_brace() {
        let mut result = expand_glob("**/*.{ts,tsx}");
        result.sort();
        assert_eq!(result, vec!["**/*.ts", "**/*.tsx"]);
    }

    #[test]
    fn expand_glob_three_alternatives() {
        let mut result = expand_glob("src/**/*.{ts,tsx,js}");
        result.sort();
        // Path-based globs get **/ prefix
        assert_eq!(
            result,
            vec!["**/src/**/*.js", "**/src/**/*.ts", "**/src/**/*.tsx"]
        );
    }

    #[test]
    fn expand_glob_no_comma_passthrough() {
        // Braces without commas should pass through (e.g. character classes)
        assert_eq!(expand_glob("**/*.[tj]s"), vec!["**/*.[tj]s"]);
    }

    #[test]
    fn expand_glob_auto_prefix_path_glob() {
        // Path-based globs without **/ prefix get auto-prefixed
        assert_eq!(
            expand_glob("apps/web/src/**/*.tsx"),
            vec!["**/apps/web/src/**/*.tsx"]
        );
    }

    #[test]
    fn expand_glob_no_double_prefix() {
        // Already prefixed with **/ should not get double-prefixed
        assert_eq!(
            expand_glob("**/apps/web/src/**/*.tsx"),
            vec!["**/apps/web/src/**/*.tsx"]
        );
    }

    #[test]
    fn expand_glob_simple_extension_no_prefix() {
        // Simple extension globs (no /) should not get prefixed
        assert_eq!(expand_glob("*.ts"), vec!["*.ts"]);
    }

    #[test]
    fn build_glob_set_brace_expansion() {
        let gs = build_glob_set(&["**/*.{ts,tsx}".into()]).unwrap();
        assert!(gs.is_match("src/foo.ts"));
        assert!(gs.is_match("src/foo.tsx"));
        assert!(!gs.is_match("src/foo.js"));
    }

    #[test]
    fn build_glob_set_from_pattern_brace_expansion() {
        let gs = build_glob_set_from_pattern("**/*.{ts,tsx,js,jsx}").unwrap();
        assert!(gs.is_match("src/components/Button.tsx"));
        assert!(gs.is_match("lib/utils.js"));
        assert!(!gs.is_match("src/main.rs"));
    }

    #[test]
    fn build_glob_set_from_pattern_path_glob() {
        let gs = build_glob_set_from_pattern("src/components/**/*.{ts,tsx}").unwrap();
        assert!(gs.is_match("src/components/Button.tsx"));
        assert!(gs.is_match("src/components/deep/nested/Card.ts"));
        assert!(!gs.is_match("lib/utils.tsx"));
    }

    #[test]
    fn build_glob_set_path_glob_matches_absolute() {
        // The real-world case: "apps/web/src/**/*.{ts,tsx}" must match absolute paths
        let gs = build_glob_set_from_pattern("apps/web/src/**/*.{ts,tsx}").unwrap();
        assert!(gs.is_match("/Users/dev/project/apps/web/src/components/Foo.tsx"));
        assert!(gs.is_match("apps/web/src/index.ts"));
        assert!(!gs.is_match("/Users/dev/project/apps/api/src/index.ts"));
    }

    // ── rule grouping tests ──

    #[test]
    fn build_rules_groups_same_glob() {
        let rules = vec![
            TomlRule {
                id: "no-console".into(),
                rule_type: "banned-pattern".into(),
                pattern: Some("console\\.log".into()),
                message: "no console".into(),
                glob: Some("**/*.ts".into()),
                regex: true,
                ..Default::default()
            },
            TomlRule {
                id: "no-debugger".into(),
                rule_type: "banned-pattern".into(),
                pattern: Some("debugger".into()),
                message: "no debugger".into(),
                glob: Some("**/*.ts".into()),
                ..Default::default()
            },
        ];

        let built = build_rules(&rules).unwrap();
        // Both rules share the same glob, so they should be in one group
        assert_eq!(built.rule_groups.len(), 1);
        assert_eq!(built.rule_groups[0].rules.len(), 2);
    }

    #[test]
    fn build_rules_separates_different_globs() {
        let rules = vec![
            TomlRule {
                id: "no-console".into(),
                rule_type: "banned-pattern".into(),
                pattern: Some("console\\.log".into()),
                message: "no console".into(),
                glob: Some("**/*.ts".into()),
                regex: true,
                ..Default::default()
            },
            TomlRule {
                id: "no-debugger".into(),
                rule_type: "banned-pattern".into(),
                pattern: Some("debugger".into()),
                message: "no debugger".into(),
                glob: Some("**/*.tsx".into()),
                ..Default::default()
            },
        ];

        let built = build_rules(&rules).unwrap();
        // Different globs -> separate groups
        assert_eq!(built.rule_groups.len(), 2);
        assert_eq!(built.rule_groups[0].rules.len(), 1);
        assert_eq!(built.rule_groups[1].rules.len(), 1);
    }

    // ── run_scan integration tests ──

    #[test]
    fn run_scan_with_banned_pattern() {
        let dir = tempfile::tempdir().unwrap();

        // Write config
        let config = dir.path().join("baseline.toml");
        fs::write(
            &config,
            r#"
[baseline]

[[rule]]
id = "no-console"
type = "banned-pattern"
severity = "error"
pattern = "console\\.log"
regex = true
message = "Do not use console.log"
"#,
        )
        .unwrap();

        // Write a source file
        let src_dir = dir.path().join("src");
        fs::create_dir(&src_dir).unwrap();
        fs::write(src_dir.join("app.ts"), "console.log('hi');\nfoo();\n").unwrap();

        let result = run_scan(&config, &[src_dir]).unwrap();
        assert_eq!(result.violations.len(), 1);
        assert_eq!(result.violations[0].rule_id, "no-console");
        assert_eq!(result.files_scanned, 1);
        assert_eq!(result.rules_loaded, 1);
    }

    #[test]
    fn run_scan_no_violations() {
        let dir = tempfile::tempdir().unwrap();

        let config = dir.path().join("baseline.toml");
        fs::write(
            &config,
            r#"
[baseline]

[[rule]]
id = "no-console"
type = "banned-pattern"
severity = "error"
pattern = "console\\.log"
regex = true
message = "Do not use console.log"
glob = "**/*.ts"
"#,
        )
        .unwrap();

        let src_dir = dir.path().join("src");
        fs::create_dir(&src_dir).unwrap();
        fs::write(src_dir.join("app.ts"), "doStuff();\n").unwrap();

        let result = run_scan(&config, &[src_dir]).unwrap();
        assert!(result.violations.is_empty());
        assert_eq!(result.files_scanned, 1);
    }

    #[test]
    fn run_scan_excludes_files() {
        let dir = tempfile::tempdir().unwrap();

        let config = dir.path().join("baseline.toml");
        fs::write(
            &config,
            r#"
[baseline]
exclude = ["**/dist/**"]

[[rule]]
id = "no-console"
type = "banned-pattern"
severity = "error"
pattern = "console\\.log"
regex = true
message = "no console"
"#,
        )
        .unwrap();

        // File in dist should be excluded
        let dist_dir = dir.path().join("dist");
        fs::create_dir(&dist_dir).unwrap();
        fs::write(dist_dir.join("app.ts"), "console.log('hi');\n").unwrap();

        let result = run_scan(&config, &[dir.path().to_path_buf()]).unwrap();
        // The dist file should be excluded
        for v in &result.violations {
            assert!(!v.file.to_string_lossy().contains("dist"));
        }
    }

    #[test]
    fn run_scan_file_presence_rule() {
        let dir = tempfile::tempdir().unwrap();

        let config = dir.path().join("baseline.toml");
        fs::write(
            &config,
            r#"
[baseline]

[[rule]]
id = "has-readme"
type = "file-presence"
severity = "error"
required_files = ["README.md"]
message = "README.md is required"
"#,
        )
        .unwrap();

        // No README.md in dir
        let result = run_scan(&config, &[dir.path().to_path_buf()]).unwrap();
        assert!(result.violations.iter().any(|v| v.rule_id == "has-readme"));
    }

    #[test]
    fn run_scan_missing_config_errors() {
        let result = run_scan(
            Path::new("/nonexistent/baseline.toml"),
            &[PathBuf::from(".")],
        );
        assert!(result.is_err());
        assert!(matches!(result.err().unwrap(), ScanError::ConfigRead(_)));
    }

    #[test]
    fn run_scan_invalid_config_errors() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("baseline.toml");
        fs::write(&config, "this is not valid toml [[[").unwrap();

        let result = run_scan(&config, &[dir.path().to_path_buf()]);
        assert!(result.is_err());
        assert!(matches!(result.err().unwrap(), ScanError::ConfigParse(_)));
    }

    #[test]
    fn run_scan_with_ratchet_rule() {
        let dir = tempfile::tempdir().unwrap();

        let config = dir.path().join("baseline.toml");
        fs::write(
            &config,
            r#"
[baseline]

[[rule]]
id = "legacy-api"
type = "ratchet"
severity = "warning"
pattern = "legacyCall"
max_count = 5
message = "legacy api usage"
"#,
        )
        .unwrap();

        let src_dir = dir.path().join("src");
        fs::create_dir(&src_dir).unwrap();
        fs::write(src_dir.join("app.ts"), "legacyCall();\nlegacyCall();\n").unwrap();

        let result = run_scan(&config, &[src_dir]).unwrap();
        // 2 matches, max 5 -> suppressed
        assert!(result.violations.is_empty());
        assert_eq!(result.ratchet_counts["legacy-api"], (2, 5));
    }

    // ── run_scan_stdin tests ──

    #[test]
    fn run_scan_stdin_finds_violations() {
        let dir = tempfile::tempdir().unwrap();

        let config = dir.path().join("baseline.toml");
        fs::write(
            &config,
            r#"
[baseline]

[[rule]]
id = "no-console"
type = "banned-pattern"
severity = "error"
pattern = "console\\.log"
regex = true
message = "no console.log"
"#,
        )
        .unwrap();

        let result =
            run_scan_stdin(&config, "console.log('hello');\nfoo();\n", "test.ts").unwrap();
        assert_eq!(result.violations.len(), 1);
        assert_eq!(result.files_scanned, 1);
    }

    #[test]
    fn run_scan_stdin_no_violations() {
        let dir = tempfile::tempdir().unwrap();

        let config = dir.path().join("baseline.toml");
        fs::write(
            &config,
            r#"
[baseline]

[[rule]]
id = "no-console"
type = "banned-pattern"
severity = "error"
pattern = "console\\.log"
regex = true
message = "no console.log"
glob = "**/*.ts"
"#,
        )
        .unwrap();

        let result = run_scan_stdin(&config, "doStuff();\n", "app.ts").unwrap();
        assert!(result.violations.is_empty());
    }

    #[test]
    fn run_scan_stdin_glob_filters_filename() {
        let dir = tempfile::tempdir().unwrap();

        let config = dir.path().join("baseline.toml");
        fs::write(
            &config,
            r#"
[baseline]

[[rule]]
id = "no-console"
type = "banned-pattern"
severity = "error"
pattern = "console\\.log"
regex = true
message = "no console.log"
glob = "**/*.tsx"
"#,
        )
        .unwrap();

        // File doesn't match glob
        let result =
            run_scan_stdin(&config, "console.log('hello');\n", "app.rs").unwrap();
        assert!(result.violations.is_empty());
    }

    // ── run_baseline tests ──

    #[test]
    fn run_baseline_counts_ratchet_matches() {
        let dir = tempfile::tempdir().unwrap();

        let config = dir.path().join("baseline.toml");
        fs::write(
            &config,
            r#"
[baseline]

[[rule]]
id = "legacy-api"
type = "ratchet"
severity = "warning"
pattern = "legacyCall"
max_count = 100
message = "legacy usage"
"#,
        )
        .unwrap();

        let src_dir = dir.path().join("src");
        fs::create_dir(&src_dir).unwrap();
        fs::write(
            src_dir.join("app.ts"),
            "legacyCall();\nlegacyCall();\nlegacyCall();\n",
        )
        .unwrap();

        let result = run_baseline(&config, &[src_dir]).unwrap();
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].rule_id, "legacy-api");
        assert_eq!(result.entries[0].count, 3);
        assert_eq!(result.files_scanned, 1);
    }

    #[test]
    fn run_baseline_skips_non_ratchet_rules() {
        let dir = tempfile::tempdir().unwrap();

        let config = dir.path().join("baseline.toml");
        fs::write(
            &config,
            r#"
[baseline]

[[rule]]
id = "no-console"
type = "banned-pattern"
severity = "error"
pattern = "console\\.log"
regex = true
message = "no console"

[[rule]]
id = "legacy-api"
type = "ratchet"
severity = "warning"
pattern = "legacyCall"
max_count = 100
message = "legacy usage"
"#,
        )
        .unwrap();

        let src_dir = dir.path().join("src");
        fs::create_dir(&src_dir).unwrap();
        fs::write(src_dir.join("app.ts"), "console.log('hi');\nlegacyCall();\n").unwrap();

        let result = run_baseline(&config, &[src_dir]).unwrap();
        // Only ratchet rules appear in baseline
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].rule_id, "legacy-api");
    }

    // ── collect_files tests ──

    #[test]
    fn collect_files_single_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.ts");
        fs::write(&file, "content").unwrap();

        let empty_glob = build_glob_set(&[]).unwrap();
        let files = collect_files(&[file.clone()], &empty_glob);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0], file);
    }

    #[test]
    fn collect_files_directory_walk() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        fs::create_dir(&sub).unwrap();
        fs::write(sub.join("a.ts"), "a").unwrap();
        fs::write(sub.join("b.ts"), "b").unwrap();

        let empty_glob = build_glob_set(&[]).unwrap();
        let files = collect_files(&[dir.path().to_path_buf()], &empty_glob);
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn collect_files_excludes_patterns() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("keep.ts"), "keep").unwrap();
        fs::write(dir.path().join("skip.log"), "skip").unwrap();

        let exclude = build_glob_set(&["*.log".into()]).unwrap();
        let files = collect_files(&[dir.path().to_path_buf()], &exclude);
        assert!(files.iter().all(|f| !f.to_string_lossy().ends_with(".log")));
        assert!(files.iter().any(|f| f.to_string_lossy().ends_with(".ts")));
    }

    // ── run_scan with presets ──

    #[test]
    fn run_scan_with_preset() {
        let dir = tempfile::tempdir().unwrap();

        let config = dir.path().join("baseline.toml");
        fs::write(
            &config,
            r#"
[baseline]
extends = ["shadcn-strict"]
"#,
        )
        .unwrap();

        let src_dir = dir.path().join("src");
        fs::create_dir(&src_dir).unwrap();
        fs::write(src_dir.join("app.tsx"), "export default function App() { return <div>hi</div>; }\n").unwrap();

        let result = run_scan(&config, &[src_dir]).unwrap();
        // Just verify it doesn't error
        assert!(result.rules_loaded > 0);
    }

    // ── run_scan with plugins ──

    #[test]
    fn run_scan_with_plugin() {
        let dir = tempfile::tempdir().unwrap();

        let plugin_path = dir.path().join("custom-rules.toml");
        fs::write(
            &plugin_path,
            r#"
[[rule]]
id = "no-todo"
type = "banned-pattern"
severity = "warning"
pattern = "TODO"
message = "No TODOs allowed"
"#,
        )
        .unwrap();

        let config = dir.path().join("baseline.toml");
        fs::write(
            &config,
            format!(
                r#"
[baseline]
plugins = ["{}"]
"#,
                plugin_path.display()
            ),
        )
        .unwrap();

        let src_dir = dir.path().join("src");
        fs::create_dir(&src_dir).unwrap();
        fs::write(src_dir.join("app.ts"), "// TODO: fix this\n").unwrap();

        let result = run_scan(&config, &[src_dir]).unwrap();
        assert!(result.violations.iter().any(|v| v.rule_id == "no-todo"));
    }

    #[test]
    fn run_scan_skip_no_matching_files() {
        let dir = tempfile::tempdir().unwrap();

        let config = dir.path().join("baseline.toml");
        fs::write(
            &config,
            r#"
[baseline]

[[rule]]
id = "no-console"
type = "banned-pattern"
severity = "error"
pattern = "console\\.log"
regex = true
message = "no console"
glob = "**/*.tsx"
"#,
        )
        .unwrap();

        let src_dir = dir.path().join("src");
        fs::create_dir(&src_dir).unwrap();
        // Write a .rs file that won't match the *.tsx glob
        fs::write(src_dir.join("app.rs"), "console.log('hello');\n").unwrap();

        let result = run_scan(&config, &[src_dir]).unwrap();
        assert!(result.violations.is_empty());
        // The file shouldn't even be read since no rule matches
        assert_eq!(result.files_scanned, 0);
    }
}
