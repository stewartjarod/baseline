use crate::config::Severity;
use crate::rules::Violation;
use crate::scan::ScanResult;
use serde_json::json;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

/// Print violations grouped by file with ANSI colors.
pub fn print_pretty(result: &ScanResult) {
    let mut out = std::io::stdout();
    write_pretty(result, &mut out);
}

fn write_pretty(result: &ScanResult, out: &mut dyn Write) {
    if result.violations.is_empty() {
        let _ = writeln!(
            out,
            "\x1b[32m✓\x1b[0m No violations found ({} files scanned, {} rules loaded)",
            result.files_scanned, result.rules_loaded
        );
        write_ratchet_summary_pretty(&result.ratchet_counts, out);
        return;
    }

    // Group violations by file
    let mut by_file: BTreeMap<String, Vec<&Violation>> = BTreeMap::new();
    for v in &result.violations {
        by_file
            .entry(v.file.display().to_string())
            .or_default()
            .push(v);
    }

    for (file, violations) in &by_file {
        let _ = writeln!(out, "\n\x1b[4m{}\x1b[0m", file);
        for v in violations {
            let severity_str = match v.severity {
                Severity::Error => "\x1b[31merror\x1b[0m",
                Severity::Warning => "\x1b[33mwarn \x1b[0m",
            };

            let location = match (v.line, v.column) {
                (Some(l), Some(c)) => format!("{}:{}", l, c),
                (Some(l), None) => format!("{}:1", l),
                _ => "1:1".to_string(),
            };

            let _ = writeln!(
                out,
                "  \x1b[90m{:<8}\x1b[0m {} \x1b[90m{:<25}\x1b[0m {}",
                location, severity_str, v.rule_id, v.message
            );

            if let Some(ref source) = v.source_line {
                let _ = writeln!(out, "           \x1b[90m│\x1b[0m {}", source.trim());
            }

            if let Some(ref suggest) = v.suggest {
                let _ = writeln!(out, "           \x1b[90m└─\x1b[0m \x1b[36m{}\x1b[0m", suggest);
            }
        }
    }

    let errors = result
        .violations
        .iter()
        .filter(|v| v.severity == Severity::Error)
        .count();
    let warnings = result
        .violations
        .iter()
        .filter(|v| v.severity == Severity::Warning)
        .count();

    let _ = writeln!(out);
    let _ = write!(out, "\x1b[1m");
    if errors > 0 {
        let _ = write!(out, "\x1b[31m{} error{}\x1b[0m\x1b[1m", errors, if errors == 1 { "" } else { "s" });
    }
    if errors > 0 && warnings > 0 {
        let _ = write!(out, ", ");
    }
    if warnings > 0 {
        let _ = write!(out, "\x1b[33m{} warning{}\x1b[0m\x1b[1m", warnings, if warnings == 1 { "" } else { "s" });
    }
    let _ = writeln!(
        out,
        " ({} files scanned, {} rules loaded)\x1b[0m",
        result.files_scanned, result.rules_loaded
    );

    write_ratchet_summary_pretty(&result.ratchet_counts, out);
}

fn write_ratchet_summary_pretty(
    ratchet_counts: &HashMap<String, (usize, usize)>,
    out: &mut dyn Write,
) {
    if ratchet_counts.is_empty() {
        return;
    }

    let _ = writeln!(out, "\n\x1b[1mRatchet rules:\x1b[0m");
    let mut sorted: Vec<_> = ratchet_counts.iter().collect();
    sorted.sort_by_key(|(id, _)| (*id).clone());

    for (rule_id, &(found, max)) in &sorted {
        let status = if found <= max {
            format!("\x1b[32m✓ pass\x1b[0m ({}/{})", found, max)
        } else {
            format!("\x1b[31m✗ OVER\x1b[0m ({}/{})", found, max)
        };
        let _ = writeln!(out, "  {:<30} {}", rule_id, status);
    }
}

/// Print violations as structured JSON.
pub fn print_json(result: &ScanResult) {
    let mut out = std::io::stdout();
    write_json(result, &mut out);
}

fn write_json(result: &ScanResult, out: &mut dyn Write) {
    let violations: Vec<_> = result
        .violations
        .iter()
        .map(|v| {
            json!({
                "rule_id": v.rule_id,
                "severity": match v.severity {
                    Severity::Error => "error",
                    Severity::Warning => "warning",
                },
                "file": v.file.display().to_string(),
                "line": v.line,
                "column": v.column,
                "message": v.message,
                "suggest": v.suggest,
                "source_line": v.source_line,
                "fix": v.fix.as_ref().map(|f| json!({
                    "old": f.old,
                    "new": f.new,
                })),
            })
        })
        .collect();

    let ratchet: serde_json::Map<String, serde_json::Value> = result
        .ratchet_counts
        .iter()
        .map(|(id, &(found, max))| {
            (
                id.clone(),
                json!({ "found": found, "max": max, "pass": found <= max }),
            )
        })
        .collect();

    let output = json!({
        "violations": violations,
        "summary": {
            "total": result.violations.len(),
            "errors": result.violations.iter().filter(|v| v.severity == Severity::Error).count(),
            "warnings": result.violations.iter().filter(|v| v.severity == Severity::Warning).count(),
            "files_scanned": result.files_scanned,
            "rules_loaded": result.rules_loaded,
        },
        "ratchet": ratchet,
    });

    let _ = writeln!(out, "{}", serde_json::to_string_pretty(&output).unwrap());
}

/// Print violations in compact one-line-per-violation format.
/// Violations go to stdout; summary goes to stderr.
pub fn print_compact(result: &ScanResult) {
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    write_compact(result, &mut stdout, &mut stderr);
}

fn write_compact(result: &ScanResult, out: &mut dyn Write, err: &mut dyn Write) {
    for v in &result.violations {
        let severity = match v.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        let line = v.line.unwrap_or(1);
        let col = v.column.unwrap_or(1);

        let _ = writeln!(
            out,
            "{}:{}:{}: {}[{}] {}",
            v.file.display(),
            line,
            col,
            severity,
            v.rule_id,
            v.message
        );
    }

    write_summary_stderr(result, err);
    write_ratchet_stderr(&result.ratchet_counts, err);
}

/// Print violations as GitHub Actions workflow commands.
/// Violations go to stdout; summary goes to stderr.
pub fn print_github(result: &ScanResult) {
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    write_github(result, &mut stdout, &mut stderr);
}

fn write_github(result: &ScanResult, out: &mut dyn Write, err: &mut dyn Write) {
    for v in &result.violations {
        let level = match v.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };

        let line = v.line.unwrap_or(1);
        let mut props = format!("file={},line={}", v.file.display(), line);
        if let Some(col) = v.column {
            props.push_str(&format!(",col={}", col));
        }
        props.push_str(&format!(",title={}", v.rule_id));

        let _ = writeln!(out, "::{} {}::{}", level, props, v.message);
    }

    // Ratchet failures as annotations
    let mut sorted: Vec<_> = result.ratchet_counts.iter().collect();
    sorted.sort_by_key(|(id, _)| (*id).clone());
    for (rule_id, &(found, max)) in &sorted {
        if found > max {
            let _ = writeln!(
                out,
                "::error title=ratchet-{}::Ratchet rule '{}' exceeded budget: {} found, max {}",
                rule_id, rule_id, found, max
            );
        }
    }

    write_summary_stderr(result, err);
}

fn write_summary_stderr(result: &ScanResult, err: &mut dyn Write) {
    let errors = result
        .violations
        .iter()
        .filter(|v| v.severity == Severity::Error)
        .count();
    let warnings = result
        .violations
        .iter()
        .filter(|v| v.severity == Severity::Warning)
        .count();

    if errors > 0 || warnings > 0 {
        let mut parts = Vec::new();
        if errors > 0 {
            parts.push(format!(
                "{} error{}",
                errors,
                if errors == 1 { "" } else { "s" }
            ));
        }
        if warnings > 0 {
            parts.push(format!(
                "{} warning{}",
                warnings,
                if warnings == 1 { "" } else { "s" }
            ));
        }
        let _ = writeln!(
            err,
            "{} ({} files scanned, {} rules loaded)",
            parts.join(", "),
            result.files_scanned,
            result.rules_loaded
        );
    } else {
        let _ = writeln!(
            err,
            "No violations found ({} files scanned, {} rules loaded)",
            result.files_scanned,
            result.rules_loaded
        );
    }
}

fn write_ratchet_stderr(
    ratchet_counts: &HashMap<String, (usize, usize)>,
    err: &mut dyn Write,
) {
    if ratchet_counts.is_empty() {
        return;
    }

    let mut sorted: Vec<_> = ratchet_counts.iter().collect();
    sorted.sort_by_key(|(id, _)| (*id).clone());

    for (rule_id, &(found, max)) in &sorted {
        let status = if found <= max { "pass" } else { "OVER" };
        let _ = writeln!(err, "ratchet: {} {} ({}/{})", rule_id, status, found, max);
    }
}

/// Print violations in SARIF v2.1.0 format for GitHub Code Scanning.
pub fn print_sarif(result: &ScanResult) {
    let mut out = std::io::stdout();
    write_sarif(result, &mut out);
}

fn write_sarif(result: &ScanResult, out: &mut dyn Write) {
    // Collect unique rules
    let mut rule_ids: Vec<String> = result
        .violations
        .iter()
        .map(|v| v.rule_id.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    rule_ids.sort();

    let rule_index: HashMap<&str, usize> = rule_ids
        .iter()
        .enumerate()
        .map(|(i, id)| (id.as_str(), i))
        .collect();

    let rules: Vec<serde_json::Value> = rule_ids
        .iter()
        .map(|id| {
            json!({
                "id": id,
                "shortDescription": { "text": id },
            })
        })
        .collect();

    let results: Vec<serde_json::Value> = result
        .violations
        .iter()
        .map(|v| {
            let level = match v.severity {
                Severity::Error => "error",
                Severity::Warning => "warning",
            };

            let location = json!({
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": v.file.display().to_string(),
                    },
                    "region": {
                        "startLine": v.line.unwrap_or(1),
                        "startColumn": v.column.unwrap_or(1),
                    }
                }
            });

            let mut result_obj = json!({
                "ruleId": v.rule_id,
                "ruleIndex": rule_index.get(v.rule_id.as_str()).unwrap_or(&0),
                "level": level,
                "message": { "text": v.message },
                "locations": [location],
            });

            // Add fix if available
            if let Some(ref fix) = v.fix {
                result_obj["fixes"] = json!([{
                    "description": { "text": v.suggest.as_deref().unwrap_or("Apply fix") },
                    "artifactChanges": [{
                        "artifactLocation": {
                            "uri": v.file.display().to_string(),
                        },
                        "replacements": [{
                            "deletedRegion": {
                                "startLine": v.line.unwrap_or(1),
                                "startColumn": v.column.unwrap_or(1),
                            },
                            "insertedContent": { "text": &fix.new }
                        }]
                    }]
                }]);
            }

            result_obj
        })
        .collect();

    let sarif = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "guardrails",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/AstroGuard/guardrails",
                    "rules": rules,
                }
            },
            "results": results,
        }]
    });

    let _ = writeln!(out, "{}", serde_json::to_string_pretty(&sarif).unwrap());
}

/// Print violations as a Markdown report (for GitHub PR summaries).
pub fn print_markdown(result: &ScanResult) {
    let mut out = std::io::stdout();
    write_markdown(result, &mut out);
}

fn write_markdown(result: &ScanResult, out: &mut dyn Write) {
    let _ = writeln!(out, "## Guardrails Report\n");

    let errors = result
        .violations
        .iter()
        .filter(|v| v.severity == Severity::Error)
        .count();
    let warnings = result
        .violations
        .iter()
        .filter(|v| v.severity == Severity::Warning)
        .count();

    // Summary line
    if errors == 0 && warnings == 0 {
        let _ = writeln!(out, "\\:white_check_mark: **No violations found** ({} files scanned, {} rules loaded)\n", result.files_scanned, result.rules_loaded);
    } else {
        let mut parts = Vec::new();
        if errors > 0 {
            parts.push(format!(
                "{} error{}",
                errors,
                if errors == 1 { "" } else { "s" }
            ));
        }
        if warnings > 0 {
            parts.push(format!(
                "{} warning{}",
                warnings,
                if warnings == 1 { "" } else { "s" }
            ));
        }
        let _ = writeln!(
            out,
            "**{}** in {} files ({} rules loaded)\n",
            parts.join(", "),
            result.files_scanned,
            result.rules_loaded
        );
    }

    // Changed-only context
    if let (Some(count), Some(ref base)) = (result.changed_files_count, &result.base_ref) {
        let _ = writeln!(
            out,
            "> Scanned {} changed file{} against `{}`\n",
            count,
            if count == 1 { "" } else { "s" },
            base
        );
    }

    if result.violations.is_empty() && result.ratchet_counts.is_empty() {
        return;
    }

    // Group by severity then by file
    let error_violations: Vec<&Violation> = result
        .violations
        .iter()
        .filter(|v| v.severity == Severity::Error)
        .collect();
    let warning_violations: Vec<&Violation> = result
        .violations
        .iter()
        .filter(|v| v.severity == Severity::Warning)
        .collect();

    if !error_violations.is_empty() {
        write_markdown_severity_section(out, "Errors", &error_violations);
    }
    if !warning_violations.is_empty() {
        write_markdown_severity_section(out, "Warnings", &warning_violations);
    }

    // Ratchet section
    if !result.ratchet_counts.is_empty() {
        let _ = writeln!(out, "### Ratchet Rules\n");
        let _ = writeln!(out, "| Rule | Status | Count |");
        let _ = writeln!(out, "|------|--------|-------|");

        let mut sorted: Vec<_> = result.ratchet_counts.iter().collect();
        sorted.sort_by_key(|(id, _)| (*id).clone());

        for (rule_id, &(found, max)) in &sorted {
            let status = if found <= max {
                "\\:white_check_mark: pass"
            } else {
                "\\:x: OVER"
            };
            let _ = writeln!(out, "| `{}` | {} | {}/{} |", rule_id, status, found, max);
        }
        let _ = writeln!(out);
    }
}

fn write_markdown_severity_section(out: &mut dyn Write, title: &str, violations: &[&Violation]) {
    let _ = writeln!(out, "### {}\n", title);

    // Group by file
    let mut by_file: BTreeMap<String, Vec<&&Violation>> = BTreeMap::new();
    for v in violations {
        by_file
            .entry(v.file.display().to_string())
            .or_default()
            .push(v);
    }

    for (file, file_violations) in &by_file {
        let _ = writeln!(out, "**`{}`**\n", file);
        let _ = writeln!(out, "| Line | Rule | Message | Suggestion |");
        let _ = writeln!(out, "|------|------|---------|------------|");

        for v in file_violations {
            let line = v.line.map(|l| l.to_string()).unwrap_or_else(|| "-".to_string());
            let suggest = v.suggest.as_deref().unwrap_or("");
            let _ = writeln!(
                out,
                "| {} | `{}` | {} | {} |",
                line, v.rule_id, v.message, suggest
            );
        }
        let _ = writeln!(out);
    }
}

/// Apply fixes from violations to source files. Returns the number of fixes applied.
/// Fixes are targeted to the specific line where the violation occurred to avoid
/// accidentally replacing a different occurrence of the same pattern.
pub fn apply_fixes(result: &ScanResult, dry_run: bool) -> usize {
    // Group fixable violations by file, keeping line info for targeted replacement
    let mut fixes_by_file: BTreeMap<String, Vec<(Option<usize>, &str, &str)>> = BTreeMap::new();

    for v in &result.violations {
        if let Some(ref fix) = v.fix {
            fixes_by_file
                .entry(v.file.display().to_string())
                .or_default()
                .push((v.line, &fix.old, &fix.new));
        }
    }

    let mut total_applied = 0;

    for (file_path, fixes) in &fixes_by_file {
        let path = Path::new(file_path);
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        // Preserve trailing newline if present
        let trailing_newline = content.ends_with('\n');
        let mut applied = 0;

        for (line_num, old, new) in fixes {
            if let Some(ln) = line_num {
                // Line-targeted: only replace within the specific line (1-indexed)
                if *ln > 0 && *ln <= lines.len() {
                    let line = &lines[*ln - 1];
                    if line.contains(*old) {
                        lines[*ln - 1] = line.replacen(*old, *new, 1);
                        applied += 1;
                    }
                }
            } else {
                // No line info — fall back to first-occurrence replacement
                let joined = lines.join("\n");
                if joined.contains(*old) {
                    let modified = joined.replacen(*old, *new, 1);
                    lines = modified.lines().map(|l| l.to_string()).collect();
                    applied += 1;
                }
            }
        }

        if applied > 0 && !dry_run {
            let mut modified = lines.join("\n");
            if trailing_newline {
                modified.push('\n');
            }
            if let Err(e) = std::fs::write(path, &modified) {
                eprintln!(
                    "\x1b[31merror\x1b[0m: failed to write {}: {}",
                    file_path, e
                );
                continue;
            }
        }

        total_applied += applied;
    }

    total_applied
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Severity;
    use std::path::PathBuf;

    fn make_result(violations: Vec<Violation>) -> ScanResult {
        ScanResult {
            violations,
            files_scanned: 5,
            rules_loaded: 2,
            ratchet_counts: HashMap::new(),
            changed_files_count: None,
            base_ref: None,
        }
    }

    fn make_violation(
        file: &str,
        line: usize,
        col: usize,
        severity: Severity,
        rule_id: &str,
        message: &str,
    ) -> Violation {
        Violation {
            rule_id: rule_id.to_string(),
            severity,
            file: PathBuf::from(file),
            line: Some(line),
            column: Some(col),
            message: message.to_string(),
            suggest: None,
            source_line: None,
            fix: None,
        }
    }

    #[test]
    fn compact_single_error() {
        let result = make_result(vec![make_violation(
            "src/Foo.tsx",
            12,
            24,
            Severity::Error,
            "dark-mode",
            "bg-white missing dark variant",
        )]);
        let mut out = Vec::new();
        let mut err = Vec::new();
        write_compact(&result, &mut out, &mut err);

        let stdout = String::from_utf8(out).unwrap();
        assert_eq!(
            stdout,
            "src/Foo.tsx:12:24: error[dark-mode] bg-white missing dark variant\n"
        );
    }

    #[test]
    fn compact_mixed_severities() {
        let result = make_result(vec![
            make_violation("a.ts", 1, 1, Severity::Error, "r1", "err msg"),
            make_violation("b.ts", 5, 10, Severity::Warning, "r2", "warn msg"),
        ]);
        let mut out = Vec::new();
        let mut err = Vec::new();
        write_compact(&result, &mut out, &mut err);

        let stdout = String::from_utf8(out).unwrap();
        assert!(stdout.contains("a.ts:1:1: error[r1] err msg\n"));
        assert!(stdout.contains("b.ts:5:10: warning[r2] warn msg\n"));

        let stderr = String::from_utf8(err).unwrap();
        assert!(stderr.contains("1 error, 1 warning"));
    }

    #[test]
    fn compact_no_violations() {
        let result = make_result(vec![]);
        let mut out = Vec::new();
        let mut err = Vec::new();
        write_compact(&result, &mut out, &mut err);

        let stdout = String::from_utf8(out).unwrap();
        assert!(stdout.is_empty());

        let stderr = String::from_utf8(err).unwrap();
        assert!(stderr.contains("No violations found"));
    }

    #[test]
    fn compact_ratchet_on_stderr() {
        let mut result = make_result(vec![]);
        result
            .ratchet_counts
            .insert("legacy-api".to_string(), (3, 5));
        let mut out = Vec::new();
        let mut err = Vec::new();
        write_compact(&result, &mut out, &mut err);

        let stderr = String::from_utf8(err).unwrap();
        assert!(stderr.contains("ratchet: legacy-api pass (3/5)"));
    }

    #[test]
    fn github_single_warning() {
        let result = make_result(vec![make_violation(
            "src/Foo.tsx",
            15,
            8,
            Severity::Warning,
            "theme-tokens",
            "raw color class",
        )]);
        let mut out = Vec::new();
        let mut err = Vec::new();
        write_github(&result, &mut out, &mut err);

        let stdout = String::from_utf8(out).unwrap();
        assert_eq!(
            stdout,
            "::warning file=src/Foo.tsx,line=15,col=8,title=theme-tokens::raw color class\n"
        );
    }

    #[test]
    fn github_missing_column_omits_col() {
        let v = Violation {
            rule_id: "test".to_string(),
            severity: Severity::Error,
            file: PathBuf::from("a.ts"),
            line: Some(3),
            column: None,
            message: "msg".to_string(),
            suggest: None,
            source_line: None,
            fix: None,
        };
        let result = make_result(vec![v]);
        let mut out = Vec::new();
        let mut err = Vec::new();
        write_github(&result, &mut out, &mut err);

        let stdout = String::from_utf8(out).unwrap();
        assert_eq!(stdout, "::error file=a.ts,line=3,title=test::msg\n");
        assert!(!stdout.contains("col="));
    }

    #[test]
    fn github_ratchet_over_budget() {
        let mut result = make_result(vec![]);
        result
            .ratchet_counts
            .insert("legacy-api".to_string(), (10, 5));
        let mut out = Vec::new();
        let mut err = Vec::new();
        write_github(&result, &mut out, &mut err);

        let stdout = String::from_utf8(out).unwrap();
        assert!(stdout.contains("::error title=ratchet-legacy-api"));
        assert!(stdout.contains("10 found, max 5"));
    }

    #[test]
    fn github_ratchet_pass_is_silent() {
        let mut result = make_result(vec![]);
        result
            .ratchet_counts
            .insert("legacy-api".to_string(), (3, 5));
        let mut out = Vec::new();
        let mut err = Vec::new();
        write_github(&result, &mut out, &mut err);

        let stdout = String::from_utf8(out).unwrap();
        assert!(stdout.is_empty());
    }

    // ── write_markdown tests ──

    #[test]
    fn markdown_no_violations() {
        let result = make_result(vec![]);
        let mut out = Vec::new();
        write_markdown(&result, &mut out);

        let output = String::from_utf8(out).unwrap();
        assert!(output.contains("## Guardrails Report"));
        assert!(output.contains("No violations found"));
        assert!(output.contains("5 files scanned"));
    }

    #[test]
    fn markdown_errors_and_warnings() {
        let result = make_result(vec![
            make_violation("src/a.tsx", 10, 5, Severity::Error, "dark-mode", "missing dark variant"),
            make_violation("src/a.tsx", 20, 1, Severity::Warning, "theme-tokens", "raw color"),
            make_violation("src/b.tsx", 3, 1, Severity::Error, "dark-mode", "missing dark variant"),
        ]);
        let mut out = Vec::new();
        write_markdown(&result, &mut out);

        let output = String::from_utf8(out).unwrap();
        assert!(output.contains("## Guardrails Report"));
        assert!(output.contains("2 errors, 1 warning"));
        assert!(output.contains("### Errors"));
        assert!(output.contains("### Warnings"));
        assert!(output.contains("`src/a.tsx`"));
        assert!(output.contains("`src/b.tsx`"));
        assert!(output.contains("| Line | Rule | Message | Suggestion |"));
    }

    #[test]
    fn markdown_with_ratchet() {
        let mut result = make_result(vec![]);
        result
            .ratchet_counts
            .insert("legacy-api".to_string(), (3, 5));
        result
            .ratchet_counts
            .insert("old-pattern".to_string(), (10, 5));
        let mut out = Vec::new();
        write_markdown(&result, &mut out);

        let output = String::from_utf8(out).unwrap();
        assert!(output.contains("### Ratchet Rules"));
        assert!(output.contains("| Rule | Status | Count |"));
        assert!(output.contains("`legacy-api`"));
        assert!(output.contains("pass"));
        assert!(output.contains("`old-pattern`"));
        assert!(output.contains("OVER"));
    }

    #[test]
    fn markdown_with_changed_only_context() {
        let mut result = make_result(vec![
            make_violation("src/a.tsx", 1, 1, Severity::Error, "r1", "msg"),
        ]);
        result.changed_files_count = Some(3);
        result.base_ref = Some("main".into());
        let mut out = Vec::new();
        write_markdown(&result, &mut out);

        let output = String::from_utf8(out).unwrap();
        assert!(output.contains("Scanned 3 changed files against `main`"));
    }

    #[test]
    fn markdown_single_changed_file() {
        let mut result = make_result(vec![]);
        result.changed_files_count = Some(1);
        result.base_ref = Some("develop".into());
        let mut out = Vec::new();
        write_markdown(&result, &mut out);

        let output = String::from_utf8(out).unwrap();
        assert!(output.contains("Scanned 1 changed file against `develop`"));
    }

    #[test]
    fn markdown_violation_with_suggestion() {
        let mut v = make_violation("src/a.tsx", 5, 1, Severity::Warning, "theme-tokens", "raw color");
        v.suggest = Some("Use bg-background instead".into());
        let result = make_result(vec![v]);
        let mut out = Vec::new();
        write_markdown(&result, &mut out);

        let output = String::from_utf8(out).unwrap();
        assert!(output.contains("Use bg-background instead"));
    }

    #[test]
    fn markdown_violation_no_line_number() {
        let v = Violation {
            rule_id: "has-readme".into(),
            severity: Severity::Error,
            file: PathBuf::from("project"),
            line: None,
            column: None,
            message: "README.md missing".into(),
            suggest: None,
            source_line: None,
            fix: None,
        };
        let result = make_result(vec![v]);
        let mut out = Vec::new();
        write_markdown(&result, &mut out);

        let output = String::from_utf8(out).unwrap();
        // No line number should show "-"
        assert!(output.contains("| - |"));
    }

    // ── write_summary_stderr tests ──

    #[test]
    fn summary_stderr_errors_only() {
        let result = make_result(vec![
            make_violation("a.ts", 1, 1, Severity::Error, "r1", "e1"),
            make_violation("a.ts", 2, 1, Severity::Error, "r2", "e2"),
        ]);
        let mut err = Vec::new();
        write_summary_stderr(&result, &mut err);

        let stderr = String::from_utf8(err).unwrap();
        assert!(stderr.contains("2 errors"));
        assert!(!stderr.contains("warning"));
    }

    #[test]
    fn summary_stderr_warnings_only() {
        let result = make_result(vec![
            make_violation("a.ts", 1, 1, Severity::Warning, "r1", "w1"),
        ]);
        let mut err = Vec::new();
        write_summary_stderr(&result, &mut err);

        let stderr = String::from_utf8(err).unwrap();
        assert!(stderr.contains("1 warning"));
        assert!(!stderr.contains("error"));
    }

    #[test]
    fn summary_stderr_plural_errors_and_warnings() {
        let result = make_result(vec![
            make_violation("a.ts", 1, 1, Severity::Error, "r1", "e1"),
            make_violation("a.ts", 2, 1, Severity::Error, "r2", "e2"),
            make_violation("a.ts", 3, 1, Severity::Warning, "r3", "w1"),
            make_violation("a.ts", 4, 1, Severity::Warning, "r4", "w2"),
            make_violation("a.ts", 5, 1, Severity::Warning, "r5", "w3"),
        ]);
        let mut err = Vec::new();
        write_summary_stderr(&result, &mut err);

        let stderr = String::from_utf8(err).unwrap();
        assert!(stderr.contains("2 errors"));
        assert!(stderr.contains("3 warnings"));
    }

    #[test]
    fn summary_stderr_no_violations() {
        let result = make_result(vec![]);
        let mut err = Vec::new();
        write_summary_stderr(&result, &mut err);

        let stderr = String::from_utf8(err).unwrap();
        assert!(stderr.contains("No violations found"));
    }

    // ── write_ratchet_stderr tests ──

    #[test]
    fn ratchet_stderr_empty() {
        let counts = HashMap::new();
        let mut err = Vec::new();
        write_ratchet_stderr(&counts, &mut err);

        let stderr = String::from_utf8(err).unwrap();
        assert!(stderr.is_empty());
    }

    #[test]
    fn ratchet_stderr_pass_and_over() {
        let mut counts = HashMap::new();
        counts.insert("a-rule".to_string(), (2usize, 5usize));
        counts.insert("b-rule".to_string(), (10, 3));
        let mut err = Vec::new();
        write_ratchet_stderr(&counts, &mut err);

        let stderr = String::from_utf8(err).unwrap();
        assert!(stderr.contains("ratchet: a-rule pass (2/5)"));
        assert!(stderr.contains("ratchet: b-rule OVER (10/3)"));
    }

    // ── compact with missing line/column ──

    #[test]
    fn compact_missing_line_defaults_to_1() {
        let v = Violation {
            rule_id: "test".to_string(),
            severity: Severity::Error,
            file: PathBuf::from("a.ts"),
            line: None,
            column: None,
            message: "msg".to_string(),
            suggest: None,
            source_line: None,
            fix: None,
        };
        let result = make_result(vec![v]);
        let mut out = Vec::new();
        let mut err = Vec::new();
        write_compact(&result, &mut out, &mut err);

        let stdout = String::from_utf8(out).unwrap();
        assert!(stdout.contains("a.ts:1:1: error[test] msg"));
    }

    // ── github with missing line ──

    #[test]
    fn github_missing_line_defaults_to_1() {
        let v = Violation {
            rule_id: "test".to_string(),
            severity: Severity::Warning,
            file: PathBuf::from("b.ts"),
            line: None,
            column: None,
            message: "msg".to_string(),
            suggest: None,
            source_line: None,
            fix: None,
        };
        let result = make_result(vec![v]);
        let mut out = Vec::new();
        let mut err = Vec::new();
        write_github(&result, &mut out, &mut err);

        let stdout = String::from_utf8(out).unwrap();
        assert!(stdout.contains("line=1"));
        assert!(!stdout.contains("col="));
    }

    // ── apply_fixes tests ──

    #[test]
    fn apply_fixes_line_targeted() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.tsx");
        std::fs::write(&file, "let a = bg-white;\nlet b = bg-white;\n").unwrap();

        let result = ScanResult {
            violations: vec![Violation {
                rule_id: "theme".into(),
                severity: Severity::Warning,
                file: file.clone(),
                line: Some(1),
                column: Some(9),
                message: "raw color".into(),
                suggest: Some("Use bg-background".into()),
                source_line: None,
                fix: Some(crate::rules::Fix {
                    old: "bg-white".into(),
                    new: "bg-background".into(),
                }),
            }],
            files_scanned: 1,
            rules_loaded: 1,
            ratchet_counts: HashMap::new(),
            changed_files_count: None,
            base_ref: None,
        };

        let count = apply_fixes(&result, false);
        assert_eq!(count, 1);

        let content = std::fs::read_to_string(&file).unwrap();
        // Only line 1 should be fixed
        assert!(content.starts_with("let a = bg-background;"));
        assert!(content.contains("let b = bg-white;"));
    }

    #[test]
    fn apply_fixes_no_line_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.tsx");
        std::fs::write(&file, "bg-white is used here\n").unwrap();

        let result = ScanResult {
            violations: vec![Violation {
                rule_id: "theme".into(),
                severity: Severity::Warning,
                file: file.clone(),
                line: None,
                column: None,
                message: "raw color".into(),
                suggest: None,
                source_line: None,
                fix: Some(crate::rules::Fix {
                    old: "bg-white".into(),
                    new: "bg-background".into(),
                }),
            }],
            files_scanned: 1,
            rules_loaded: 1,
            ratchet_counts: HashMap::new(),
            changed_files_count: None,
            base_ref: None,
        };

        let count = apply_fixes(&result, false);
        assert_eq!(count, 1);

        let content = std::fs::read_to_string(&file).unwrap();
        assert!(content.contains("bg-background"));
    }

    #[test]
    fn apply_fixes_dry_run_no_write() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.tsx");
        std::fs::write(&file, "bg-white\n").unwrap();

        let result = ScanResult {
            violations: vec![Violation {
                rule_id: "theme".into(),
                severity: Severity::Warning,
                file: file.clone(),
                line: Some(1),
                column: Some(1),
                message: "raw color".into(),
                suggest: None,
                source_line: None,
                fix: Some(crate::rules::Fix {
                    old: "bg-white".into(),
                    new: "bg-background".into(),
                }),
            }],
            files_scanned: 1,
            rules_loaded: 1,
            ratchet_counts: HashMap::new(),
            changed_files_count: None,
            base_ref: None,
        };

        let count = apply_fixes(&result, true);
        assert_eq!(count, 1);

        // File should not be modified
        let content = std::fs::read_to_string(&file).unwrap();
        assert!(content.contains("bg-white"));
    }

    #[test]
    fn apply_fixes_no_fixable_violations() {
        let result = make_result(vec![
            make_violation("a.ts", 1, 1, Severity::Error, "r1", "msg"),
        ]);
        let count = apply_fixes(&result, false);
        assert_eq!(count, 0);
    }

    #[test]
    fn apply_fixes_preserves_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.tsx");
        std::fs::write(&file, "bg-white\n").unwrap();

        let result = ScanResult {
            violations: vec![Violation {
                rule_id: "theme".into(),
                severity: Severity::Warning,
                file: file.clone(),
                line: Some(1),
                column: Some(1),
                message: "raw color".into(),
                suggest: None,
                source_line: None,
                fix: Some(crate::rules::Fix {
                    old: "bg-white".into(),
                    new: "bg-background".into(),
                }),
            }],
            files_scanned: 1,
            rules_loaded: 1,
            ratchet_counts: HashMap::new(),
            changed_files_count: None,
            base_ref: None,
        };

        apply_fixes(&result, false);
        let content = std::fs::read_to_string(&file).unwrap();
        assert!(content.ends_with('\n'));
    }

    #[test]
    fn apply_fixes_nonexistent_file_skipped() {
        let result = ScanResult {
            violations: vec![Violation {
                rule_id: "theme".into(),
                severity: Severity::Warning,
                file: PathBuf::from("/nonexistent/file.tsx"),
                line: Some(1),
                column: Some(1),
                message: "msg".into(),
                suggest: None,
                source_line: None,
                fix: Some(crate::rules::Fix {
                    old: "old".into(),
                    new: "new".into(),
                }),
            }],
            files_scanned: 1,
            rules_loaded: 1,
            ratchet_counts: HashMap::new(),
            changed_files_count: None,
            base_ref: None,
        };

        let count = apply_fixes(&result, false);
        assert_eq!(count, 0);
    }

    // ── write_json tests ──

    #[test]
    fn json_with_violations_and_ratchet() {
        let mut v = make_violation("src/a.tsx", 10, 5, Severity::Error, "dark-mode", "missing dark");
        v.suggest = Some("add dark variant".into());
        v.source_line = Some("  <div className=\"bg-white\">".into());
        v.fix = Some(crate::rules::Fix {
            old: "bg-white".into(),
            new: "bg-background".into(),
        });

        let mut result = make_result(vec![v]);
        result.ratchet_counts.insert("legacy".into(), (2, 5));

        let mut out = Vec::new();
        write_json(&result, &mut out);

        let output = String::from_utf8(out).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(parsed["summary"]["total"], 1);
        assert_eq!(parsed["summary"]["errors"], 1);
        assert_eq!(parsed["summary"]["warnings"], 0);
        assert_eq!(parsed["summary"]["files_scanned"], 5);
        assert_eq!(parsed["summary"]["rules_loaded"], 2);
        assert_eq!(parsed["violations"][0]["rule_id"], "dark-mode");
        assert_eq!(parsed["violations"][0]["severity"], "error");
        assert_eq!(parsed["violations"][0]["suggest"], "add dark variant");
        assert_eq!(parsed["violations"][0]["fix"]["old"], "bg-white");
        assert_eq!(parsed["violations"][0]["fix"]["new"], "bg-background");
        assert!(parsed["ratchet"]["legacy"]["pass"].as_bool().unwrap());
        assert_eq!(parsed["ratchet"]["legacy"]["found"], 2);
        assert_eq!(parsed["ratchet"]["legacy"]["max"], 5);
    }

    #[test]
    fn json_empty_violations() {
        let result = make_result(vec![]);
        let mut out = Vec::new();
        write_json(&result, &mut out);

        let output = String::from_utf8(out).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(parsed["summary"]["total"], 0);
        assert!(parsed["violations"].as_array().unwrap().is_empty());
    }

    #[test]
    fn json_warning_severity() {
        let result = make_result(vec![
            make_violation("a.ts", 1, 1, Severity::Warning, "r1", "warn msg"),
        ]);
        let mut out = Vec::new();
        write_json(&result, &mut out);

        let output = String::from_utf8(out).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(parsed["violations"][0]["severity"], "warning");
        assert_eq!(parsed["summary"]["warnings"], 1);
    }

    #[test]
    fn json_violation_without_fix() {
        let result = make_result(vec![
            make_violation("a.ts", 1, 1, Severity::Error, "r1", "msg"),
        ]);
        let mut out = Vec::new();
        write_json(&result, &mut out);

        let output = String::from_utf8(out).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert!(parsed["violations"][0]["fix"].is_null());
    }

    // ── write_sarif tests ──

    #[test]
    fn sarif_full_output() {
        let mut v = make_violation("src/a.tsx", 10, 5, Severity::Error, "dark-mode", "missing dark");
        v.fix = Some(crate::rules::Fix {
            old: "bg-white".into(),
            new: "bg-background".into(),
        });
        v.suggest = Some("Use bg-background".into());

        let result = make_result(vec![
            v,
            make_violation("src/b.tsx", 3, 1, Severity::Warning, "theme-tokens", "raw color"),
        ]);

        let mut out = Vec::new();
        write_sarif(&result, &mut out);

        let output = String::from_utf8(out).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(parsed["version"], "2.1.0");
        assert_eq!(parsed["runs"][0]["tool"]["driver"]["name"], "guardrails");

        // Rules should be sorted and deduplicated
        let rules = parsed["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["id"], "dark-mode");
        assert_eq!(rules[1]["id"], "theme-tokens");

        // Results should have all violations
        let results = parsed["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["level"], "error");
        assert_eq!(results[1]["level"], "warning");

        // First result should have fix
        assert!(results[0]["fixes"].is_array());
        assert_eq!(results[0]["fixes"][0]["artifactChanges"][0]["replacements"][0]["insertedContent"]["text"], "bg-background");
        assert_eq!(results[0]["fixes"][0]["description"]["text"], "Use bg-background");

        // Second result should not have fixes key set
        assert!(results[1].get("fixes").is_none());
    }

    #[test]
    fn sarif_empty_violations() {
        let result = make_result(vec![]);
        let mut out = Vec::new();
        write_sarif(&result, &mut out);

        let output = String::from_utf8(out).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert!(parsed["runs"][0]["results"].as_array().unwrap().is_empty());
        assert!(parsed["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap().is_empty());
    }

    #[test]
    fn sarif_fix_without_suggest_uses_default() {
        let mut v = make_violation("a.tsx", 1, 1, Severity::Error, "r1", "msg");
        v.fix = Some(crate::rules::Fix {
            old: "old".into(),
            new: "new".into(),
        });
        // v.suggest is None

        let result = make_result(vec![v]);
        let mut out = Vec::new();
        write_sarif(&result, &mut out);

        let output = String::from_utf8(out).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(
            parsed["runs"][0]["results"][0]["fixes"][0]["description"]["text"],
            "Apply fix"
        );
    }

    #[test]
    fn sarif_missing_line_col_defaults_to_1() {
        let v = Violation {
            rule_id: "r1".into(),
            severity: Severity::Error,
            file: PathBuf::from("a.tsx"),
            line: None,
            column: None,
            message: "msg".into(),
            suggest: None,
            source_line: None,
            fix: None,
        };
        let result = make_result(vec![v]);
        let mut out = Vec::new();
        write_sarif(&result, &mut out);

        let output = String::from_utf8(out).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        let region = &parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"];
        assert_eq!(region["startLine"], 1);
        assert_eq!(region["startColumn"], 1);
    }

    // ── compact with ratchet OVER ──

    #[test]
    fn compact_ratchet_over_on_stderr() {
        let mut result = make_result(vec![]);
        result
            .ratchet_counts
            .insert("legacy-api".to_string(), (10, 5));
        let mut out = Vec::new();
        let mut err = Vec::new();
        write_compact(&result, &mut out, &mut err);

        let stderr = String::from_utf8(err).unwrap();
        assert!(stderr.contains("ratchet: legacy-api OVER (10/5)"));
    }

    // ── github with multiple violations ──

    #[test]
    fn github_multiple_violations() {
        let result = make_result(vec![
            make_violation("a.ts", 1, 1, Severity::Error, "r1", "e1"),
            make_violation("b.ts", 5, 10, Severity::Warning, "r2", "w1"),
        ]);
        let mut out = Vec::new();
        let mut err = Vec::new();
        write_github(&result, &mut out, &mut err);

        let stdout = String::from_utf8(out).unwrap();
        assert!(stdout.contains("::error file=a.ts,line=1,col=1,title=r1::e1"));
        assert!(stdout.contains("::warning file=b.ts,line=5,col=10,title=r2::w1"));

        let stderr = String::from_utf8(err).unwrap();
        assert!(stderr.contains("1 error, 1 warning"));
    }

    // ── markdown with only errors, no warnings ──

    #[test]
    fn markdown_errors_only() {
        let result = make_result(vec![
            make_violation("src/a.tsx", 1, 1, Severity::Error, "r1", "err"),
        ]);
        let mut out = Vec::new();
        write_markdown(&result, &mut out);

        let output = String::from_utf8(out).unwrap();
        assert!(output.contains("1 error"));
        assert!(!output.contains("warning"));
        assert!(output.contains("### Errors"));
        assert!(!output.contains("### Warnings"));
    }

    // ── markdown with only warnings, no errors ──

    #[test]
    fn markdown_warnings_only() {
        let result = make_result(vec![
            make_violation("src/a.tsx", 1, 1, Severity::Warning, "r1", "warn"),
        ]);
        let mut out = Vec::new();
        write_markdown(&result, &mut out);

        let output = String::from_utf8(out).unwrap();
        assert!(output.contains("1 warning"));
        assert!(!output.contains("error"));
        assert!(!output.contains("### Errors"));
        assert!(output.contains("### Warnings"));
    }

    // ── markdown ratchet only (no violations) ──

    #[test]
    fn markdown_ratchet_only_no_violations() {
        let mut result = make_result(vec![]);
        result.ratchet_counts.insert("r1".into(), (1, 5));
        let mut out = Vec::new();
        write_markdown(&result, &mut out);

        let output = String::from_utf8(out).unwrap();
        assert!(output.contains("No violations found"));
        assert!(output.contains("### Ratchet Rules"));
    }

    // ── summary stderr: singular error and warning ──

    #[test]
    fn summary_stderr_singular_counts() {
        let result = make_result(vec![
            make_violation("a.ts", 1, 1, Severity::Error, "r1", "e"),
            make_violation("a.ts", 2, 1, Severity::Warning, "r2", "w"),
        ]);
        let mut err = Vec::new();
        write_summary_stderr(&result, &mut err);

        let stderr = String::from_utf8(err).unwrap();
        // Should say "1 error" not "1 errors"
        assert!(stderr.contains("1 error,"));
        assert!(stderr.contains("1 warning"));
        assert!(!stderr.contains("errors"));
        assert!(!stderr.contains("warnings"));
    }

    // ── apply_fixes with multiple fixes in same file ──

    #[test]
    fn apply_fixes_multiple_in_same_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.tsx");
        std::fs::write(&file, "bg-white text-gray-900\nbg-white text-gray-500\n").unwrap();

        let result = ScanResult {
            violations: vec![
                Violation {
                    rule_id: "theme".into(),
                    severity: Severity::Warning,
                    file: file.clone(),
                    line: Some(1),
                    column: Some(1),
                    message: "raw color".into(),
                    suggest: None,
                    source_line: None,
                    fix: Some(crate::rules::Fix {
                        old: "bg-white".into(),
                        new: "bg-background".into(),
                    }),
                },
                Violation {
                    rule_id: "theme".into(),
                    severity: Severity::Warning,
                    file: file.clone(),
                    line: Some(2),
                    column: Some(1),
                    message: "raw color".into(),
                    suggest: None,
                    source_line: None,
                    fix: Some(crate::rules::Fix {
                        old: "bg-white".into(),
                        new: "bg-background".into(),
                    }),
                },
            ],
            files_scanned: 1,
            rules_loaded: 1,
            ratchet_counts: HashMap::new(),
            changed_files_count: None,
            base_ref: None,
        };

        let count = apply_fixes(&result, false);
        assert_eq!(count, 2);

        let content = std::fs::read_to_string(&file).unwrap();
        assert!(!content.contains("bg-white"));
        assert_eq!(content.matches("bg-background").count(), 2);
    }

    // ── write_pretty tests ──

    #[test]
    fn pretty_no_violations() {
        let result = make_result(vec![]);
        let mut out = Vec::new();
        write_pretty(&result, &mut out);

        let output = String::from_utf8(out).unwrap();
        assert!(output.contains("No violations found"));
        assert!(output.contains("5 files scanned"));
        assert!(output.contains("2 rules loaded"));
    }

    #[test]
    fn pretty_with_error_and_warning() {
        let result = make_result(vec![
            make_violation("src/a.tsx", 10, 5, Severity::Error, "dark-mode", "missing dark variant"),
            make_violation("src/a.tsx", 20, 1, Severity::Warning, "theme-tokens", "raw color"),
        ]);
        let mut out = Vec::new();
        write_pretty(&result, &mut out);

        let output = String::from_utf8(out).unwrap();
        assert!(output.contains("src/a.tsx"));
        assert!(output.contains("10:5"));
        assert!(output.contains("20:1"));
        assert!(output.contains("error"));
        assert!(output.contains("warn"));
        assert!(output.contains("1 error"));
        assert!(output.contains("1 warning"));
    }

    #[test]
    fn pretty_errors_only_no_warning_count() {
        let result = make_result(vec![
            make_violation("a.ts", 1, 1, Severity::Error, "r1", "e1"),
        ]);
        let mut out = Vec::new();
        write_pretty(&result, &mut out);

        let output = String::from_utf8(out).unwrap();
        assert!(output.contains("1 error"));
        assert!(!output.contains("warning"));
    }

    #[test]
    fn pretty_warnings_only() {
        let result = make_result(vec![
            make_violation("a.ts", 1, 1, Severity::Warning, "r1", "w1"),
            make_violation("a.ts", 2, 1, Severity::Warning, "r2", "w2"),
        ]);
        let mut out = Vec::new();
        write_pretty(&result, &mut out);

        let output = String::from_utf8(out).unwrap();
        assert!(output.contains("2 warnings"));
        assert!(!output.contains("error"));
    }

    #[test]
    fn pretty_with_source_line() {
        let mut v = make_violation("a.tsx", 5, 1, Severity::Error, "r1", "msg");
        v.source_line = Some("  <div className=\"bg-white\">".into());
        let result = make_result(vec![v]);
        let mut out = Vec::new();
        write_pretty(&result, &mut out);

        let output = String::from_utf8(out).unwrap();
        assert!(output.contains("<div className=\"bg-white\">"));
    }

    #[test]
    fn pretty_with_suggestion() {
        let mut v = make_violation("a.tsx", 5, 1, Severity::Error, "r1", "msg");
        v.suggest = Some("Use bg-background instead".into());
        let result = make_result(vec![v]);
        let mut out = Vec::new();
        write_pretty(&result, &mut out);

        let output = String::from_utf8(out).unwrap();
        assert!(output.contains("Use bg-background instead"));
    }

    #[test]
    fn pretty_line_only_no_column() {
        let v = Violation {
            rule_id: "r1".into(),
            severity: Severity::Error,
            file: PathBuf::from("a.ts"),
            line: Some(7),
            column: None,
            message: "msg".into(),
            suggest: None,
            source_line: None,
            fix: None,
        };
        let result = make_result(vec![v]);
        let mut out = Vec::new();
        write_pretty(&result, &mut out);

        let output = String::from_utf8(out).unwrap();
        assert!(output.contains("7:1"));
    }

    #[test]
    fn pretty_no_line_no_column() {
        let v = Violation {
            rule_id: "r1".into(),
            severity: Severity::Error,
            file: PathBuf::from("a.ts"),
            line: None,
            column: None,
            message: "msg".into(),
            suggest: None,
            source_line: None,
            fix: None,
        };
        let result = make_result(vec![v]);
        let mut out = Vec::new();
        write_pretty(&result, &mut out);

        let output = String::from_utf8(out).unwrap();
        assert!(output.contains("1:1"));
    }

    #[test]
    fn pretty_multiple_files_grouped() {
        let result = make_result(vec![
            make_violation("src/a.tsx", 1, 1, Severity::Error, "r1", "m1"),
            make_violation("src/b.tsx", 2, 1, Severity::Error, "r1", "m2"),
            make_violation("src/a.tsx", 5, 1, Severity::Warning, "r2", "m3"),
        ]);
        let mut out = Vec::new();
        write_pretty(&result, &mut out);

        let output = String::from_utf8(out).unwrap();
        // Files should appear as group headers
        assert!(output.contains("src/a.tsx"));
        assert!(output.contains("src/b.tsx"));
    }

    #[test]
    fn pretty_with_ratchet() {
        let mut result = make_result(vec![
            make_violation("a.ts", 1, 1, Severity::Error, "r1", "msg"),
        ]);
        result.ratchet_counts.insert("legacy".into(), (3, 5));
        let mut out = Vec::new();
        write_pretty(&result, &mut out);

        let output = String::from_utf8(out).unwrap();
        assert!(output.contains("Ratchet rules:"));
        assert!(output.contains("legacy"));
        assert!(output.contains("pass"));
    }

    // ── write_ratchet_summary_pretty tests ──

    #[test]
    fn ratchet_summary_pretty_empty() {
        let counts = HashMap::new();
        let mut out = Vec::new();
        write_ratchet_summary_pretty(&counts, &mut out);

        let output = String::from_utf8(out).unwrap();
        assert!(output.is_empty());
    }

    #[test]
    fn ratchet_summary_pretty_pass_and_over() {
        let mut counts = HashMap::new();
        counts.insert("a-rule".to_string(), (2usize, 5usize));
        counts.insert("b-rule".to_string(), (10, 3));
        let mut out = Vec::new();
        write_ratchet_summary_pretty(&counts, &mut out);

        let output = String::from_utf8(out).unwrap();
        assert!(output.contains("Ratchet rules:"));
        assert!(output.contains("a-rule"));
        assert!(output.contains("pass"));
        assert!(output.contains("(2/5)"));
        assert!(output.contains("b-rule"));
        assert!(output.contains("OVER"));
        assert!(output.contains("(10/3)"));
    }

    #[test]
    fn pretty_no_violations_with_ratchet() {
        let mut result = make_result(vec![]);
        result.ratchet_counts.insert("legacy".into(), (2, 10));
        let mut out = Vec::new();
        write_pretty(&result, &mut out);

        let output = String::from_utf8(out).unwrap();
        assert!(output.contains("No violations found"));
        assert!(output.contains("Ratchet rules:"));
        assert!(output.contains("legacy"));
    }

    #[test]
    fn pretty_plural_errors() {
        let result = make_result(vec![
            make_violation("a.ts", 1, 1, Severity::Error, "r1", "e1"),
            make_violation("a.ts", 2, 1, Severity::Error, "r2", "e2"),
        ]);
        let mut out = Vec::new();
        write_pretty(&result, &mut out);

        let output = String::from_utf8(out).unwrap();
        assert!(output.contains("2 errors"));
    }

    #[test]
    fn pretty_mixed_with_comma() {
        let result = make_result(vec![
            make_violation("a.ts", 1, 1, Severity::Error, "r1", "e1"),
            make_violation("a.ts", 2, 1, Severity::Warning, "r2", "w1"),
        ]);
        let mut out = Vec::new();
        write_pretty(&result, &mut out);

        let output = String::from_utf8(out).unwrap();
        // Should have comma between error and warning counts
        assert!(output.contains("1 error"));
        assert!(output.contains("1 warning"));
    }
}
