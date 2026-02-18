use crate::config::{RuleConfig, Severity};
use crate::rules::ast::{collect_class_attributes, parse_file};
use crate::rules::{Rule, RuleBuildError, ScanContext, Violation};
use regex::Regex;
use std::collections::HashMap;

/// Enforces usage of shadcn/ui semantic token classes instead of raw Tailwind
/// color utilities.
///
/// In a properly themed shadcn project, you should use classes like `bg-background`,
/// `text-foreground`, `bg-muted`, `border-border` etc. that resolve to CSS custom
/// properties — not raw Tailwind colors like `bg-white`, `text-gray-900`, `border-slate-200`.
///
/// This rule catches raw color classes and suggests the semantic replacement.
///
/// By default it ships with a comprehensive mapping. You can extend or override
/// it via the `token_map` config field: `["bg-white=bg-background", "text-black=text-foreground"]`.
pub struct TailwindThemeTokensRule {
    id: String,
    severity: Severity,
    message: String,
    glob: Option<String>,
    /// Map from banned raw class → suggested semantic token class.
    token_map: HashMap<String, String>,
    /// Regex to find color utility classes in source.
    color_re: Regex,
    /// Regex to extract class attribute values.
    class_context_re: Regex,
}

/// Default mapping of raw Tailwind color classes → shadcn semantic tokens.
fn default_token_map() -> HashMap<String, String> {
    let mut map = HashMap::new();

    // ── Background colors ──
    // Light theme backgrounds
    map.insert("bg-white".into(), "bg-background".into());
    map.insert("bg-slate-50".into(), "bg-muted".into());
    map.insert("bg-gray-50".into(), "bg-muted".into());
    map.insert("bg-zinc-50".into(), "bg-muted".into());
    map.insert("bg-neutral-50".into(), "bg-muted".into());
    map.insert("bg-slate-100".into(), "bg-muted".into());
    map.insert("bg-gray-100".into(), "bg-muted".into());
    map.insert("bg-zinc-100".into(), "bg-muted".into());
    map.insert("bg-neutral-100".into(), "bg-muted".into());

    // Dark theme backgrounds (when used as dark: overrides)
    map.insert("bg-slate-900".into(), "bg-background".into());
    map.insert("bg-gray-900".into(), "bg-background".into());
    map.insert("bg-zinc-900".into(), "bg-background".into());
    map.insert("bg-neutral-900".into(), "bg-background".into());
    map.insert("bg-slate-950".into(), "bg-background".into());
    map.insert("bg-gray-950".into(), "bg-background".into());
    map.insert("bg-zinc-950".into(), "bg-background".into());
    map.insert("bg-neutral-950".into(), "bg-background".into());
    map.insert("bg-black".into(), "bg-foreground or bg-background".into());

    // Card backgrounds
    map.insert("bg-slate-200".into(), "bg-card or bg-muted".into());
    map.insert("bg-gray-200".into(), "bg-card or bg-muted".into());
    map.insert("bg-zinc-200".into(), "bg-card or bg-muted".into());

    // ── Text colors ──
    map.insert("text-black".into(), "text-foreground".into());
    map.insert("text-white".into(), "text-foreground (in dark) or text-primary-foreground".into());
    map.insert("text-slate-900".into(), "text-foreground".into());
    map.insert("text-gray-900".into(), "text-foreground".into());
    map.insert("text-zinc-900".into(), "text-foreground".into());
    map.insert("text-neutral-900".into(), "text-foreground".into());
    map.insert("text-slate-950".into(), "text-foreground".into());
    map.insert("text-gray-950".into(), "text-foreground".into());
    map.insert("text-zinc-950".into(), "text-foreground".into());

    // Muted text
    map.insert("text-slate-500".into(), "text-muted-foreground".into());
    map.insert("text-gray-500".into(), "text-muted-foreground".into());
    map.insert("text-zinc-500".into(), "text-muted-foreground".into());
    map.insert("text-neutral-500".into(), "text-muted-foreground".into());
    map.insert("text-slate-400".into(), "text-muted-foreground".into());
    map.insert("text-gray-400".into(), "text-muted-foreground".into());
    map.insert("text-zinc-400".into(), "text-muted-foreground".into());
    map.insert("text-neutral-400".into(), "text-muted-foreground".into());
    map.insert("text-slate-600".into(), "text-muted-foreground".into());
    map.insert("text-gray-600".into(), "text-muted-foreground".into());
    map.insert("text-zinc-600".into(), "text-muted-foreground".into());

    // ── Border colors ──
    map.insert("border-slate-200".into(), "border-border".into());
    map.insert("border-gray-200".into(), "border-border".into());
    map.insert("border-zinc-200".into(), "border-border".into());
    map.insert("border-neutral-200".into(), "border-border".into());
    map.insert("border-slate-300".into(), "border-border".into());
    map.insert("border-gray-300".into(), "border-border".into());
    map.insert("border-zinc-300".into(), "border-border".into());
    map.insert("border-slate-700".into(), "border-border".into());
    map.insert("border-gray-700".into(), "border-border".into());
    map.insert("border-zinc-700".into(), "border-border".into());
    map.insert("border-slate-800".into(), "border-border".into());
    map.insert("border-gray-800".into(), "border-border".into());
    map.insert("border-zinc-800".into(), "border-border".into());

    // ── Ring colors ──
    map.insert("ring-slate-200".into(), "ring-ring".into());
    map.insert("ring-gray-200".into(), "ring-ring".into());
    map.insert("ring-slate-400".into(), "ring-ring".into());
    map.insert("ring-gray-400".into(), "ring-ring".into());
    map.insert("ring-slate-700".into(), "ring-ring".into());

    // ── Divide colors ──
    map.insert("divide-slate-200".into(), "divide-border".into());
    map.insert("divide-gray-200".into(), "divide-border".into());
    map.insert("divide-zinc-200".into(), "divide-border".into());

    // ── Primary action colors (common patterns) ──
    // These are project-specific so we map the common shadcn defaults
    map.insert("bg-slate-900".to_string(), "bg-primary".into());
    map.insert("text-slate-50".into(), "text-primary-foreground".into());
    map.insert("text-gray-50".into(), "text-primary-foreground".into());

    // ── Destructive patterns ──
    map.insert("bg-red-500".into(), "bg-destructive".into());
    map.insert("bg-red-600".into(), "bg-destructive".into());
    map.insert("text-red-500".into(), "text-destructive".into());
    map.insert("text-red-600".into(), "text-destructive".into());
    map.insert("border-red-500".into(), "border-destructive".into());

    // ── Accent/secondary ──
    map.insert("bg-slate-100".to_string(), "bg-accent or bg-secondary".into());
    map.insert("bg-gray-100".to_string(), "bg-accent or bg-secondary".into());

    map
}

impl TailwindThemeTokensRule {
    pub fn new(config: &RuleConfig) -> Result<Self, RuleBuildError> {
        let mut token_map = default_token_map();

        // Override/extend with user-provided mappings
        for entry in &config.token_map {
            let parts: Vec<&str> = entry.splitn(2, '=').collect();
            if parts.len() == 2 {
                token_map.insert(parts[0].trim().to_string(), parts[1].trim().to_string());
            }
        }

        // Remove any explicitly allowed classes from the ban map
        for cls in &config.allowed_classes {
            token_map.remove(cls);
        }

        // Build regex to detect any Tailwind color utility
        let color_re = Regex::new(
            r"\b(bg|text|border|ring|outline|shadow|divide|accent|caret|fill|stroke|decoration|placeholder|from|via|to)-(white|black|slate|gray|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose)(?:-(\d{2,3}))?(?:/\d+)?\b"
        ).map_err(|e| RuleBuildError::InvalidRegex(config.id.clone(), e))?;

        let class_context_re = Regex::new(
            r#"(?:className|class)\s*=|(?:cn|clsx|classNames|cva|twMerge)\s*\("#,
        ).map_err(|e| RuleBuildError::InvalidRegex(config.id.clone(), e))?;

        let default_glob = "**/*.{tsx,jsx,html}".to_string();

        Ok(Self {
            id: config.id.clone(),
            severity: config.severity,
            message: config.message.clone(),
            glob: config.glob.clone().or(Some(default_glob)),
            token_map,
            color_re,
            class_context_re,
        })
    }

    /// Check if a line appears to contain Tailwind classes
    /// (within className, class, cn(), clsx(), etc.)
    fn line_has_class_context(&self, line: &str) -> bool {
        self.class_context_re.is_match(line)
    }
}

impl Rule for TailwindThemeTokensRule {
    fn id(&self) -> &str {
        &self.id
    }

    fn severity(&self) -> Severity {
        self.severity
    }

    fn file_glob(&self) -> Option<&str> {
        self.glob.as_deref()
    }

    fn check_file(&self, ctx: &ScanContext) -> Vec<Violation> {
        if let Some(tree) = parse_file(ctx.file_path, ctx.content) {
            return self.check_with_ast(&tree, ctx);
        }
        self.check_with_regex(ctx)
    }
}

impl TailwindThemeTokensRule {
    fn check_with_ast(&self, tree: &tree_sitter::Tree, ctx: &ScanContext) -> Vec<Violation> {
        let mut violations = Vec::new();
        let source = ctx.content.as_bytes();

        for attr_fragments in collect_class_attributes(tree, source) {
            for frag in &attr_fragments {
                for class in frag.value.split_whitespace() {
                    if class.starts_with("dark:") {
                        continue;
                    }

                    // Strip variant prefixes (hover:, focus:, etc.) to get base class
                    let base_class = class.rsplit(':').next().unwrap_or(class);

                    if let Some(replacement) = self.token_map.get(base_class) {
                        if self.color_re.is_match(base_class) {
                            let line = frag.line + 1;
                            let col_offset = frag.value.find(class).unwrap_or(0);
                            let col = frag.col + col_offset + 1;

                            let msg = if self.message.is_empty() {
                                format!(
                                    "Raw color class '{}' — use semantic token '{}' for theme support",
                                    base_class, replacement
                                )
                            } else {
                                format!("{}: '{}' → '{}'", self.message, base_class, replacement)
                            };

                            let source_line =
                                ctx.content.lines().nth(line - 1).map(|l| l.to_string());

                            violations.push(Violation {
                                rule_id: self.id.clone(),
                                severity: self.severity,
                                file: ctx.file_path.to_path_buf(),
                                line: Some(line),
                                column: Some(col),
                                message: msg,
                                suggest: Some(format!(
                                    "Replace '{}' with '{}'",
                                    base_class, replacement
                                )),
                                source_line,
                                fix: Some(crate::rules::Fix {
                                    old: base_class.to_string(),
                                    new: replacement.clone(),
                                }),
                            });
                        }
                    }
                }
            }
        }

        violations
    }

    fn check_with_regex(&self, ctx: &ScanContext) -> Vec<Violation> {
        let mut violations = Vec::new();

        for (line_num, line) in ctx.content.lines().enumerate() {
            if !self.line_has_class_context(line) {
                continue;
            }

            for cap in self.color_re.captures_iter(line) {
                let full_match = cap.get(0).unwrap().as_str();

                let match_start = cap.get(0).unwrap().start();
                if match_start >= 5 {
                    let prefix = &line[match_start.saturating_sub(5)..match_start];
                    if prefix.ends_with("dark:") {
                        continue;
                    }
                }

                if let Some(replacement) = self.token_map.get(full_match) {
                    let msg = if self.message.is_empty() {
                        format!(
                            "Raw color class '{}' — use semantic token '{}' for theme support",
                            full_match, replacement
                        )
                    } else {
                        format!("{}: '{}' → '{}'", self.message, full_match, replacement)
                    };

                    violations.push(Violation {
                        rule_id: self.id.clone(),
                        severity: self.severity,
                        file: ctx.file_path.to_path_buf(),
                        line: Some(line_num + 1),
                        column: Some(cap.get(0).unwrap().start() + 1),
                        message: msg,
                        suggest: Some(format!("Replace '{}' with '{}'", full_match, replacement)),
                        source_line: Some(line.to_string()),
                        fix: Some(crate::rules::Fix {
                            old: full_match.to_string(),
                            new: replacement.clone(),
                        }),
                    });
                }
            }
        }

        violations
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RuleConfig, Severity};
    use crate::rules::{Rule, ScanContext};
    use std::path::Path;

    fn make_rule() -> TailwindThemeTokensRule {
        let config = RuleConfig {
            id: "tailwind-theme-tokens".into(),
            severity: Severity::Warning,
            message: String::new(),
            ..Default::default()
        };
        TailwindThemeTokensRule::new(&config).unwrap()
    }

    fn check(rule: &TailwindThemeTokensRule, content: &str) -> Vec<Violation> {
        let ctx = ScanContext {
            file_path: Path::new("test.tsx"),
            content,
        };
        rule.check_file(&ctx)
    }

    // ── BadCard.tsx lines should flag violations ──

    #[test]
    fn flags_bg_white() {
        let rule = make_rule();
        let line = r#"    <div className="bg-white border border-gray-200 rounded-lg">"#;
        let violations = check(&rule, line);
        assert!(violations.iter().any(|v| v.message.contains("bg-white")));
    }

    #[test]
    fn flags_text_gray_900() {
        let rule = make_rule();
        let line = r#"          <h3 className="text-gray-900 font-semibold">{name}</h3>"#;
        let violations = check(&rule, line);
        assert!(violations.iter().any(|v| v.message.contains("text-gray-900")));
    }

    #[test]
    fn flags_text_gray_500_as_muted() {
        let rule = make_rule();
        let line = r#"          <p className="text-gray-500 text-sm">{email}</p>"#;
        let violations = check(&rule, line);
        let v = violations.iter().find(|v| v.message.contains("text-gray-500"));
        assert!(v.is_some(), "text-gray-500 should be flagged");
        assert!(
            v.unwrap().suggest.as_ref().unwrap().contains("text-muted-foreground"),
            "should suggest text-muted-foreground"
        );
    }

    #[test]
    fn flags_border_gray_200() {
        let rule = make_rule();
        let line = r#"    <div className="border border-gray-200 rounded">"#;
        let violations = check(&rule, line);
        let v = violations.iter().find(|v| v.message.contains("border-gray-200"));
        assert!(v.is_some());
        assert!(v.unwrap().suggest.as_ref().unwrap().contains("border-border"));
    }

    #[test]
    fn flags_bg_red_500_as_destructive() {
        let rule = make_rule();
        let line = r#"    <div className="bg-red-500 text-white p-4">"#;
        let violations = check(&rule, line);
        let v = violations.iter().find(|v| v.message.contains("bg-red-500"));
        assert!(v.is_some());
        assert!(v.unwrap().suggest.as_ref().unwrap().contains("bg-destructive"));
    }

    #[test]
    fn flags_bg_slate_900() {
        let rule = make_rule();
        let line = r#"        <button className="bg-slate-900 text-white px-4 py-2">"#;
        let violations = check(&rule, line);
        assert!(violations.iter().any(|v| v.message.contains("bg-slate-900")));
    }

    // ── GoodCard.tsx lines should pass clean ──

    #[test]
    fn semantic_bg_muted_passes() {
        let rule = make_rule();
        let line = r#"          <div className="w-12 h-12 bg-muted flex items-center">"#;
        let violations = check(&rule, line);
        assert!(violations.is_empty(), "bg-muted should not be flagged");
    }

    #[test]
    fn semantic_text_muted_foreground_passes() {
        let rule = make_rule();
        let line = r#"            <span className="text-muted-foreground text-lg">"#;
        let violations = check(&rule, line);
        assert!(violations.is_empty());
    }

    #[test]
    fn semantic_border_border_passes() {
        let rule = make_rule();
        let line = r#"        <div className="border-t border-border pt-4">"#;
        let violations = check(&rule, line);
        assert!(violations.is_empty());
    }

    #[test]
    fn semantic_destructive_tokens_pass() {
        let rule = make_rule();
        let line = r#"    <div className="bg-destructive text-destructive-foreground border border-destructive">"#;
        let violations = check(&rule, line);
        assert!(violations.is_empty());
    }

    #[test]
    fn semantic_primary_tokens_pass() {
        let rule = make_rule();
        let line = r#"<div className={cn("bg-primary text-primary-foreground")} />"#;
        let violations = check(&rule, line);
        assert!(violations.is_empty());
    }

    // ── dark: prefixed classes are skipped ──

    #[test]
    fn dark_prefix_skipped() {
        let rule = make_rule();
        let line = r#"<div className="bg-white dark:bg-slate-900">"#;
        let violations = check(&rule, line);
        // bg-white should be flagged, but dark:bg-slate-900 should NOT
        assert!(
            !violations.iter().any(|v| v.message.contains("dark:bg-slate-900")),
            "dark: prefixed classes should be skipped"
        );
    }

    // ── Non-class context is ignored ──

    #[test]
    fn non_class_context_ignored() {
        let rule = make_rule();
        let line = r#"const myColor = "bg-white";"#;
        let violations = check(&rule, line);
        assert!(violations.is_empty(), "color outside className context should be ignored");
    }

    // ── cn()/clsx() context is detected ──

    #[test]
    fn cn_call_context_detected() {
        let rule = make_rule();
        let line = r#"<div className={cn("bg-gray-100 text-gray-600")} />"#;
        let violations = check(&rule, line);
        assert!(!violations.is_empty(), "raw colors inside cn() should be flagged");
    }

    // ── Custom token_map overrides ──

    #[test]
    fn custom_token_map_override() {
        let config = RuleConfig {
            id: "tailwind-theme-tokens".into(),
            severity: Severity::Warning,
            message: String::new(),
            token_map: vec!["bg-blue-500=bg-brand".into()],
            ..Default::default()
        };
        let rule = TailwindThemeTokensRule::new(&config).unwrap();
        let line = r#"<div className="bg-blue-500">"#;
        let violations = check(&rule, line);
        let v = violations.iter().find(|v| v.message.contains("bg-blue-500"));
        assert!(v.is_some());
        assert!(v.unwrap().suggest.as_ref().unwrap().contains("bg-brand"));
    }

    // ── allowed_classes removes from ban map ──

    #[test]
    fn allowed_class_not_flagged() {
        let config = RuleConfig {
            id: "tailwind-theme-tokens".into(),
            severity: Severity::Warning,
            message: String::new(),
            allowed_classes: vec!["bg-white".into()],
            ..Default::default()
        };
        let rule = TailwindThemeTokensRule::new(&config).unwrap();
        let line = r#"<div className="bg-white">"#;
        let violations = check(&rule, line);
        assert!(
            !violations.iter().any(|v| v.message.contains("bg-white")),
            "explicitly allowed class should not be flagged"
        );
    }

    // ── Violation metadata ──

    #[test]
    fn violation_has_correct_line_number() {
        let rule = make_rule();
        let content = "const x = 1;\n<div className=\"bg-white p-4\">\n</div>";
        let violations = check(&rule, content);
        assert!(violations.iter().any(|v| v.line == Some(2)));
    }

    #[test]
    fn violation_has_source_line() {
        let rule = make_rule();
        let line = r#"<div className="bg-white">"#;
        let violations = check(&rule, line);
        assert!(!violations.is_empty());
        assert_eq!(violations[0].source_line.as_deref(), Some(line));
    }

    // ── Full file tests ──

    #[test]
    fn bad_card_full_file() {
        let rule = make_rule();
        let content = include_str!("../../examples/BadCard.tsx");
        let violations = check(&rule, content);
        assert!(
            violations.len() >= 5,
            "BadCard.tsx should have many violations, got {}",
            violations.len()
        );
    }

    #[test]
    fn good_card_full_file() {
        let rule = make_rule();
        let content = include_str!("../../examples/GoodCard.tsx");
        let violations = check(&rule, content);
        assert!(
            violations.is_empty(),
            "GoodCard.tsx should have no violations, got {}: {:?}",
            violations.len(),
            violations.iter().map(|v| &v.message).collect::<Vec<_>>()
        );
    }

    // ── AST-specific tests ──

    #[test]
    fn multiline_cn_all_args_detected() {
        let rule = make_rule();
        let content = r#"<span className={cn(
            "px-2 py-1 rounded-full text-xs font-medium",
            status === 'active' && "bg-green-100 text-green-800",
            status === 'inactive' && "bg-gray-100 text-gray-600",
        )} />"#;
        let violations = check(&rule, content);
        assert!(
            violations.len() >= 2,
            "multi-line cn() should detect raw colors across args, got {}",
            violations.len()
        );
    }

    #[test]
    fn ternary_both_branches_checked() {
        let rule = make_rule();
        let content = r#"<div className={active ? "bg-white" : "bg-gray-100"} />"#;
        let violations = check(&rule, content);
        assert!(
            violations.len() >= 2,
            "both ternary branches should be checked, got {}",
            violations.len()
        );
    }

    #[test]
    fn data_object_no_false_positive() {
        let rule = make_rule();
        let content = r#"const config = { className: "bg-white text-gray-900" };"#;
        let violations = check(&rule, content);
        assert!(
            violations.is_empty(),
            "non-JSX className key should not trigger violations"
        );
    }
}
