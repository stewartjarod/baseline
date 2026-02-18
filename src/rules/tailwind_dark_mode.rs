use crate::config::{RuleConfig, Severity};
use crate::rules::ast::{collect_class_attributes, parse_file};
use crate::rules::{Rule, RuleBuildError, ScanContext, Violation};
use regex::Regex;
use std::collections::HashSet;

/// Enforces that hardcoded Tailwind color utilities always have a `dark:` counterpart.
///
/// For example, `className="bg-white text-black"` will be flagged because there
/// are no `dark:bg-*` or `dark:text-*` variants present. shadcn semantic token
/// classes like `bg-background` and `text-foreground` are allowed by default
/// because they resolve via CSS variables that already handle both themes.
///
/// This rule scans JSX/TSX/HTML files for class attributes and analyzes the
/// Tailwind classes within them.
pub struct TailwindDarkModeRule {
    id: String,
    severity: Severity,
    message: String,
    suggest: Option<String>,
    glob: Option<String>,
    /// Classes that are exempt (don't need a dark: variant).
    allowed: HashSet<String>,
    /// Regex to extract className/class attribute values.
    class_attr_re: Regex,
    /// Regex to identify color utility classes.
    color_utility_re: Regex,
    /// Regex to find cn/clsx/classNames/cva/twMerge function calls.
    cn_fn_re: Regex,
    /// Regex to extract quoted strings inside function calls.
    cn_str_re: Regex,
}

/// The Tailwind color utility prefixes that are theme-sensitive.
const COLOR_PREFIXES: &[&str] = &[
    "bg-", "text-", "border-", "ring-", "outline-", "shadow-",
    "divide-", "accent-", "caret-", "fill-", "stroke-",
    "decoration-", "placeholder-",
    // Gradient stops
    "from-", "via-", "to-",
];

/// Tailwind color names (used to build the detection regex).
const TAILWIND_COLORS: &[&str] = &[
    "slate", "gray", "zinc", "neutral", "stone",
    "red", "orange", "amber", "yellow", "lime",
    "green", "emerald", "teal", "cyan", "sky",
    "blue", "indigo", "violet", "purple", "fuchsia",
    "pink", "rose",
    // Named colors
    "white", "black",
];

/// shadcn/ui semantic token classes that already handle light/dark via CSS variables.
/// These never need a `dark:` variant.
const SEMANTIC_TOKEN_SUFFIXES: &[&str] = &[
    "background", "foreground",
    "card", "card-foreground",
    "popover", "popover-foreground",
    "primary", "primary-foreground",
    "secondary", "secondary-foreground",
    "muted", "muted-foreground",
    "accent", "accent-foreground",
    "destructive", "destructive-foreground",
    "border", "input", "ring",
    "chart-1", "chart-2", "chart-3", "chart-4", "chart-5",
    "sidebar-background", "sidebar-foreground",
    "sidebar-primary", "sidebar-primary-foreground",
    "sidebar-accent", "sidebar-accent-foreground",
    "sidebar-border", "sidebar-ring",
];

/// Classes that inherently don't need dark: variants.
const ALWAYS_ALLOWED_SUFFIXES: &[&str] = &[
    "transparent", "current", "inherit", "auto",
];

impl TailwindDarkModeRule {
    pub fn new(config: &RuleConfig) -> Result<Self, RuleBuildError> {
        let mut allowed = HashSet::new();

        // Build the set of allowed classes (semantic tokens + special values)
        for prefix in COLOR_PREFIXES {
            for suffix in SEMANTIC_TOKEN_SUFFIXES {
                allowed.insert(format!("{}{}", prefix, suffix));
            }
            for suffix in ALWAYS_ALLOWED_SUFFIXES {
                allowed.insert(format!("{}{}", prefix, suffix));
            }
        }

        // Add user-provided allowed classes
        for cls in &config.allowed_classes {
            allowed.insert(cls.clone());
        }

        // Regex to find className="..." or class="..." (handles multi-line with `)
        // Also matches className={cn("...", "...")} and className={clsx(...)}
        // We capture the full attribute value to extract classes from.
        let class_attr_re = Regex::new(
            r#"(?:className|class)\s*=\s*(?:"([^"]*?)"|'([^']*?)'|\{[^}]*?(?:`([^`]*?)`|"([^"]*?)"|'([^']*?)'))"#,
        ).map_err(|e| RuleBuildError::InvalidRegex(config.id.clone(), e))?;

        // Build regex that matches color utility classes.
        // Pattern: (bg|text|border|...)-{color}(-{shade})?
        // Examples: bg-white, text-gray-900, border-slate-200/50
        let prefix_group = COLOR_PREFIXES.iter()
            .map(|p| regex::escape(p.trim_end_matches('-')))
            .collect::<Vec<_>>()
            .join("|");
        let color_group = TAILWIND_COLORS.join("|");

        let color_re_str = format!(
            r"\b({})-({})(?:-(\d{{2,3}}))?(?:/\d+)?\b",
            prefix_group, color_group
        );
        let color_utility_re = Regex::new(&color_re_str)
            .map_err(|e| RuleBuildError::InvalidRegex(config.id.clone(), e))?;

        let cn_fn_re = Regex::new(r#"(?:cn|clsx|classNames|cva|twMerge)\s*\("#)
            .map_err(|e| RuleBuildError::InvalidRegex(config.id.clone(), e))?;
        let cn_str_re = Regex::new(r#"['"`]([^'"`]+?)['"`]"#)
            .map_err(|e| RuleBuildError::InvalidRegex(config.id.clone(), e))?;

        let default_glob = "**/*.{tsx,jsx,html}".to_string();

        Ok(Self {
            id: config.id.clone(),
            severity: config.severity,
            message: config.message.clone(),
            suggest: config.suggest.clone(),
            glob: config.glob.clone().or(Some(default_glob)),
            allowed,
            class_attr_re,
            color_utility_re,
            cn_fn_re,
            cn_str_re,
        })
    }

    /// Extract all class strings from a line of source code.
    fn extract_class_strings<'a>(&self, line: &'a str) -> Vec<&'a str> {
        let mut results = Vec::new();
        for cap in self.class_attr_re.captures_iter(line) {
            // Try each capture group (different quote styles)
            for i in 1..=5 {
                if let Some(m) = cap.get(i) {
                    results.push(m.as_str());
                }
            }
        }
        results
    }

    /// Check if a color utility class has a corresponding `dark:` variant in the same class list.
    fn find_missing_dark_variants(&self, class_string: &str) -> Vec<(String, Option<String>)> {
        let classes: Vec<&str> = class_string.split_whitespace().collect();

        // Collect all dark: prefixed classes
        let dark_classes: HashSet<String> = classes.iter()
            .filter(|c| c.starts_with("dark:"))
            .map(|c| c.strip_prefix("dark:").unwrap().to_string())
            .collect();

        let mut violations = Vec::new();

        for class in &classes {
            // Skip dark: prefixed classes themselves
            if class.starts_with("dark:") || class.starts_with("hover:") || class.starts_with("focus:") {
                continue;
            }

            // Skip non-color utility classes
            if !self.color_utility_re.is_match(class) {
                continue;
            }

            // Skip allowed classes (semantic tokens, transparent, etc.)
            if self.allowed.contains(*class) {
                continue;
            }

            // Check if there's a matching dark: variant
            // We look for any dark: class that shares the same prefix (e.g., dark:bg-*)
            let prefix = class.split('-').next().unwrap_or("");
            let has_dark = dark_classes.iter().any(|dc| dc.starts_with(prefix));

            if !has_dark {
                let suggestion = suggest_semantic_token(class);
                violations.push((class.to_string(), suggestion));
            }
        }

        violations
    }
}

/// Suggest a semantic token replacement for a raw color class.
fn suggest_semantic_token(class: &str) -> Option<String> {
    // Common mappings
    let parts: Vec<&str> = class.splitn(2, '-').collect();
    if parts.len() < 2 {
        return None;
    }
    let prefix = parts[0]; // bg, text, border, etc.
    let color_part = parts[1]; // white, black, gray-100, etc.

    let token = match color_part {
        "white" => match prefix {
            "bg" => Some("bg-background"),
            "text" => Some("text-foreground"),
            _ => None,
        },
        "black" => match prefix {
            "bg" => Some("bg-foreground"),
            "text" => Some("text-background"),
            _ => None,
        },
        s if s.starts_with("gray") || s.starts_with("slate") || s.starts_with("zinc") || s.starts_with("neutral") => {
            // Extract shade
            let shade: Option<u32> = s.split('-').nth(1).and_then(|n| n.parse().ok());
            match (prefix, shade) {
                ("bg", Some(50..=200)) => Some("bg-muted"),
                ("bg", Some(800..=950)) => Some("bg-background (in dark theme)"),
                ("text", Some(400..=600)) => Some("text-muted-foreground"),
                ("text", Some(700..=950)) => Some("text-foreground"),
                ("border", _) => Some("border-border"),
                _ => None,
            }
        },
        _ => None,
    };

    token.map(|t| format!("Use '{}' instead — it adapts to light/dark automatically", t))
}

impl Rule for TailwindDarkModeRule {
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

impl TailwindDarkModeRule {
    fn check_with_ast(&self, tree: &tree_sitter::Tree, ctx: &ScanContext) -> Vec<Violation> {
        let mut violations = Vec::new();
        let source = ctx.content.as_bytes();

        for attr_fragments in collect_class_attributes(tree, source) {
            let full_class_string: String = attr_fragments
                .iter()
                .map(|f| f.value.as_str())
                .collect::<Vec<_>>()
                .join(" ");

            let missing = self.find_missing_dark_variants(&full_class_string);

            for (class, token_suggestion) in missing {
                let (line, col) = attr_fragments
                    .iter()
                    .find_map(|f| {
                        f.value.split_whitespace().find(|&c| c == class).map(|_| {
                            let offset = f.value.find(&class).unwrap_or(0);
                            (f.line + 1, f.col + offset + 1)
                        })
                    })
                    .unwrap_or((1, 1));

                let msg = if self.message.is_empty() {
                    format!("Class '{}' sets a color without a dark: variant", class)
                } else {
                    format!("{}: '{}'", self.message, class)
                };

                let suggest = token_suggestion
                    .or_else(|| self.suggest.clone())
                    .or_else(|| {
                        Some(format!(
                            "Add 'dark:{}' or replace with a semantic token class",
                            suggest_dark_counterpart(&class)
                        ))
                    });

                let source_line = ctx.content.lines().nth(line - 1).map(|l| l.to_string());

                violations.push(Violation {
                    rule_id: self.id.clone(),
                    severity: self.severity,
                    file: ctx.file_path.to_path_buf(),
                    line: Some(line),
                    column: Some(col),
                    message: msg,
                    suggest,
                    source_line,
                    fix: None,
                });
            }
        }

        violations
    }

    fn check_with_regex(&self, ctx: &ScanContext) -> Vec<Violation> {
        let mut violations = Vec::new();

        for (line_num, line) in ctx.content.lines().enumerate() {
            let class_strings = self.extract_class_strings(line);
            let extra_strings = self.extract_cn_strings(line);

            for class_str in class_strings
                .iter()
                .copied()
                .chain(extra_strings.iter().map(|s| s.as_str()))
            {
                let missing = self.find_missing_dark_variants(class_str);

                for (class, token_suggestion) in missing {
                    let msg = if self.message.is_empty() {
                        format!("Class '{}' sets a color without a dark: variant", class)
                    } else {
                        format!("{}: '{}'", self.message, class)
                    };

                    let suggest = token_suggestion
                        .or_else(|| self.suggest.clone())
                        .or_else(|| {
                            Some(format!(
                                "Add 'dark:{}' or replace with a semantic token class",
                                suggest_dark_counterpart(&class)
                            ))
                        });

                    violations.push(Violation {
                        rule_id: self.id.clone(),
                        severity: self.severity,
                        file: ctx.file_path.to_path_buf(),
                        line: Some(line_num + 1),
                        column: line.find(&class).map(|c| c + 1),
                        message: msg,
                        suggest,
                        source_line: Some(line.to_string()),
                        fix: None,
                    });
                }
            }
        }

        violations
    }

    /// Extract string arguments from cn(), clsx(), classNames() calls.
    fn extract_cn_strings(&self, line: &str) -> Vec<String> {
        let mut results = Vec::new();

        if let Some(fn_match) = self.cn_fn_re.find(line) {
            let remainder = &line[fn_match.end()..];
            for cap in self.cn_str_re.captures_iter(remainder) {
                if let Some(m) = cap.get(1) {
                    let s = m.as_str();
                    if s.contains('-') || s.contains(' ') {
                        results.push(s.to_string());
                    }
                }
            }
        }

        results
    }
}

/// Suggest a dark mode counterpart for a color class.
fn suggest_dark_counterpart(class: &str) -> String {
    let parts: Vec<&str> = class.splitn(2, '-').collect();
    if parts.len() < 2 {
        return class.to_string();
    }

    let prefix = parts[0];
    let color_part = parts[1];

    // Invert common patterns
    match color_part {
        "white" => format!("{}-slate-950", prefix),
        "black" => format!("{}-white", prefix),
        s => {
            // Try to invert shade: 100 → 900, 200 → 800, etc.
            let color_parts: Vec<&str> = s.rsplitn(2, '-').collect();
            if color_parts.len() == 2 {
                if let Ok(shade) = color_parts[0].parse::<u32>() {
                    let inverted = match shade {
                        50 => 950, 100 => 900, 200 => 800, 300 => 700,
                        400 => 600, 500 => 500, 600 => 400, 700 => 300,
                        800 => 200, 900 => 100, 950 => 50,
                        _ => shade,
                    };
                    return format!("{}-{}-{}", prefix, color_parts[1], inverted);
                }
            }
            format!("{}-{}", prefix, s)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RuleConfig, Severity};
    use crate::rules::{Rule, ScanContext};
    use std::path::Path;

    fn make_rule() -> TailwindDarkModeRule {
        let config = RuleConfig {
            id: "tailwind-dark-mode".into(),
            severity: Severity::Warning,
            message: String::new(),
            ..Default::default()
        };
        TailwindDarkModeRule::new(&config).unwrap()
    }

    fn check(rule: &TailwindDarkModeRule, content: &str) -> Vec<Violation> {
        let ctx = ScanContext {
            file_path: Path::new("test.tsx"),
            content,
        };
        rule.check_file(&ctx)
    }

    // ── BadCard.tsx should flag violations ──

    #[test]
    fn bad_card_flags_hardcoded_bg_white() {
        let rule = make_rule();
        let line = r#"    <div className="bg-white border border-gray-200 rounded-lg shadow-sm p-6">"#;
        let violations = check(&rule, line);
        assert!(!violations.is_empty(), "bg-white without dark: should be flagged");
        assert!(violations.iter().any(|v| v.message.contains("bg-white")));
    }

    #[test]
    fn bad_card_flags_hardcoded_text_colors() {
        let rule = make_rule();
        let line = r#"          <h3 className="text-gray-900 font-semibold text-lg">{name}</h3>"#;
        let violations = check(&rule, line);
        assert!(violations.iter().any(|v| v.message.contains("text-gray-900")));
    }

    #[test]
    fn bad_card_flags_muted_text() {
        let rule = make_rule();
        let line = r#"          <p className="text-gray-500 text-sm">{email}</p>"#;
        let violations = check(&rule, line);
        assert!(violations.iter().any(|v| v.message.contains("text-gray-500")));
    }

    #[test]
    fn bad_card_flags_border_color() {
        let rule = make_rule();
        let line = r#"      <div className="mt-4 pt-4 border-t border-gray-200">"#;
        let violations = check(&rule, line);
        assert!(violations.iter().any(|v| v.message.contains("border-gray-200")));
    }

    #[test]
    fn bad_card_flags_button_bg() {
        let rule = make_rule();
        let line = r#"        <button className="bg-slate-900 text-white px-4 py-2 rounded-md hover:bg-slate-800">"#;
        let violations = check(&rule, line);
        assert!(violations.iter().any(|v| v.message.contains("bg-slate-900")));
    }

    #[test]
    fn bad_card_flags_destructive_colors() {
        let rule = make_rule();
        let line = r#"    <div className="bg-red-500 text-white p-4 rounded-md border border-red-600">"#;
        let violations = check(&rule, line);
        assert!(violations.iter().any(|v| v.message.contains("bg-red-500")));
    }

    // ── GoodCard.tsx should pass clean ──

    #[test]
    fn good_card_semantic_bg_muted_passes() {
        let rule = make_rule();
        let line = r#"          <div className="w-12 h-12 rounded-full bg-muted flex items-center justify-center">"#;
        let violations = check(&rule, line);
        assert!(violations.is_empty(), "bg-muted is a semantic token and should pass");
    }

    #[test]
    fn good_card_semantic_text_muted_foreground_passes() {
        let rule = make_rule();
        let line = r#"            <span className="text-muted-foreground text-lg font-bold">"#;
        let violations = check(&rule, line);
        assert!(violations.is_empty(), "text-muted-foreground should pass");
    }

    #[test]
    fn good_card_semantic_border_passes() {
        let rule = make_rule();
        let line = r#"        <div className="border-t border-border pt-4">"#;
        let violations = check(&rule, line);
        assert!(violations.is_empty(), "border-border should pass");
    }

    #[test]
    fn good_card_destructive_semantic_passes() {
        let rule = make_rule();
        let line = r#"    <div className="bg-destructive text-destructive-foreground p-4 rounded-md border border-destructive">"#;
        let violations = check(&rule, line);
        assert!(violations.is_empty(), "destructive semantic tokens should pass");
    }

    // ── dark: variant suppresses violation ──

    #[test]
    fn dark_variant_present_no_violation() {
        let rule = make_rule();
        let line = r#"<div className="bg-white dark:bg-slate-900 text-black dark:text-white">"#;
        let violations = check(&rule, line);
        assert!(violations.is_empty(), "dark: variants present should suppress violations");
    }

    // ── cn() function calls ──

    #[test]
    fn cn_call_with_hardcoded_colors_flagged() {
        let rule = make_rule();
        let line = r#"<div className={cn("bg-gray-100 text-gray-600")} />"#;
        let violations = check(&rule, line);
        assert!(!violations.is_empty(), "hardcoded colors inside cn() should be flagged");
    }

    #[test]
    fn cn_call_with_semantic_tokens_passes() {
        let rule = make_rule();
        let line = r#"<div className={cn("bg-primary text-primary-foreground")} />"#;
        let violations = check(&rule, line);
        assert!(violations.is_empty(), "semantic tokens inside cn() should pass");
    }

    // ── transparent / current always allowed ──

    #[test]
    fn transparent_and_current_always_pass() {
        let rule = make_rule();
        let line = r#"<div className="bg-transparent text-current">"#;
        let violations = check(&rule, line);
        assert!(violations.is_empty(), "transparent and current should always be allowed");
    }

    // ── allowed_classes config ──

    #[test]
    fn custom_allowed_class_suppresses_violation() {
        let config = RuleConfig {
            id: "tailwind-dark-mode".into(),
            severity: Severity::Warning,
            message: String::new(),
            allowed_classes: vec!["bg-white".into()],
            ..Default::default()
        };
        let rule = TailwindDarkModeRule::new(&config).unwrap();
        let line = r#"<div className="bg-white">"#;
        let violations = check(&rule, line);
        assert!(violations.is_empty(), "explicitly allowed class should not be flagged");
    }

    // ── Non-class lines should be ignored ──

    #[test]
    fn plain_text_no_violations() {
        let rule = make_rule();
        let violations = check(&rule, "const color = 'bg-white';");
        assert!(violations.is_empty(), "non-className usage should not be flagged");
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
            violations.len() >= 4,
            "multi-line cn() should detect all hardcoded colors, got {}",
            violations.len()
        );
    }

    #[test]
    fn dark_variant_across_cn_args_no_violation() {
        let rule = make_rule();
        let content = r#"<div className={cn("bg-white", "dark:bg-slate-900")} />"#;
        let violations = check(&rule, content);
        assert!(
            violations.is_empty(),
            "dark: in separate cn() arg should suppress violation for same attribute"
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
