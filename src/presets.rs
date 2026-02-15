use crate::cli::toml_config::TomlRule;
use std::collections::HashMap;
use std::fmt;

#[derive(Debug)]
pub enum PresetError {
    UnknownPreset {
        name: String,
        available: Vec<&'static str>,
    },
}

impl fmt::Display for PresetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PresetError::UnknownPreset { name, available } => {
                write!(
                    f,
                    "unknown preset '{}'. available presets: {}",
                    name,
                    available.join(", ")
                )
            }
        }
    }
}

impl std::error::Error for PresetError {}

#[derive(Debug, Clone, Copy)]
enum Preset {
    ShadcnStrict,
    ShadcnMigrate,
    AiSafety,
    Security,
    Nextjs,
    AiCodegen,
}

/// Returns the list of all available preset names.
pub fn available_presets() -> &'static [&'static str] {
    &[
        "shadcn-strict",
        "shadcn-migrate",
        "ai-safety",
        "security",
        "nextjs",
        "ai-codegen",
    ]
}

fn resolve_preset(name: &str) -> Option<Preset> {
    match name {
        "shadcn-strict" => Some(Preset::ShadcnStrict),
        "shadcn-migrate" => Some(Preset::ShadcnMigrate),
        "ai-safety" => Some(Preset::AiSafety),
        "security" => Some(Preset::Security),
        "nextjs" => Some(Preset::Nextjs),
        "ai-codegen" => Some(Preset::AiCodegen),
        _ => None,
    }
}

fn preset_rules(preset: Preset) -> Vec<TomlRule> {
    match preset {
        Preset::ShadcnStrict => vec![
            TomlRule {
                id: "enforce-dark-mode".into(),
                rule_type: "tailwind-dark-mode".into(),
                severity: "error".into(),
                glob: Some("**/*.{tsx,jsx}".into()),
                message: "Missing dark: variant for color class".into(),
                suggest: Some(
                    "Use a shadcn semantic token class or add an explicit dark: counterpart"
                        .into(),
                ),
                ..Default::default()
            },
            TomlRule {
                id: "use-theme-tokens".into(),
                rule_type: "tailwind-theme-tokens".into(),
                severity: "error".into(),
                glob: Some("**/*.{tsx,jsx}".into()),
                message: "Use shadcn semantic token instead of raw color".into(),
                ..Default::default()
            },
            TomlRule {
                id: "no-inline-styles".into(),
                rule_type: "banned-pattern".into(),
                severity: "warning".into(),
                glob: Some("**/*.{tsx,jsx}".into()),
                pattern: Some("style={{".into()),
                message: "Avoid inline styles — use Tailwind utility classes instead".into(),
                suggest: Some("Replace style={{ ... }} with Tailwind classes".into()),
                ..Default::default()
            },
            TomlRule {
                id: "no-css-in-js".into(),
                rule_type: "banned-import".into(),
                severity: "error".into(),
                packages: vec![
                    "styled-components".into(),
                    "@emotion/styled".into(),
                    "@emotion/css".into(),
                    "@emotion/react".into(),
                ],
                message: "CSS-in-JS libraries conflict with Tailwind — use utility classes instead"
                    .into(),
                ..Default::default()
            },
            TomlRule {
                id: "no-competing-frameworks".into(),
                rule_type: "banned-dependency".into(),
                severity: "error".into(),
                packages: vec![
                    "bootstrap".into(),
                    "bulma".into(),
                    "@mui/material".into(),
                    "antd".into(),
                ],
                message:
                    "Competing CSS framework detected — this project uses Tailwind + shadcn/ui"
                        .into(),
                ..Default::default()
            },
        ],
        Preset::ShadcnMigrate => vec![
            TomlRule {
                id: "enforce-dark-mode".into(),
                rule_type: "tailwind-dark-mode".into(),
                severity: "error".into(),
                glob: Some("**/*.{tsx,jsx}".into()),
                message: "Missing dark: variant for color class".into(),
                suggest: Some(
                    "Use a shadcn semantic token class or add an explicit dark: counterpart"
                        .into(),
                ),
                ..Default::default()
            },
            TomlRule {
                id: "use-theme-tokens".into(),
                rule_type: "tailwind-theme-tokens".into(),
                severity: "warning".into(),
                glob: Some("**/*.{tsx,jsx}".into()),
                message: "Use shadcn semantic token instead of raw color".into(),
                ..Default::default()
            },
        ],
        Preset::AiSafety => vec![
            TomlRule {
                id: "no-moment".into(),
                rule_type: "banned-dependency".into(),
                severity: "error".into(),
                packages: vec!["moment".into(), "moment-timezone".into()],
                message: "moment.js is deprecated — use date-fns or Temporal API".into(),
                ..Default::default()
            },
            TomlRule {
                id: "no-lodash".into(),
                rule_type: "banned-dependency".into(),
                severity: "error".into(),
                packages: vec!["lodash".into()],
                message: "lodash is unnecessary — use native JS methods".into(),
                ..Default::default()
            },
            TomlRule {
                id: "no-deprecated-request".into(),
                rule_type: "banned-dependency".into(),
                severity: "error".into(),
                packages: vec!["request".into(), "request-promise".into()],
                message: "The 'request' package is deprecated — use 'node-fetch' or 'undici'".into(),
                ..Default::default()
            },
        ],
        Preset::Security => vec![
            TomlRule {
                id: "no-env-files".into(),
                rule_type: "file-presence".into(),
                severity: "error".into(),
                forbidden_files: vec![
                    ".env".into(),
                    ".env.local".into(),
                    ".env.development".into(),
                    ".env.production".into(),
                    ".env.staging".into(),
                ],
                message: "Environment files must not be committed — add to .gitignore".into(),
                ..Default::default()
            },
            TomlRule {
                id: "no-hardcoded-secrets".into(),
                rule_type: "banned-pattern".into(),
                severity: "error".into(),
                pattern: Some(r#"(?i)(?:api_key|apikey|secret_key|secretkey|auth_token|access_token|private_key|password|passwd|secret|client_secret)\s*[:=]\s*["'][a-zA-Z0-9_\-]{8,}"#.into()),
                regex: true,
                exclude_glob: vec!["**/*.test.*".into(), "**/*.spec.*".into()],
                message: "Hardcoded secret detected — use environment variables instead".into(),
                ..Default::default()
            },
            TomlRule {
                id: "no-eval".into(),
                rule_type: "banned-pattern".into(),
                severity: "error".into(),
                pattern: Some(r"\beval\s*\(".into()),
                regex: true,
                message: "eval() is a security risk — avoid arbitrary code execution".into(),
                ..Default::default()
            },
            TomlRule {
                id: "no-dangerous-html".into(),
                rule_type: "banned-pattern".into(),
                severity: "error".into(),
                pattern: Some("dangerouslySetInnerHTML".into()),
                message: "dangerouslySetInnerHTML can lead to XSS — sanitize content or use a safe alternative".into(),
                ..Default::default()
            },
            TomlRule {
                id: "no-innerhtml".into(),
                rule_type: "banned-pattern".into(),
                severity: "error".into(),
                pattern: Some(r"\.innerHTML\s*\+?=".into()),
                regex: true,
                message: "Direct innerHTML assignment can lead to XSS — use textContent or a sanitizer".into(),
                ..Default::default()
            },
            TomlRule {
                id: "no-console-log".into(),
                rule_type: "banned-pattern".into(),
                severity: "warning".into(),
                pattern: Some(r"console\.(log|debug)\(".into()),
                regex: true,
                exclude_glob: vec!["**/*.test.*".into(), "**/*.spec.*".into()],
                message: "Remove console.log/debug before deploying to production".into(),
                ..Default::default()
            },
            TomlRule {
                id: "no-document-write".into(),
                rule_type: "banned-pattern".into(),
                severity: "error".into(),
                pattern: Some(r"document\.write\s*\(".into()),
                regex: true,
                message: "document.write() is an XSS risk and blocks rendering — use DOM APIs instead".into(),
                ..Default::default()
            },
            TomlRule {
                id: "no-postmessage-wildcard".into(),
                rule_type: "banned-pattern".into(),
                severity: "error".into(),
                pattern: Some(r#"\.postMessage\(.*,\s*['"]\*['"]"#.into()),
                regex: true,
                message: "postMessage with '*' origin exposes data to any window — specify the target origin".into(),
                ..Default::default()
            },
            TomlRule {
                id: "no-outerhtml".into(),
                rule_type: "banned-pattern".into(),
                severity: "error".into(),
                pattern: Some(r"\.outerHTML\s*\+?=".into()),
                regex: true,
                message: "Direct outerHTML assignment can lead to XSS — use DOM APIs or a sanitizer".into(),
                ..Default::default()
            },
            TomlRule {
                id: "no-http-links".into(),
                rule_type: "banned-pattern".into(),
                severity: "warning".into(),
                glob: Some("**/*.{ts,tsx,js,jsx}".into()),
                pattern: Some(r#"['"]http://"#.into()),
                regex: true,
                exclude_glob: vec!["**/*.test.*".into(), "**/*.spec.*".into()],
                message: "Insecure http:// URL — use https:// instead".into(),
                ..Default::default()
            },
        ],
        Preset::Nextjs => vec![
            TomlRule {
                id: "use-next-image".into(),
                rule_type: "banned-pattern".into(),
                severity: "warning".into(),
                glob: Some("**/*.{tsx,jsx}".into()),
                pattern: Some(r"<img\s".into()),
                regex: true,
                message: "Use next/image instead of <img> for automatic optimization".into(),
                suggest: Some("Import Image from 'next/image' and use <Image> component".into()),
                ..Default::default()
            },
            TomlRule {
                id: "no-next-head".into(),
                rule_type: "banned-import".into(),
                severity: "error".into(),
                glob: Some("app/**".into()),
                packages: vec!["next/head".into()],
                message: "next/head is not supported in App Router — use the Metadata API instead".into(),
                ..Default::default()
            },
            TomlRule {
                id: "no-private-env-client".into(),
                rule_type: "banned-pattern".into(),
                severity: "error".into(),
                glob: Some("**/*.{ts,tsx,js,jsx}".into()),
                // Alternation-based exclusion of NEXT_PUBLIC_ (regex crate lacks lookahead)
                pattern: Some(r"process\.env\.(?:[A-MO-Za-z_]\w*|N[A-DF-Za-z0-9_]\w*|NE[A-WYZa-z0-9_]\w*|NEX[A-SU-Za-z0-9_]\w*|NEXT[A-Za-z0-9]\w*|NEXT_[A-OQ-Za-z0-9_]\w*|NEXT_P[A-TV-Za-z0-9_]\w*|NEXT_PU[A-AC-Za-z0-9_]\w*|NEXT_PUB[A-KM-Za-z0-9_]\w*|NEXT_PUBL[A-HJ-Za-z0-9_]\w*|NEXT_PUBLI[A-BD-Za-z0-9_]\w*|NEXT_PUBLIC[A-Za-z0-9]\w*)".into()),
                regex: true,
                file_contains: Some("use client".into()),
                message: "Private env vars are undefined in client components — prefix with NEXT_PUBLIC_".into(),
                ..Default::default()
            },
            TomlRule {
                id: "require-use-client-for-hooks".into(),
                rule_type: "required-pattern".into(),
                severity: "error".into(),
                glob: Some("app/**".into()),
                pattern: Some("use client".into()),
                regex: true,
                condition_pattern: Some(r"use(State|Effect|Context|Reducer|Callback|Memo|Ref|Transition|DeferredValue|InsertionEffect|SyncExternalStore|FormStatus|Optimistic)\s*\(".into()),
                message: "Files using React hooks must include 'use client' directive in App Router".into(),
                ..Default::default()
            },
            TomlRule {
                id: "use-next-link".into(),
                rule_type: "banned-pattern".into(),
                severity: "warning".into(),
                glob: Some("**/*.{tsx,jsx}".into()),
                pattern: Some(r#"<a\s+href=["']/"#.into()),
                regex: true,
                message: "Use next/link instead of <a> for client-side navigation".into(),
                suggest: Some("Import Link from 'next/link' and use <Link> component".into()),
                ..Default::default()
            },
            TomlRule {
                id: "no-next-router-in-app".into(),
                rule_type: "banned-import".into(),
                severity: "error".into(),
                glob: Some("app/**".into()),
                packages: vec!["next/router".into()],
                message: "next/router is not available in App Router — use next/navigation instead".into(),
                ..Default::default()
            },
            TomlRule {
                id: "no-sync-scripts".into(),
                rule_type: "banned-pattern".into(),
                severity: "warning".into(),
                glob: Some("**/*.{tsx,jsx}".into()),
                pattern: Some(r"<script\s".into()),
                regex: true,
                message: "Use next/script instead of <script> for optimized script loading".into(),
                suggest: Some("Import Script from 'next/script' and use <Script> component".into()),
                ..Default::default()
            },
            TomlRule {
                id: "no-link-fonts".into(),
                rule_type: "banned-pattern".into(),
                severity: "warning".into(),
                glob: Some("**/*.{tsx,jsx}".into()),
                pattern: Some(r"<link[^>]*fonts\.googleapis\.com".into()),
                regex: true,
                message: "Use next/font instead of Google Fonts <link> for zero layout shift".into(),
                suggest: Some("Import from 'next/font/google' for automatic font optimization".into()),
                ..Default::default()
            },
        ],
        Preset::AiCodegen => vec![
            TomlRule {
                id: "no-placeholder-text".into(),
                rule_type: "banned-pattern".into(),
                severity: "warning".into(),
                pattern: Some(r"(?i)lorem ipsum".into()),
                regex: true,
                message: "Placeholder text detected — replace with real content".into(),
                ..Default::default()
            },
            TomlRule {
                id: "no-unresolved-todos".into(),
                rule_type: "banned-pattern".into(),
                severity: "warning".into(),
                pattern: Some(r"(?://|/?\*)\s*(TODO|FIXME|HACK|XXX)\b".into()),
                regex: true,
                message: "Unresolved TODO/FIXME comment — address or remove before merging".into(),
                ..Default::default()
            },
            TomlRule {
                id: "no-type-any".into(),
                rule_type: "banned-pattern".into(),
                severity: "error".into(),
                glob: Some("**/*.{ts,tsx}".into()),
                pattern: Some(r"[:<,]\s*any\b".into()),
                regex: true,
                exclude_glob: vec!["**/*.d.ts".into()],
                message: "Avoid using 'any' type — use a specific type or 'unknown'".into(),
                ..Default::default()
            },
            TomlRule {
                id: "no-empty-catch".into(),
                rule_type: "banned-pattern".into(),
                severity: "error".into(),
                pattern: Some(r"catch\s*\([^)]*\)\s*\{\s*\}".into()),
                regex: true,
                message: "Empty catch block swallows errors — handle or re-throw the error".into(),
                ..Default::default()
            },
            TomlRule {
                id: "no-console-log".into(),
                rule_type: "banned-pattern".into(),
                severity: "warning".into(),
                pattern: Some(r"console\.(log|debug)\(".into()),
                regex: true,
                exclude_glob: vec!["**/*.test.*".into(), "**/*.spec.*".into()],
                message: "Remove console.log/debug before merging — use a proper logger if needed".into(),
                ..Default::default()
            },
            TomlRule {
                id: "no-ts-ignore".into(),
                rule_type: "banned-pattern".into(),
                severity: "error".into(),
                glob: Some("**/*.{ts,tsx}".into()),
                pattern: Some("@ts-ignore".into()),
                message: "Use @ts-expect-error instead of @ts-ignore for type suppressions".into(),
                ..Default::default()
            },
            TomlRule {
                id: "no-as-any".into(),
                rule_type: "banned-pattern".into(),
                severity: "error".into(),
                glob: Some("**/*.{ts,tsx}".into()),
                pattern: Some(r"\bas\s+any\b".into()),
                regex: true,
                message: "Avoid 'as any' type assertion — use proper types or 'as unknown'".into(),
                ..Default::default()
            },
            TomlRule {
                id: "no-eslint-disable".into(),
                rule_type: "banned-pattern".into(),
                severity: "warning".into(),
                pattern: Some("eslint-disable".into()),
                message: "Remove eslint-disable comment — fix the underlying issue instead".into(),
                ..Default::default()
            },
            TomlRule {
                id: "no-ts-nocheck".into(),
                rule_type: "banned-pattern".into(),
                severity: "error".into(),
                glob: Some("**/*.{ts,tsx}".into()),
                pattern: Some("@ts-nocheck".into()),
                message: "Do not disable type checking for entire files — fix type errors instead".into(),
                ..Default::default()
            },
            TomlRule {
                id: "no-var".into(),
                rule_type: "banned-pattern".into(),
                severity: "error".into(),
                glob: Some("**/*.{ts,tsx,js,jsx}".into()),
                pattern: Some(r"\bvar\s+\w".into()),
                regex: true,
                exclude_glob: vec!["**/*.d.ts".into()],
                message: "Use 'let' or 'const' instead of 'var'".into(),
                ..Default::default()
            },
            TomlRule {
                id: "no-require-in-ts".into(),
                rule_type: "banned-pattern".into(),
                severity: "warning".into(),
                glob: Some("**/*.{ts,tsx}".into()),
                pattern: Some(r"\brequire\s*\(".into()),
                regex: true,
                message: "Use ES module 'import' instead of CommonJS 'require()' in TypeScript".into(),
                ..Default::default()
            },
            TomlRule {
                id: "no-non-null-assertion".into(),
                rule_type: "banned-pattern".into(),
                severity: "warning".into(),
                glob: Some("**/*.{ts,tsx}".into()),
                pattern: Some(r"\w![.\[]".into()),
                regex: true,
                message: "Avoid non-null assertion (!) — use optional chaining (?.) or proper null checks".into(),
                ..Default::default()
            },
        ],
    }
}

/// Merge preset rules with user-defined rules. User rules with the same `id`
/// as a preset rule replace the preset version entirely. New user rules are
/// appended after all preset rules.
fn merge_rules(preset_rules: Vec<TomlRule>, user_rules: &[TomlRule]) -> Vec<TomlRule> {
    let mut merged = preset_rules;

    // Index preset rules by id for O(1) lookup
    let mut id_to_index: HashMap<String, usize> = HashMap::new();
    for (i, rule) in merged.iter().enumerate() {
        id_to_index.insert(rule.id.clone(), i);
    }

    for user_rule in user_rules {
        if let Some(&idx) = id_to_index.get(&user_rule.id) {
            // User rule overrides preset rule with same id
            merged[idx] = user_rule.clone();
        } else {
            // New user rule appended
            merged.push(user_rule.clone());
        }
    }

    merged
}

/// Resolve all `extends` presets and merge with user-defined rules.
/// Returns the final list of `TomlRule` entries ready for the build pipeline.
pub fn resolve_rules(
    extends: &[String],
    user_rules: &[TomlRule],
) -> Result<Vec<TomlRule>, PresetError> {
    if extends.is_empty() {
        return Ok(user_rules.to_vec());
    }

    // Collect all preset rules in order, later presets override earlier ones
    let mut all_preset_rules: Vec<TomlRule> = Vec::new();
    let mut seen: HashMap<String, usize> = HashMap::new();

    for preset_name in extends {
        let preset = resolve_preset(preset_name).ok_or_else(|| PresetError::UnknownPreset {
            name: preset_name.clone(),
            available: available_presets().to_vec(),
        })?;

        for rule in preset_rules(preset) {
            if let Some(&idx) = seen.get(&rule.id) {
                // Later preset overrides earlier for same id
                all_preset_rules[idx] = rule;
            } else {
                seen.insert(rule.id.clone(), all_preset_rules.len());
                all_preset_rules.push(rule);
            }
        }
    }

    Ok(merge_rules(all_preset_rules, user_rules))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shadcn_strict_has_five_rules() {
        let rules = preset_rules(Preset::ShadcnStrict);
        assert_eq!(rules.len(), 5);
        let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"enforce-dark-mode"));
        assert!(ids.contains(&"use-theme-tokens"));
        assert!(ids.contains(&"no-inline-styles"));
        assert!(ids.contains(&"no-css-in-js"));
        assert!(ids.contains(&"no-competing-frameworks"));
    }

    #[test]
    fn shadcn_migrate_has_two_rules() {
        let rules = preset_rules(Preset::ShadcnMigrate);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].id, "enforce-dark-mode");
        assert_eq!(rules[1].id, "use-theme-tokens");
        // migrate uses warning for theme tokens
        assert_eq!(rules[1].severity, "warning");
    }

    #[test]
    fn ai_safety_has_three_rules() {
        let rules = preset_rules(Preset::AiSafety);
        assert_eq!(rules.len(), 3);
        let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"no-moment"));
        assert!(ids.contains(&"no-lodash"));
        assert!(ids.contains(&"no-deprecated-request"));
    }

    #[test]
    fn resolve_unknown_preset_errors() {
        let result = resolve_rules(&["unknown-preset".to_string()], &[]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("unknown preset 'unknown-preset'"));
        assert!(msg.contains("shadcn-strict"));
    }

    #[test]
    fn resolve_empty_extends_returns_user_rules() {
        let user_rules = vec![TomlRule {
            id: "custom-rule".into(),
            rule_type: "banned-pattern".into(),
            pattern: Some("TODO".into()),
            message: "No TODOs".into(),
            ..Default::default()
        }];
        let result = resolve_rules(&[], &user_rules).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "custom-rule");
    }

    #[test]
    fn user_rule_overrides_preset() {
        let user_rules = vec![TomlRule {
            id: "use-theme-tokens".into(),
            rule_type: "tailwind-theme-tokens".into(),
            severity: "warning".into(),
            glob: Some("**/*.{tsx,jsx}".into()),
            message: "Custom message".into(),
            ..Default::default()
        }];
        let result = resolve_rules(&["shadcn-strict".to_string()], &user_rules).unwrap();
        assert_eq!(result.len(), 5);
        let token_rule = result.iter().find(|r| r.id == "use-theme-tokens").unwrap();
        assert_eq!(token_rule.severity, "warning");
        assert_eq!(token_rule.message, "Custom message");
    }

    #[test]
    fn user_rule_appended_after_preset() {
        let user_rules = vec![TomlRule {
            id: "my-custom".into(),
            rule_type: "banned-pattern".into(),
            pattern: Some("foo".into()),
            message: "no foo".into(),
            ..Default::default()
        }];
        let result = resolve_rules(&["shadcn-strict".to_string()], &user_rules).unwrap();
        assert_eq!(result.len(), 6);
        assert_eq!(result[5].id, "my-custom");
    }

    #[test]
    fn later_preset_overrides_earlier() {
        // shadcn-strict sets use-theme-tokens severity to "error"
        // shadcn-migrate sets it to "warning"
        let result = resolve_rules(
            &["shadcn-strict".to_string(), "shadcn-migrate".to_string()],
            &[],
        )
        .unwrap();
        let token_rule = result.iter().find(|r| r.id == "use-theme-tokens").unwrap();
        assert_eq!(token_rule.severity, "warning");
        // Should have 5 unique rules (strict has 5, migrate shares 2 ids)
        assert_eq!(result.len(), 5);
    }

    #[test]
    fn multiple_presets_combine() {
        let result = resolve_rules(
            &["shadcn-migrate".to_string(), "ai-safety".to_string()],
            &[],
        )
        .unwrap();
        // 2 from migrate + 3 from ai-safety = 5
        assert_eq!(result.len(), 5);
    }

    #[test]
    fn security_has_ten_rules() {
        let rules = preset_rules(Preset::Security);
        assert_eq!(rules.len(), 10);
        let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"no-env-files"));
        assert!(ids.contains(&"no-hardcoded-secrets"));
        assert!(ids.contains(&"no-eval"));
        assert!(ids.contains(&"no-dangerous-html"));
        assert!(ids.contains(&"no-innerhtml"));
        assert!(ids.contains(&"no-console-log"));
        assert!(ids.contains(&"no-document-write"));
        assert!(ids.contains(&"no-postmessage-wildcard"));
        assert!(ids.contains(&"no-outerhtml"));
        assert!(ids.contains(&"no-http-links"));
    }

    #[test]
    fn nextjs_has_eight_rules() {
        let rules = preset_rules(Preset::Nextjs);
        assert_eq!(rules.len(), 8);
        let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"use-next-image"));
        assert!(ids.contains(&"no-next-head"));
        assert!(ids.contains(&"no-private-env-client"));
        assert!(ids.contains(&"require-use-client-for-hooks"));
        assert!(ids.contains(&"use-next-link"));
        assert!(ids.contains(&"no-next-router-in-app"));
        assert!(ids.contains(&"no-sync-scripts"));
        assert!(ids.contains(&"no-link-fonts"));
    }

    #[test]
    fn ai_codegen_has_twelve_rules() {
        let rules = preset_rules(Preset::AiCodegen);
        assert_eq!(rules.len(), 12);
        let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"no-placeholder-text"));
        assert!(ids.contains(&"no-unresolved-todos"));
        assert!(ids.contains(&"no-type-any"));
        assert!(ids.contains(&"no-empty-catch"));
        assert!(ids.contains(&"no-console-log"));
        assert!(ids.contains(&"no-ts-ignore"));
        assert!(ids.contains(&"no-as-any"));
        assert!(ids.contains(&"no-eslint-disable"));
        assert!(ids.contains(&"no-ts-nocheck"));
        assert!(ids.contains(&"no-var"));
        assert!(ids.contains(&"no-require-in-ts"));
        assert!(ids.contains(&"no-non-null-assertion"));
    }

    #[test]
    fn all_preset_names_resolve() {
        for name in available_presets() {
            assert!(
                resolve_preset(name).is_some(),
                "preset '{}' should resolve",
                name
            );
        }
    }

    #[test]
    fn all_preset_regex_patterns_compile() {
        use regex::Regex;
        for name in available_presets() {
            let preset = resolve_preset(name).unwrap();
            for rule in preset_rules(preset) {
                if rule.regex {
                    if let Some(ref pat) = rule.pattern {
                        Regex::new(pat).unwrap_or_else(|e| {
                            panic!("preset '{}', rule '{}': invalid pattern: {}", name, rule.id, e)
                        });
                    }
                    if let Some(ref pat) = rule.condition_pattern {
                        Regex::new(pat).unwrap_or_else(|e| {
                            panic!(
                                "preset '{}', rule '{}': invalid condition_pattern: {}",
                                name, rule.id, e
                            )
                        });
                    }
                }
            }
        }
    }

    #[test]
    fn no_private_env_client_pattern_correctness() {
        use regex::Regex;
        let rules = preset_rules(Preset::Nextjs);
        let rule = rules.iter().find(|r| r.id == "no-private-env-client").unwrap();
        let re = Regex::new(rule.pattern.as_ref().unwrap()).unwrap();

        // Should match private env vars
        assert!(re.is_match("process.env.DATABASE_URL"));
        assert!(re.is_match("process.env.API_SECRET"));
        assert!(re.is_match("process.env.NODE_ENV"));
        assert!(re.is_match("process.env.NEXT_RUNTIME"));

        // Should NOT match NEXT_PUBLIC_ prefixed vars
        assert!(!re.is_match("process.env.NEXT_PUBLIC_API_URL"));
        assert!(!re.is_match("process.env.NEXT_PUBLIC_STRIPE_KEY"));
    }

    /// Helper: get a compiled Regex for a preset rule by preset and rule id.
    fn regex_for(preset: Preset, rule_id: &str) -> regex::Regex {
        let rules = preset_rules(preset);
        let rule = rules
            .iter()
            .find(|r| r.id == rule_id)
            .unwrap_or_else(|| panic!("rule '{}' not found", rule_id));
        regex::Regex::new(rule.pattern.as_ref().unwrap()).unwrap()
    }

    // ── Security pattern tests ─────────────────────────────────────────

    #[test]
    fn no_document_write_pattern() {
        let re = regex_for(Preset::Security, "no-document-write");
        assert!(re.is_match("document.write('hello')"));
        assert!(re.is_match("document.write (html)"));
        assert!(re.is_match("  document.write('<div>')"));
        // read access is fine
        assert!(!re.is_match("const w = document.writeln"));
        assert!(!re.is_match("documentWriter()"));
    }

    #[test]
    fn no_postmessage_wildcard_pattern() {
        let re = regex_for(Preset::Security, "no-postmessage-wildcard");
        assert!(re.is_match("window.postMessage(data, '*')"));
        assert!(re.is_match(r#"iframe.contentWindow.postMessage({}, "*")"#));
        assert!(re.is_match("  w.postMessage(msg, '*')"));
        // specific origins are fine
        assert!(!re.is_match("window.postMessage(data, 'https://example.com')"));
        assert!(!re.is_match("window.postMessage(data, origin)"));
    }

    #[test]
    fn no_outerhtml_pattern() {
        let re = regex_for(Preset::Security, "no-outerhtml");
        assert!(re.is_match("el.outerHTML = '<div>'"));
        assert!(re.is_match("el.outerHTML += '<span>'"));
        assert!(re.is_match("  node.outerHTML = html"));
        // reading outerHTML is fine
        assert!(!re.is_match("const html = el.outerHTML"));
        assert!(!re.is_match("console.log(el.outerHTML)"));
    }

    #[test]
    fn no_http_links_pattern() {
        let re = regex_for(Preset::Security, "no-http-links");
        assert!(re.is_match(r#"fetch("http://api.example.com")"#));
        assert!(re.is_match("const url = 'http://cdn.example.com'"));
        // https is fine
        assert!(!re.is_match(r#"fetch("https://api.example.com")"#));
        // not in a string literal
        assert!(!re.is_match("// visit http://example.com"));
    }

    #[test]
    fn no_hardcoded_secrets_expanded() {
        let re = regex_for(Preset::Security, "no-hardcoded-secrets");
        // original keywords still work
        assert!(re.is_match(r#"api_key = "abc12345678""#));
        assert!(re.is_match(r#"API_KEY: "abc12345678""#));
        // new keywords
        assert!(re.is_match(r#"password = "mysecretpass""#));
        assert!(re.is_match(r#"PASSWORD: "supersecret1""#));
        assert!(re.is_match(r#"client_secret = "abcdefghij""#));
        // short values (< 8 chars) should NOT match
        assert!(!re.is_match(r#"password = "short""#));
        // no string value should NOT match
        assert!(!re.is_match("password = getPassword()"));
    }

    // ── Next.js pattern tests ──────────────────────────────────────────

    #[test]
    fn no_sync_scripts_pattern() {
        let re = regex_for(Preset::Nextjs, "no-sync-scripts");
        assert!(re.is_match(r#"<script src="analytics.js">"#));
        assert!(re.is_match(r#"<script type="application/ld+json">"#));
        // next/script component (uppercase) should NOT match
        assert!(!re.is_match(r#"<Script src="analytics.js">"#));
        // closing tag should NOT match
        assert!(!re.is_match("</script>"));
    }

    #[test]
    fn no_link_fonts_pattern() {
        let re = regex_for(Preset::Nextjs, "no-link-fonts");
        assert!(re.is_match(
            r#"<link href="https://fonts.googleapis.com/css2?family=Inter" rel="stylesheet" />"#
        ));
        assert!(re.is_match(
            r#"<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Roboto">"#
        ));
        // other link tags should NOT match
        assert!(!re.is_match(r#"<link rel="stylesheet" href="/styles.css" />"#));
        // next/link is fine
        assert!(!re.is_match(r#"<Link href="/fonts">"#));
    }

    // ── AI Codegen pattern tests ───────────────────────────────────────

    #[test]
    fn no_eslint_disable_pattern() {
        let rules = preset_rules(Preset::AiCodegen);
        let rule = rules.iter().find(|r| r.id == "no-eslint-disable").unwrap();
        let pat = rule.pattern.as_ref().unwrap();
        // literal match (no regex)
        assert!(!rule.regex);
        assert!("// eslint-disable-next-line no-console".contains(pat.as_str()));
        assert!("/* eslint-disable */".contains(pat.as_str()));
        assert!("/* eslint-disable-next-line */".contains(pat.as_str()));
    }

    #[test]
    fn no_var_pattern() {
        let re = regex_for(Preset::AiCodegen, "no-var");
        assert!(re.is_match("var x = 1"));
        assert!(re.is_match("var foo = 'bar'"));
        assert!(re.is_match("  var count = 0;"));
        // should NOT match these
        assert!(!re.is_match("const variable = 1"));
        assert!(!re.is_match("let variance = 2"));
        assert!(!re.is_match("const isVariable = true"));
    }

    #[test]
    fn no_require_in_ts_pattern() {
        let re = regex_for(Preset::AiCodegen, "no-require-in-ts");
        assert!(re.is_match("const fs = require('fs')"));
        assert!(re.is_match("const x = require('./module')"));
        assert!(re.is_match("require('dotenv').config()"));
        // import is fine
        assert!(!re.is_match("import fs from 'fs'"));
        // require.resolve is different (no parens right after require)
        assert!(!re.is_match("require.resolve('./path')"));
    }

    #[test]
    fn no_non_null_assertion_pattern() {
        let re = regex_for(Preset::AiCodegen, "no-non-null-assertion");
        // should match non-null assertions
        assert!(re.is_match("user!.name"));
        assert!(re.is_match("items![0]"));
        assert!(re.is_match("this.ref!.current"));
        assert!(re.is_match("data!.results"));
        // should NOT match these
        assert!(!re.is_match("x !== y"));
        assert!(!re.is_match("x != y"));
        assert!(!re.is_match("if (!foo) {}"));
        assert!(!re.is_match("!!value"));
        assert!(!re.is_match("foo!==bar"));
    }

    #[test]
    fn no_non_null_assertion_no_false_positives_on_strings() {
        let re = regex_for(Preset::AiCodegen, "no-non-null-assertion");
        // String ending in '!' with method call — quote sits between ! and .
        assert!(!re.is_match(r#""Warning!".toUpperCase()"#));
        assert!(!re.is_match(r#"'Error!'.length"#));
        assert!(!re.is_match(r#"'Click me!'[0]"#));
    }

    #[test]
    fn no_innerhtml_catches_plus_equals() {
        let re = regex_for(Preset::Security, "no-innerhtml");
        assert!(re.is_match("el.innerHTML = html"));
        assert!(re.is_match("el.innerHTML += '<br>'"));
        assert!(re.is_match("el.innerHTML  =  content"));
        assert!(!re.is_match("const x = el.innerHTML"));
    }

    #[test]
    fn no_type_any_catches_generics() {
        let re = regex_for(Preset::AiCodegen, "no-type-any");
        // type annotation
        assert!(re.is_match("const x: any = 1"));
        // generic position
        assert!(re.is_match("Array<any>"));
        assert!(re.is_match("Promise<any>"));
        assert!(re.is_match("Record<string, any>"));
        assert!(re.is_match("Map<string, any>"));
        // should NOT match word 'any' in other contexts
        assert!(!re.is_match("// handle any case"));
        assert!(!re.is_match("const anything = 1"));
        assert!(!re.is_match("if (any_flag) {}"));
    }
}
