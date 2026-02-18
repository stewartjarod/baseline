use crate::cli::toml_config::{ScopedPreset, TomlRule};
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
    React,
    NextjsBestPractices,
    Accessibility,
    ReactNative,
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
        "react",
        "nextjs-best-practices",
        "accessibility",
        "react-native",
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
        "react" => Some(Preset::React),
        "nextjs-best-practices" => Some(Preset::NextjsBestPractices),
        "accessibility" => Some(Preset::Accessibility),
        "react-native" => Some(Preset::ReactNative),
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
            TomlRule {
                id: "no-paste-prevention".into(),
                rule_type: "banned-pattern".into(),
                severity: "warning".into(),
                pattern: Some(r"onPaste[^=]*=[^;]*preventDefault".into()),
                regex: true,
                message: "Preventing paste harms accessibility and password manager users".into(),
                suggest: Some("Remove onPaste preventDefault — let users paste freely".into()),
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
        Preset::React => {
            #[allow(unused_mut)]
            let mut rules = vec![
                // ── Correctness ──────────────────────────────────────────
                TomlRule {
                    id: "no-array-index-key".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "error".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    pattern: Some(r"key=\{[a-zA-Z_]*[iI](?:ndex|dx)".into()),
                    regex: true,
                    message: "Don't use array index as key — causes bugs on reorder/filter".into(),
                    suggest: Some("Use a stable unique identifier from the data instead".into()),
                    ..Default::default()
                },
                TomlRule {
                    id: "no-conditional-render-zero".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "warning".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    pattern: Some(r"\{\s*\w+\.length\s*&&".into()),
                    regex: true,
                    message: "array.length && <JSX> renders '0' when empty — use array.length > 0".into(),
                    suggest: Some("Replace {arr.length && ...} with {arr.length > 0 && ...}".into()),
                    ..Default::default()
                },
                // no-nested-component-def: regex heuristic without `ast`, AST version with `ast`
                #[cfg(not(feature = "ast"))]
                TomlRule {
                    id: "no-nested-component-def".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "error".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    pattern: Some(r"^\s+(?:const|let|function)\s+[A-Z][a-zA-Z0-9]*\s*(?::\s*React\.FC|=\s*(?:\([^)]*\)|[a-zA-Z_]\w*)\s*(?::\s*[A-Za-z<>\[\]|&, ]+)?\s*=>|=\s*function|\()".into()),
                    regex: true,
                    message: "Component defined inside another component — causes remounting on every render".into(),
                    suggest: Some("Move component definition to module scope or extract to a separate file".into()),
                    ..Default::default()
                },
                #[cfg(feature = "ast")]
                TomlRule {
                    id: "no-nested-component-def".into(),
                    rule_type: "no-nested-components".into(),
                    severity: "error".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    message: "Component defined inside another component — causes remounting on every render".into(),
                    suggest: Some("Move component definition to module scope or extract to a separate file".into()),
                    ..Default::default()
                },
                // ── Security ─────────────────────────────────────────────
                TomlRule {
                    id: "no-dangerous-html".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "warning".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    pattern: Some("dangerouslySetInnerHTML".into()),
                    message: "dangerouslySetInnerHTML can lead to XSS — sanitize content or use a safe alternative".into(),
                    ..Default::default()
                },
                // ── Performance: bundle size ─────────────────────────────
                TomlRule {
                    id: "no-full-lodash-import".into(),
                    rule_type: "banned-import".into(),
                    severity: "warning".into(),
                    packages: vec!["lodash".into()],
                    message: "Importing all of lodash (~70kb) — use lodash-es or per-function imports like lodash/debounce".into(),
                    ..Default::default()
                },
                TomlRule {
                    id: "no-moment".into(),
                    rule_type: "banned-import".into(),
                    severity: "warning".into(),
                    packages: vec!["moment".into(), "moment-timezone".into()],
                    message: "moment.js is 300kb+ and deprecated — use date-fns, dayjs, or Temporal API".into(),
                    ..Default::default()
                },
                TomlRule {
                    id: "no-moment-dep".into(),
                    rule_type: "banned-dependency".into(),
                    severity: "warning".into(),
                    packages: vec!["moment".into(), "moment-timezone".into()],
                    message: "moment.js is 300kb+ and deprecated — use date-fns, dayjs, or Temporal API".into(),
                    ..Default::default()
                },
                TomlRule {
                    id: "no-new-function".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "error".into(),
                    pattern: Some(r"\bnew\s+Function\s*\(".into()),
                    regex: true,
                    message: "new Function() is equivalent to eval() — avoid dynamic code execution".into(),
                    ..Default::default()
                },
                // ── Performance: rendering ───────────────────────────────
                TomlRule {
                    id: "no-transition-all".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "warning".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    pattern: Some(r#"transition:\s*["']all"#.into()),
                    regex: true,
                    message: "transition: 'all' is expensive — list specific properties to transition".into(),
                    ..Default::default()
                },
                TomlRule {
                    id: "no-layout-animation".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "warning".into(),
                    glob: Some("**/*.{tsx,jsx,css}".into()),
                    pattern: Some(r"(?:animation|transition)(?:-property)?:\s*(?:.*\b(?:width|height|top|left|right|bottom|margin|padding)\b)".into()),
                    regex: true,
                    message: "Animating layout properties (width/height/margin) triggers expensive reflows — use transform instead".into(),
                    suggest: Some("Use transform: scale() or translate() for smooth GPU-accelerated animations".into()),
                    ..Default::default()
                },
                // ── Async ─────────────────────────────────────────────────
                TomlRule {
                    id: "no-sequential-await".into(),
                    rule_type: "window-pattern".into(),
                    severity: "warning".into(),
                    glob: Some("**/*.{ts,tsx,js,jsx}".into()),
                    pattern: Some(r"^\s*(?:const\s+\w+\s*=\s*)?await\s".into()),
                    condition_pattern: Some(r"^\s*(?:const\s+\w+\s*=\s*)?await\s".into()),
                    max_count: Some(3),
                    regex: true,
                    message: "Sequential await statements may run slower than necessary — use Promise.all() for independent operations".into(),
                    suggest: Some("const [a, b] = await Promise.all([fetchA(), fetchB()])".into()),
                    ..Default::default()
                },
                // ── State & Effects ──────────────────────────────────────
                TomlRule {
                    id: "no-derived-state-effect".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "warning".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    pattern: Some(r"useEffect\(\(\)\s*(?:=>)?\s*\{?\s*set[A-Z]\w*\(".into()),
                    regex: true,
                    message: "useEffect that only calls setState is derived state — compute during render instead".into(),
                    suggest: Some("Replace with: const derived = useMemo(() => compute(dep), [dep])".into()),
                    ..Default::default()
                },
                TomlRule {
                    id: "no-fetch-in-effect".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "warning".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    pattern: Some(r"useEffect\([^)]*\(\)\s*(?:=>)?\s*\{[^}]*\bfetch\s*\(".into()),
                    regex: true,
                    message: "Avoid fetch() inside useEffect — use a data-fetching library (React Query, SWR) or server components".into(),
                    ..Default::default()
                },
                TomlRule {
                    id: "no-lazy-state-init".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "warning".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    pattern: Some(r"useState\(\w+\(.*\)\)".into()),
                    regex: true,
                    message: "Expensive function call in useState runs every render — use lazy initializer: useState(() => fn())".into(),
                    suggest: Some("Wrap in a function: useState(() => computeValue()) for one-time initialization".into()),
                    ..Default::default()
                },
                TomlRule {
                    id: "no-object-dep-array".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "warning".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    pattern: Some(r"(?:useEffect|useMemo|useCallback)\([^)]+,\s*\[[^\]]*(?:\{[^}]*\}|\[[^\]]*\])".into()),
                    regex: true,
                    message: "Object/array literal in dependency array creates a new reference every render — extract to useMemo or a ref".into(),
                    ..Default::default()
                },
                TomlRule {
                    id: "no-default-object-prop".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "warning".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    pattern: Some(r"(?:function\s+[A-Z]|const\s+[A-Z]\w*\s*=)\s*.*(?:\{\s*\w+\s*=\s*(?:\{\}|\[\])\s*[,}])".into()),
                    regex: true,
                    message: "Default {} or [] in component params creates a new reference every render — extract to a module-level constant".into(),
                    ..Default::default()
                },
                // ── React 19 / composition ───────────────────────────
                TomlRule {
                    id: "no-forwardref".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "warning".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    pattern: Some(r"\bforwardRef\s*[<(]".into()),
                    regex: true,
                    message: "forwardRef is unnecessary in React 19 — ref is a regular prop now".into(),
                    suggest: Some("Accept ref as a prop directly: function Component({ ref, ...props })".into()),
                    ..Default::default()
                },
                TomlRule {
                    id: "no-use-context".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "warning".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    pattern: Some(r"\buseContext\s*\(".into()),
                    regex: true,
                    message: "useContext is replaced by use() in React 19".into(),
                    suggest: Some("Replace useContext(MyContext) with use(MyContext)".into()),
                    ..Default::default()
                },
                // ── Correctness ──────────────────────────────────────
                TomlRule {
                    id: "no-unsafe-createcontext-default".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "warning".into(),
                    glob: Some("**/*.{tsx,jsx,ts,js}".into()),
                    pattern: Some(r#"createContext\s*\(\s*(?:\{\}|\[\]|undefined|0|''|"")\s*\)"#.into()),
                    regex: true,
                    message: "Unsafe createContext default value — use null and handle the missing-provider case".into(),
                    suggest: Some("Use createContext<T>(null) and throw in a custom hook if context is null".into()),
                    ..Default::default()
                },
                TomlRule {
                    id: "no-effect-callback-sync".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "warning".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    pattern: Some(r"useEffect\(\(\)\s*(?:=>)?\s*\{?\s*on[A-Z]\w*\(".into()),
                    regex: true,
                    message: "Calling event callbacks directly in useEffect may indicate misuse — effects should synchronize, not fire events".into(),
                    suggest: Some("Move the callback invocation to a user action handler or derive state instead".into()),
                    ..Default::default()
                },
                TomlRule {
                    id: "no-usestate-localstorage-eager".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "warning".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    pattern: Some(r"useState\(\s*(?:JSON\.parse\s*\()?localStorage\.getItem\(".into()),
                    regex: true,
                    message: "localStorage.getItem in useState runs on every render and breaks SSR — use a lazy initializer".into(),
                    suggest: Some("Use useState(() => localStorage.getItem(...)) for lazy initialization".into()),
                    ..Default::default()
                },
                // ── Performance / bundle ─────────────────────────────
                TomlRule {
                    id: "no-regexp-in-render".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "warning".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    pattern: Some(r"new\s+RegExp\s*\(".into()),
                    regex: true,
                    message: "new RegExp() in a component body re-compiles every render — extract to module scope or useMemo".into(),
                    suggest: Some("Move the RegExp to module scope: const MY_RE = new RegExp(...)".into()),
                    ..Default::default()
                },
                TomlRule {
                    id: "no-lucide-barrel".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "warning".into(),
                    pattern: Some(r#"(?:import\s+.*?\s+from\s+|import\s+|require\s*\(\s*)['"]lucide-react['"]"#.into()),
                    regex: true,
                    message: "Barrel import from lucide-react pulls in all icons — use lucide-react/icons/IconName".into(),
                    suggest: Some("Import specific icons: import { Icon } from 'lucide-react/icons/Icon'".into()),
                    ..Default::default()
                },
                TomlRule {
                    id: "no-mui-barrel".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "warning".into(),
                    pattern: Some(r#"(?:import\s+.*?\s+from\s+|import\s+|require\s*\(\s*)['"]@mui/material['"]"#.into()),
                    regex: true,
                    message: "Barrel import from @mui/material increases bundle size — use deep imports".into(),
                    suggest: Some("Import specific components: import Button from '@mui/material/Button'".into()),
                    ..Default::default()
                },
                TomlRule {
                    id: "no-mui-icons-barrel".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "warning".into(),
                    pattern: Some(r#"(?:import\s+.*?\s+from\s+|import\s+|require\s*\(\s*)['"]@mui/icons-material['"]"#.into()),
                    regex: true,
                    message: "Barrel import from @mui/icons-material increases bundle size — use deep imports".into(),
                    suggest: Some("Import specific icons: import HomeIcon from '@mui/icons-material/Home'".into()),
                    ..Default::default()
                },
                TomlRule {
                    id: "no-react-icons-barrel".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "warning".into(),
                    pattern: Some(r#"(?:import\s+.*?\s+from\s+|import\s+|require\s*\(\s*)['"]react-icons['"]"#.into()),
                    regex: true,
                    message: "Barrel import from react-icons pulls in all icon sets — import from a specific set".into(),
                    suggest: Some("Import from a specific set: import { FaHome } from 'react-icons/fa'".into()),
                    ..Default::default()
                },
                TomlRule {
                    id: "no-date-fns-barrel".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "warning".into(),
                    pattern: Some(r#"(?:import\s+.*?\s+from\s+|import\s+|require\s*\(\s*)['"]date-fns['"]"#.into()),
                    regex: true,
                    message: "Barrel import from date-fns increases bundle size — use subpath imports".into(),
                    suggest: Some("Import specific functions: import { format } from 'date-fns/format'".into()),
                    ..Default::default()
                },
            ];

            // ── AST-powered rules (require `ast` feature) ────────────
            #[cfg(feature = "ast")]
            {
                rules.push(TomlRule {
                    id: "max-component-size".into(),
                    rule_type: "max-component-size".into(),
                    severity: "warning".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    max_count: Some(150),
                    message: "Component exceeds 150 lines — split into smaller components".into(),
                    suggest: Some("Extract logic into custom hooks or break into sub-components".into()),
                    ..Default::default()
                });
                rules.push(TomlRule {
                    id: "prefer-use-reducer".into(),
                    rule_type: "prefer-use-reducer".into(),
                    severity: "warning".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    max_count: Some(4),
                    message: "Component has 4+ useState calls — consider useReducer for related state".into(),
                    suggest: Some("Group related state into a single useReducer".into()),
                    ..Default::default()
                });
                rules.push(TomlRule {
                    id: "no-cascading-set-state".into(),
                    rule_type: "no-cascading-set-state".into(),
                    severity: "warning".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    max_count: Some(3),
                    message: "useEffect has 3+ setState calls — consider useReducer or derived state".into(),
                    suggest: Some("Combine state updates with useReducer or compute derived values".into()),
                    ..Default::default()
                });
            }

            rules
        }
        Preset::NextjsBestPractices => {
            #[allow(unused_mut)]
            let mut rules = vec![
                // ── Images & Media ───────────────────────────────────────
                TomlRule {
                    id: "use-next-image".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "warning".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    pattern: Some(r"<img\s".into()),
                    regex: true,
                    exclude_glob: vec!["**/opengraph-image.*".into(), "**/og/**".into()],
                    message: "Use next/image instead of <img> for automatic optimization".into(),
                    suggest: Some("Import Image from 'next/image' and use <Image> component".into()),
                    ..Default::default()
                },
                TomlRule {
                    id: "next-image-fill-needs-sizes".into(),
                    rule_type: "window-pattern".into(),
                    severity: "warning".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    pattern: Some(r"<Image[^>]*\bfill\b".into()),
                    condition_pattern: Some(r"\bsizes\s*=".into()),
                    max_count: Some(3),
                    regex: true,
                    message: "<Image fill> without sizes attribute downloads unnecessarily large images".into(),
                    suggest: Some("Add sizes prop, e.g. sizes=\"(max-width: 768px) 100vw, 50vw\"".into()),
                    ..Default::default()
                },
                // ── Routing & Navigation ─────────────────────────────────
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
                    id: "no-next-head".into(),
                    rule_type: "banned-import".into(),
                    severity: "error".into(),
                    glob: Some("app/**".into()),
                    packages: vec!["next/head".into()],
                    message: "next/head is not supported in App Router — use the Metadata API instead".into(),
                    ..Default::default()
                },
                TomlRule {
                    id: "no-client-side-redirect".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "warning".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    pattern: Some(r"useEffect\([^)]*\(\)\s*(?:=>)?\s*\{[^}]*(?:router\.push|window\.location)".into()),
                    regex: true,
                    message: "Avoid client-side redirects in useEffect — use server-side redirect() or middleware".into(),
                    suggest: Some("Move redirect logic to middleware.ts or use redirect() in a server component".into()),
                    ..Default::default()
                },
                // ── Scripts & Fonts ──────────────────────────────────────
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
                TomlRule {
                    id: "no-css-link".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "warning".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    pattern: Some(r#"<link[^>]*rel=["']stylesheet["']"#.into()),
                    regex: true,
                    message: "Import CSS files directly instead of using <link rel=\"stylesheet\">".into(),
                    suggest: Some("Use import './styles.css' for automatic bundling and optimization".into()),
                    ..Default::default()
                },
                // ── Server/Client Boundary ───────────────────────────────
                TomlRule {
                    id: "no-private-env-client".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "error".into(),
                    glob: Some("**/*.{ts,tsx,js,jsx}".into()),
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
                    id: "no-async-client-component".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "error".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    pattern: Some(r"(?:export\s+default\s+)?async\s+function\s+[A-Z]".into()),
                    regex: true,
                    file_contains: Some("use client".into()),
                    message: "Client components cannot be async — only server components support async/await".into(),
                    suggest: Some("Remove 'use client' to make this a server component, or remove async and use useEffect for data fetching".into()),
                    ..Default::default()
                },
                // ── SEO ──────────────────────────────────────────────────
                TomlRule {
                    id: "require-metadata-in-pages".into(),
                    rule_type: "required-pattern".into(),
                    severity: "warning".into(),
                    glob: Some("app/**/page.{ts,tsx,js,jsx}".into()),
                    pattern: Some(r"(?:export\s+(?:const\s+metadata|(?:async\s+)?function\s+generateMetadata))".into()),
                    regex: true,
                    message: "Page files should export metadata or generateMetadata for SEO".into(),
                    suggest: Some("Add: export const metadata = { title: '...', description: '...' }".into()),
                    ..Default::default()
                },
                // ── Server Actions ───────────────────────────────────────
                TomlRule {
                    id: "no-redirect-in-try-catch".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "error".into(),
                    glob: Some("**/*.{ts,tsx,js,jsx}".into()),
                    pattern: Some(r"try\s*\{[^}]*\bredirect\s*\(".into()),
                    regex: true,
                    message: "redirect() throws a special error — calling it inside try/catch will swallow the redirect".into(),
                    suggest: Some("Move redirect() outside the try/catch block".into()),
                    ..Default::default()
                },
                // ── Server Actions ───────────────────────────────────
                TomlRule {
                    id: "server-action-requires-auth".into(),
                    rule_type: "required-pattern".into(),
                    severity: "warning".into(),
                    glob: Some("app/**/*.{ts,tsx}".into()),
                    pattern: Some(r"(?:verifySession|getSession|auth\(\)|currentUser|getServerSession)".into()),
                    regex: true,
                    condition_pattern: Some("'use server'".into()),
                    message: "Server actions should verify authentication before performing mutations".into(),
                    suggest: Some("Add an auth check: const session = await getSession()".into()),
                    ..Default::default()
                },
                TomlRule {
                    id: "server-action-requires-validation".into(),
                    rule_type: "required-pattern".into(),
                    severity: "warning".into(),
                    glob: Some("app/**/*.{ts,tsx}".into()),
                    pattern: Some(r"(?:\.parse\(|\.safeParse\(|z\.object\(|\.validate\()".into()),
                    regex: true,
                    condition_pattern: Some("'use server'".into()),
                    message: "Server actions should validate input — never trust client data".into(),
                    suggest: Some("Use Zod or similar: const data = schema.parse(formData)".into()),
                    ..Default::default()
                },
                // ── Hydration ────────────────────────────────────────
                TomlRule {
                    id: "no-suppress-hydration-warning".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "warning".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    pattern: Some("suppressHydrationWarning".into()),
                    message: "suppressHydrationWarning hides real bugs — fix the mismatch instead".into(),
                    suggest: Some("Use useEffect + state to defer client-only content, or move to a Client Component".into()),
                    ..Default::default()
                },
            ];

            // ── AST-powered rules (require `ast` feature) ────────────
            #[cfg(feature = "ast")]
            {
                rules.push(TomlRule {
                    id: "max-component-size".into(),
                    rule_type: "max-component-size".into(),
                    severity: "warning".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    max_count: Some(150),
                    message: "Component exceeds 150 lines — split into smaller components".into(),
                    suggest: Some("Extract logic into custom hooks or break into sub-components".into()),
                    ..Default::default()
                });
                rules.push(TomlRule {
                    id: "no-nested-components".into(),
                    rule_type: "no-nested-components".into(),
                    severity: "error".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    message: "Component defined inside another component — causes remounting on every render".into(),
                    suggest: Some("Move component definition to module scope or extract to a separate file".into()),
                    ..Default::default()
                });
                rules.push(TomlRule {
                    id: "prefer-use-reducer".into(),
                    rule_type: "prefer-use-reducer".into(),
                    severity: "warning".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    max_count: Some(4),
                    message: "Component has 4+ useState calls — consider useReducer for related state".into(),
                    suggest: Some("Group related state into a single useReducer".into()),
                    ..Default::default()
                });
                rules.push(TomlRule {
                    id: "no-cascading-set-state".into(),
                    rule_type: "no-cascading-set-state".into(),
                    severity: "warning".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    max_count: Some(3),
                    message: "useEffect has 3+ setState calls — consider useReducer or derived state".into(),
                    suggest: Some("Combine state updates with useReducer or compute derived values".into()),
                    ..Default::default()
                });
            }

            rules
        }
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
        Preset::Accessibility => {
            #[allow(unused_mut)]
            let mut rules = vec![
                TomlRule {
                    id: "no-div-click-handler".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "error".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    pattern: Some(r"<div[^>]+onClick\s*=".into()),
                    regex: true,
                    message: "Non-interactive <div> with onClick is not keyboard accessible — use <button> instead".into(),
                    suggest: Some("Replace <div onClick=...> with <button onClick=...>".into()),
                    ..Default::default()
                },
                TomlRule {
                    id: "no-span-click-handler".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "error".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    pattern: Some(r"<span[^>]+onClick\s*=".into()),
                    regex: true,
                    message: "Non-interactive <span> with onClick is not keyboard accessible — use <button> instead".into(),
                    suggest: Some("Replace <span onClick=...> with <button onClick=...>".into()),
                    ..Default::default()
                },
                TomlRule {
                    id: "no-outline-none".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "warning".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    pattern: Some(r"\boutline-none\b".into()),
                    regex: true,
                    message: "outline-none removes the focus indicator — keyboard users can't see what's focused".into(),
                    suggest: Some("Use focus-visible:outline-none with a custom focus ring instead".into()),
                    ..Default::default()
                },
                TomlRule {
                    id: "no-user-scalable-no".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "error".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    pattern: Some(r"user-scalable\s*=\s*no".into()),
                    regex: true,
                    message: "user-scalable=no prevents zooming — violates WCAG 1.4.4 (Resize Text)".into(),
                    suggest: Some("Remove user-scalable=no to allow pinch-to-zoom".into()),
                    ..Default::default()
                },
                TomlRule {
                    id: "no-autofocus-unrestricted".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "warning".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    pattern: Some(r"\bautoFocus\b".into()),
                    regex: true,
                    message: "autoFocus can disorient screen reader users — use it sparingly (e.g., modals only)".into(),
                    suggest: Some("Remove autoFocus or limit to modal/dialog initial focus".into()),
                    ..Default::default()
                },
                TomlRule {
                    id: "no-transition-all-tailwind".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "warning".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    pattern: Some(r"\btransition-all\b".into()),
                    regex: true,
                    message: "transition-all can cause motion sickness — transition specific properties and respect prefers-reduced-motion".into(),
                    suggest: Some("Use transition-colors, transition-opacity, or transition-transform instead".into()),
                    ..Default::default()
                },
                TomlRule {
                    id: "no-hardcoded-date-format".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "warning".into(),
                    glob: Some("**/*.{ts,tsx,js,jsx}".into()),
                    pattern: Some(r"\.toDateString\(\s*\)|\.toLocaleString\(\s*\)|\.toLocaleDateString\(\s*\)".into()),
                    regex: true,
                    message: "Date formatting without explicit locale is inconsistent across browsers — pass a locale".into(),
                    suggest: Some("Pass an explicit locale: .toLocaleDateString('en-US', { ... })".into()),
                    ..Default::default()
                },
                TomlRule {
                    id: "no-inline-navigation-onclick".into(),
                    rule_type: "banned-pattern".into(),
                    severity: "warning".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    pattern: Some(r"onClick[^=]*=[^;]*window\.location".into()),
                    regex: true,
                    message: "onClick with window.location bypasses browser navigation — use <a> or router for accessible navigation".into(),
                    suggest: Some("Use <a href=...> or your router's <Link> component instead".into()),
                    ..Default::default()
                },
            ];

            #[cfg(feature = "ast")]
            {
                rules.push(TomlRule {
                    id: "require-img-alt".into(),
                    rule_type: "require-img-alt".into(),
                    severity: "error".into(),
                    glob: Some("**/*.{tsx,jsx}".into()),
                    message: "img element must have an alt attribute for screen readers".into(),
                    suggest: Some("Add alt=\"description\" or alt=\"\" for decorative images".into()),
                    ..Default::default()
                });
            }

            rules
        }
        Preset::ReactNative => vec![
            TomlRule {
                id: "rn-no-touchable-opacity".into(),
                rule_type: "banned-pattern".into(),
                severity: "warning".into(),
                glob: Some("**/*.{tsx,jsx}".into()),
                pattern: Some(r"<TouchableOpacity|import\s+\{[^}]*TouchableOpacity".into()),
                regex: true,
                message: "TouchableOpacity is deprecated — use Pressable instead".into(),
                suggest: Some("Replace <TouchableOpacity> with <Pressable>".into()),
                ..Default::default()
            },
            TomlRule {
                id: "rn-no-touchable-highlight".into(),
                rule_type: "banned-pattern".into(),
                severity: "warning".into(),
                glob: Some("**/*.{tsx,jsx}".into()),
                pattern: Some(r"<TouchableHighlight|import\s+\{[^}]*TouchableHighlight".into()),
                regex: true,
                message: "TouchableHighlight is deprecated — use Pressable instead".into(),
                suggest: Some("Replace <TouchableHighlight> with <Pressable>".into()),
                ..Default::default()
            },
            TomlRule {
                id: "rn-no-legacy-shadow".into(),
                rule_type: "banned-pattern".into(),
                severity: "warning".into(),
                glob: Some("**/*.{tsx,jsx,ts,js}".into()),
                pattern: Some(r"shadowColor\s*:|shadowOffset\s*:|shadowOpacity\s*:|shadowRadius\s*:".into()),
                regex: true,
                message: "Legacy shadow properties are iOS-only — use boxShadow (RN 0.76+) for cross-platform shadows".into(),
                suggest: Some("Use style={{ boxShadow: '0 2px 4px rgba(0,0,0,0.1)' }}".into()),
                ..Default::default()
            },
            TomlRule {
                id: "rn-no-rn-image-import".into(),
                rule_type: "banned-pattern".into(),
                severity: "warning".into(),
                glob: Some("**/*.{tsx,jsx}".into()),
                pattern: Some(r"import\s+\{[^}]*\bImage\b[^}]*\}\s+from\s+['\x22]react-native['\x22]".into()),
                regex: true,
                message: "react-native Image lacks caching and modern formats — use expo-image instead".into(),
                suggest: Some("Replace with: import { Image } from 'expo-image'".into()),
                ..Default::default()
            },
            TomlRule {
                id: "rn-no-custom-header".into(),
                rule_type: "banned-pattern".into(),
                severity: "warning".into(),
                glob: Some("**/*.{tsx,jsx,ts,js}".into()),
                pattern: Some(r"header:\s*\(\)\s*=>".into()),
                regex: true,
                message: "Custom header render function loses native header animations — use headerTitle or screen options".into(),
                suggest: Some("Use screenOptions={{ headerTitle: ... }} instead of header: () => ...".into()),
                ..Default::default()
            },
            TomlRule {
                id: "rn-no-fonts-usefonts".into(),
                rule_type: "banned-pattern".into(),
                severity: "warning".into(),
                glob: Some("**/*.{tsx,jsx}".into()),
                pattern: Some(r"useFonts\s*\(\s*\{".into()),
                regex: true,
                message: "useFonts blocks rendering with a loading screen — use expo-font config plugin for build-time font loading".into(),
                suggest: Some("Add fonts to app.json expo-font plugin for instant availability".into()),
                ..Default::default()
            },
            TomlRule {
                id: "rn-no-font-loadasync".into(),
                rule_type: "banned-pattern".into(),
                severity: "warning".into(),
                glob: Some("**/*.{tsx,jsx,ts,js}".into()),
                pattern: Some(r"Font\.loadAsync\s*\(".into()),
                regex: true,
                message: "Font.loadAsync blocks rendering — use expo-font config plugin for build-time font loading".into(),
                suggest: Some("Add fonts to app.json expo-font plugin for instant availability".into()),
                ..Default::default()
            },
            TomlRule {
                id: "rn-no-inline-intl-numberformat".into(),
                rule_type: "banned-pattern".into(),
                severity: "warning".into(),
                glob: Some("**/*.{tsx,jsx}".into()),
                pattern: Some(r"new\s+Intl\.NumberFormat\s*\(".into()),
                regex: true,
                message: "new Intl.NumberFormat() in a component body re-creates the formatter every render — extract to module scope".into(),
                suggest: Some("Move to module scope: const fmt = new Intl.NumberFormat(...)".into()),
                ..Default::default()
            },
            TomlRule {
                id: "rn-no-inline-intl-datetimeformat".into(),
                rule_type: "banned-pattern".into(),
                severity: "warning".into(),
                glob: Some("**/*.{tsx,jsx}".into()),
                pattern: Some(r"new\s+Intl\.DateTimeFormat\s*\(".into()),
                regex: true,
                message: "new Intl.DateTimeFormat() in a component body re-creates the formatter every render — extract to module scope".into(),
                suggest: Some("Move to module scope: const fmt = new Intl.DateTimeFormat(...)".into()),
                ..Default::default()
            },
            TomlRule {
                id: "rn-no-js-stack-navigator".into(),
                rule_type: "banned-import".into(),
                severity: "warning".into(),
                packages: vec!["@react-navigation/stack".into()],
                message: "JS-based stack navigator is slow — use @react-navigation/native-stack for native performance".into(),
                suggest: Some("Replace with: import { createNativeStackNavigator } from '@react-navigation/native-stack'".into()),
                ..Default::default()
            },
            TomlRule {
                id: "rn-no-js-bottom-tabs".into(),
                rule_type: "banned-import".into(),
                severity: "warning".into(),
                packages: vec!["@react-navigation/bottom-tabs".into()],
                message: "JS-based bottom tabs lack native feel — use react-native-bottom-tabs for native tab bar".into(),
                suggest: Some("Replace with: import { createNativeBottomTabNavigator } from 'react-native-bottom-tabs'".into()),
                ..Default::default()
            },
            TomlRule {
                id: "rn-no-linear-gradient-lib".into(),
                rule_type: "banned-import".into(),
                severity: "warning".into(),
                packages: vec!["expo-linear-gradient".into()],
                message: "expo-linear-gradient adds a JS bridge — use React Native's built-in linearGradient style (0.76+)".into(),
                suggest: Some("Use style={{ experimental_backgroundImage: 'linear-gradient(...)' }}".into()),
                ..Default::default()
            },
            TomlRule {
                id: "rn-no-js-bottom-sheet".into(),
                rule_type: "banned-dependency".into(),
                severity: "warning".into(),
                packages: vec!["@gorhom/bottom-sheet".into()],
                message: "@gorhom/bottom-sheet uses JS animations — use expo-bottom-sheet or react-native-bottom-sheet for native performance".into(),
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

/// Prefix a glob pattern with a scoped path.
/// Strips a leading `**/` if present so patterns like `**/*.tsx` become `{path}/**/*.tsx`.
fn scope_glob(path: &str, glob: &str) -> String {
    let stripped = glob.strip_prefix("**/").unwrap_or(glob);
    format!("{path}/{stripped}")
}

/// Resolve scoped presets and return rules with globs prefixed to the scoped path.
pub fn resolve_scoped_rules(
    scoped: &[ScopedPreset],
    user_rules: &[TomlRule],
) -> Result<Vec<TomlRule>, PresetError> {
    let mut result: Vec<TomlRule> = Vec::new();

    for entry in scoped {
        let preset = resolve_preset(&entry.preset).ok_or_else(|| PresetError::UnknownPreset {
            name: entry.preset.clone(),
            available: available_presets().to_vec(),
        })?;

        for mut rule in preset_rules(preset) {
            // Prefix glob
            rule.glob = Some(match rule.glob {
                Some(g) => scope_glob(&entry.path, &g),
                None => format!("{}/**", entry.path),
            });

            // Prefix exclude_glob entries
            rule.exclude_glob = rule
                .exclude_glob
                .iter()
                .map(|g| scope_glob(&entry.path, g))
                .collect();

            // Prefix file-presence paths
            rule.required_files = rule
                .required_files
                .iter()
                .map(|f| format!("{}/{f}", entry.path))
                .collect();
            rule.forbidden_files = rule
                .forbidden_files
                .iter()
                .map(|f| format!("{}/{f}", entry.path))
                .collect();

            // User rules with the same id override scoped preset rules
            if user_rules.iter().any(|u| u.id == rule.id) {
                continue;
            }

            result.push(rule);
        }
    }

    Ok(result)
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
    fn security_has_eleven_rules() {
        let rules = preset_rules(Preset::Security);
        assert_eq!(rules.len(), 11);
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
        assert!(ids.contains(&"no-paste-prevention"));
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
    fn react_has_expected_rule_count() {
        let rules = preset_rules(Preset::React);
        #[cfg(not(feature = "ast"))]
        assert_eq!(rules.len(), 27);
        #[cfg(feature = "ast")]
        assert_eq!(rules.len(), 30); // 27 base + 3 AST rules (nested-component-def swapped in-place)
        let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"no-array-index-key"));
        assert!(ids.contains(&"no-conditional-render-zero"));
        assert!(ids.contains(&"no-nested-component-def"));
        assert!(ids.contains(&"no-dangerous-html"));
        assert!(ids.contains(&"no-full-lodash-import"));
        assert!(ids.contains(&"no-moment"));
        assert!(ids.contains(&"no-moment-dep"));
        assert!(ids.contains(&"no-new-function"));
        assert!(ids.contains(&"no-transition-all"));
        assert!(ids.contains(&"no-layout-animation"));
        assert!(ids.contains(&"no-sequential-await"));
        assert!(ids.contains(&"no-derived-state-effect"));
        assert!(ids.contains(&"no-fetch-in-effect"));
        assert!(ids.contains(&"no-lazy-state-init"));
        assert!(ids.contains(&"no-object-dep-array"));
        assert!(ids.contains(&"no-default-object-prop"));
        // React 19 / composition
        assert!(ids.contains(&"no-forwardref"));
        assert!(ids.contains(&"no-use-context"));
        // Correctness
        assert!(ids.contains(&"no-unsafe-createcontext-default"));
        assert!(ids.contains(&"no-effect-callback-sync"));
        assert!(ids.contains(&"no-usestate-localstorage-eager"));
        // Performance / bundle
        assert!(ids.contains(&"no-regexp-in-render"));
        assert!(ids.contains(&"no-lucide-barrel"));
        assert!(ids.contains(&"no-mui-barrel"));
        assert!(ids.contains(&"no-mui-icons-barrel"));
        assert!(ids.contains(&"no-react-icons-barrel"));
        assert!(ids.contains(&"no-date-fns-barrel"));
        #[cfg(feature = "ast")]
        {
            assert!(ids.contains(&"max-component-size"));
            assert!(ids.contains(&"prefer-use-reducer"));
            assert!(ids.contains(&"no-cascading-set-state"));
            // no-nested-component-def uses AST type when feature is enabled
            let nested_rule = rules.iter().find(|r| r.id == "no-nested-component-def").unwrap();
            assert_eq!(nested_rule.rule_type, "no-nested-components");
        }
        #[cfg(not(feature = "ast"))]
        {
            let nested_rule = rules.iter().find(|r| r.id == "no-nested-component-def").unwrap();
            assert_eq!(nested_rule.rule_type, "banned-pattern");
        }
    }

    #[test]
    fn nextjs_best_practices_has_expected_rule_count() {
        let rules = preset_rules(Preset::NextjsBestPractices);
        #[cfg(not(feature = "ast"))]
        assert_eq!(rules.len(), 17);
        #[cfg(feature = "ast")]
        assert_eq!(rules.len(), 21); // 17 base + 4 AST rules
        let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"use-next-image"));
        assert!(ids.contains(&"next-image-fill-needs-sizes"));
        assert!(ids.contains(&"use-next-link"));
        assert!(ids.contains(&"no-next-router-in-app"));
        assert!(ids.contains(&"no-next-head"));
        assert!(ids.contains(&"no-client-side-redirect"));
        assert!(ids.contains(&"no-sync-scripts"));
        assert!(ids.contains(&"no-link-fonts"));
        assert!(ids.contains(&"no-css-link"));
        assert!(ids.contains(&"no-private-env-client"));
        assert!(ids.contains(&"require-use-client-for-hooks"));
        assert!(ids.contains(&"no-async-client-component"));
        assert!(ids.contains(&"require-metadata-in-pages"));
        assert!(ids.contains(&"no-redirect-in-try-catch"));
        assert!(ids.contains(&"server-action-requires-auth"));
        assert!(ids.contains(&"server-action-requires-validation"));
        assert!(ids.contains(&"no-suppress-hydration-warning"));
        #[cfg(feature = "ast")]
        {
            assert!(ids.contains(&"max-component-size"));
            assert!(ids.contains(&"no-nested-components"));
            assert!(ids.contains(&"prefer-use-reducer"));
            assert!(ids.contains(&"no-cascading-set-state"));
        }
    }

    #[test]
    fn accessibility_has_expected_rule_count() {
        let rules = preset_rules(Preset::Accessibility);
        #[cfg(not(feature = "ast"))]
        assert_eq!(rules.len(), 8);
        #[cfg(feature = "ast")]
        assert_eq!(rules.len(), 9); // 8 base + 1 AST rule (require-img-alt)
        let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"no-div-click-handler"));
        assert!(ids.contains(&"no-span-click-handler"));
        assert!(ids.contains(&"no-outline-none"));
        assert!(ids.contains(&"no-user-scalable-no"));
        assert!(ids.contains(&"no-autofocus-unrestricted"));
        assert!(ids.contains(&"no-transition-all-tailwind"));
        assert!(ids.contains(&"no-hardcoded-date-format"));
        assert!(ids.contains(&"no-inline-navigation-onclick"));
        #[cfg(feature = "ast")]
        assert!(ids.contains(&"require-img-alt"));
    }

    #[test]
    fn react_native_has_thirteen_rules() {
        let rules = preset_rules(Preset::ReactNative);
        assert_eq!(rules.len(), 13);
        let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"rn-no-touchable-opacity"));
        assert!(ids.contains(&"rn-no-touchable-highlight"));
        assert!(ids.contains(&"rn-no-legacy-shadow"));
        assert!(ids.contains(&"rn-no-rn-image-import"));
        assert!(ids.contains(&"rn-no-custom-header"));
        assert!(ids.contains(&"rn-no-fonts-usefonts"));
        assert!(ids.contains(&"rn-no-font-loadasync"));
        assert!(ids.contains(&"rn-no-inline-intl-numberformat"));
        assert!(ids.contains(&"rn-no-inline-intl-datetimeformat"));
        assert!(ids.contains(&"rn-no-js-stack-navigator"));
        assert!(ids.contains(&"rn-no-js-bottom-tabs"));
        assert!(ids.contains(&"rn-no-linear-gradient-lib"));
        assert!(ids.contains(&"rn-no-js-bottom-sheet"));
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

    // ── React preset pattern tests ──────────────────────────────────

    #[test]
    fn no_forwardref_pattern() {
        let re = regex_for(Preset::React, "no-forwardref");
        assert!(re.is_match("const Input = forwardRef<HTMLInputElement>((props, ref) => {"));
        assert!(re.is_match("const Btn = forwardRef((props, ref) => <button />)"));
        assert!(re.is_match("export default forwardRef(MyComponent)"));
        // should NOT match
        assert!(!re.is_match("// removed forwardRef"));
        assert!(!re.is_match("const forwardRefValue = 42"));
    }

    #[test]
    fn no_use_context_pattern() {
        let re = regex_for(Preset::React, "no-use-context");
        assert!(re.is_match("const theme = useContext(ThemeContext)"));
        assert!(re.is_match("const val = useContext(Ctx)"));
        // should NOT match
        assert!(!re.is_match("const ctx = useContextSelector(Ctx, s => s.val)"));
        assert!(!re.is_match("// useContext is deprecated"));
    }

    #[test]
    fn no_unsafe_createcontext_default_pattern() {
        let re = regex_for(Preset::React, "no-unsafe-createcontext-default");
        // unsafe defaults
        assert!(re.is_match("const Ctx = createContext({})"));
        assert!(re.is_match("const Ctx = createContext([])"));
        assert!(re.is_match("const Ctx = createContext(undefined)"));
        assert!(re.is_match("const Ctx = createContext(0)"));
        assert!(re.is_match("const Ctx = createContext('')"));
        assert!(re.is_match(r#"const Ctx = createContext("")"#));
        // safe: null or meaningful value
        assert!(!re.is_match("const Ctx = createContext(null)"));
        assert!(!re.is_match("const Ctx = createContext(defaultValue)"));
        assert!(!re.is_match("const Ctx = createContext({ theme: 'dark' })"));
    }

    #[test]
    fn no_effect_callback_sync_pattern() {
        let re = regex_for(Preset::React, "no-effect-callback-sync");
        assert!(re.is_match("useEffect(() => { onChange(value)"));
        assert!(re.is_match("useEffect(() => { onUpdate(data)"));
        assert!(re.is_match("useEffect(() => onSubmit(form)"));
        // should NOT match — no on* callback
        assert!(!re.is_match("useEffect(() => { setCount(1) }"));
        assert!(!re.is_match("useEffect(() => { fetchData() }"));
    }

    #[test]
    fn no_usestate_localstorage_eager_pattern() {
        let re = regex_for(Preset::React, "no-usestate-localstorage-eager");
        assert!(re.is_match("useState(localStorage.getItem('key'))"));
        assert!(re.is_match("useState(JSON.parse(localStorage.getItem('key')))"));
        // lazy initializer is fine
        assert!(!re.is_match("useState(() => localStorage.getItem('key'))"));
        // not localStorage
        assert!(!re.is_match("useState(sessionStorage.getItem('key'))"));
    }

    #[test]
    fn no_regexp_in_render_pattern() {
        let re = regex_for(Preset::React, "no-regexp-in-render");
        assert!(re.is_match("const re = new RegExp(pattern)"));
        assert!(re.is_match("new RegExp('\\\\d+', 'g')"));
        // regex literal is fine (not new RegExp)
        assert!(!re.is_match("const re = /\\d+/g"));
    }

    #[test]
    fn no_lucide_barrel_pattern() {
        let re = regex_for(Preset::React, "no-lucide-barrel");
        // barrel imports should match
        assert!(re.is_match("import { Home } from 'lucide-react'"));
        assert!(re.is_match(r#"import { Home } from "lucide-react""#));
        assert!(re.is_match("require('lucide-react')"));
        // deep imports should NOT match
        assert!(!re.is_match("import Home from 'lucide-react/icons/Home'"));
        assert!(!re.is_match("import { Home } from 'lucide-react/dist/esm/icons/home'"));
    }

    #[test]
    fn no_mui_barrel_pattern() {
        let re = regex_for(Preset::React, "no-mui-barrel");
        assert!(re.is_match("import { Button } from '@mui/material'"));
        assert!(re.is_match("require('@mui/material')"));
        // deep imports should NOT match
        assert!(!re.is_match("import Button from '@mui/material/Button'"));
        assert!(!re.is_match("import { useTheme } from '@mui/material/styles'"));
    }

    #[test]
    fn no_mui_icons_barrel_pattern() {
        let re = regex_for(Preset::React, "no-mui-icons-barrel");
        assert!(re.is_match("import { Home } from '@mui/icons-material'"));
        // deep import is fine
        assert!(!re.is_match("import HomeIcon from '@mui/icons-material/Home'"));
    }

    #[test]
    fn no_react_icons_barrel_pattern() {
        let re = regex_for(Preset::React, "no-react-icons-barrel");
        assert!(re.is_match("import { FaHome } from 'react-icons'"));
        // subpath import is fine
        assert!(!re.is_match("import { FaHome } from 'react-icons/fa'"));
    }

    #[test]
    fn no_date_fns_barrel_pattern() {
        let re = regex_for(Preset::React, "no-date-fns-barrel");
        assert!(re.is_match("import { format } from 'date-fns'"));
        assert!(re.is_match("require('date-fns')"));
        // subpath import is fine
        assert!(!re.is_match("import { format } from 'date-fns/format'"));
        assert!(!re.is_match("import { format } from 'date-fns/esm'"));
    }

    // ── Next.js best-practices pattern tests ────────────────────────

    #[test]
    fn server_action_requires_auth_patterns() {
        let rules = preset_rules(Preset::NextjsBestPractices);
        let rule = rules.iter().find(|r| r.id == "server-action-requires-auth").unwrap();
        let re = regex::Regex::new(rule.pattern.as_ref().unwrap()).unwrap();
        let cond_re = regex::Regex::new(rule.condition_pattern.as_ref().unwrap()).unwrap();
        // condition pattern matches server action files
        assert!(cond_re.is_match("'use server'"));
        assert!(!cond_re.is_match("'use client'"));
        // required pattern matches auth calls
        assert!(re.is_match("await verifySession()"));
        assert!(re.is_match("const s = await getSession()"));
        assert!(re.is_match("const s = await auth()"));
        assert!(re.is_match("const u = await currentUser()"));
        assert!(re.is_match("const s = await getServerSession()"));
        // no auth call
        assert!(!re.is_match("await db.insert(data)"));
    }

    #[test]
    fn server_action_requires_validation_patterns() {
        let rules = preset_rules(Preset::NextjsBestPractices);
        let rule = rules.iter().find(|r| r.id == "server-action-requires-validation").unwrap();
        let re = regex::Regex::new(rule.pattern.as_ref().unwrap()).unwrap();
        // validation calls
        assert!(re.is_match("const data = schema.parse(formData)"));
        assert!(re.is_match("const result = schema.safeParse(input)"));
        assert!(re.is_match("const s = z.object({})"));
        assert!(re.is_match("await body.validate()"));
        // no validation
        assert!(!re.is_match("await db.insert(formData)"));
    }

    #[test]
    fn no_suppress_hydration_warning_pattern() {
        let rules = preset_rules(Preset::NextjsBestPractices);
        let rule = rules.iter().find(|r| r.id == "no-suppress-hydration-warning").unwrap();
        let pat = rule.pattern.as_ref().unwrap();
        assert!(!rule.regex);
        assert!("<div suppressHydrationWarning>".contains(pat.as_str()));
        assert!("<body suppressHydrationWarning={true}>".contains(pat.as_str()));
        assert!(!"<div className='safe'>".contains(pat.as_str()));
    }

    // ── Security pattern tests (new) ────────────────────────────────

    #[test]
    fn no_paste_prevention_pattern() {
        let re = regex_for(Preset::Security, "no-paste-prevention");
        assert!(re.is_match("onPaste={(e) => e.preventDefault()}"));
        assert!(re.is_match("onPaste={e => { e.preventDefault() }}"));
        assert!(re.is_match("onPaste={handlePaste} // where handlePaste calls preventDefault"));
        // should NOT match unrelated
        assert!(!re.is_match("onPaste={handlePaste}"));
        assert!(!re.is_match("onCopy={(e) => e.preventDefault()}"));
    }

    // ── Accessibility pattern tests ─────────────────────────────────

    #[test]
    fn no_div_click_handler_pattern() {
        let re = regex_for(Preset::Accessibility, "no-div-click-handler");
        assert!(re.is_match("<div className='card' onClick={handleClick}>"));
        assert!(re.is_match("<div onClick = {fn}>"));
        // button is fine
        assert!(!re.is_match("<button onClick={handleClick}>"));
        // closing tag
        assert!(!re.is_match("</div>"));
        // div without onClick
        assert!(!re.is_match("<div className='card'>"));
    }

    #[test]
    fn no_span_click_handler_pattern() {
        let re = regex_for(Preset::Accessibility, "no-span-click-handler");
        assert!(re.is_match("<span role='button' onClick={handleClick}>"));
        assert!(re.is_match("<span onClick={fn}>"));
        // button is fine
        assert!(!re.is_match("<button onClick={handleClick}>"));
        // span without onClick
        assert!(!re.is_match("<span className='label'>"));
    }

    #[test]
    fn no_outline_none_pattern() {
        let re = regex_for(Preset::Accessibility, "no-outline-none");
        assert!(re.is_match("className='outline-none'"));
        assert!(re.is_match("className='focus:outline-none ring-2'"));
        // should NOT match outline-offset or outline-0
        assert!(!re.is_match("className='outline-offset-2'"));
        assert!(!re.is_match("className='outline-0'"));
    }

    #[test]
    fn no_user_scalable_no_pattern() {
        let re = regex_for(Preset::Accessibility, "no-user-scalable-no");
        assert!(re.is_match("user-scalable=no"));
        assert!(re.is_match("user-scalable = no"));
        // user-scalable=yes is fine
        assert!(!re.is_match("user-scalable=yes"));
    }

    #[test]
    fn no_autofocus_unrestricted_pattern() {
        let re = regex_for(Preset::Accessibility, "no-autofocus-unrestricted");
        assert!(re.is_match("<input autoFocus />"));
        assert!(re.is_match("<Input autoFocus={true} />"));
        // should NOT match substring
        assert!(!re.is_match("const autoFocusEnabled = true"));
    }

    #[test]
    fn no_transition_all_tailwind_pattern() {
        let re = regex_for(Preset::Accessibility, "no-transition-all-tailwind");
        assert!(re.is_match("className='transition-all duration-300'"));
        // specific transition is fine
        assert!(!re.is_match("className='transition-colors duration-300'"));
        assert!(!re.is_match("className='transition-opacity'"));
    }

    #[test]
    fn no_hardcoded_date_format_pattern() {
        let re = regex_for(Preset::Accessibility, "no-hardcoded-date-format");
        assert!(re.is_match("date.toDateString()"));
        assert!(re.is_match("date.toLocaleString()"));
        assert!(re.is_match("date.toLocaleDateString()"));
        // with locale argument is fine (not empty parens)
        assert!(!re.is_match("date.toLocaleDateString('en-US')"));
        assert!(!re.is_match("date.toLocaleString('de-DE', opts)"));
    }

    #[test]
    fn no_inline_navigation_onclick_pattern() {
        let re = regex_for(Preset::Accessibility, "no-inline-navigation-onclick");
        assert!(re.is_match("onClick={() => window.location.href = '/home'}"));
        assert!(re.is_match("onClick={() => { window.location = '/page' }}"));
        // router.push is fine (not window.location)
        assert!(!re.is_match("onClick={() => router.push('/home')}"));
    }

    // ── React Native pattern tests ──────────────────────────────────

    #[test]
    fn rn_no_touchable_opacity_pattern() {
        let re = regex_for(Preset::ReactNative, "rn-no-touchable-opacity");
        assert!(re.is_match("<TouchableOpacity onPress={fn}>"));
        assert!(re.is_match("import { TouchableOpacity } from 'react-native'"));
        assert!(re.is_match("import { View, TouchableOpacity } from 'react-native'"));
        // Pressable is fine
        assert!(!re.is_match("<Pressable onPress={fn}>"));
    }

    #[test]
    fn rn_no_touchable_highlight_pattern() {
        let re = regex_for(Preset::ReactNative, "rn-no-touchable-highlight");
        assert!(re.is_match("<TouchableHighlight onPress={fn}>"));
        assert!(re.is_match("import { TouchableHighlight } from 'react-native'"));
        // Pressable is fine
        assert!(!re.is_match("<Pressable onPress={fn}>"));
    }

    #[test]
    fn rn_no_legacy_shadow_pattern() {
        let re = regex_for(Preset::ReactNative, "rn-no-legacy-shadow");
        assert!(re.is_match("shadowColor: '#000'"));
        assert!(re.is_match("shadowOffset: { width: 0 }"));
        assert!(re.is_match("shadowOpacity: 0.25"));
        assert!(re.is_match("shadowRadius: 3.84"));
        // boxShadow is fine
        assert!(!re.is_match("boxShadow: '0 2px 4px rgba(0,0,0,0.1)'"));
    }

    #[test]
    fn rn_no_rn_image_import_pattern() {
        let re = regex_for(Preset::ReactNative, "rn-no-rn-image-import");
        assert!(re.is_match("import { Image } from 'react-native'"));
        assert!(re.is_match("import { View, Image } from 'react-native'"));
        assert!(re.is_match("import { Image, Text } from 'react-native'"));
        // expo-image is fine
        assert!(!re.is_match("import { Image } from 'expo-image'"));
        // ImageBackground is different
        assert!(!re.is_match("import { ImageBackground } from 'react-native'"));
    }

    #[test]
    fn rn_no_custom_header_pattern() {
        let re = regex_for(Preset::ReactNative, "rn-no-custom-header");
        assert!(re.is_match("header: () => <CustomHeader />"));
        assert!(re.is_match("header: () =>"));
        // headerTitle is fine
        assert!(!re.is_match("headerTitle: 'Settings'"));
    }

    #[test]
    fn rn_no_fonts_usefonts_pattern() {
        let re = regex_for(Preset::ReactNative, "rn-no-fonts-usefonts");
        assert!(re.is_match("const [loaded] = useFonts({ Inter: require('./fonts/Inter.ttf') })"));
        assert!(re.is_match("useFonts({"));
        // unrelated hooks
        assert!(!re.is_match("useForm({ mode: 'onChange' })"));
    }

    #[test]
    fn rn_no_font_loadasync_pattern() {
        let re = regex_for(Preset::ReactNative, "rn-no-font-loadasync");
        assert!(re.is_match("await Font.loadAsync({ Inter: require('./Inter.ttf') })"));
        assert!(re.is_match("Font.loadAsync(fonts)"));
        // unrelated
        assert!(!re.is_match("await Image.loadAsync(uri)"));
    }

    #[test]
    fn rn_no_inline_intl_numberformat_pattern() {
        let re = regex_for(Preset::ReactNative, "rn-no-inline-intl-numberformat");
        assert!(re.is_match("new Intl.NumberFormat('en-US').format(price)"));
        assert!(re.is_match("const fmt = new Intl.NumberFormat('de-DE', { style: 'currency' })"));
        // already extracted (no new keyword in this context, but the pattern is about new)
        assert!(!re.is_match("fmt.format(1234)"));
    }

    #[test]
    fn rn_no_inline_intl_datetimeformat_pattern() {
        let re = regex_for(Preset::ReactNative, "rn-no-inline-intl-datetimeformat");
        assert!(re.is_match("new Intl.DateTimeFormat('en-US').format(date)"));
        assert!(re.is_match("const fmt = new Intl.DateTimeFormat('ja-JP', opts)"));
        assert!(!re.is_match("fmt.format(date)"));
    }

    // ── Scoped presets tests ──────────────────────────────────────────

    #[test]
    fn scope_glob_strips_leading_double_star() {
        assert_eq!(scope_glob("apps/web", "**/*.tsx"), "apps/web/*.tsx");
        assert_eq!(
            scope_glob("apps/web", "**/*.{tsx,jsx}"),
            "apps/web/*.{tsx,jsx}"
        );
    }

    #[test]
    fn scope_glob_prepends_path_to_plain_glob() {
        assert_eq!(
            scope_glob("apps/web", "src/**/*.ts"),
            "apps/web/src/**/*.ts"
        );
    }

    #[test]
    fn scope_glob_handles_simple_filename() {
        assert_eq!(scope_glob("apps/web", "*.json"), "apps/web/*.json");
    }

    #[test]
    fn resolve_scoped_rules_prefixes_globs() {
        let scoped = vec![ScopedPreset {
            preset: "nextjs".into(),
            path: "apps/web".into(),
        }];
        let rules = resolve_scoped_rules(&scoped, &[]).unwrap();
        assert!(!rules.is_empty());
        for rule in &rules {
            let glob = rule.glob.as_ref().unwrap();
            assert!(
                glob.starts_with("apps/web/"),
                "expected glob to start with 'apps/web/', got: {glob}"
            );
        }
    }

    #[test]
    fn resolve_scoped_rules_none_glob_gets_catch_all() {
        // ai-safety has banned-dependency rules with no glob
        let scoped = vec![ScopedPreset {
            preset: "ai-safety".into(),
            path: "packages/core".into(),
        }];
        let rules = resolve_scoped_rules(&scoped, &[]).unwrap();
        // banned-dependency rules have no glob by default — should get scoped catch-all
        for rule in &rules {
            let glob = rule.glob.as_ref().unwrap();
            assert!(
                glob.starts_with("packages/core/"),
                "expected glob to start with 'packages/core/', got: {glob}"
            );
        }
    }

    #[test]
    fn resolve_scoped_rules_user_override_skips_rule() {
        let scoped = vec![ScopedPreset {
            preset: "nextjs".into(),
            path: "apps/web".into(),
        }];
        let user_rules = vec![TomlRule {
            id: "use-next-image".into(),
            rule_type: "banned-pattern".into(),
            message: "custom override".into(),
            ..Default::default()
        }];
        let rules = resolve_scoped_rules(&scoped, &user_rules).unwrap();
        // use-next-image should be skipped because the user overrides it
        assert!(
            !rules.iter().any(|r| r.id == "use-next-image"),
            "scoped rule should be skipped when user defines same id"
        );
    }

    #[test]
    fn scoped_and_global_presets_merge() {
        let global =
            resolve_rules(&["security".to_string()], &[]).unwrap();
        let scoped = resolve_scoped_rules(
            &[ScopedPreset {
                preset: "nextjs".into(),
                path: "apps/web".into(),
            }],
            &[],
        )
        .unwrap();
        let mut all = global;
        all.extend(scoped);
        // Should have security rules + nextjs scoped rules
        assert!(all.iter().any(|r| r.id == "no-eval"));
        assert!(all.iter().any(|r| r.id == "use-next-image"));
        // The nextjs rules should have scoped globs
        let next_img = all.iter().find(|r| r.id == "use-next-image").unwrap();
        assert!(next_img.glob.as_ref().unwrap().starts_with("apps/web/"));
    }

    #[test]
    fn resolve_scoped_unknown_preset_errors() {
        let scoped = vec![ScopedPreset {
            preset: "nonexistent".into(),
            path: "apps/web".into(),
        }];
        let result = resolve_scoped_rules(&scoped, &[]);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("unknown preset 'nonexistent'"));
    }

    #[test]
    fn resolve_scoped_prefixes_file_presence_paths() {
        // security preset has file-presence rules with forbidden_files
        let scoped = vec![ScopedPreset {
            preset: "security".into(),
            path: "apps/api".into(),
        }];
        let rules = resolve_scoped_rules(&scoped, &[]).unwrap();
        let fp_rule = rules.iter().find(|r| r.id == "no-env-files").unwrap();
        for f in &fp_rule.forbidden_files {
            assert!(
                f.starts_with("apps/api/"),
                "expected forbidden_file to start with 'apps/api/', got: {f}"
            );
        }
    }

    #[test]
    fn resolve_scoped_prefixes_exclude_glob() {
        // security preset's no-console-log has exclude_glob
        let scoped = vec![ScopedPreset {
            preset: "security".into(),
            path: "apps/api".into(),
        }];
        let rules = resolve_scoped_rules(&scoped, &[]).unwrap();
        let console_rule = rules.iter().find(|r| r.id == "no-console-log").unwrap();
        for eg in &console_rule.exclude_glob {
            assert!(
                eg.starts_with("apps/api/"),
                "expected exclude_glob to start with 'apps/api/', got: {eg}"
            );
        }
    }
}
