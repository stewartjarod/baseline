<p align="center">
  <img src="assets/baseline.png" alt="Baseline logo" width="300" />
</p>

<p align="center">
  <a href="https://crates.io/crates/code-baseline"><img src="https://img.shields.io/crates/v/code-baseline" alt="Crates.io"></a>
  <a href="https://www.npmjs.com/package/code-baseline"><img src="https://img.shields.io/npm/v/code-baseline" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://github.com/stewartjarod/baseline/actions"><img src="https://img.shields.io/github/actions/workflow/status/stewartjarod/baseline/ci.yml?branch=main&label=CI" alt="CI"></a>
</p>

# baseline

Stop AI from undoing your team's decisions.

A fast Rust-based CI tool that enforces bans, ratchets, and design system rules that ESLint can't express — so Cursor, Copilot, and Claude stop reintroducing the patterns you already migrated away from.

## The Problem

AI coding tools are fast. They're also confidently wrong about your team's conventions.

Cursor, Copilot, and Claude generate code from training data — not from your team's decisions. They don't know you migrated off moment.js. They don't know you banned axios. They don't know your Tailwind classes need dark mode variants. So every AI-assisted PR is a coin flip on whether it respects months of architectural work.

- **"We migrated off moment.js six months ago. Cursor just added it back in a PR."** AI tools pull from stale training data. Every deprecated package you've ever used is one autocomplete away from returning.
- **"We have 200 legacyFetch calls and the number keeps going _up_."** AI generates new code using the patterns it sees most in your codebase. Legacy patterns are self-reinforcing unless something blocks them.
- **"Our shadcn components support dark mode — except the ones AI wrote."** AI doesn't understand your design system. It reaches for `bg-white` and `text-gray-900` because that's what it learned from public repos.
- **"We banned the request package, but Copilot just added it to package.json."** Dependency-level decisions live in your team's memory. AI has no access to that context.

Linters catch syntax. Formatters fix whitespace. **baseline** enforces the decisions your team has already made — especially the ones AI keeps ignoring.

## Why not ESLint?

ESLint is great at what it does. baseline handles what it can't:

- **Ratcheting.** ESLint is pass/fail. baseline counts occurrences across your codebase and enforces a ceiling that only goes down. You can migrate 200 legacy calls to 0 at your own pace — and CI prevents regressions at every step.
- **Dependency bans.** ESLint checks source files. baseline parses `package.json` to catch banned packages before they ship — even if no source file imports them yet.
- **File presence rules.** Enforce that `README.md`, `LICENSE`, and CI configs exist. Forbid `.env` files from being committed. ESLint has no concept of project-level structure.
- **Cross-file counting.** baseline aggregates pattern matches across your entire codebase. "There should be fewer than 50 uses of legacyFetch" is a one-liner in `baseline.toml` and impossible in ESLint without a custom plugin.
- **Zero config for Tailwind/shadcn.** Built-in rules enforce dark mode variants and semantic token usage with 130+ default mappings. No plugins, no parser setup, no dependencies.
- **Speed.** Written in Rust. Single binary. No Node.js runtime. Scans a large codebase in milliseconds.

## Quick Start

```bash
# Run instantly via npm (no install needed)
npx code-baseline scan

# Or install globally
npm install -g code-baseline

# Or via Cargo
cargo install code-baseline
```

```bash
# Initialize a config in your project
baseline init

# Edit baseline.toml to fit your project...

# Scan your project
baseline scan

# Only scan files changed since main
baseline scan --changed-only

# Generate a ratchet baseline
baseline baseline .
```

## Example Output

```
src/utils/helpers.ts
  1:0  error  moment.js is deprecated — use date-fns or Temporal API  no-moment
    │ import moment from 'moment';
    → import { format } from 'date-fns'
  2:0  warning  Import specific lodash functions instead of the full package  no-lodash-full
    │ import { debounce } from 'lodash';
    → import debounce from 'lodash/debounce'
  6:3  warning  Remove console.log before committing  no-console-log
    │ console.log("formatting date");

src/components/BadCard.tsx
  7:21  error  Missing dark: variant for color class: 'bg-white'  enforce-dark-mode
    │ <div className="bg-white border border-gray-200 rounded-lg shadow-sm p-6">
    → Use 'bg-background' instead — it adapts to light/dark automatically

✗ 9 violations (7 error, 2 warning)
  Scanned 14 files with 8 rules.
```

## Configuration

Everything lives in a single `baseline.toml` at the root of your project.

### Global Settings

```toml
[baseline]
name = "my-project"
include = ["src/**/*", "lib/**/*", "app/**/*"]
exclude = [
    "**/node_modules/**",
    "**/target/**",
    "**/.git/**",
    "**/dist/**",
    "**/build/**",
]
```

The `exclude` list above is applied by default even if you don't specify it.

> **Note:** The `include` field documents which paths your project cares about, but scanning scope is controlled by the `paths` CLI argument (e.g. `baseline scan src`). The file walker also respects `.gitignore` automatically.

### Presets

Load a curated set of rules in one line with `extends`. User-defined `[[rule]]` entries with the same `id` as a preset rule override the preset version entirely.

```toml
[baseline]
extends = ["shadcn-strict", "ai-codegen"]
```

Available presets:

| Preset | Rules | Description |
|---|---|---|
| `shadcn-strict` | 5 | Dark mode enforcement (error), theme tokens (error), no inline styles, no CSS-in-JS, no competing frameworks |
| `shadcn-migrate` | 2 | Dark mode enforcement (error), theme tokens (warning) — softer, for gradual migration |
| `ai-safety` | 3 | Bans deprecated packages: moment, lodash, request |
| `security` | 10 | No .env files, no hardcoded secrets, no eval, no dangerouslySetInnerHTML, no innerHTML, no document.write, no wildcard postMessage, no http:// URLs, no console.log |
| `nextjs` | 8 | Use next/image, next/link, next/font, next/script; no next/head or next/router in App Router; no private env vars in client components; require 'use client' for hooks |
| `ai-codegen` | 12 | No placeholder text, no TODOs, no `any` type, no empty catch, no console.log, no @ts-ignore, no `as any`, no eslint-disable, no @ts-nocheck, no var, no require in TS, no non-null assertions |

### Plugins

Load additional rules from external TOML files:

```toml
[baseline]
plugins = ["./plugins/react-rules.toml", "./plugins/security-rules.toml"]
```

Plugin files contain `[[rule]]` entries in the same format as your main config:

```toml
# plugins/react-rules.toml
[[rule]]
id = "no-default-export"
type = "banned-pattern"
severity = "warning"
pattern = "export default"
glob = "src/components/**/*.tsx"
message = "Use named exports for components"
```

---

## Rule Types

### `banned-import` — Stop deprecated package imports

Detects `import`, `require`, and `export ... from` statements in JavaScript and TypeScript files. Defaults to scanning `**/*.{ts,tsx,js,jsx,mjs,cjs}`.

```toml
[[rule]]
id = "no-moment"
type = "banned-import"
severity = "error"
packages = ["moment", "moment-timezone"]
message = "moment.js is deprecated — use date-fns or Temporal API"
suggest = "import { format } from 'date-fns'"
```

Catches all of these:

```js
import moment from 'moment';           // ES6 default import
import { format } from 'moment';       // ES6 named import
import 'moment';                       // Side-effect import
const moment = require('moment');       // CommonJS require
export { default } from 'moment';      // Re-export
import debounce from 'lodash/debounce'; // Subpath import
```

---

### `banned-pattern` — Block unwanted code patterns

Matches literal strings or regex patterns in source files. Use `glob` to scope which files are checked.

```toml
[[rule]]
id = "no-console-log"
type = "banned-pattern"
severity = "warning"
pattern = "console.log("
glob = "src/**/*.ts"
message = "Remove console.log before committing — use the logger"
suggest = "import { logger } from '@company/logger'"
```

Enable regex for more precise matching:

```toml
[[rule]]
id = "no-any-type"
type = "banned-pattern"
severity = "warning"
pattern = ":\\s*any\\b"
regex = true
glob = "src/**/*.ts"
message = "Avoid 'any' — use proper typing or 'unknown'"
```

---

### `required-pattern` — Enforce that patterns exist

The inverse of `banned-pattern`. Fails if a matching file does *not* contain the pattern.

```toml
[[rule]]
id = "error-boundary-in-pages"
type = "required-pattern"
severity = "error"
glob = "src/pages/**/*.tsx"
pattern = "ErrorBoundary"
message = "All page components must wrap content in an ErrorBoundary"
```

---

### `banned-dependency` — Audit manifest files

Parses JSON manifest files for banned packages. By default checks `package.json`, scanning `dependencies`, `devDependencies`, `peerDependencies`, and `optionalDependencies`. Use the `manifest` field to check a different JSON manifest file.

```toml
[[rule]]
id = "no-request"
type = "banned-dependency"
severity = "error"
packages = ["request", "request-promise"]
message = "The 'request' package is deprecated — use 'node-fetch' or 'undici'"
```

Specify a different manifest file:

```toml
[[rule]]
id = "no-bootstrap-bower"
type = "banned-dependency"
severity = "error"
packages = ["bootstrap"]
manifest = "bower.json"
message = "Remove bootstrap from bower.json"
```

---

### `file-presence` — Enforce project structure

Require files to exist, or forbid files that shouldn't be committed.

```toml
[[rule]]
id = "project-hygiene"
type = "file-presence"
severity = "error"
required_files = ["README.md", "LICENSE", ".github/workflows/ci.yml"]
forbidden_files = [".env", ".env.local"]
message = ".env files should not be committed — use .env.example"
```

---

### `ratchet` — Drive incremental refactors

Counts total occurrences of a pattern across all matching files and enforces a ceiling. Lower the ceiling over time as you migrate. CI prevents regressions.

```toml
[[rule]]
id = "ratchet-legacy-fetch"
type = "ratchet"
severity = "error"
pattern = "legacyFetch("
max_count = 47
glob = "src/**/*.ts"
message = "Migrate remaining legacyFetch calls to apiFetch"
suggest = "import { apiFetch } from '@company/http'"
```

Use the `baseline` command to find your current counts:

```bash
$ baseline baseline .
# Writes .baseline-snapshot.json with counts for all ratchet rules
```

The workflow: set `max_count = 47` today. Next sprint, migrate a few call sites, set `max_count = 40`. The number only goes down. Any PR that adds new legacy calls fails CI.

---

### `tailwind-dark-mode` — Enforce light + dark theme coverage

Scans JSX/TSX/HTML files for Tailwind color utility classes (`bg-white`, `text-gray-900`, `border-slate-200`, etc.) and flags any that don't have a corresponding `dark:` variant in the same class attribute.

```toml
[[rule]]
id = "enforce-dark-mode"
type = "tailwind-dark-mode"
severity = "error"
glob = "**/*.{tsx,jsx}"
message = "Missing dark: variant for color class"
suggest = "Use a shadcn semantic token or add a dark: counterpart"
allowed_classes = ["bg-brand-gradient"]
```

The rule is **shadcn-aware**. It automatically allows all semantic token classes because they resolve through CSS custom properties and already handle both themes:

`bg-background`, `text-foreground`, `bg-muted`, `text-muted-foreground`, `bg-card`, `bg-primary`, `text-primary-foreground`, `bg-secondary`, `bg-accent`, `bg-destructive`, `text-destructive-foreground`, `border-border`, `ring-ring`, and all sidebar variants.

It also recognizes properly paired dark variants:

```jsx
{/* ✅ Passes — dark: variant is paired */}
<div className="bg-white dark:bg-slate-900 text-black dark:text-white">

{/* ✅ Passes — semantic tokens handle theming automatically */}
<div className="bg-background text-foreground border-border">

{/* ❌ Fails — hardcoded colors with no dark: counterpart */}
<div className="bg-white text-gray-900 border-gray-200">
```

The rule understands `className="..."`, `class="..."`, and Tailwind utility functions like `cn()`, `clsx()`, `classNames()`, `cva()`, and `twMerge()`.

When it flags a violation, it suggests the specific semantic token replacement:

```
7:21  error  Missing dark: variant for color class: 'bg-white'  enforce-dark-mode
  │ <div className="bg-white border border-gray-200 rounded-lg shadow-sm p-6">
  → Use 'bg-background' instead — it adapts to light/dark automatically
```

---

### `tailwind-theme-tokens` — Ban raw colors, enforce semantic tokens

Goes a step further than dark mode enforcement: **bans raw Tailwind color classes entirely** and requires the use of shadcn semantic token classes. Ships with a comprehensive default mapping covering backgrounds, text, borders, rings, dividers, and destructive states.

```toml
[[rule]]
id = "use-theme-tokens"
type = "tailwind-theme-tokens"
severity = "warning"
glob = "**/*.{tsx,jsx}"
message = "Use shadcn semantic token instead of raw color"
```

Default mapping includes (partial):

| Raw Tailwind Class | Semantic Token |
|---|---|
| `bg-white` | `bg-background` |
| `bg-gray-50`, `bg-slate-100` | `bg-muted` |
| `text-gray-900`, `text-black` | `text-foreground` |
| `text-gray-500`, `text-slate-400` | `text-muted-foreground` |
| `border-gray-200`, `border-slate-300` | `border-border` |
| `bg-red-500`, `bg-red-600` | `bg-destructive` |
| `text-red-500` | `text-destructive` |
| `bg-slate-900` | `bg-primary` |
| `ring-slate-200` | `ring-ring` |

Extend with your own brand tokens:

```toml
token_map = [
    "bg-indigo-600=bg-brand",
    "text-indigo-50=text-brand-foreground",
    "border-indigo-300=border-brand",
]
```

Exempt specific classes that are intentionally unthemed:

```toml
allowed_classes = ["bg-green-500", "text-red-600"]
```

---

### `window-pattern` — Enforce proximity between patterns

Checks that when a trigger pattern appears, a required pattern also appears within N lines. Useful for enforcing that certain operations always have a nearby guard, filter, or cleanup.

```toml
[[rule]]
id = "org-scoped-queries"
type = "window-pattern"
severity = "error"
pattern = "DELETE FROM"
condition_pattern = "organizationId"
max_count = 80
glob = "src/**/*.ts"
message = "DELETE queries must include organizationId within 80 lines"
suggest = "Add WHERE organizationId = $orgId to scope the query"
```

- `pattern` — the trigger pattern to look for (literal or regex)
- `condition_pattern` — the pattern that must appear within the window
- `max_count` — window size in lines (how far to search after the trigger)
- `regex` — set to `true` to treat both patterns as regex

```toml
[[rule]]
id = "async-try-catch"
type = "window-pattern"
severity = "warning"
pattern = "async ("
condition_pattern = "try {"
max_count = 10
regex = true
glob = "src/api/**/*.ts"
message = "Async handlers should have try/catch within 10 lines"
```

---

## All Rule Config Fields

| Field | Type | Used By | Description |
|---|---|---|---|
| `id` | string | All | Unique rule identifier |
| `type` | string | All | Rule type (see sections above) |
| `severity` | `error` / `warning` | All | Severity level (default: `warning`) |
| `message` | string | All | Human-readable explanation |
| `suggest` | string | All | Fix suggestion shown in output |
| `glob` | string | File rules | Narrow which files this rule applies to |
| `exclude_glob` | string[] | File rules | Skip files matching these globs, even if they match `glob` |
| `file_contains` | string | File rules | Only run this rule if the file contains this string |
| `file_not_contains` | string | File rules | Skip this rule if the file contains this string |
| `packages` | string[] | `banned-import`, `banned-dependency` | Package names to ban |
| `pattern` | string | `banned-pattern`, `required-pattern`, `ratchet`, `window-pattern` | String or regex to match |
| `condition_pattern` | string | `required-pattern`, `window-pattern` | Only enforce if this pattern is present |
| `regex` | bool | Pattern rules | Treat `pattern` as regex (default: `false`) |
| `manifest` | string | `banned-dependency` | Manifest file to check (default: `package.json`) |
| `required_files` | string[] | `file-presence` | Files that must exist |
| `forbidden_files` | string[] | `file-presence` | Files that must not exist |
| `max_count` | int | `ratchet`, `window-pattern` | Maximum allowed occurrences (ratchet) or window size in lines (window-pattern) |
| `allowed_classes` | string[] | `tailwind-dark-mode`, `tailwind-theme-tokens` | Classes exempt from checks |
| `token_map` | string[] | `tailwind-theme-tokens` | Custom `"raw=semantic"` mappings |

### Per-Rule Exclusions

Any rule can use `exclude_glob` to skip specific paths, even if they match the inclusion `glob`:

```toml
[[rule]]
id = "no-hardcoded-secrets"
type = "banned-pattern"
severity = "error"
pattern = "(?i)api_key\\s*[:=]\\s*[\"'][a-zA-Z0-9_\\-]{8,}"
regex = true
exclude_glob = ["**/*.test.*", "**/*.spec.*"]
message = "Hardcoded secret detected"
```

### File-Context Conditioning

Rules can be conditioned on the presence (or absence) of a string in the file:

```toml
# Only flag private env vars in client components
[[rule]]
id = "no-private-env-client"
type = "banned-pattern"
severity = "error"
pattern = "process.env.SECRET"
file_contains = "'use client'"
message = "Do not access private env vars in client components"

# Skip generated files
[[rule]]
id = "no-console"
type = "banned-pattern"
severity = "warning"
pattern = "console.log("
file_not_contains = "// @generated"
message = "Remove console.log before committing"
```

---

## Escape Hatches

Suppress violations with inline comments when you need to make an exception:

```jsx
{/* Same-line suppression for a specific rule */}
<div className="bg-white"> {/* baseline:allow-enforce-dark-mode */}

{/* Same-line suppression for ALL rules */}
<div className="bg-white text-gray-900"> {/* baseline:allow-all */}

{/* Next-line suppression for a specific rule */}
{/* baseline:allow-next-line enforce-dark-mode */}
<div className="bg-white">

{/* Next-line suppression for ALL rules */}
{/* baseline:allow-next-line all */}
<div className="bg-white text-gray-900">
```

Works with any comment syntax (`//`, `/* */`, `{/* */}`, `#`, `<!-- -->`).

---

## CLI Reference

```
baseline <COMMAND>

Commands:
  scan        Scan files for rule violations (primary command)
  baseline    Count ratchet pattern occurrences and write a baseline JSON file
  ratchet     Manage ratchet rules (add, tighten, import from baseline)
  init        Generate a starter baseline.toml for your project
  mcp         Run as an MCP (Model Context Protocol) server over stdio
```

### `scan` options

```
baseline scan [OPTIONS] [PATHS]...

  -c, --config <PATH>       Config file path [default: baseline.toml]
  -f, --format <FORMAT>     Output format [default: pretty]
      --stdin               Read file content from stdin instead of disk
      --filename <NAME>     Filename to use for glob matching when using --stdin
      --changed-only        Only scan files changed relative to a base branch (requires git)
      --base <REF>          Base ref for --changed-only [default: auto-detect from CI or "main"]
                            Auto-detects: GITHUB_BASE_REF, CI_MERGE_REQUEST_TARGET_BRANCH_NAME
                            (GitLab), BITBUCKET_PR_DESTINATION_BRANCH (Bitbucket)
      --fix                 Apply fixes automatically
      --dry-run             Preview fixes without applying (requires --fix)
```

### `baseline` options

```
baseline baseline [OPTIONS] <PATHS>...

  -c, --config <PATH>       Config file path [default: baseline.toml]
  -o, --output <PATH>       Output file [default: .baseline-snapshot.json]
```

### `init` options

```
baseline init [OPTIONS]

  -o, --output <PATH>       Output file [default: baseline.toml]
      --force               Overwrite existing config file
```

The `init` command auto-detects your project type and generates an appropriate starter config:
- **shadcn + Tailwind** (detected via `components.json`) — uses `extends = ["shadcn-strict"]`
- **Tailwind CSS** (detected via `tailwind.config.*`) — includes Tailwind-specific rules
- **Generic** — generates example rules as comments

### `ratchet` subcommands

Helpers for managing ratchet rules without editing TOML by hand.

```
baseline ratchet add <PATTERN> [OPTIONS] [PATHS]...

  --id <ID>                 Custom rule ID (default: slugified pattern)
  --glob <GLOB>             File glob filter [default: **/*]
  --regex                   Treat pattern as regex
  --message <MSG>           Custom message
  -c, --config <PATH>       Config file path [default: baseline.toml]
```

Counts current occurrences and appends a new `[[rule]]` with `type = "ratchet"` and `max_count` set to the current count.

```
baseline ratchet down <RULE_ID> [OPTIONS] [PATHS]...

  -c, --config <PATH>       Config file path [default: baseline.toml]
```

Re-counts occurrences and lowers `max_count` in-place. Use after migrating call sites.

```
baseline ratchet from <BASELINE_JSON> [OPTIONS]

  -c, --config <PATH>       Config file path [default: baseline.toml]
```

Creates ratchet rules from a `.baseline-snapshot.json` file (output of `baseline baseline`).

### `mcp` options

```
baseline mcp [OPTIONS]

  -c, --config <PATH>       Config file path [default: baseline.toml]
```

Runs a JSON-RPC 2.0 MCP server over stdio (protocol version `2024-11-05`). Exposes two tools:

- **`baseline_scan`** — scan files or inline content for violations. Accepts `paths` (array) or `content` + `filename` (string).
- **`baseline_list_rules`** — list all configured rules with id, type, severity, glob, and message.

### Output Formats

| Format | Flag | Use Case |
|---|---|---|
| `pretty` | `-f pretty` | Human-readable terminal output with colors, source context, and suggestions |
| `compact` | `-f compact` | One line per violation, grep-friendly |
| `json` | `-f json` | Machine-readable, for tooling integration |
| `github` | `-f github` | GitHub Actions annotation format — violations appear inline on PR diffs |
| `sarif` | `-f sarif` | SARIF v2.1.0 for GitHub Code Scanning |
| `markdown` | `-f markdown` | Markdown tables for PR summaries and `$GITHUB_STEP_SUMMARY` |

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | No violations found |
| `1` | Violations found |
| `2` | Configuration or runtime error |

---

## CI Integration

### GitHub Actions (recommended)

Use the `stewartjarod/baseline` action for the simplest setup. On pull requests it automatically scans only changed files; on pushes to main it scans everything.

```yaml
name: Baseline

on:
  pull_request:
  push:
    branches: [main]

jobs:
  baseline:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0 # Full history needed for diff-aware scanning

      - uses: dtolnay/rust-toolchain@stable

      - uses: stewartjarod/baseline@main
        with:
          paths: 'src'
          # changed-only defaults to "auto" (enabled on PRs, disabled on push)
          # base: 'main'  # Override the base branch for diff comparison
```

The action produces inline annotations on the PR diff (`--format github`) and writes a markdown summary to `$GITHUB_STEP_SUMMARY`.

### Generic CI

```yaml
- name: Run baseline
  run: baseline scan --format compact
```

### Pre-commit Hook

```bash
#!/bin/sh
baseline scan --changed-only --base HEAD
```

---

## Architecture

```
src/
├── main.rs                         CLI entry point (clap)
├── lib.rs                          Library root — re-exports public API
├── config.rs                       TOML configuration parsing
├── scan.rs                         File tree walker + rule orchestration
├── git_diff.rs                     Git diff parsing for --changed-only
├── mcp.rs                          MCP (Model Context Protocol) server
├── init.rs                         Config scaffolding (baseline init)
├── presets.rs                      Built-in rule presets
├── cli/
│   ├── mod.rs                      CLI argument definitions (clap)
│   ├── format.rs                   Output rendering (pretty, JSON, GitHub, SARIF, etc.)
│   └── toml_config.rs              TOML config validation helpers
└── rules/
    ├── mod.rs                      Rule trait, Violation type, rule registry
    ├── factory.rs                  Rule construction from config
    ├── banned_import.rs            Import detection (JS/TS)
    ├── banned_pattern.rs           Literal + regex pattern matching
    ├── required_pattern.rs         Ensure patterns exist in matching files
    ├── banned_dependency.rs        Manifest parsing (package.json)
    ├── file_presence.rs            Required/forbidden file checks
    ├── ratchet.rs                  Decreasing-count enforcement
    ├── window_pattern.rs           Sliding-window pattern matching
    ├── tailwind_dark_mode.rs       Dark mode variant enforcement
    └── tailwind_theme_tokens.rs    shadcn semantic token enforcement

examples/
├── baseline.toml                   Sample project config
├── baseline.example.toml           Documented reference for all rule types
├── plugin-react-rules.toml         Example plugin file with React rules
├── github-ci.yml                   GitHub Actions workflow example
├── claude-code-hooks.json          Claude Code hooks integration
├── BadCard.tsx                     Anti-pattern example — hardcoded colors
└── GoodCard.tsx                    Best-practice example — semantic tokens
```

### Extending with New Rules

The `Rule` trait defines the interface:

```rust
pub trait Rule: Send + Sync {
    /// Unique identifier for this rule (e.g. "tailwind-dark-mode").
    fn id(&self) -> &str;

    /// Severity level reported when the rule fires.
    fn severity(&self) -> Severity;

    /// Optional glob pattern restricting which files are scanned.
    fn file_glob(&self) -> Option<&str>;

    /// Scan a single file and return any violations found.
    fn check_file(&self, ctx: &ScanContext) -> Vec<Violation>;
}
```

To add a new rule:

1. Create `src/rules/your_rule.rs` implementing the `Rule` trait.
2. Register it in `build_rule()` in `src/rules/factory.rs` (rule types are matched as strings).
3. Add any new config fields to `RuleConfig` in `src/config.rs` and `TomlRule` in `src/cli/toml_config.rs`.

---

## Real-World Usage Patterns

### AI keeps importing moment.js — make it stop

AI coding assistants pull from training data that includes deprecated packages. baseline catches these before they land:

```toml
[[rule]]
id = "no-moment"
type = "banned-import"
severity = "error"
packages = ["moment", "moment-timezone"]
message = "moment.js is deprecated — use date-fns or Temporal API"

[[rule]]
id = "no-enzyme"
type = "banned-import"
severity = "error"
packages = ["enzyme", "enzyme-adapter-react-16", "enzyme-adapter-react-17"]
message = "Enzyme is deprecated — use @testing-library/react"

[[rule]]
id = "no-request"
type = "banned-dependency"
severity = "error"
packages = ["request", "request-promise", "axios"]
message = "Use the native fetch API or undici"
```

### AI writes bg-white. Your design system says bg-background.

You're migrating from raw Tailwind to shadcn semantic tokens. Use both Tailwind rules together:

```toml
# Hard error: every color class must work in dark mode
[[rule]]
id = "enforce-dark-mode"
type = "tailwind-dark-mode"
severity = "error"
glob = "**/*.{tsx,jsx}"

# Soft warning: prefer semantic tokens (gives teams time to migrate)
[[rule]]
id = "use-theme-tokens"
type = "tailwind-theme-tokens"
severity = "warning"
glob = "**/*.{tsx,jsx}"
token_map = ["bg-indigo-600=bg-brand", "text-indigo-50=text-brand-foreground"]
```

### 200 legacy calls and AI is adding more — ratchet them to zero

You have 200 call sites using `oldApi.fetch()` and want to migrate to `newApi.request()`:

```bash
# Step 1: Find the current count
$ baseline baseline .
# Writes .baseline-snapshot.json with counts per ratchet rule

# Step 2: Set the ceiling in baseline.toml
```

```toml
[[rule]]
id = "ratchet-old-api"
type = "ratchet"
severity = "error"
pattern = "oldApi.fetch("
max_count = 200
glob = "src/**/*.ts"
message = "Migrate to newApi.request()"
```

```bash
# Step 3: After each migration sprint, lower the ceiling
# Sprint 1: max_count = 180
# Sprint 2: max_count = 150
# Sprint 3: max_count = 120
# ...
# Done:     max_count = 0
```

---

## Future Directions

- **Tree-sitter integration** — AST-aware rules for scope-sensitive matching (e.g., "ban `any` in function parameters but not in type guards")
- **WASM plugin system** — distribute custom rules as portable WASM modules
- **Watch mode** — re-run on file changes during development
- **Monorepo support** — per-package config inheritance with shared base rules

## Inspiration

This project was inspired by Matt Holden's concept of [guardrail coding](https://www.fuzzycomputer.com/posts/guardrail-coding) — the idea that AI coding tools should be guided by deterministic environment constraints (linters, rules, tests) rather than fuzzy prompt-space instructions. Follow Matt at [@holdenmatt](https://x.com/holdenmatt).

## License

MIT
