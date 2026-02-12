# guardrails

Stop AI from undoing your team's decisions.

A fast Rust-based CI tool that enforces bans, ratchets, and design system rules that ESLint can't express — so Cursor, Copilot, and Claude stop reintroducing the patterns you already migrated away from.

## The Problem

AI coding tools are fast. They're also confidently wrong about your team's conventions.

Cursor, Copilot, and Claude generate code from training data — not from your team's decisions. They don't know you migrated off moment.js. They don't know you banned axios. They don't know your Tailwind classes need dark mode variants. So every AI-assisted PR is a coin flip on whether it respects months of architectural work.

- **"We migrated off moment.js six months ago. Cursor just added it back in a PR."** AI tools pull from stale training data. Every deprecated package you've ever used is one autocomplete away from returning.
- **"We have 200 legacyFetch calls and the number keeps going _up_."** AI generates new code using the patterns it sees most in your codebase. Legacy patterns are self-reinforcing unless something blocks them.
- **"Our shadcn components support dark mode — except the ones AI wrote."** AI doesn't understand your design system. It reaches for `bg-white` and `text-gray-900` because that's what it learned from public repos.
- **"We banned the request package, but Copilot just added it to package.json."** Dependency-level decisions live in your team's memory. AI has no access to that context.

Linters catch syntax. Formatters fix whitespace. **guardrails** enforces the decisions your team has already made — especially the ones AI keeps ignoring.

## Why not ESLint?

ESLint is great at what it does. guardrails handles what it can't:

- **Ratcheting.** ESLint is pass/fail. guardrails counts occurrences across your codebase and enforces a ceiling that only goes down. You can migrate 200 legacy calls to 0 at your own pace — and CI prevents regressions at every step.
- **Dependency bans.** ESLint checks source files. guardrails parses `package.json`, `Cargo.toml`, `requirements.txt`, and `go.mod` to catch banned packages before they ship — even if no source file imports them yet.
- **File presence rules.** Enforce that `README.md`, `LICENSE`, and CI configs exist. Forbid `.env` files from being committed. ESLint has no concept of project-level structure.
- **Cross-file counting.** guardrails aggregates pattern matches across your entire codebase. "There should be fewer than 50 uses of legacyFetch" is a one-liner in `guardrails.toml` and impossible in ESLint without a custom plugin.
- **Zero config for Tailwind/shadcn.** Built-in rules enforce dark mode variants and semantic token usage with 130+ default mappings. No plugins, no parser setup, no dependencies.
- **Speed.** Written in Rust. Single binary. No Node.js runtime. Scans a large codebase in milliseconds.

## Quick Start

```bash
# Build from source
cargo build --release

# Initialize a config in your project
guardrails init

# Edit guardrails.toml to fit your project...

# Run checks
guardrails

# Validate config without scanning
guardrails validate

# Count occurrences (useful for ratchet baselines)
guardrails count "legacyFetch(" --glob "src/**/*.ts"
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

Everything lives in a single `guardrails.toml` at the root of your project.

### Global Settings

```toml
[guardrails]
name = "my-project"
include = ["src/**/*", "lib/**/*", "app/**/*"]
exclude = [
    "**/node_modules/**",
    "**/target/**",
    "**/.git/**",
    "**/dist/**",
    "**/build/**",
]
root = "."  # optional, defaults to current directory
```

The `exclude` list above is applied by default even if you don't specify it.

---

## Rule Types

### `banned-import` — Stop deprecated package imports

Detects `import`, `require`, `from ... import`, and `use` statements across JavaScript, TypeScript, Python, and Rust.

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
import moment from 'moment';           // ES6
const moment = require('moment');       // CommonJS
```
```python
import moment                           # Python
from moment import format               # Python
```
```rust
use moment::format;                     // Rust
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

Checks `package.json`, `Cargo.toml`, `requirements.txt`, `pyproject.toml`, and `go.mod` for banned packages. Parses `dependencies`, `devDependencies`, `peerDependencies`, and `optionalDependencies` in `package.json`; `dependencies`, `dev-dependencies`, and `build-dependencies` in `Cargo.toml`.

```toml
[[rule]]
id = "no-request"
type = "banned-dependency"
severity = "error"
packages = ["request", "request-promise"]
manifest = "package.json"
message = "The 'request' package is deprecated — use 'node-fetch' or 'undici'"
```

Omit `manifest` to check all recognized manifest files automatically.

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

Use the `count` command to find your current baseline:

```bash
$ guardrails count "legacyFetch(" --glob "src/**/*.ts"

  12 occurrences in src/api/client.ts
   8 occurrences in src/hooks/useData.ts
  ...

→ Total: 47 occurrences across 12 files
  Use this as your max_count value to start ratcheting down.
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

## All Rule Config Fields

| Field | Type | Used By | Description |
|---|---|---|---|
| `id` | string | All | Unique rule identifier |
| `type` | string | All | Rule type (see sections above) |
| `severity` | `error` / `warning` / `info` | All | Severity level (default: `error`) |
| `message` | string | All | Human-readable explanation |
| `suggest` | string | All | Fix suggestion shown in output |
| `enabled` | bool | All | Enable/disable (default: `true`) |
| `glob` | string | File rules | Narrow which files this rule applies to |
| `packages` | string[] | `banned-import`, `banned-dependency` | Package names to ban |
| `pattern` | string | `banned-pattern`, `required-pattern`, `ratchet` | String or regex to match |
| `regex` | bool | Pattern rules | Treat `pattern` as regex (default: `false`) |
| `manifest` | string | `banned-dependency` | Manifest file to check (omit for auto-detect) |
| `required_files` | string[] | `file-presence` | Files that must exist |
| `forbidden_files` | string[] | `file-presence` | Files that must not exist |
| `max_count` | int | `ratchet` | Maximum allowed occurrences |
| `allowed_classes` | string[] | `tailwind-dark-mode`, `tailwind-theme-tokens` | Classes exempt from checks |
| `token_map` | string[] | `tailwind-theme-tokens` | Custom `"raw=semantic"` mappings |

---

## CLI Reference

```
guardrails [OPTIONS] [COMMAND]

Commands:
  check       Run guardrail checks (default when no command given)
  init        Create a starter guardrails.toml
  validate    Validate config without running checks
  count       Count pattern occurrences for ratchet baselines

Options:
  -c, --config <PATH>     Config file path [default: guardrails.toml]
  -f, --format <FORMAT>   Output format [default: pretty]
  -r, --root <PATH>       Override scan root directory
  --errors-only           Only report errors (hide warnings and info)
  --strict                Fail with exit code 1 on warnings too
  -h, --help              Print help
  -V, --version           Print version
```

### Output Formats

| Format | Flag | Use Case |
|---|---|---|
| `pretty` | `-f pretty` | Human-readable terminal output with colors, source context, and suggestions |
| `compact` | `-f compact` | One line per violation, grep-friendly |
| `json` | `-f json` | Machine-readable, for tooling integration |
| `github-actions` | `-f github` | Native GitHub annotation format — violations appear inline on PR diffs |

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | No errors (warnings may be present unless `--strict`) |
| `1` | Violations found |
| `2` | Configuration or runtime error |

---

## CI Integration

### GitHub Actions

```yaml
jobs:
  guardrails:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run guardrails
        run: ./guardrails -f github-actions --strict
```

Violations appear as inline annotations directly on the PR diff:

```
::error file=src/utils/helpers.ts,line=1,title=no-moment::moment.js is deprecated — use date-fns
::warning file=src/utils/helpers.ts,line=6,col=3,title=no-console-log::Remove console.log before committing
```

### Generic CI

```yaml
- name: Run guardrails
  run: guardrails -f compact --strict
```

### Pre-commit Hook

```bash
#!/bin/sh
guardrails --errors-only
```

---

## Architecture

```
src/
├── main.rs                         CLI entry point (clap)
├── lib.rs                          Library root
├── config.rs                       TOML configuration parsing
├── scanner.rs                      File tree walker + rule orchestration
├── report.rs                       Output rendering (pretty, JSON, GitHub Actions, compact)
└── rules/
    ├── mod.rs                      Rule trait, Violation type, rule registry
    ├── banned_import.rs            Import detection (JS/TS/Python/Rust)
    ├── banned_pattern.rs           Literal + regex pattern matching
    ├── required_pattern.rs         Ensure patterns exist in matching files
    ├── banned_dependency.rs        Manifest parsing (package.json, Cargo.toml, etc.)
    ├── file_presence.rs            Required/forbidden file checks
    ├── ratchet.rs                  Decreasing-count enforcement
    ├── tailwind_dark_mode.rs       Dark mode variant enforcement
    └── tailwind_theme_tokens.rs    shadcn semantic token enforcement

tests/
└── integration_tests.rs            15 integration tests covering all rule types

examples/
└── shadcn-project/                 Before/after example of Tailwind theme enforcement
    ├── guardrails.toml
    └── src/components/
        ├── BadCard.tsx              28 violations — hardcoded colors
        └── GoodCard.tsx             0 violations — semantic tokens
```

### Extending with New Rules

The `Rule` trait defines the interface:

```rust
pub trait Rule: Send + Sync {
    fn id(&self) -> &str;
    fn severity(&self) -> Severity;

    /// Check a single file. Called for each file matching the glob.
    fn check_file(&self, ctx: &ScanContext) -> Vec<Violation>;

    /// Check the project as a whole (manifests, file presence, ratchet totals).
    fn check_project(&self, root: &Path) -> Vec<Violation>;

    /// Whether this rule scans individual files.
    fn is_file_rule(&self) -> bool;

    /// Optional glob to narrow file matching beyond the global include/exclude.
    fn file_glob(&self) -> Option<&str>;
}
```

To add a new rule:

1. Create `src/rules/your_rule.rs` implementing the `Rule` trait.
2. Add a variant to `RuleType` in `src/config.rs`.
3. Register it in `build_rule()` in `src/rules/mod.rs`.
4. Add any new config fields to `RuleConfig` in `src/config.rs`.

---

## Real-World Usage Patterns

### AI keeps importing moment.js — make it stop

AI coding assistants pull from training data that includes deprecated packages. guardrails catches these before they land:

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
$ guardrails count "oldApi.fetch(" --glob "src/**/*.ts"
→ Total: 200 occurrences across 43 files

# Step 2: Set the ceiling in guardrails.toml
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
- **Auto-fix** — not just detection, but automated rewrites
- **Baseline files** — `guardrails baseline` to auto-generate ratchet counts into `.guardrails-baseline.json`
- **WASM plugin system** — distribute custom rules as portable WASM modules
- **Watch mode** — re-run on file changes during development
- **Monorepo support** — per-package config inheritance with shared base rules

## License

MIT
