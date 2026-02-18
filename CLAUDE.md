# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Baseline is a code quality enforcement tool that lints React/TypeScript projects for Tailwind CSS best practices and semantic theming. Rules are implemented in Rust and configured via TOML.

## Build Commands

- `cargo check` — type-check without building
- `cargo build` — compile the library
- `cargo test` — run all tests
- tree-sitter AST support is built in unconditionally

## Architecture

**Rule system**: Plugin-based architecture where each rule implements the `Rule` trait (`id()`, `severity()`, `file_glob()`, `check_file()`). Rules receive a `ScanContext` (file path + content) and return `Vec<Violation>`.

**Core types** (from `crate::config` and `crate::rules`):
- `RuleConfig` — parsed TOML rule configuration (`src/config.rs`)
- `Severity` — error/warning levels (`src/config.rs`)
- `ScanContext` — file being scanned (path + content) (`src/rules/mod.rs`)
- `Violation` — detected issue (rule_id, severity, file, line, column, message, suggest, source_line) (`src/rules/mod.rs`)
- `RuleBuildError` — construction errors (e.g., `InvalidRegex`) (`src/rules/mod.rs`)

**Nine regex/string rule types** (in `src/rules/`):
- `BannedImportRule` — detects banned imports in JS/TS (`import`, `require`, `export from`)
- `BannedPatternRule` — literal or regex pattern matching
- `RequiredPatternRule` — ensures patterns exist in matching files (supports `condition_pattern`)
- `BannedDependencyRule` — checks JSON manifest files (default: `package.json`)
- `FilePresenceRule` — required/forbidden file checks
- `RatchetRule` — decreasing-count enforcement
- `WindowPatternRule` — proximity enforcement (trigger + required pattern within N lines)
- `TailwindDarkModeRule` — ensures hardcoded Tailwind color classes have `dark:` variants
- `TailwindThemeTokensRule` — bans raw Tailwind color classes, suggests semantic tokens (~130+ default mappings)

**Five AST rule types** (in `src/rules/ast/`):
- `MaxComponentSizeRule` — flags React components exceeding a line count (`max_count`, default 150)
- `NoNestedComponentsRule` — detects component definitions inside other components
- `PreferUseReducerRule` — flags components with too many `useState` calls (`max_count`, default 4)
- `NoCascadingSetStateRule` — flags `useEffect` callbacks with too many `set*` calls (`max_count`, default 3)
- `RequireImgAltRule` — flags `<img>` elements missing an `alt` attribute

**AST infrastructure** (`src/rules/ast/mod.rs`): Uses tree-sitter for parsing TSX/TS/JSX/JS files. `parse_file()` detects language from extension and returns a syntax tree. `is_component_node()` identifies PascalCase function declarations, arrow functions, and class declarations as React components.

**Tailwind class extraction**: Both Tailwind rules detect classes from `className=`, `class=`, and utility function calls (`cn()`, `clsx()`, `classNames()`, `cva()`, `twMerge()`). They skip `dark:`, `hover:`, and `focus:` prefixed classes.

**Ten built-in presets** (`src/presets.rs`): `shadcn-strict`, `shadcn-migrate`, `ai-safety`, `security`, `nextjs`, `ai-codegen`, `react`, `nextjs-best-practices`, `accessibility`, `react-native`.

## Configuration

`examples/baseline.toml` is the sample config. `examples/baseline.example.toml` documents all supported rule types:
- `banned-import`, `banned-pattern`, `required-pattern`, `banned-dependency`, `file-presence`, `ratchet`, `window-pattern`, `tailwind-dark-mode`, `tailwind-theme-tokens`

Each `[[rule]]` has: `id`, `type`, `severity`, `glob`, `message`, `suggest`, plus type-specific fields (`allowed_classes`, `token_map`, `packages`, `pattern`, `max_count`, `exclude_glob`, `file_contains`, `file_not_contains`, `condition_pattern`, etc.).

AST rule types: `max-component-size`, `no-nested-components`, `prefer-use-reducer`, `no-cascading-set-state`, `require-img-alt`.

## Example Files

`examples/BadCard.tsx` and `examples/GoodCard.tsx` demonstrate anti-patterns vs. best practices for shadcn/ui theming. Use these as reference when writing or modifying rules.
