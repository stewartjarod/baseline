# Changelog

## [v1.5.1] - 2026-02-18

### Bug Fixes
- Fix HTML-tag rule false positives on template literal strings: add `skip_strings` to use-next-image, use-next-link, no-sync-scripts, no-link-fonts, no-css-link (ba8f136)

### Other
- Fix claude-code-hooks example: use correct hook format, parse file path from stdin (d2c4fe8)

## [v1.5.0] - 2026-02-18

### Features
- Add 6 AST rules: no-outline-none, no-div-click-handler, no-span-click-handler, no-derived-state-effect, no-regexp-in-render, no-object-dep-array (05ddd26)
- Split `react` preset (35 rules) into `react` (18 correctness) + `react-opinions` (12 style/perf) (05ddd26)
- Add `react-19` preset with no-forwardref and no-use-context (05ddd26)
- Rename `ai-safety` preset to `dependency-hygiene` (backward-compatible alias kept) (05ddd26)
- Migrate Tailwind rules from regex to AST-based class extraction (71015ac)

### Bug Fixes
- Remove 5 high-false-positive rules from react preset: no-forwardref, no-use-context, no-hardcoded-jsx-id, no-direct-window-listener, no-effect-callback-sync (05ddd26)
- Fix no-suppress-hydration-warning: exclude layout files (official Next.js dark mode pattern) (05ddd26)
- Fix no-hardcoded-secrets: add skip_strings, expand exclude_glob for fixtures/mocks (05ddd26)
- Fix next-image-fill-needs-sizes: increase window size from 3 to 7 lines (05ddd26)

## [v1.4.2] - 2026-02-17

### Other
- add bulletproof React rules to react preset: SSR safety, composition, portability (95a5467)

## [v1.4.1] - 2026-02-17

### Other
- remove `ast` feature flag: tree-sitter now built in unconditionally — `skip_strings` and AST rules work for all users including npm/npx (b2cf187)
- update logo (c45d786)

## [v1.4.0] - 2026-02-17

### Features
- add `skip_strings` to BannedPatternRule: ignore matches inside string literals and template strings using tree-sitter (requires `ast` feature) (6845d84)
- skip minified/bundled files automatically (lines exceeding 500 chars) (6845d84)
- scoped presets support `exclude_rules` to skip specific rules (6845d84)

## [v1.3.0] - 2026-02-17

### Features
- add scoped presets for monorepo support (f4e1433)

## [v1.2.2] - 2026-02-17

### Other
- rebuild npm platform packages with binaries via OIDC publishing

## [v1.2.1] - 2026-02-17

### Other
- migrate npm platform packages to @code-baseline scoped org

## [v1.2.0] - 2026-02-17

### Features
- add accessibility and react-native presets, expand react/nextjs/security (ad792f1)

## [v1.1.0] - 2026-02-17

### Features
- add tree-sitter AST support behind `ast` feature flag with 4 structural rules: `max-component-size`, `no-nested-components`, `prefer-use-reducer`, `no-cascading-set-state`
- add AST rules to react and nextjs-best-practices presets (conditional on `ast` feature)
- add no-sequential-await and no-derived-state-effect to react preset (b3e4a30)
- add react and nextjs-best-practices presets (e9c1225)

### Other
- comprehensive documentation audit and corrections (217fcd4)
- add CI workflow for cargo test (e52e0e2)
- add crates.io, npm, license, and CI badges to README (d82d753)

## [v1.0.1] - 2026-02-17

### Other
- update brand assets and logo
- add v1.0.0 changelog entry

## [v1.0.0] - 2026-02-17

### Breaking Changes
- rebrand guardrails to baseline (crate: code-baseline) (85cdad8)

## [v0.5.0] - 2026-02-16

### Features
- add ratchet add/down/from CLI commands (87db4b6)

## [v0.4.0] - 2026-02-14

### Features
- add security, nextjs, and ai-codegen presets (03dfedf)
- add forbidden_files support to file-presence rule (32da08c)

### Other
- add npm install instructions to README (dcb25f9)

## [v0.3.5] - 2026-02-12

### Bug Fixes
- chmod binary executable at runtime if npm strips permissions (62a5c72)

## [v0.3.4] - 2026-02-12

### Bug Fixes
- remove bin field from platform packages to avoid npx symlink conflict (9fbb692)

## [v0.3.3] - 2026-02-12

### Bug Fixes
- use direct path resolution for platform binary in npx (12701c8)

## [v0.3.2] - 2026-02-12

### Bug Fixes
- resolve platform binary from package's node_modules path (6608d07)

## [v0.3.1] - 2026-02-12

### Bug Fixes
- mark platform binaries as executable via bin field (93b4dd6)
- upgrade npm CLI for trusted publishing OIDC support (5d8bc4a)
- download artifacts to separate dir in npm release workflow (7548f1a)

## [v0.3.0] - 2026-02-12

### Features
- add npm binary distribution for `npx code-baseline` (5eb18de)

### Bug Fixes
- include Cargo.lock in release commit step (de19f11)

## [v0.2.0] - 2026-02-12

### Features
- add /release skill for automated crate publishing (13e9b3e)

### Performance
- parallelize file processing with rayon and reduce redundant work (1c83906)
