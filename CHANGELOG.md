# Changelog

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
