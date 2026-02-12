# Changelog

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
- add npm binary distribution for `npx code-guardrails` (5eb18de)

### Bug Fixes
- include Cargo.lock in release commit step (de19f11)

## [v0.2.0] - 2026-02-12

### Features
- add /release skill for automated crate publishing (13e9b3e)

### Performance
- parallelize file processing with rayon and reduce redundant work (1c83906)
