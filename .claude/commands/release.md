# Release

Automate the full release flow for this crate: determine version bump, generate changelog, bump Cargo.toml, commit, tag, publish to crates.io, and create a GitHub release.

## Instructions

You are performing a release of the `guardrails` crate. Follow each step carefully and ask for confirmation before any irreversible action (publish, push, GitHub release).

### Step 1: Determine the version bump

The user may pass an explicit bump level as `$ARGUMENTS` (one of `patch`, `minor`, or `major`). If provided, use that.

If no argument is provided, determine the bump automatically from conventional commits since the last git tag:

1. Run `git describe --tags --abbrev=0` to find the latest tag.
2. Run `git log <latest-tag>..HEAD --pretty=format:"%s"` to get commit subjects since that tag.
3. Apply these rules (highest wins):
   - If any subject contains `BREAKING CHANGE` or has a `!:` (e.g. `feat!:`, `fix!:`), bump = **major**
   - If any subject starts with `feat:` or `feat(`, bump = **minor**
   - Otherwise (e.g. `fix:`, `perf:`, `chore:`, `docs:`, etc.), bump = **patch**
4. If there are zero commits since the last tag, stop and tell the user there is nothing to release.

Read the current version from `Cargo.toml` and compute the new version using semver rules:
- **patch**: `0.1.2` → `0.1.3`
- **minor**: `0.1.2` → `0.2.0`
- **major**: `0.1.2` → `1.0.0`

Print the determined bump level and new version, then proceed.

### Step 2: Generate changelog entry

Group commits since the last tag by type into these sections (skip empty sections):

- **Features** — commits starting with `feat:`/`feat(`
- **Bug Fixes** — commits starting with `fix:`/`fix(`
- **Performance** — commits starting with `perf:`/`perf(`
- **Other** — everything else (exclude `chore: release` commits)

Format the new changelog entry as:

```
## [v{new_version}] - {YYYY-MM-DD}

### Features
- {description} ({short_hash})

### Bug Fixes
- {description} ({short_hash})

...
```

Use `git log <latest-tag>..HEAD --pretty=format:"%h %s"` to get hashes and subjects.

If `CHANGELOG.md` exists, prepend the new section after any existing `# Changelog` header. If it does not exist, create it with a `# Changelog` header followed by the new section.

### Step 3: Bump version in Cargo.toml

Edit the `version = "..."` line in `Cargo.toml` to the new version. Only change the version field in `[package]`.

### Step 4: Run checks

Run `cargo check` to verify the project still compiles after the version bump. If it fails, stop and report the error.

### Step 5: Commit and tag

Stage `Cargo.toml` and `CHANGELOG.md`, then commit:

```
git add Cargo.toml CHANGELOG.md
git commit -m "chore: release v{new_version}"
```

Then create an annotated tag:

```
git tag -a v{new_version} -m "v{new_version}"
```

### Step 6: Publish to crates.io

**Ask the user for confirmation before this step.**

Show them:
- The new version number
- The changelog entry
- That this will run `cargo publish` and `git push --follow-tags`

If confirmed:

```
cargo publish
git push --follow-tags
```

If the user declines, tell them the commit and tag are local and they can publish manually later.

### Step 7: Create GitHub release

**Ask the user for confirmation before this step** (can be combined with Step 6 confirmation).

Create a GitHub release using the changelog entry as the body:

```
gh release create v{new_version} --title "v{new_version}" --notes "{changelog_entry}"
```

### Summary

After all steps complete, print a summary:
- Previous version → New version
- Bump type used
- Number of commits included
- Link to the GitHub release (if created)
- Link to the crates.io page: `https://crates.io/crates/guardrails`
