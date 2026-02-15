use crate::config::{RuleConfig, Severity};
use crate::rules::{Rule, RuleBuildError, ScanContext, Violation};
use std::path::PathBuf;

/// Ensures that specific files exist (or do not exist) in the project.
///
/// Unlike other rules, this doesn't scan file content — it checks whether
/// required files are present and forbidden files are absent. Useful for
/// enforcing project conventions like "every project must have a .env.example"
/// or ".env files should not be committed."
///
/// The `required_files` config field lists relative paths that must exist.
/// The `forbidden_files` config field lists relative paths that must NOT exist.
/// The rule emits one violation per missing required file or present forbidden file.
#[derive(Debug)]
pub struct FilePresenceRule {
    id: String,
    severity: Severity,
    message: String,
    suggest: Option<String>,
    required_files: Vec<String>,
    forbidden_files: Vec<String>,
}

impl FilePresenceRule {
    pub fn new(config: &RuleConfig) -> Result<Self, RuleBuildError> {
        if config.required_files.is_empty() && config.forbidden_files.is_empty() {
            return Err(RuleBuildError::MissingField(
                config.id.clone(),
                "required_files or forbidden_files",
            ));
        }

        Ok(Self {
            id: config.id.clone(),
            severity: config.severity,
            message: config.message.clone(),
            suggest: config.suggest.clone(),
            required_files: config.required_files.clone(),
            forbidden_files: config.forbidden_files.clone(),
        })
    }

    /// Check which required files are missing and which forbidden files exist.
    /// Returns violations for each missing required file or present forbidden file.
    pub fn check_paths(&self, root_paths: &[PathBuf]) -> Vec<Violation> {
        let mut violations = Vec::new();

        for required in &self.required_files {
            let exists = root_paths.iter().any(|root| {
                let check_path = if root.is_dir() {
                    root.join(required)
                } else {
                    // If root is a file, check relative to its parent
                    root.parent()
                        .map(|p| p.join(required))
                        .unwrap_or_else(|| PathBuf::from(required))
                };
                check_path.exists()
            });

            if !exists {
                let msg = if self.message.is_empty() {
                    format!("Required file '{}' is missing", required)
                } else {
                    format!("{}: '{}'", self.message, required)
                };

                violations.push(Violation {
                    rule_id: self.id.clone(),
                    severity: self.severity,
                    file: PathBuf::from(required),
                    line: None,
                    column: None,
                    message: msg,
                    suggest: self.suggest.clone(),
                    source_line: None,
                    fix: None,
                });
            }
        }

        for forbidden in &self.forbidden_files {
            let exists = root_paths.iter().any(|root| {
                let check_path = if root.is_dir() {
                    root.join(forbidden)
                } else {
                    root.parent()
                        .map(|p| p.join(forbidden))
                        .unwrap_or_else(|| PathBuf::from(forbidden))
                };
                check_path.exists()
            });

            if exists {
                let msg = if self.message.is_empty() {
                    format!("Forbidden file '{}' must not exist", forbidden)
                } else {
                    format!("{}: '{}'", self.message, forbidden)
                };

                violations.push(Violation {
                    rule_id: self.id.clone(),
                    severity: self.severity,
                    file: PathBuf::from(forbidden),
                    line: None,
                    column: None,
                    message: msg,
                    suggest: self.suggest.clone(),
                    source_line: None,
                    fix: None,
                });
            }
        }

        violations
    }
}

impl Rule for FilePresenceRule {
    fn id(&self) -> &str {
        &self.id
    }

    fn severity(&self) -> Severity {
        self.severity
    }

    fn file_glob(&self) -> Option<&str> {
        // File presence rules don't scan files — they check for existence
        None
    }

    fn check_file(&self, _ctx: &ScanContext) -> Vec<Violation> {
        // File presence checking is done via check_paths, not check_file
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;

    fn make_rule(files: Vec<&str>) -> FilePresenceRule {
        let config = RuleConfig {
            id: "test-file-presence".into(),
            severity: Severity::Error,
            message: "required file missing".into(),
            suggest: Some("create the required file".into()),
            required_files: files.into_iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        };
        FilePresenceRule::new(&config).unwrap()
    }

    #[test]
    fn file_exists_no_violation() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".env.example"), "").unwrap();
        let rule = make_rule(vec![".env.example"]);
        let violations = rule.check_paths(&[dir.path().to_path_buf()]);
        assert!(violations.is_empty());
    }

    #[test]
    fn file_missing_one_violation() {
        let dir = TempDir::new().unwrap();
        let rule = make_rule(vec![".env.example"]);
        let violations = rule.check_paths(&[dir.path().to_path_buf()]);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].message.contains(".env.example"));
    }

    #[test]
    fn multiple_files_partial_missing() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("README.md"), "# Hello").unwrap();
        let rule = make_rule(vec!["README.md", "LICENSE", ".env.example"]);
        let violations = rule.check_paths(&[dir.path().to_path_buf()]);
        assert_eq!(violations.len(), 2);
    }

    #[test]
    fn nested_file_exists() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("src/lib")).unwrap();
        fs::write(dir.path().join("src/lib/index.ts"), "").unwrap();
        let rule = make_rule(vec!["src/lib/index.ts"]);
        let violations = rule.check_paths(&[dir.path().to_path_buf()]);
        assert!(violations.is_empty());
    }

    #[test]
    fn missing_both_fields_error() {
        let config = RuleConfig {
            id: "test".into(),
            severity: Severity::Error,
            message: "test".into(),
            ..Default::default()
        };
        let err = FilePresenceRule::new(&config).unwrap_err();
        assert!(matches!(err, RuleBuildError::MissingField(_, _)));
    }

    fn make_forbidden_rule(files: Vec<&str>) -> FilePresenceRule {
        let config = RuleConfig {
            id: "test-forbidden".into(),
            severity: Severity::Error,
            message: "".into(),
            forbidden_files: files.into_iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        };
        FilePresenceRule::new(&config).unwrap()
    }

    #[test]
    fn forbidden_file_absent_no_violation() {
        let dir = TempDir::new().unwrap();
        let rule = make_forbidden_rule(vec![".env"]);
        let violations = rule.check_paths(&[dir.path().to_path_buf()]);
        assert!(violations.is_empty());
    }

    #[test]
    fn forbidden_file_present_violation() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".env"), "SECRET=abc").unwrap();
        let rule = make_forbidden_rule(vec![".env"]);
        let violations = rule.check_paths(&[dir.path().to_path_buf()]);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].message.contains(".env"));
    }

    #[test]
    fn forbidden_multiple_some_present() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".env"), "").unwrap();
        fs::write(dir.path().join(".env.local"), "").unwrap();
        let rule = make_forbidden_rule(vec![".env", ".env.local", ".env.production"]);
        let violations = rule.check_paths(&[dir.path().to_path_buf()]);
        assert_eq!(violations.len(), 2);
    }

    #[test]
    fn forbidden_only_allows_construction() {
        let config = RuleConfig {
            id: "test".into(),
            severity: Severity::Error,
            message: "test".into(),
            forbidden_files: vec![".env".into()],
            ..Default::default()
        };
        assert!(FilePresenceRule::new(&config).is_ok());
    }

    #[test]
    fn mixed_required_and_forbidden() {
        let dir = TempDir::new().unwrap();
        // README exists (required, satisfied), .env exists (forbidden, violation)
        fs::write(dir.path().join("README.md"), "# Hello").unwrap();
        fs::write(dir.path().join(".env"), "SECRET=abc").unwrap();

        let config = RuleConfig {
            id: "test-mixed".into(),
            severity: Severity::Error,
            message: "".into(),
            required_files: vec!["README.md".into(), "LICENSE".into()],
            forbidden_files: vec![".env".into()],
            ..Default::default()
        };
        let rule = FilePresenceRule::new(&config).unwrap();
        let violations = rule.check_paths(&[dir.path().to_path_buf()]);
        // LICENSE missing + .env present = 2 violations
        assert_eq!(violations.len(), 2);
    }
}
