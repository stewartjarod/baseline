use crate::config::{RuleConfig, Severity};
use crate::rules::ast::parse_file;
use crate::rules::{Rule, RuleBuildError, ScanContext, Violation};

/// Flags `<img>` elements that are missing an `alt` attribute.
///
/// Walks the AST for `jsx_self_closing_element` and `jsx_opening_element`
/// nodes with tag name `img` and checks that at least one child
/// `jsx_attribute` has the name `alt`.
pub struct RequireImgAltRule {
    id: String,
    severity: Severity,
    message: String,
    suggest: Option<String>,
    glob: Option<String>,
}

impl RequireImgAltRule {
    pub fn new(config: &RuleConfig) -> Result<Self, RuleBuildError> {
        Ok(Self {
            id: config.id.clone(),
            severity: config.severity,
            message: config.message.clone(),
            suggest: config.suggest.clone(),
            glob: config.glob.clone(),
        })
    }
}

impl Rule for RequireImgAltRule {
    fn id(&self) -> &str {
        &self.id
    }

    fn severity(&self) -> Severity {
        self.severity
    }

    fn file_glob(&self) -> Option<&str> {
        self.glob.as_deref()
    }

    fn check_file(&self, ctx: &ScanContext) -> Vec<Violation> {
        let mut violations = Vec::new();
        let tree = match parse_file(ctx.file_path, ctx.content) {
            Some(t) => t,
            None => return violations,
        };
        let source = ctx.content.as_bytes();
        self.visit(tree.root_node(), source, ctx, &mut violations);
        violations
    }
}

impl RequireImgAltRule {
    fn visit(
        &self,
        node: tree_sitter::Node,
        source: &[u8],
        ctx: &ScanContext,
        violations: &mut Vec<Violation>,
    ) {
        let kind = node.kind();
        if kind == "jsx_self_closing_element" || kind == "jsx_opening_element" {
            if self.is_img_tag(&node, source) && !self.has_alt_attribute(&node, source) {
                let row = node.start_position().row;
                violations.push(Violation {
                    rule_id: self.id.clone(),
                    severity: self.severity,
                    file: ctx.file_path.to_path_buf(),
                    line: Some(row + 1),
                    column: Some(node.start_position().column + 1),
                    message: self.message.clone(),
                    suggest: self.suggest.clone(),
                    source_line: ctx.content.lines().nth(row).map(String::from),
                    fix: None,
                });
            }
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.visit(child, source, ctx, violations);
            }
        }
    }

    fn is_img_tag(&self, node: &tree_sitter::Node, source: &[u8]) -> bool {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "identifier" || child.kind() == "member_expression" {
                    if let Ok(name) = child.utf8_text(source) {
                        return name == "img";
                    }
                }
            }
        }
        false
    }

    fn has_alt_attribute(&self, node: &tree_sitter::Node, source: &[u8]) -> bool {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "jsx_attribute" {
                    if let Some(name_node) = child.child(0) {
                        if let Ok(name) = name_node.utf8_text(source) {
                            if name == "alt" {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn make_rule() -> RequireImgAltRule {
        RequireImgAltRule::new(&RuleConfig {
            id: "require-img-alt".into(),
            severity: Severity::Error,
            message: "img element must have an alt attribute".into(),
            suggest: Some("Add alt=\"description\" or alt=\"\" for decorative images".into()),
            glob: Some("**/*.{tsx,jsx}".into()),
            ..Default::default()
        })
        .unwrap()
    }

    fn check(rule: &RequireImgAltRule, content: &str) -> Vec<Violation> {
        let ctx = ScanContext {
            file_path: Path::new("test.tsx"),
            content,
        };
        rule.check_file(&ctx)
    }

    #[test]
    fn img_with_alt_no_violation() {
        let rule = make_rule();
        let violations = check(&rule, r#"function App() { return <img alt="photo" src="/a.jpg" />; }"#);
        assert!(violations.is_empty());
    }

    #[test]
    fn img_with_empty_alt_no_violation() {
        let rule = make_rule();
        let violations = check(&rule, r#"function App() { return <img alt="" src="/a.jpg" />; }"#);
        assert!(violations.is_empty());
    }

    #[test]
    fn img_without_alt_violation() {
        let rule = make_rule();
        let violations = check(&rule, r#"function App() { return <img src="/a.jpg" />; }"#);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule_id, "require-img-alt");
    }

    #[test]
    fn img_opening_element_without_alt() {
        let rule = make_rule();
        let violations = check(&rule, r#"function App() { return <img src="/a.jpg"></img>; }"#);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn non_img_element_ignored() {
        let rule = make_rule();
        let violations = check(&rule, r#"function App() { return <div className="foo" />; }"#);
        assert!(violations.is_empty());
    }

    #[test]
    fn uppercase_image_component_ignored() {
        let rule = make_rule();
        let violations = check(&rule, r#"function App() { return <Image src="/a.jpg" />; }"#);
        assert!(violations.is_empty());
    }

    #[test]
    fn multiple_imgs_mixed() {
        let rule = make_rule();
        let content = r#"function App() {
  return (
    <div>
      <img alt="ok" src="/a.jpg" />
      <img src="/b.jpg" />
      <img src="/c.jpg" />
    </div>
  );
}"#;
        let violations = check(&rule, content);
        assert_eq!(violations.len(), 2);
    }

    #[test]
    fn non_tsx_file_skipped() {
        let rule = make_rule();
        let ctx = ScanContext {
            file_path: Path::new("test.rs"),
            content: "fn main() {}",
        };
        assert!(rule.check_file(&ctx).is_empty());
    }
}
