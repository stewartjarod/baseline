pub mod max_component_size;
pub mod no_cascading_set_state;
pub mod no_nested_components;
pub mod prefer_use_reducer;
pub mod require_img_alt;

pub use max_component_size::MaxComponentSizeRule;
pub use no_cascading_set_state::NoCascadingSetStateRule;
pub use no_nested_components::NoNestedComponentsRule;
pub use prefer_use_reducer::PreferUseReducerRule;
pub use require_img_alt::RequireImgAltRule;

use std::path::Path;

/// Supported languages for AST parsing.
#[derive(Debug, Clone, Copy)]
pub enum Lang {
    Tsx,
    Typescript,
    Jsx,
    Javascript,
}

/// Detect language from file extension.
pub fn detect_language(path: &Path) -> Option<Lang> {
    match path.extension()?.to_str()? {
        "tsx" => Some(Lang::Tsx),
        "ts" => Some(Lang::Typescript),
        "jsx" => Some(Lang::Jsx),
        "js" => Some(Lang::Javascript),
        _ => None,
    }
}

/// Parse a file into a tree-sitter syntax tree.
pub fn parse_file(path: &Path, content: &str) -> Option<tree_sitter::Tree> {
    let lang = detect_language(path)?;
    let mut parser = tree_sitter::Parser::new();
    let ts_lang: tree_sitter::Language = match lang {
        Lang::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
        Lang::Typescript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        Lang::Jsx | Lang::Javascript => tree_sitter_javascript::LANGUAGE.into(),
    };
    parser.set_language(&ts_lang).ok()?;
    parser.parse(content, None)
}

/// Check if a tree-sitter node represents a React component declaration.
///
/// Recognizes PascalCase function declarations, arrow functions assigned to
/// PascalCase variables, and PascalCase class declarations.
pub fn is_component_node(node: &tree_sitter::Node, source: &[u8]) -> bool {
    match node.kind() {
        "function_declaration" => node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(source).ok())
            .map_or(false, starts_with_uppercase),
        "arrow_function" => node
            .parent()
            .filter(|p| p.kind() == "variable_declarator")
            .and_then(|p| p.child_by_field_name("name"))
            .and_then(|n| n.utf8_text(source).ok())
            .map_or(false, starts_with_uppercase),
        "class_declaration" => node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(source).ok())
            .map_or(false, starts_with_uppercase),
        _ => false,
    }
}

fn starts_with_uppercase(name: &str) -> bool {
    name.chars()
        .next()
        .map_or(false, |c| c.is_ascii_uppercase())
}

/// Count calls to a specific function within a node's subtree,
/// skipping nested component definitions.
pub fn count_calls_in_scope(
    node: tree_sitter::Node,
    source: &[u8],
    target_name: &str,
) -> usize {
    let mut count = 0;
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if is_component_node(&child, source) {
                continue;
            }
            if child.kind() == "call_expression" && is_call_to(&child, source, target_name) {
                count += 1;
            }
            count += count_calls_in_scope(child, source, target_name);
        }
    }
    count
}

/// Check if a call_expression node calls a function with the given name.
fn is_call_to(node: &tree_sitter::Node, source: &[u8], name: &str) -> bool {
    node.child_by_field_name("function")
        .filter(|f| f.kind() == "identifier")
        .and_then(|f| f.utf8_text(source).ok())
        .map_or(false, |n| n == name)
}

/// A fragment of a class string extracted from a JSX className/class attribute.
#[derive(Debug)]
pub struct ClassFragment {
    pub value: String,
    pub line: usize,
    pub col: usize,
}

/// Utility function names that accept class strings as arguments.
const CLASSNAME_UTILS: &[&str] = &["cn", "clsx", "classNames", "cva", "twMerge"];

/// Extract string fragments from a className attribute value node.
///
/// Recursively handles strings, jsx_expression, call_expression (cn/clsx/etc),
/// binary_expression, ternary_expression, template_string, arrays, and
/// parenthesized_expression.
pub fn extract_classname_strings(node: tree_sitter::Node, source: &[u8]) -> Vec<ClassFragment> {
    let mut fragments = Vec::new();
    match node.kind() {
        "string" => {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "string_fragment" {
                        if let Ok(text) = child.utf8_text(source) {
                            if !text.is_empty() {
                                fragments.push(ClassFragment {
                                    value: text.to_string(),
                                    line: child.start_position().row,
                                    col: child.start_position().column,
                                });
                            }
                        }
                    }
                }
            }
        }
        "jsx_expression" => {
            for i in 0..node.named_child_count() {
                if let Some(child) = node.named_child(i) {
                    fragments.extend(extract_classname_strings(child, source));
                }
            }
        }
        "call_expression" => {
            let is_util = node
                .child_by_field_name("function")
                .filter(|f| f.kind() == "identifier")
                .and_then(|f| f.utf8_text(source).ok())
                .map_or(false, |name| CLASSNAME_UTILS.contains(&name));
            if is_util {
                if let Some(args) = node.child_by_field_name("arguments") {
                    fragments.extend(extract_classname_strings(args, source));
                }
            }
        }
        "arguments" | "array" | "parenthesized_expression" => {
            for i in 0..node.named_child_count() {
                if let Some(child) = node.named_child(i) {
                    fragments.extend(extract_classname_strings(child, source));
                }
            }
        }
        "binary_expression" => {
            if let Some(left) = node.child_by_field_name("left") {
                fragments.extend(extract_classname_strings(left, source));
            }
            if let Some(right) = node.child_by_field_name("right") {
                fragments.extend(extract_classname_strings(right, source));
            }
        }
        "ternary_expression" => {
            if let Some(cons) = node.child_by_field_name("consequence") {
                fragments.extend(extract_classname_strings(cons, source));
            }
            if let Some(alt) = node.child_by_field_name("alternative") {
                fragments.extend(extract_classname_strings(alt, source));
            }
        }
        "template_string" => {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    match child.kind() {
                        "string_fragment" => {
                            if let Ok(text) = child.utf8_text(source) {
                                if !text.is_empty() {
                                    fragments.push(ClassFragment {
                                        value: text.to_string(),
                                        line: child.start_position().row,
                                        col: child.start_position().column,
                                    });
                                }
                            }
                        }
                        "template_substitution" => {
                            for j in 0..child.named_child_count() {
                                if let Some(sub) = child.named_child(j) {
                                    fragments.extend(extract_classname_strings(sub, source));
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        _ => {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    fragments.extend(extract_classname_strings(child, source));
                }
            }
        }
    }
    fragments
}

/// Walk the syntax tree and collect class strings from all className/class JSX attributes.
///
/// Returns `Vec<Vec<ClassFragment>>` — outer vec is per-attribute, inner vec is
/// all class string fragments from that attribute.
pub fn collect_class_attributes(tree: &tree_sitter::Tree, source: &[u8]) -> Vec<Vec<ClassFragment>> {
    let mut result = Vec::new();
    collect_class_attrs_walk(tree.root_node(), source, &mut result);
    result
}

fn collect_class_attrs_walk(
    node: tree_sitter::Node,
    source: &[u8],
    result: &mut Vec<Vec<ClassFragment>>,
) {
    if node.kind() == "jsx_attribute" {
        let is_class_attr = node
            .named_child(0)
            .and_then(|n| n.utf8_text(source).ok())
            .map_or(false, |name| name == "className" || name == "class");
        if is_class_attr {
            if let Some(value) = node.named_child(1) {
                let fragments = extract_classname_strings(value, source);
                if !fragments.is_empty() {
                    result.push(fragments);
                }
            }
            return;
        }
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            collect_class_attrs_walk(child, source, result);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn detect_tsx() {
        assert!(matches!(
            detect_language(Path::new("foo.tsx")),
            Some(Lang::Tsx)
        ));
    }

    #[test]
    fn detect_ts() {
        assert!(matches!(
            detect_language(Path::new("bar.ts")),
            Some(Lang::Typescript)
        ));
    }

    #[test]
    fn detect_jsx() {
        assert!(matches!(
            detect_language(Path::new("baz.jsx")),
            Some(Lang::Jsx)
        ));
    }

    #[test]
    fn detect_js() {
        assert!(matches!(
            detect_language(Path::new("qux.js")),
            Some(Lang::Javascript)
        ));
    }

    #[test]
    fn detect_unknown() {
        assert!(detect_language(Path::new("file.rs")).is_none());
    }

    #[test]
    fn parse_tsx_file() {
        let content = "function App() { return <div />; }";
        let tree = parse_file(Path::new("app.tsx"), content);
        assert!(tree.is_some());
    }

    #[test]
    fn parse_unknown_ext_returns_none() {
        let tree = parse_file(Path::new("app.rs"), "fn main() {}");
        assert!(tree.is_none());
    }

    #[test]
    fn component_function_declaration() {
        let content = "function MyComponent() { return <div />; }";
        let tree = parse_file(Path::new("a.tsx"), content).unwrap();
        let root = tree.root_node();
        let func = root.child(0).unwrap();
        assert!(is_component_node(&func, content.as_bytes()));
    }

    #[test]
    fn non_component_lowercase() {
        let content = "function helper() { return 1; }";
        let tree = parse_file(Path::new("a.tsx"), content).unwrap();
        let root = tree.root_node();
        let func = root.child(0).unwrap();
        assert!(!is_component_node(&func, content.as_bytes()));
    }

    #[test]
    fn component_arrow_function() {
        let content = "const MyComponent = () => { return <div />; };";
        let tree = parse_file(Path::new("a.tsx"), content).unwrap();
        let source = content.as_bytes();
        let root = tree.root_node();
        // Walk to find the arrow_function
        let mut found = false;
        visit_all(root, &mut |node| {
            if node.kind() == "arrow_function" && is_component_node(&node, source) {
                found = true;
            }
        });
        assert!(found);
    }

    fn visit_all<F: FnMut(tree_sitter::Node)>(node: tree_sitter::Node, f: &mut F) {
        f(node);
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                visit_all(child, f);
            }
        }
    }

    #[test]
    fn extract_simple_classname_string() {
        let content = r#"<div className="bg-white text-black" />"#;
        let tree = parse_file(Path::new("a.tsx"), content).unwrap();
        let attrs = collect_class_attributes(&tree, content.as_bytes());
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].len(), 1);
        assert_eq!(attrs[0][0].value, "bg-white text-black");
    }

    #[test]
    fn extract_cn_call_strings() {
        let content = r#"<div className={cn("bg-white", "text-black")} />"#;
        let tree = parse_file(Path::new("a.tsx"), content).unwrap();
        let attrs = collect_class_attributes(&tree, content.as_bytes());
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].len(), 2);
        assert_eq!(attrs[0][0].value, "bg-white");
        assert_eq!(attrs[0][1].value, "text-black");
    }

    #[test]
    fn extract_multiline_cn_call() {
        let content = "<div className={cn(\n  \"bg-white\",\n  active && \"text-black\",\n  \"p-4\"\n)} />";
        let tree = parse_file(Path::new("a.tsx"), content).unwrap();
        let attrs = collect_class_attributes(&tree, content.as_bytes());
        assert_eq!(attrs.len(), 1);
        let values: Vec<&str> = attrs[0].iter().map(|f| f.value.as_str()).collect();
        assert_eq!(values, vec!["bg-white", "text-black", "p-4"]);
    }

    #[test]
    fn extract_ternary_expression() {
        let content = r#"<div className={active ? "bg-white" : "bg-gray-100"} />"#;
        let tree = parse_file(Path::new("a.tsx"), content).unwrap();
        let attrs = collect_class_attributes(&tree, content.as_bytes());
        assert_eq!(attrs.len(), 1);
        let values: Vec<&str> = attrs[0].iter().map(|f| f.value.as_str()).collect();
        assert_eq!(values, vec!["bg-white", "bg-gray-100"]);
    }

    #[test]
    fn no_class_attrs_in_data_object() {
        let content = r#"const obj = { className: "bg-white" };"#;
        let tree = parse_file(Path::new("a.tsx"), content).unwrap();
        let attrs = collect_class_attributes(&tree, content.as_bytes());
        assert!(attrs.is_empty());
    }

    #[test]
    fn non_util_call_not_extracted() {
        let content = r#"<div className={getClass("special")} />"#;
        let tree = parse_file(Path::new("a.tsx"), content).unwrap();
        let attrs = collect_class_attributes(&tree, content.as_bytes());
        assert!(attrs.is_empty(), "non-utility calls should produce no fragments");
    }
}
