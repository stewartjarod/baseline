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
}
