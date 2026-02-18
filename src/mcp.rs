use crate::cli::toml_config::TomlConfig;
use crate::presets;
use crate::scan;
use serde_json::json;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

/// Run a simple MCP-compatible server over stdio.
///
/// Reads JSON-RPC requests from stdin, processes them, and writes
/// JSON-RPC responses to stdout. Supports the MCP protocol for
/// tool discovery and execution.
pub fn run_mcp_server(config_path: &Path) {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    // Read line-delimited JSON-RPC messages
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };

        if line.trim().is_empty() {
            continue;
        }

        let request: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let error_response = json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": { "code": -32700, "message": format!("Parse error: {}", e) }
                });
                let _ = writeln!(stdout, "{}", error_response);
                let _ = stdout.flush();
                continue;
            }
        };

        let id = request.get("id").cloned();
        let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = request.get("params").cloned().unwrap_or(json!({}));

        let response = match method {
            "initialize" => handle_initialize(id.clone()),
            "tools/list" => handle_tools_list(id.clone()),
            "tools/call" => handle_tools_call(id.clone(), &params, config_path),
            "notifications/initialized" | "notifications/cancelled" => continue,
            _ => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32601, "message": format!("Unknown method: {}", method) }
            }),
        };

        let _ = writeln!(stdout, "{}", response);
        let _ = stdout.flush();
    }
}

fn handle_initialize(id: Option<serde_json::Value>) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "baseline",
                "version": env!("CARGO_PKG_VERSION")
            }
        }
    })
}

fn handle_tools_list(id: Option<serde_json::Value>) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "tools": [
                {
                    "name": "baseline_scan",
                    "description": "Scan files for rule violations. Returns structured violations with fix suggestions.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "paths": {
                                "type": "array",
                                "items": { "type": "string" },
                                "description": "File or directory paths to scan"
                            },
                            "content": {
                                "type": "string",
                                "description": "Inline file content to scan (alternative to paths)"
                            },
                            "filename": {
                                "type": "string",
                                "description": "Virtual filename for glob matching when using content"
                            }
                        }
                    }
                },
                {
                    "name": "baseline_list_rules",
                    "description": "List all configured rules and their descriptions.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {}
                    }
                }
            ]
        }
    })
}

fn handle_tools_call(
    id: Option<serde_json::Value>,
    params: &serde_json::Value,
    config_path: &Path,
) -> serde_json::Value {
    let tool_name = params
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("");

    let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

    match tool_name {
        "baseline_scan" => handle_scan(&id, &arguments, config_path),
        "baseline_list_rules" => handle_list_rules(&id, config_path),
        _ => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32602, "message": format!("Unknown tool: {}", tool_name) }
        }),
    }
}

fn handle_scan(
    id: &Option<serde_json::Value>,
    arguments: &serde_json::Value,
    config_path: &Path,
) -> serde_json::Value {
    // Check for inline content mode
    if let Some(content) = arguments.get("content").and_then(|c| c.as_str()) {
        let filename = arguments
            .get("filename")
            .and_then(|f| f.as_str())
            .unwrap_or("stdin.tsx");

        match scan::run_scan_stdin(config_path, content, filename) {
            Ok(result) => {
                let violations = format_violations_json(&result);
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "content": [{ "type": "text", "text": violations.to_string() }]
                    }
                })
            }
            Err(e) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "content": [{ "type": "text", "text": format!("Error: {}", e) }],
                    "isError": true
                }
            }),
        }
    } else {
        // File paths mode
        let paths: Vec<PathBuf> = arguments
            .get("paths")
            .and_then(|p| p.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(PathBuf::from))
                    .collect()
            })
            .unwrap_or_else(|| vec![PathBuf::from(".")]);

        match scan::run_scan(config_path, &paths) {
            Ok(result) => {
                let violations = format_violations_json(&result);
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "content": [{ "type": "text", "text": violations.to_string() }]
                    }
                })
            }
            Err(e) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "content": [{ "type": "text", "text": format!("Error: {}", e) }],
                    "isError": true
                }
            }),
        }
    }
}

fn handle_list_rules(
    id: &Option<serde_json::Value>,
    config_path: &Path,
) -> serde_json::Value {
    let config_text = match std::fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(e) => {
            return json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "content": [{ "type": "text", "text": format!("Error reading config: {}", e) }],
                    "isError": true
                }
            });
        }
    };

    let toml_config: TomlConfig = match toml::from_str(&config_text) {
        Ok(c) => c,
        Err(e) => {
            return json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "content": [{ "type": "text", "text": format!("Error parsing config: {}", e) }],
                    "isError": true
                }
            });
        }
    };

    let mut resolved = match presets::resolve_rules(&toml_config.baseline.extends, &toml_config.rule) {
        Ok(r) => r,
        Err(e) => {
            return json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "content": [{ "type": "text", "text": format!("Error resolving rules: {}", e) }],
                    "isError": true
                }
            });
        }
    };

    match presets::resolve_scoped_rules(&toml_config.baseline.scoped, &toml_config.rule) {
        Ok(scoped) => resolved.extend(scoped),
        Err(e) => {
            return json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "content": [{ "type": "text", "text": format!("Error resolving scoped rules: {}", e) }],
                    "isError": true
                }
            });
        }
    }

    let rules: Vec<serde_json::Value> = resolved
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "type": r.rule_type,
                "severity": r.severity,
                "glob": r.glob,
                "message": r.message,
            })
        })
        .collect();

    let text = serde_json::to_string_pretty(&json!({ "rules": rules })).unwrap();

    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [{ "type": "text", "text": text }]
        }
    })
}

fn format_violations_json(result: &scan::ScanResult) -> serde_json::Value {
    use crate::config::Severity;

    let violations: Vec<serde_json::Value> = result
        .violations
        .iter()
        .map(|v| {
            let mut obj = json!({
                "rule_id": v.rule_id,
                "severity": match v.severity {
                    Severity::Error => "error",
                    Severity::Warning => "warning",
                },
                "file": v.file.display().to_string(),
                "line": v.line,
                "column": v.column,
                "message": v.message,
                "suggest": v.suggest,
            });

            if let Some(ref fix) = v.fix {
                obj["fix"] = json!({ "old": fix.old, "new": fix.new });
            }

            obj
        })
        .collect();

    json!({
        "violations": violations,
        "summary": {
            "total": result.violations.len(),
            "errors": result.violations.iter().filter(|v| v.severity == Severity::Error).count(),
            "warnings": result.violations.iter().filter(|v| v.severity == Severity::Warning).count(),
            "files_scanned": result.files_scanned,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Severity;
    use crate::rules::Violation;
    use std::collections::HashMap;
    use std::path::PathBuf;

    #[test]
    fn initialize_returns_protocol_version() {
        let resp = handle_initialize(Some(json!(1)));
        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 1);
        assert_eq!(resp["result"]["protocolVersion"], "2024-11-05");
        assert_eq!(resp["result"]["serverInfo"]["name"], "baseline");
    }

    #[test]
    fn tools_list_returns_both_tools() {
        let resp = handle_tools_list(Some(json!(2)));
        assert_eq!(resp["jsonrpc"], "2.0");
        let tools = resp["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0]["name"], "baseline_scan");
        assert_eq!(tools[1]["name"], "baseline_list_rules");
    }

    #[test]
    fn format_violations_empty() {
        let result = scan::ScanResult {
            violations: vec![],
            files_scanned: 3,
            rules_loaded: 2,
            ratchet_counts: HashMap::new(),
            changed_files_count: None,
            base_ref: None,
        };
        let json = format_violations_json(&result);
        assert_eq!(json["summary"]["total"], 0);
        assert_eq!(json["summary"]["files_scanned"], 3);
        assert!(json["violations"].as_array().unwrap().is_empty());
    }

    #[test]
    fn format_violations_with_fix() {
        let result = scan::ScanResult {
            violations: vec![Violation {
                rule_id: "test-rule".into(),
                severity: Severity::Error,
                file: PathBuf::from("test.tsx"),
                line: Some(5),
                column: Some(10),
                message: "bad class".into(),
                suggest: Some("use good class".into()),
                source_line: None,
                fix: Some(crate::rules::Fix {
                    old: "bg-red-500".into(),
                    new: "bg-destructive".into(),
                }),
            }],
            files_scanned: 1,
            rules_loaded: 1,
            ratchet_counts: HashMap::new(),
            changed_files_count: None,
            base_ref: None,
        };
        let json = format_violations_json(&result);
        assert_eq!(json["summary"]["total"], 1);
        assert_eq!(json["summary"]["errors"], 1);
        let v = &json["violations"][0];
        assert_eq!(v["rule_id"], "test-rule");
        assert_eq!(v["fix"]["old"], "bg-red-500");
        assert_eq!(v["fix"]["new"], "bg-destructive");
    }

    #[test]
    fn format_violations_counts_severities() {
        let result = scan::ScanResult {
            violations: vec![
                Violation {
                    rule_id: "r1".into(),
                    severity: Severity::Error,
                    file: PathBuf::from("a.ts"),
                    line: Some(1),
                    column: None,
                    message: "err".into(),
                    suggest: None,
                    source_line: None,
                    fix: None,
                },
                Violation {
                    rule_id: "r2".into(),
                    severity: Severity::Warning,
                    file: PathBuf::from("b.ts"),
                    line: Some(2),
                    column: None,
                    message: "warn".into(),
                    suggest: None,
                    source_line: None,
                    fix: None,
                },
            ],
            files_scanned: 2,
            rules_loaded: 2,
            ratchet_counts: HashMap::new(),
            changed_files_count: None,
            base_ref: None,
        };
        let json = format_violations_json(&result);
        assert_eq!(json["summary"]["errors"], 1);
        assert_eq!(json["summary"]["warnings"], 1);
        assert_eq!(json["summary"]["total"], 2);
    }

    #[test]
    fn unknown_tool_returns_error() {
        let resp = handle_tools_call(
            Some(json!(3)),
            &json!({ "name": "nonexistent_tool", "arguments": {} }),
            std::path::Path::new("baseline.toml"),
        );
        assert!(resp["error"].is_object());
        assert_eq!(resp["error"]["code"], -32602);
    }
}
