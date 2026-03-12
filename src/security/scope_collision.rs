//! Scope collision detection for MCP gateway tool namespaces.
//!
//! When multiple upstream MCP servers register tools with identical names,
//! the gateway must detect and report the collision to prevent ambiguous routing.
//!
//! # Attack Vector
//!
//! A malicious backend could register a tool with the same name as a legitimate
//! tool on another backend, causing the gateway to route calls to the wrong
//! (attacker-controlled) server.
//!
//! # Reference
//!
//! - [Doyensec MCP AuthN/Z research](https://blog.doyensec.com/2026/03/05/mcp-nightmare.html)
//! - OWASP MCP Top 10: Scope Namespace Collision

use std::collections::HashMap;

use tracing::warn;

use crate::protocol::Tool;

/// Shell metacharacters that are rejected in tool names.
const DANGEROUS_TOOL_NAME_CHARS: &[char] = &[
    '`', '$', '|', ';', '&', '>', '<', '!', '{', '}', '(', ')', '[', ']',
    '\'', '"', '\n', '\r',
];

/// A detected collision between tool names across backends.
#[derive(Debug, Clone)]
pub struct ScopeCollision {
    /// The tool name that collides.
    pub tool_name: String,
    /// All backends that expose a tool with this name.
    pub backends: Vec<String>,
}

/// Detect tool name collisions across multiple backends.
///
/// Takes a slice of `(backend_name, tools)` pairs and returns all
/// tool names that appear in more than one backend.
///
/// # Example
///
/// ```rust
/// use mcp_gateway::security::scope_collision::detect_collisions;
/// use mcp_gateway::protocol::Tool;
/// use serde_json::json;
///
/// let tools_a = vec![Tool {
///     name: "search".to_string(),
///     title: None,
///     description: None,
///     input_schema: json!({}),
///     output_schema: None,
///     annotations: None,
/// }];
/// let tools_b = vec![Tool {
///     name: "search".to_string(),
///     title: None,
///     description: None,
///     input_schema: json!({}),
///     output_schema: None,
///     annotations: None,
/// }];
///
/// let backends = vec![
///     ("backend_a".to_string(), tools_a),
///     ("backend_b".to_string(), tools_b),
/// ];
///
/// let collisions = detect_collisions(&backends);
/// assert_eq!(collisions.len(), 1);
/// assert_eq!(collisions[0].tool_name, "search");
/// ```
pub fn detect_collisions(backends: &[(String, Vec<Tool>)]) -> Vec<ScopeCollision> {
    // Map: tool_name -> list of backends exposing that tool
    let mut tool_owners: HashMap<&str, Vec<&str>> = HashMap::new();

    for (backend_name, tools) in backends {
        for tool in tools {
            tool_owners
                .entry(tool.name.as_str())
                .or_default()
                .push(backend_name.as_str());
        }
    }

    let mut collisions: Vec<ScopeCollision> = tool_owners
        .into_iter()
        .filter(|(_, owners)| owners.len() > 1)
        .map(|(name, owners)| {
            let collision = ScopeCollision {
                tool_name: name.to_string(),
                backends: owners.into_iter().map(String::from).collect(),
            };
            warn!(
                tool = collision.tool_name.as_str(),
                backends = ?collision.backends,
                "SECURITY: Tool name collision detected across backends"
            );
            collision
        })
        .collect();

    // Sort for deterministic output
    collisions.sort_by(|a, b| a.tool_name.cmp(&b.tool_name));
    collisions
}

/// Validate that a tool name follows safe naming conventions.
///
/// Rejects names containing:
/// - Path traversal sequences (`..`, `/`, `\`)
/// - Control characters
/// - Shell metacharacters that could enable injection
/// - Names exceeding 128 characters
/// - Empty names
///
/// # Errors
///
/// Returns `Err(reason)` if the name is invalid.
pub fn validate_tool_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Tool name must not be empty".to_string());
    }

    if name.len() > 128 {
        return Err(format!(
            "Tool name exceeds maximum length of 128 characters (got {})",
            name.len()
        ));
    }

    // Path traversal
    if name.contains("..") || name.contains('/') || name.contains('\\') {
        return Err(format!(
            "Tool name '{name}' contains path traversal characters"
        ));
    }

    // Null bytes
    if name.contains('\0') {
        return Err(format!("Tool name '{name}' contains null bytes"));
    }

    // Control characters (ASCII 0x00-0x1F except common whitespace, plus DEL 0x7F)
    if name.chars().any(|c| {
        let code = c as u32;
        (code <= 0x1F && code != 0x09 && code != 0x0A && code != 0x0D) || code == 0x7F
    }) {
        return Err(format!(
            "Tool name '{name}' contains control characters"
        ));
    }

    // Shell metacharacters that could enable injection
    for &ch in DANGEROUS_TOOL_NAME_CHARS {
        if name.contains(ch) {
            return Err(format!(
                "Tool name '{name}' contains potentially dangerous character '{ch}'"
            ));
        }
    }

    // Must start with alphanumeric or underscore
    if let Some(first) = name.chars().next() {
        if !first.is_alphanumeric() && first != '_' {
            return Err(format!(
                "Tool name '{name}' must start with alphanumeric or underscore"
            ));
        }
    }

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_tool(name: &str) -> Tool {
        Tool {
            name: name.to_string(),
            title: None,
            description: None,
            input_schema: json!({}),
            output_schema: None,
            annotations: None,
        }
    }

    // -- detect_collisions --

    #[test]
    fn no_collisions_when_names_are_unique() {
        let backends = vec![
            ("a".to_string(), vec![make_tool("tool_a")]),
            ("b".to_string(), vec![make_tool("tool_b")]),
        ];
        let collisions = detect_collisions(&backends);
        assert!(collisions.is_empty());
    }

    #[test]
    fn detects_collision_between_two_backends() {
        let backends = vec![
            ("a".to_string(), vec![make_tool("search")]),
            ("b".to_string(), vec![make_tool("search")]),
        ];
        let collisions = detect_collisions(&backends);
        assert_eq!(collisions.len(), 1);
        assert_eq!(collisions[0].tool_name, "search");
        assert_eq!(collisions[0].backends.len(), 2);
    }

    #[test]
    fn detects_collision_across_three_backends() {
        let backends = vec![
            ("a".to_string(), vec![make_tool("read")]),
            ("b".to_string(), vec![make_tool("read")]),
            ("c".to_string(), vec![make_tool("read")]),
        ];
        let collisions = detect_collisions(&backends);
        assert_eq!(collisions.len(), 1);
        assert_eq!(collisions[0].backends.len(), 3);
    }

    #[test]
    fn multiple_collisions_detected() {
        let backends = vec![
            ("a".to_string(), vec![make_tool("search"), make_tool("read")]),
            ("b".to_string(), vec![make_tool("search"), make_tool("read")]),
        ];
        let collisions = detect_collisions(&backends);
        assert_eq!(collisions.len(), 2);
        assert_eq!(collisions[0].tool_name, "read");
        assert_eq!(collisions[1].tool_name, "search");
    }

    #[test]
    fn empty_backends_no_collisions() {
        let backends: Vec<(String, Vec<Tool>)> = vec![];
        let collisions = detect_collisions(&backends);
        assert!(collisions.is_empty());
    }

    #[test]
    fn single_backend_no_collisions() {
        let backends = vec![(
            "a".to_string(),
            vec![make_tool("t1"), make_tool("t2")],
        )];
        let collisions = detect_collisions(&backends);
        assert!(collisions.is_empty());
    }

    // -- validate_tool_name --

    #[test]
    fn valid_tool_names() {
        assert!(validate_tool_name("search_web").is_ok());
        assert!(validate_tool_name("read_file").is_ok());
        assert!(validate_tool_name("gateway_invoke").is_ok());
        assert!(validate_tool_name("_private_tool").is_ok());
        assert!(validate_tool_name("tool123").is_ok());
        assert!(validate_tool_name("my-tool").is_ok());
        assert!(validate_tool_name("ns.tool").is_ok());
    }

    #[test]
    fn rejects_empty_name() {
        assert!(validate_tool_name("").is_err());
    }

    #[test]
    fn rejects_path_traversal() {
        assert!(validate_tool_name("../../../etc/passwd").is_err());
        assert!(validate_tool_name("tool/subpath").is_err());
        assert!(validate_tool_name("tool\\name").is_err());
        assert!(validate_tool_name("..").is_err());
    }

    #[test]
    fn rejects_shell_metacharacters() {
        assert!(validate_tool_name("tool`whoami`").is_err());
        assert!(validate_tool_name("tool$(id)").is_err());
        assert!(validate_tool_name("tool|cat /etc/passwd").is_err());
        assert!(validate_tool_name("tool;rm -rf /").is_err());
        assert!(validate_tool_name("tool&bg").is_err());
        assert!(validate_tool_name("tool>output").is_err());
    }

    #[test]
    fn rejects_null_bytes() {
        assert!(validate_tool_name("tool\0name").is_err());
    }

    #[test]
    fn rejects_control_characters() {
        assert!(validate_tool_name("tool\x07name").is_err());
        assert!(validate_tool_name("tool\x1Bname").is_err());
    }

    #[test]
    fn rejects_too_long_name() {
        let long_name = "a".repeat(129);
        assert!(validate_tool_name(&long_name).is_err());
        let ok_name = "a".repeat(128);
        assert!(validate_tool_name(&ok_name).is_ok());
    }

    #[test]
    fn rejects_names_starting_with_special() {
        assert!(validate_tool_name("-tool").is_err());
        assert!(validate_tool_name(".tool").is_err());
        assert!(validate_tool_name(" tool").is_err());
    }
}
