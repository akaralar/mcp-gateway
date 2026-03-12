//! Meta-tool MCP schema definitions.
//!
//! Pure constructors for the `Tool` values exposed by the gateway's meta-MCP
//! interface. Kept separate from the helper utilities so the schema definitions
//! can be updated without touching the routing/search logic.

use serde_json::json;

use crate::protocol::Tool;

// ============================================================================
// Traditional meta-tool definitions (used when Code Mode is OFF)
// ============================================================================

/// Build the base set of 4 meta-tools.
pub(crate) fn build_base_tools() -> Vec<Tool> {
    vec![
        Tool {
            name: "gateway_list_servers".to_string(),
            title: Some("List Servers".to_string()),
            description: Some("List all available MCP backend servers".to_string()),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
            output_schema: None,
            annotations: None,
        },
        Tool {
            name: "gateway_list_tools".to_string(),
            title: Some("List Tools".to_string()),
            description: Some(
                "List tools from a backend server. Omit server to list ALL tools across all backends."
                    .to_string(),
            ),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "server": {
                        "type": "string",
                        "description": "Name of backend server. Omit to list ALL tools across all backends."
                    }
                },
                "required": []
            }),
            output_schema: None,
            annotations: None,
        },
        Tool {
            name: "gateway_search_tools".to_string(),
            title: Some("Search Tools".to_string()),
            description: Some("Search for tools across all backends by keyword".to_string()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search keyword"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum results (default 10)",
                        "default": 10
                    }
                },
                "required": ["query"]
            }),
            output_schema: None,
            annotations: None,
        },
        Tool {
            name: "gateway_invoke".to_string(),
            title: Some("Invoke Tool".to_string()),
            description: Some("Invoke a tool on a specific backend".to_string()),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "server": {
                        "type": "string",
                        "description": "Backend server name"
                    },
                    "tool": {
                        "type": "string",
                        "description": "Tool name to invoke"
                    },
                    "arguments": {
                        "type": "object",
                        "description": "Tool arguments",
                        "default": {}
                    }
                },
                "required": ["server", "tool"]
            }),
            output_schema: None,
            annotations: None,
        },
    ]
}

/// Build the optional stats tool definition.
pub(crate) fn build_stats_tool() -> Tool {
    Tool {
        name: "gateway_get_stats".to_string(),
        title: Some("Get Gateway Statistics".to_string()),
        description: Some(
            "Get usage statistics including invocations, cache hits, \
             token savings, and top tools"
                .to_string(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {
                "price_per_million": {
                    "type": "number",
                    "description": "Token price per million for cost calculations (default 15.0 for Opus 4.6)",
                    "default": 15.0
                }
            },
            "required": []
        }),
        output_schema: None,
        annotations: None,
    }
}

/// Build the playbook runner meta-tool definition.
pub(crate) fn build_playbook_tool() -> Tool {
    Tool {
        name: "gateway_run_playbook".to_string(),
        title: Some("Run Playbook".to_string()),
        description: Some(
            "Execute a multi-step playbook (collapses multiple tool calls into one invocation)"
                .to_string(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Playbook name to execute"
                },
                "arguments": {
                    "type": "object",
                    "description": "Playbook input arguments",
                    "default": {}
                }
            },
            "required": ["name"]
        }),
        output_schema: None,
        annotations: None,
    }
}

/// Build the webhook status meta-tool definition.
pub(crate) fn build_webhook_status_tool() -> Tool {
    Tool {
        name: "gateway_webhook_status".to_string(),
        title: Some("Webhook Status".to_string()),
        description: Some(
            "List registered webhook endpoints and their delivery statistics \
             (received, delivered, failures, last event)"
                .to_string(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {},
            "required": []
        }),
        output_schema: None,
        annotations: None,
    }
}

/// Build the `gateway_kill_server` meta-tool definition.
pub(crate) fn build_kill_server_tool() -> Tool {
    Tool {
        name: "gateway_kill_server".to_string(),
        title: Some("Kill Server".to_string()),
        description: Some(
            "Immediately disable routing to a backend server (operator kill switch). \
             The server's tools remain visible in search/list but are marked as disabled."
                .to_string(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {
                "server": {
                    "type": "string",
                    "description": "Name of the backend server to disable"
                }
            },
            "required": ["server"]
        }),
        output_schema: None,
        annotations: None,
    }
}

/// Build the `gateway_revive_server` meta-tool definition.
pub(crate) fn build_revive_server_tool() -> Tool {
    Tool {
        name: "gateway_revive_server".to_string(),
        title: Some("Revive Server".to_string()),
        description: Some(
            "Re-enable routing to a previously disabled backend server. \
             Also resets the error budget so the server gets a clean slate."
                .to_string(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {
                "server": {
                    "type": "string",
                    "description": "Name of the backend server to re-enable"
                }
            },
            "required": ["server"]
        }),
        output_schema: None,
        annotations: None,
    }
}

/// Build the `gateway_set_profile` meta-tool definition.
pub(crate) fn build_set_profile_tool() -> Tool {
    Tool {
        name: "gateway_set_profile".to_string(),
        title: Some("Set Routing Profile".to_string()),
        description: Some(
            "Switch the active routing profile for this session. \
             A routing profile restricts which tools and backends are available."
                .to_string(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {
                "profile": {
                    "type": "string",
                    "description": "Name of the routing profile to activate (e.g. \"research\", \"coding\")"
                }
            },
            "required": ["profile"]
        }),
        output_schema: None,
        annotations: None,
    }
}

/// Build the `gateway_get_profile` meta-tool definition.
pub(crate) fn build_get_profile_tool() -> Tool {
    Tool {
        name: "gateway_get_profile".to_string(),
        title: Some("Get Routing Profile".to_string()),
        description: Some(
            "Show the active routing profile for this session and what it allows or denies."
                .to_string(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {},
            "required": []
        }),
        output_schema: None,
        annotations: None,
    }
}

/// Build the `gateway_list_disabled_capabilities` meta-tool definition.
///
/// Surfaces the per-capability error budget state, allowing operators
/// and LLM agents to see which capabilities are temporarily suspended and when
/// they will auto-recover.
pub(crate) fn build_list_disabled_capabilities_tool() -> Tool {
    Tool {
        name: "gateway_list_disabled_capabilities".to_string(),
        title: Some("List Disabled Capabilities".to_string()),
        description: Some(
            "List capabilities that have been automatically disabled due to a high error rate. \
             Each entry shows the backend, capability name, and how long it has been suspended. \
             Disabled capabilities auto-recover after the configured cooldown period (default 5 min). \
             Use gateway_revive_server to manually re-enable an entire backend immediately."
                .to_string(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {},
            "required": []
        }),
        output_schema: None,
        annotations: None,
    }
}

/// Build the `gateway_list_profiles` meta-tool definition.
pub(crate) fn build_list_profiles_tool() -> Tool {
    Tool {
        name: "gateway_list_profiles".to_string(),
        title: Some("List Tool Profiles".to_string()),
        description: Some(
            "List all available routing profiles with their descriptions. \
             Use gateway_set_profile to switch to a profile that narrows \
             the visible toolset to the current task (e.g. \"coding\", \"research\")."
                .to_string(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {},
            "required": []
        }),
        output_schema: None,
        annotations: None,
    }
}

/// Build the `gateway_reload_config` meta-tool definition.
pub(crate) fn build_reload_config_tool() -> Tool {
    Tool {
        name: "gateway_reload_config".to_string(),
        title: Some("Reload Config".to_string()),
        description: Some(
            "Trigger an immediate reload of config.yaml from disk without restarting the gateway. \
             Returns a summary of what changed (backends added/removed/modified, profile updates). \
             Server host/port changes require a restart and are reported but not applied."
                .to_string(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {},
            "required": []
        }),
        output_schema: None,
        annotations: None,
    }
}

/// Construct the full meta-tool list, optionally including stats, webhooks, playbooks, and reload.
pub(crate) fn build_meta_tools(
    stats_enabled: bool,
    webhooks_enabled: bool,
    reload_enabled: bool,
) -> Vec<Tool> {
    let mut tools = build_base_tools();
    if stats_enabled {
        tools.push(build_stats_tool());
    }
    if webhooks_enabled {
        tools.push(build_webhook_status_tool());
    }
    tools.push(build_playbook_tool());
    tools.push(build_kill_server_tool());
    tools.push(build_revive_server_tool());
    tools.push(build_set_profile_tool());
    tools.push(build_get_profile_tool());
    tools.push(build_list_disabled_capabilities_tool());
    tools.push(build_list_profiles_tool());
    if reload_enabled {
        tools.push(build_reload_config_tool());
    }
    tools
}

// ============================================================================
// Code Mode tool definitions (used when Code Mode is ON)
// ============================================================================

/// Build the `gateway_search` meta-tool for Code Mode.
///
/// In Code Mode this replaces the traditional tool list; agents search for
/// tools by keyword and then execute them by name via `gateway_execute`.
pub(crate) fn build_code_mode_search_tool() -> Tool {
    Tool {
        name: "gateway_search".to_string(),
        title: Some("Search Tools".to_string()),
        description: Some(
            "Search the gateway tool registry by name, description, or tag. \
             Returns matching tools with their full schemas. \
             Supports keyword queries, multi-word queries (any word matches), \
             and glob-style patterns (e.g. \"file_*\", \"*search*\")."
                .to_string(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query: keyword, multi-word, or glob pattern (e.g. \"file_*\", \"*search*\")"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of results to return (default 10)",
                    "default": 10
                },
                "include_schema": {
                    "type": "boolean",
                    "description": "Include the full input schema for each matching tool (default true)",
                    "default": true
                }
            },
            "required": ["query"]
        }),
        output_schema: None,
        annotations: None,
    }
}

/// Build the `gateway_execute` meta-tool for Code Mode.
///
/// Executes a single tool or a sequential chain of tool calls.
pub(crate) fn build_code_mode_execute_tool() -> Tool {
    Tool {
        name: "gateway_execute".to_string(),
        title: Some("Execute Tool".to_string()),
        description: Some(
            "Execute a gateway tool by name with arguments. \
             Use `tool` + `arguments` for a single call. \
             Use `chain` for sequential execution where each step can \
             reference the previous result."
                .to_string(),
        ),
        input_schema: json!({
            "type": "object",
            "properties": {
                "tool": {
                    "type": "string",
                    "description": "Tool name from gateway_search results (format: \"server:tool_name\" or bare tool name)"
                },
                "arguments": {
                    "type": "object",
                    "description": "Tool arguments matching its input schema",
                    "default": {}
                },
                "chain": {
                    "type": "array",
                    "description": "Optional: ordered list of tool calls to execute sequentially. Each element: {\"tool\": \"name\", \"arguments\": {...}}",
                    "items": {
                        "type": "object",
                        "properties": {
                            "tool": {"type": "string"},
                            "arguments": {"type": "object"}
                        },
                        "required": ["tool"]
                    }
                }
            }
        }),
        output_schema: None,
        annotations: None,
    }
}

/// Build the two-tool Code Mode tool list.
///
/// Returns `[gateway_search, gateway_execute]` — the complete tool surface
/// when Code Mode is active. Context consumption is near-zero because only
/// two small schemas are exposed instead of all 180+ backend tool schemas.
pub(crate) fn build_code_mode_tools() -> Vec<Tool> {
    vec![
        build_code_mode_search_tool(),
        build_code_mode_execute_tool(),
    ]
}
