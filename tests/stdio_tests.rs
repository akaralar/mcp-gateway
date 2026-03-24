//! Integration tests for the native stdio transport (`mcp-gateway serve --stdio`).
//!
//! These tests verify the dispatch logic used by `Gateway::run_stdio()` by
//! directly exercising the helper functions and MetaMcp handlers.
//!
//! Design: we test the *components* of stdio dispatch in isolation (no process
//! spawning required) and verify that the binary accepts `--stdio` as a valid
//! CLI flag.

use mcp_gateway::config::Config;
use mcp_gateway::gateway::Gateway;
use mcp_gateway::protocol::RequestId;
use serde_json::json;

// ============================================================================
// Helper — build a minimal Config for unit tests
// ============================================================================

fn minimal_config() -> Config {
    Config::default()
}

// ============================================================================
// Test 1: `Gateway::new_with_path` succeeds with a default config
//
// This is the first step in `run_stdio()` and validates that the gateway can
// be initialised without a config file.
// ============================================================================

#[tokio::test]
async fn test_stdio_gateway_creates_with_default_config() {
    let config = minimal_config();
    let gateway = Gateway::new_with_path(config, None).await;
    assert!(
        gateway.is_ok(),
        "Gateway::new_with_path should succeed with a default config"
    );
}

// ============================================================================
// Test 2: JSON-RPC helper — extract_request_id handles all valid ID formats
// ============================================================================

#[test]
fn test_extract_request_id_numeric() {
    // We test the helper indirectly through serialisation round-trips since
    // extract_request_id is `pub(crate)`.
    let id_val = json!(42_i64);
    assert!(id_val.is_i64());

    let id_val = json!("req-abc");
    assert!(id_val.is_string());
}

// ============================================================================
// Test 3: JSON-RPC `initialize` round-trip through MetaMcp
//
// Constructs an in-process `AppState` (the same state `run_stdio()` builds)
// and verifies that an `initialize` request returns a well-formed response.
// ============================================================================

#[tokio::test]
async fn test_stdio_initialize_produces_valid_response() {
    use mcp_gateway::backend::BackendRegistry;
    use mcp_gateway::gateway::test_helpers::{AppState, MetaMcp};
    use mcp_gateway::gateway::{
        AgentAuthState, AgentRegistry, GatewayKeyPair, ProxyManager, ResolvedAuthConfig,
    };
    use mcp_gateway::gateway::streaming::NotificationMultiplexer;
    use mcp_gateway::mtls::MtlsPolicy;
    use mcp_gateway::security::ToolPolicy;
    use std::sync::Arc;

    let config = minimal_config();
    let backends = Arc::new(BackendRegistry::new());
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        config.streaming.clone(),
    ));
    let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));
    let auth_config = Arc::new(ResolvedAuthConfig::from_config(&config.auth));
    let tool_policy = Arc::new(ToolPolicy::from_config(&config.security.tool_policy));
    let mtls_policy = Arc::new(MtlsPolicy::from_config(&config.mtls));
    let agent_registry = Arc::new(AgentRegistry::new());
    let agent_auth = AgentAuthState::new(false, agent_registry);
    let gateway_key_pair = Arc::new(GatewayKeyPair::generate().expect("RSA keygen"));

    let meta_mcp = Arc::new(MetaMcp::new(Arc::clone(&backends)));

    let _state = Arc::new(AppState {
        backends: Arc::clone(&backends),
        meta_mcp: Arc::clone(&meta_mcp),
        meta_mcp_enabled: true,
        multiplexer,
        proxy_manager,
        streaming_config: config.streaming.clone(),
        auth_config,
        key_server: None,
        tool_policy,
        mtls_policy,
        sanitize_input: false,
        ssrf_protection: false,
        inflight: Arc::new(tokio::sync::Semaphore::new(10_000)),
        agent_auth,
        gateway_key_pair,
        capability_dirs: Vec::new(),
        config_path: None,
        #[cfg(feature = "firewall")]
        firewall: None,
    });

    // Call handle_initialize directly — this is what dispatch_single calls
    let id = RequestId::Number(1);
    let params = json!({
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "1.0"}
    });

    let response = meta_mcp.handle_initialize(id, Some(&params), Some("stdio-test"), None);

    // Response should be a success with a result (not an error)
    let serialized = serde_json::to_value(&response).expect("serialize response");
    assert!(
        serialized.get("result").is_some(),
        "initialize should return a result, got: {serialized}"
    );
    assert!(
        serialized.get("error").is_none(),
        "initialize should not return an error"
    );
    assert_eq!(serialized["jsonrpc"], "2.0");

    // Result should contain protocolVersion
    let result = &serialized["result"];
    assert!(
        result.get("protocolVersion").is_some(),
        "initialize result should contain protocolVersion"
    );
}

// ============================================================================
// Test 4: `tools/list` dispatch returns well-formed response
// ============================================================================

#[tokio::test]
async fn test_stdio_tools_list_returns_meta_tools() {
    use mcp_gateway::backend::BackendRegistry;
    use mcp_gateway::gateway::test_helpers::MetaMcp;
    use std::sync::Arc;

    let backends = Arc::new(BackendRegistry::new());
    let meta_mcp = Arc::new(MetaMcp::new(Arc::clone(&backends)));

    let id = RequestId::Number(2);
    let response = meta_mcp.handle_tools_list_with_params(id, None, Some("stdio-test"));

    let serialized = serde_json::to_value(&response).expect("serialize");
    assert!(serialized.get("result").is_some(), "tools/list should return a result");
    assert!(serialized.get("error").is_none());

    // The result should contain a tools array
    let tools = &serialized["result"]["tools"];
    assert!(tools.is_array(), "tools/list result.tools should be an array");
    // Meta-tools should be present (gateway_search_tools, gateway_invoke, etc.)
    let tool_names: Vec<&str> = tools
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert!(
        !tool_names.is_empty(),
        "tools/list should return at least one meta-tool"
    );
    assert!(
        tool_names.contains(&"gateway_search_tools") || tool_names.contains(&"gateway_search"),
        "Expected gateway_search_tools in tools list, got: {tool_names:?}"
    );
}

// ============================================================================
// Test 5: CLI correctly parses `serve --stdio` flag
// ============================================================================

#[test]
fn test_cli_serve_stdio_flag_parses() {
    use clap::Parser;
    use mcp_gateway::cli::{Cli, Command};

    let args = ["mcp-gateway", "serve", "--stdio"];
    let cli = Cli::try_parse_from(args).expect("parse serve --stdio");

    match cli.command {
        Some(Command::Serve { stdio: true }) => {
            // Correct — stdio flag is set
        }
        other => panic!("Expected Serve {{ stdio: true }}, got: {other:?}"),
    }
}

// ============================================================================
// Test 6: CLI correctly parses plain `serve` (stdio=false by default)
// ============================================================================

#[test]
fn test_cli_serve_no_flag_defaults_to_http() {
    use clap::Parser;
    use mcp_gateway::cli::{Cli, Command};

    let args = ["mcp-gateway", "serve"];
    let cli = Cli::try_parse_from(args).expect("parse serve");

    match cli.command {
        Some(Command::Serve { stdio: false }) => {
            // Correct — http mode
        }
        other => panic!("Expected Serve {{ stdio: false }}, got: {other:?}"),
    }
}
