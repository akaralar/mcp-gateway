//! Secret injection proxy — credential brokering at the gateway level.
//!
//! Agents call `gateway_execute(tool="weather_forecast", args={...})` and the
//! gateway transparently injects credentials (API keys, OAuth tokens, basic auth)
//! before forwarding to the backend MCP server. Agents never see raw secrets.
//!
//! # Design
//!
//! Each backend can declare zero or more [`CredentialRule`]s. A rule specifies:
//! - Which tools it applies to (glob patterns, or `["*"]` for all)
//! - The credential type (API key, bearer token, basic auth, custom header)
//! - Where the credential value comes from (`{env.VAR}`, `{keychain.SERVICE}`, literal)
//! - Where to inject: into the tool arguments, HTTP headers, or query parameters
//!
//! At dispatch time, [`SecretInjector::inject`] resolves each matching rule and
//! merges the credential into the outbound request. Header overwrites are enforced:
//! injected values always replace agent-supplied values with the same key.
//!
//! # Security properties
//!
//! - Agents never receive raw credential values (injection happens after the agent call)
//! - Domain-scoped: credentials only flow to their intended backend
//! - Header overwrite protection: injected headers overwrite any agent-supplied duplicates
//! - Audit trail: every injection is logged with backend, tool, credential name, and timestamp

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::secrets::SecretResolver;

// ============================================================================
// Configuration types
// ============================================================================

/// A single credential rule for a backend.
///
/// # YAML example
///
/// ```yaml
/// backends:
///   weather_api:
///     http_url: "http://localhost:8080/mcp"
///     secrets:
///       - name: api_key
///         credential_type: api_key
///         value: "{env.WEATHER_API_KEY}"
///         inject_as: argument
///         inject_key: api_key
///         tools: ["*"]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRule {
    /// Human-readable name for audit logging (e.g., `"openai_api_key"`)
    pub name: String,

    /// Type of credential (informational, used for audit logs)
    #[serde(default = "default_credential_type")]
    pub credential_type: CredentialType,

    /// The credential value — supports `{env.VAR}`, `{keychain.SERVICE}`, or literal.
    ///
    /// Resolved at first use via [`SecretResolver`] and cached for the session.
    pub value: String,

    /// Where to inject the resolved credential
    #[serde(default)]
    pub inject_as: InjectTarget,

    /// The key name for injection:
    /// - For `argument`: the JSON key to set in the tool arguments object
    /// - For `header`: the HTTP header name (e.g., "Authorization")
    /// - For `query`: the query parameter name
    pub inject_key: String,

    /// Tool name patterns this rule applies to. Empty or `["*"]` means all tools.
    /// Supports glob patterns (e.g., `"create_*"`, `"weather_*"`).
    #[serde(default = "default_tools_match")]
    pub tools: Vec<String>,
}

/// Credential type for audit purposes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialType {
    /// API key (e.g., `X-API-Key: xxx`)
    ApiKey,
    /// Bearer token (e.g., `Authorization: Bearer xxx`)
    Bearer,
    /// Basic auth (e.g., `Authorization: Basic base64(user:pass)`)
    BasicAuth,
    /// Custom header or argument injection
    Custom,
}

/// Where to inject the credential in the outbound request.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InjectTarget {
    /// Inject into the tool call arguments JSON object
    #[default]
    Argument,
    /// Inject as an HTTP header on the backend transport
    Header,
    /// Inject as a query parameter (for HTTP backends)
    Query,
}

fn default_credential_type() -> CredentialType {
    CredentialType::ApiKey
}

fn default_tools_match() -> Vec<String> {
    vec!["*".to_string()]
}

// ============================================================================
// Injection result
// ============================================================================

/// The result of secret injection — contains the modified arguments and any
/// additional headers to set on the outbound transport.
#[derive(Debug, Clone)]
pub struct InjectionResult {
    /// Modified tool arguments with injected credentials
    pub arguments: serde_json::Value,
    /// Additional headers to inject on the outbound HTTP request.
    /// Empty for stdio backends (credentials go into arguments instead).
    pub headers: HashMap<String, String>,
    /// Number of credentials injected (for audit logging)
    pub injected_count: usize,
    /// Names of injected credentials (for audit logging)
    pub injected_names: Vec<String>,
}

// ============================================================================
// SecretInjector
// ============================================================================

/// Resolves and injects credentials into tool calls at dispatch time.
///
/// Holds a [`SecretResolver`] for resolving `{env.VAR}` and `{keychain.SERVICE}`
/// patterns, and the per-backend credential rules from config.
pub struct SecretInjector {
    /// Secret resolver (handles env vars, keychain, caching)
    resolver: Arc<SecretResolver>,
    /// Per-backend credential rules, keyed by backend name
    rules: HashMap<String, Vec<CredentialRule>>,
}

impl SecretInjector {
    /// Create a new secret injector with the given per-backend rules.
    #[must_use]
    pub fn new(rules: HashMap<String, Vec<CredentialRule>>) -> Self {
        Self {
            resolver: Arc::new(SecretResolver::new()),
            rules,
        }
    }

    /// Create an empty injector (no rules configured).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            resolver: Arc::new(SecretResolver::new()),
            rules: HashMap::new(),
        }
    }

    /// Returns `true` if any backend has credential rules configured.
    #[must_use]
    pub fn has_rules(&self) -> bool {
        !self.rules.is_empty()
    }

    /// Returns the number of credential rules for a given backend.
    #[must_use]
    pub fn rule_count(&self, backend: &str) -> usize {
        self.rules.get(backend).map_or(0, Vec::len)
    }

    /// Inject credentials for a tool call on a specific backend.
    ///
    /// Resolves all matching credential rules and returns an [`InjectionResult`]
    /// with the modified arguments and any additional headers.
    ///
    /// # Errors
    ///
    /// Returns an error if a credential value cannot be resolved (e.g., missing
    /// keychain entry or undefined environment variable referenced without default).
    pub fn inject(
        &self,
        backend: &str,
        tool: &str,
        arguments: serde_json::Value,
    ) -> crate::Result<InjectionResult> {
        let Some(rules) = self.rules.get(backend) else {
            return Ok(InjectionResult {
                arguments,
                headers: HashMap::new(),
                injected_count: 0,
                injected_names: Vec::new(),
            });
        };

        let mut args = arguments;
        let mut headers: HashMap<String, String> = HashMap::new();
        let mut injected_names: Vec<String> = Vec::new();

        for rule in rules {
            if !tool_matches_rule(tool, &rule.tools) {
                continue;
            }

            // Resolve the credential value
            let resolved_value = self.resolver.resolve(&rule.value).map_err(|e| {
                warn!(
                    backend = backend,
                    credential = %rule.name,
                    error = %e,
                    "Failed to resolve credential"
                );
                crate::Error::Config(format!(
                    "Failed to resolve credential '{}' for backend '{}': {e}",
                    rule.name, backend
                ))
            })?;

            // Skip injection if the resolved value is empty (missing env var without default)
            if resolved_value.is_empty() {
                warn!(
                    backend = backend,
                    credential = %rule.name,
                    "Credential resolved to empty value, skipping injection"
                );
                continue;
            }

            match rule.inject_as {
                InjectTarget::Argument => {
                    // Inject into the tool arguments JSON object
                    if let Some(obj) = args.as_object_mut() {
                        // Overwrite protection: always set, never let agent override
                        obj.insert(rule.inject_key.clone(), serde_json::Value::String(resolved_value));
                    }
                }
                InjectTarget::Header => {
                    // Inject as an HTTP header (overwrite any existing agent-supplied header)
                    headers.insert(rule.inject_key.clone(), resolved_value);
                }
                InjectTarget::Query => {
                    // Query parameters are injected as headers with a special prefix
                    // that the transport layer can recognize and append to the URL.
                    // For now, we inject as a special argument key.
                    if let Some(obj) = args.as_object_mut() {
                        obj.insert(
                            format!("__query_{}", rule.inject_key),
                            serde_json::Value::String(resolved_value),
                        );
                    }
                }
            }

            injected_names.push(rule.name.clone());

            // Audit log: credential injected
            info!(
                backend = backend,
                tool = tool,
                credential = %rule.name,
                credential_type = ?rule.credential_type,
                inject_as = ?rule.inject_as,
                inject_key = %rule.inject_key,
                "Secret injected"
            );
        }

        let injected_count = injected_names.len();
        if injected_count > 0 {
            debug!(
                backend = backend,
                tool = tool,
                count = injected_count,
                credentials = ?injected_names,
                "Secret injection complete"
            );
        }

        Ok(InjectionResult {
            arguments: args,
            headers,
            injected_count,
            injected_names,
        })
    }

    /// Update rules for a backend (for hot-reload support).
    pub fn update_rules(&mut self, backend: &str, rules: Vec<CredentialRule>) {
        if rules.is_empty() {
            self.rules.remove(backend);
        } else {
            self.rules.insert(backend.to_string(), rules);
        }
    }

    /// Clear the secret resolver cache (e.g., after credential rotation).
    pub fn clear_cache(&self) {
        self.resolver.clear_cache();
    }

    /// List configured backend names (for diagnostics).
    #[must_use]
    pub fn configured_backends(&self) -> Vec<&str> {
        self.rules.keys().map(String::as_str).collect()
    }

    /// Return a redacted summary of rules for a backend (safe for logs/diagnostics).
    #[must_use]
    pub fn redacted_rules(&self, backend: &str) -> Vec<RedactedRule> {
        self.rules.get(backend).map_or_else(Vec::new, |rules| {
            rules
                .iter()
                .map(|r| RedactedRule {
                    name: r.name.clone(),
                    credential_type: r.credential_type.clone(),
                    inject_as: r.inject_as.clone(),
                    inject_key: r.inject_key.clone(),
                    tools: r.tools.clone(),
                })
                .collect()
        })
    }
}

/// Redacted credential rule — safe for logging and diagnostics.
/// Does NOT contain the actual credential value.
#[derive(Debug, Clone, Serialize)]
pub struct RedactedRule {
    /// Credential name
    pub name: String,
    /// Credential type
    pub credential_type: CredentialType,
    /// Injection target
    pub inject_as: InjectTarget,
    /// Injection key
    pub inject_key: String,
    /// Tool patterns
    pub tools: Vec<String>,
}

// ============================================================================
// Tool matching
// ============================================================================

/// Check if a tool name matches any of the rule's tool patterns.
fn tool_matches_rule(tool: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return true;
    }

    for pattern in patterns {
        if pattern == "*" {
            return true;
        }
        if glob_match(pattern, tool) {
            return true;
        }
    }

    false
}

/// Simple glob matching (supports `*` as wildcard).
fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    // Exact match
    if pattern == value {
        return true;
    }

    // Prefix wildcard: `*_suffix` matches `anything_suffix`
    if let Some(suffix) = pattern.strip_prefix('*') {
        return value.ends_with(suffix);
    }

    // Suffix wildcard: `prefix_*` matches `prefix_anything`
    if let Some(prefix) = pattern.strip_suffix('*') {
        return value.starts_with(prefix);
    }

    // Contains wildcard: `pre*suf` matches `pre_anything_suf`
    if let Some(star_pos) = pattern.find('*') {
        let prefix = &pattern[..star_pos];
        let suffix = &pattern[star_pos + 1..];
        return value.starts_with(prefix) && value.ends_with(suffix) && value.len() >= prefix.len() + suffix.len();
    }

    false
}

// ============================================================================
// Builder from config
// ============================================================================

impl SecretInjector {
    /// Build a `SecretInjector` from the parsed gateway config.
    ///
    /// Extracts `secrets` fields from each backend config and aggregates them.
    #[must_use]
    pub fn from_backend_configs(
        backends: &HashMap<String, crate::config::BackendConfig>,
    ) -> Self {
        let mut rules: HashMap<String, Vec<CredentialRule>> = HashMap::new();

        for (name, config) in backends {
            if !config.secrets.is_empty() {
                rules.insert(name.clone(), config.secrets.clone());
                info!(
                    backend = %name,
                    credentials = config.secrets.len(),
                    "Secret injection rules loaded"
                );
            }
        }

        if rules.is_empty() {
            Self::empty()
        } else {
            let total: usize = rules.values().map(Vec::len).sum();
            info!(
                backends = rules.len(),
                total_rules = total,
                "Secret injection proxy initialized"
            );
            Self::new(rules)
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(unsafe_code)] // Tests use set_var/remove_var which are unsafe in edition 2024
mod tests {
    use super::*;
    use serde_json::json;

    // ── glob matching ────────────────────────────────────────────────────

    #[test]
    fn glob_match_exact() {
        assert!(glob_match("get_weather", "get_weather"));
        assert!(!glob_match("get_weather", "get_forecast"));
    }

    #[test]
    fn glob_match_star() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
    }

    #[test]
    fn glob_match_prefix_wildcard() {
        assert!(glob_match("get_*", "get_weather"));
        assert!(glob_match("get_*", "get_forecast"));
        assert!(!glob_match("get_*", "set_weather"));
    }

    #[test]
    fn glob_match_suffix_wildcard() {
        assert!(glob_match("*_weather", "get_weather"));
        assert!(glob_match("*_weather", "set_weather"));
        assert!(!glob_match("*_weather", "get_forecast"));
    }

    #[test]
    fn glob_match_contains_wildcard() {
        assert!(glob_match("get_*_v2", "get_weather_v2"));
        assert!(!glob_match("get_*_v2", "get_weather_v3"));
    }

    // ── tool_matches_rule ─────────────────────────────────────────────────

    #[test]
    fn matches_rule_empty_patterns_matches_all() {
        assert!(tool_matches_rule("any_tool", &[]));
    }

    #[test]
    fn matches_rule_wildcard_matches_all() {
        assert!(tool_matches_rule("any_tool", &["*".to_string()]));
    }

    #[test]
    fn matches_rule_specific_pattern() {
        assert!(tool_matches_rule(
            "weather_forecast",
            &["weather_*".to_string()]
        ));
        assert!(!tool_matches_rule(
            "search_web",
            &["weather_*".to_string()]
        ));
    }

    // ── inject ────────────────────────────────────────────────────────────

    #[test]
    fn inject_no_rules_returns_unchanged() {
        let injector = SecretInjector::empty();
        let args = json!({"city": "Helsinki"});
        let result = injector.inject("weather", "get_forecast", args.clone()).unwrap();
        assert_eq!(result.arguments, args);
        assert_eq!(result.injected_count, 0);
        assert!(result.headers.is_empty());
    }

    #[test]
    fn inject_argument_type() {
        // Set a test env var
        unsafe { std::env::set_var("TEST_SECRET_KEY_88", "sk-test-12345") };

        let rules = HashMap::from([(
            "weather".to_string(),
            vec![CredentialRule {
                name: "api_key".to_string(),
                credential_type: CredentialType::ApiKey,
                value: "{env.TEST_SECRET_KEY_88}".to_string(),
                inject_as: InjectTarget::Argument,
                inject_key: "api_key".to_string(),
                tools: vec!["*".to_string()],
            }],
        )]);

        let injector = SecretInjector::new(rules);
        let args = json!({"city": "Helsinki"});
        let result = injector.inject("weather", "get_forecast", args).unwrap();

        assert_eq!(result.arguments["city"], "Helsinki");
        assert_eq!(result.arguments["api_key"], "sk-test-12345");
        assert_eq!(result.injected_count, 1);
        assert_eq!(result.injected_names, vec!["api_key"]);

        unsafe { std::env::remove_var("TEST_SECRET_KEY_88") };
    }

    #[test]
    fn inject_header_type() {
        unsafe { std::env::set_var("TEST_BEARER_TOKEN_88", "bearer-abc-123") };

        let rules = HashMap::from([(
            "linear".to_string(),
            vec![CredentialRule {
                name: "linear_token".to_string(),
                credential_type: CredentialType::Bearer,
                value: "Bearer {env.TEST_BEARER_TOKEN_88}".to_string(),
                inject_as: InjectTarget::Header,
                inject_key: "Authorization".to_string(),
                tools: vec!["*".to_string()],
            }],
        )]);

        let injector = SecretInjector::new(rules);
        let args = json!({"title": "Bug report"});
        let result = injector.inject("linear", "create_issue", args).unwrap();

        // Arguments unchanged (injection goes to headers)
        assert_eq!(result.arguments["title"], "Bug report");
        assert!(!result.arguments.as_object().unwrap().contains_key("Authorization"));

        // Header injected
        assert_eq!(
            result.headers.get("Authorization").unwrap(),
            "Bearer bearer-abc-123"
        );
        assert_eq!(result.injected_count, 1);

        unsafe { std::env::remove_var("TEST_BEARER_TOKEN_88") };
    }

    #[test]
    fn inject_tool_pattern_filtering() {
        unsafe { std::env::set_var("TEST_WRITE_KEY_88", "write-secret") };

        let rules = HashMap::from([(
            "api".to_string(),
            vec![CredentialRule {
                name: "write_key".to_string(),
                credential_type: CredentialType::ApiKey,
                value: "{env.TEST_WRITE_KEY_88}".to_string(),
                inject_as: InjectTarget::Argument,
                inject_key: "auth_token".to_string(),
                tools: vec!["create_*".to_string(), "update_*".to_string()],
            }],
        )]);

        let injector = SecretInjector::new(rules);

        // Matching tool: should inject
        let result = injector
            .inject("api", "create_item", json!({}))
            .unwrap();
        assert_eq!(result.injected_count, 1);
        assert_eq!(result.arguments["auth_token"], "write-secret");

        // Non-matching tool: should NOT inject
        let result = injector
            .inject("api", "list_items", json!({}))
            .unwrap();
        assert_eq!(result.injected_count, 0);
        assert!(result.arguments.as_object().unwrap().is_empty());

        unsafe { std::env::remove_var("TEST_WRITE_KEY_88") };
    }

    #[test]
    fn inject_multiple_rules() {
        unsafe { std::env::set_var("TEST_KEY_A_88", "key-a") };
        unsafe { std::env::set_var("TEST_KEY_B_88", "key-b") };

        let rules = HashMap::from([(
            "multi".to_string(),
            vec![
                CredentialRule {
                    name: "key_a".to_string(),
                    credential_type: CredentialType::ApiKey,
                    value: "{env.TEST_KEY_A_88}".to_string(),
                    inject_as: InjectTarget::Argument,
                    inject_key: "key_a".to_string(),
                    tools: vec!["*".to_string()],
                },
                CredentialRule {
                    name: "key_b".to_string(),
                    credential_type: CredentialType::Bearer,
                    value: "Bearer {env.TEST_KEY_B_88}".to_string(),
                    inject_as: InjectTarget::Header,
                    inject_key: "Authorization".to_string(),
                    tools: vec!["*".to_string()],
                },
            ],
        )]);

        let injector = SecretInjector::new(rules);
        let result = injector
            .inject("multi", "some_tool", json!({"data": 42}))
            .unwrap();

        assert_eq!(result.injected_count, 2);
        assert_eq!(result.arguments["key_a"], "key-a");
        assert_eq!(result.arguments["data"], 42);
        assert_eq!(
            result.headers.get("Authorization").unwrap(),
            "Bearer key-b"
        );

        unsafe { std::env::remove_var("TEST_KEY_A_88") };
        unsafe { std::env::remove_var("TEST_KEY_B_88") };
    }

    #[test]
    fn inject_overwrite_protection() {
        // Agent tries to set their own api_key — injector should overwrite it
        unsafe { std::env::set_var("TEST_REAL_KEY_88", "real-secret") };

        let rules = HashMap::from([(
            "backend".to_string(),
            vec![CredentialRule {
                name: "api_key".to_string(),
                credential_type: CredentialType::ApiKey,
                value: "{env.TEST_REAL_KEY_88}".to_string(),
                inject_as: InjectTarget::Argument,
                inject_key: "api_key".to_string(),
                tools: vec!["*".to_string()],
            }],
        )]);

        let injector = SecretInjector::new(rules);
        // Agent supplies a fake api_key
        let args = json!({"api_key": "agent-supplied-fake", "query": "test"});
        let result = injector.inject("backend", "search", args).unwrap();

        // Gateway-injected value must win
        assert_eq!(result.arguments["api_key"], "real-secret");
        assert_eq!(result.arguments["query"], "test");

        unsafe { std::env::remove_var("TEST_REAL_KEY_88") };
    }

    #[test]
    fn inject_empty_resolved_value_skipped() {
        // Missing env var resolves to empty string — should be skipped
        let rules = HashMap::from([(
            "backend".to_string(),
            vec![CredentialRule {
                name: "missing_key".to_string(),
                credential_type: CredentialType::ApiKey,
                value: "{env.NONEXISTENT_VAR_SECRET_INJ_88}".to_string(),
                inject_as: InjectTarget::Argument,
                inject_key: "api_key".to_string(),
                tools: vec!["*".to_string()],
            }],
        )]);

        let injector = SecretInjector::new(rules);
        let args = json!({"query": "test"});
        let result = injector.inject("backend", "search", args).unwrap();

        assert_eq!(result.injected_count, 0);
        assert!(!result.arguments.as_object().unwrap().contains_key("api_key"));
    }

    #[test]
    fn inject_wrong_backend_returns_unchanged() {
        let rules = HashMap::from([(
            "weather".to_string(),
            vec![CredentialRule {
                name: "key".to_string(),
                credential_type: CredentialType::ApiKey,
                value: "secret".to_string(),
                inject_as: InjectTarget::Argument,
                inject_key: "api_key".to_string(),
                tools: vec!["*".to_string()],
            }],
        )]);

        let injector = SecretInjector::new(rules);
        let args = json!({"query": "test"});
        let result = injector.inject("other_backend", "search", args.clone()).unwrap();

        assert_eq!(result.arguments, args);
        assert_eq!(result.injected_count, 0);
    }

    // ── from_backend_configs ──────────────────────────────────────────────

    #[test]
    fn from_backend_configs_empty() {
        let backends: HashMap<String, crate::config::BackendConfig> = HashMap::new();
        let injector = SecretInjector::from_backend_configs(&backends);
        assert!(!injector.has_rules());
    }

    #[test]
    fn from_backend_configs_with_rules() {
        let mut backend = crate::config::BackendConfig::default();
        backend.secrets = vec![CredentialRule {
            name: "test_key".to_string(),
            credential_type: CredentialType::ApiKey,
            value: "test-value".to_string(),
            inject_as: InjectTarget::Argument,
            inject_key: "api_key".to_string(),
            tools: vec!["*".to_string()],
        }];

        let backends = HashMap::from([("test_backend".to_string(), backend)]);
        let injector = SecretInjector::from_backend_configs(&backends);

        assert!(injector.has_rules());
        assert_eq!(injector.rule_count("test_backend"), 1);
        assert_eq!(injector.rule_count("nonexistent"), 0);
    }

    // ── redacted_rules ────────────────────────────────────────────────────

    #[test]
    fn redacted_rules_does_not_contain_value() {
        let rules = HashMap::from([(
            "backend".to_string(),
            vec![CredentialRule {
                name: "secret".to_string(),
                credential_type: CredentialType::ApiKey,
                value: "super-secret-value".to_string(),
                inject_as: InjectTarget::Argument,
                inject_key: "key".to_string(),
                tools: vec!["*".to_string()],
            }],
        )]);

        let injector = SecretInjector::new(rules);
        let redacted = injector.redacted_rules("backend");

        assert_eq!(redacted.len(), 1);
        assert_eq!(redacted[0].name, "secret");
        // The redacted struct should NOT have a `value` field
        let json = serde_json::to_string(&redacted[0]).unwrap();
        assert!(!json.contains("super-secret-value"));
    }

    // ── update_rules ──────────────────────────────────────────────────────

    #[test]
    fn update_rules_adds_and_removes() {
        let mut injector = SecretInjector::empty();
        assert!(!injector.has_rules());

        injector.update_rules(
            "new_backend",
            vec![CredentialRule {
                name: "key".to_string(),
                credential_type: CredentialType::ApiKey,
                value: "val".to_string(),
                inject_as: InjectTarget::Argument,
                inject_key: "k".to_string(),
                tools: vec![],
            }],
        );
        assert!(injector.has_rules());
        assert_eq!(injector.rule_count("new_backend"), 1);

        // Remove by passing empty rules
        injector.update_rules("new_backend", vec![]);
        assert!(!injector.has_rules());
    }

    // ── configured_backends ───────────────────────────────────────────────

    #[test]
    fn configured_backends_lists_names() {
        let rules = HashMap::from([
            ("alpha".to_string(), vec![]),
            ("beta".to_string(), vec![]),
        ]);
        let injector = SecretInjector::new(rules);
        let mut backends = injector.configured_backends();
        backends.sort();
        assert_eq!(backends, vec!["alpha", "beta"]);
    }

    // ── serialization roundtrip ──────────────────────────────────────────

    #[test]
    fn credential_rule_yaml_roundtrip() {
        let yaml = r#"
name: weather_key
credential_type: api_key
value: "{env.WEATHER_KEY}"
inject_as: argument
inject_key: api_key
tools: ["get_*", "search_*"]
"#;

        let rule: CredentialRule = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(rule.name, "weather_key");
        assert_eq!(rule.credential_type, CredentialType::ApiKey);
        assert_eq!(rule.inject_as, InjectTarget::Argument);
        assert_eq!(rule.tools, vec!["get_*", "search_*"]);

        // Roundtrip
        let serialized = serde_yaml::to_string(&rule).unwrap();
        let deserialized: CredentialRule = serde_yaml::from_str(&serialized).unwrap();
        assert_eq!(deserialized.name, "weather_key");
    }

    #[test]
    fn credential_rule_default_values() {
        let yaml = r#"
name: simple
value: "literal-secret"
inject_key: token
"#;

        let rule: CredentialRule = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(rule.credential_type, CredentialType::ApiKey); // default
        assert_eq!(rule.inject_as, InjectTarget::Argument); // default
        assert_eq!(rule.tools, vec!["*"]); // default
    }

    // ── query injection ───────────────────────────────────────────────────

    #[test]
    fn inject_query_type() {
        let rules = HashMap::from([(
            "api".to_string(),
            vec![CredentialRule {
                name: "api_key".to_string(),
                credential_type: CredentialType::ApiKey,
                value: "query-key-123".to_string(),
                inject_as: InjectTarget::Query,
                inject_key: "apikey".to_string(),
                tools: vec!["*".to_string()],
            }],
        )]);

        let injector = SecretInjector::new(rules);
        let result = injector.inject("api", "search", json!({})).unwrap();

        // Query params injected as __query_ prefixed argument
        assert_eq!(result.arguments["__query_apikey"], "query-key-123");
        assert_eq!(result.injected_count, 1);
    }

    // ── literal value (no env/keychain) ───────────────────────────────────

    #[test]
    fn inject_literal_value() {
        let rules = HashMap::from([(
            "backend".to_string(),
            vec![CredentialRule {
                name: "static_key".to_string(),
                credential_type: CredentialType::Custom,
                value: "literal-api-key-abc123".to_string(),
                inject_as: InjectTarget::Argument,
                inject_key: "token".to_string(),
                tools: vec!["*".to_string()],
            }],
        )]);

        let injector = SecretInjector::new(rules);
        let result = injector.inject("backend", "test", json!({})).unwrap();
        assert_eq!(result.arguments["token"], "literal-api-key-abc123");
    }
}
