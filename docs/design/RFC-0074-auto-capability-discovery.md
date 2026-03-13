# RFC-0074: Auto-Capability Discovery from URL

**Status**: Draft
**Author**: Mikko Parkkola
**Date**: 2026-03-13
**LOC Budget**: ~600-700 (OpenAPI/Swagger only; GraphQL deferred to Phase 2)
**Feature Gate**: `#[cfg(feature = "discovery")]` (default-enabled)

---

## Problem

The gateway's value proposition is "Any REST API -> MCP tool -- no code." Today that requires either (a) manual YAML writing (~30 sec per endpoint, error-prone), or (b) `cap import spec.yaml` from a local OpenAPI file. But the user must first find and download the spec. Most production APIs publish discoverable specifications at well-known paths. The gap between "I have a URL" and "I have working capabilities" should be zero commands, not three.

No MCP gateway or API integration tool today offers recursive, multi-format API discovery from a bare URL. Postman requires manual import. Swagger Inspector requires browser-based interaction. Neither produces MCP-compatible output.

## Goals

1. `mcp-gateway cap import-url <URL>` generates capability YAML files from a bare API base URL
2. Support OpenAPI 3.x, Swagger 2.0, and heuristic HTML doc parsing. GraphQL support is Phase 2 (deferred — GraphQL-to-capability conversion needs its own design for POST body templates).
3. Reuse existing `OpenApiConverter` for the heavy lifting -- discovery is the NEW part
4. SSRF protection via existing `security/ssrf.rs` on every fetched URL
5. Quality scoring so users get useful endpoints, not noise
6. Deduplication against existing capabilities in the local directory

## Non-Goals

- Headless browser rendering (no chromiumoxide dependency)
- Proprietary API format support (WSDL, gRPC reflection)
- Ongoing monitoring of spec changes (that is a watcher concern)
- Generating auth credentials (discovery suggests auth type, user provides creds)

## Architecture

### Data Flow

```
  User: mcp-gateway cap import-url https://api.stripe.com

  +-----------+     +------------------+     +------------------+
  |  URL      |---->|  DiscoveryChain  |---->|  SpecNormalizer  |
  |  (bare)   |     |  (probe order)   |     |  (to OpenAPI)    |
  +-----------+     +------------------+     +------------------+
                            |                        |
                    [SSRF check]              [OpenApiConverter]
                    [Auth probe]                     |
                    [Redirect follow]                v
                            |                +------------------+
                            v                |  QualityScorer   |
                    +------------------+     +------------------+
                    |  SpecDetector    |              |
                    |  (format sniff)  |              v
                    +------------------+     +------------------+
                                             |  DeduplicateFilter|
                                             +------------------+
                                                     |
                                                     v
                                             +------------------+
                                             |  GeneratedCapability[]  |
                                             |  -> write YAML files    |
                                             +------------------+
```

### Discovery Chain (probed in parallel, first success wins by priority order)

| Step | Probe URL | Format |
|------|-----------|--------|
| 1 | `<URL>/.well-known/openapi.json` | OpenAPI 3.x |
| 2 | `<URL>/openapi.json` | OpenAPI 3.x |
| 3 | `<URL>/openapi.yaml` | OpenAPI 3.x |
| 4 | `<URL>/swagger.json` | Swagger 2.0 |
| 5 | `<URL>/swagger.yaml` | Swagger 2.0 |
| 6 | `<URL>/api-docs` | Swagger UI JSON |
| 7 | ~~`<URL>/graphql` (introspection POST)~~ | ~~GraphQL~~ *(Phase 2 — deferred)* |
| 8 | HTML at `<URL>` -- scan for spec links | Link extraction |
| 9 | `<URL>/docs`, `/api/docs`, `/api/v1` | Common patterns |
| 10 | `<URL>/robots.txt` -- extract API paths | Heuristic |

### Module Layout

```
src/commands/discover.rs       -- CLI handler (~80 LOC)
src/capability/discovery/
    mod.rs                     -- DiscoveryEngine, public API (~60 LOC)
    chain.rs                   -- DiscoveryChain, probe ordering (~120 LOC)
    detector.rs                -- SpecDetector: format sniffing (~80 LOC)
    graphql.rs                 -- GraphQL introspection -> OpenAPI (Phase 2 — deferred)
    html_scanner.rs            -- HTML link/meta extraction (~80 LOC)
    quality.rs                 -- QualityScorer (~60 LOC)
    dedup.rs                   -- DeduplicateFilter (~40 LOC)
```

Total: ~620 LOC (within budget). GraphQL converter (~100 LOC) deferred to Phase 2.

## Rust Type Definitions

```rust
// src/capability/discovery/mod.rs

use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use crate::security::ssrf::validate_url_not_ssrf;

/// Result of discovering an API specification from a URL.
#[derive(Debug, Clone)]
pub struct DiscoveryResult {
    /// The URL where the spec was found.
    pub spec_url: String,
    /// Detected specification format.
    pub format: SpecFormat,
    /// Raw spec content (JSON or YAML string).
    pub spec_content: String,
    /// How the spec was discovered (for logging/UX).
    pub discovery_method: DiscoveryMethod,
}

/// Detected API specification format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpecFormat {
    OpenApi3,
    Swagger2,
    GraphQL,
}

/// How the spec was found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoveryMethod {
    /// Found at a well-known path (e.g., /openapi.json).
    WellKnownPath(String),
    /// Found via an HTML page link or meta tag.
    HtmlLink(String),
    /// GraphQL introspection query succeeded.
    GraphQLIntrospection,
    /// Found in robots.txt API path hints.
    RobotsTxt,
}

/// Options controlling the discovery process.
#[derive(Debug, Clone)]
pub struct DiscoveryOptions {
    /// Name prefix for generated capabilities (e.g., "stripe").
    pub prefix: Option<String>,
    /// Output directory for generated YAML files.
    pub output_dir: PathBuf,
    /// Authorization header value (e.g., "Bearer sk_test_xxx").
    pub auth: Option<String>,
    /// Maximum number of endpoints to generate (default: 50).
    pub max_endpoints: usize,
    /// If true, print what would be generated without writing files.
    pub dry_run: bool,
    /// If true, prompt user to confirm each endpoint (not for v1).
    pub interactive: bool,
    /// Existing capability names to skip (dedup).
    pub existing_names: Vec<String>,
    /// Request timeout for spec fetching.
    pub timeout: std::time::Duration,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            prefix: None,
            output_dir: PathBuf::from("capabilities"),
            auth: None,
            max_endpoints: 50,
            dry_run: false,
            interactive: false,
            existing_names: Vec::new(),
            timeout: std::time::Duration::from_secs(30),
        }
    }
}

/// Quality score for a discovered endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct EndpointQuality {
    /// Capability name.
    pub name: String,
    /// Score 0-100. Higher = more useful to an LLM.
    pub score: u32,
    /// Reasons contributing to the score.
    pub reasons: Vec<String>,
}

/// The main discovery engine.
pub struct DiscoveryEngine {
    client: reqwest::Client,
    options: DiscoveryOptions,
}

impl DiscoveryEngine {
    pub fn new(options: DiscoveryOptions) -> Self {
        let client = reqwest::Client::builder()
            .timeout(options.timeout)
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                if validate_url_not_ssrf(attempt.url().as_str()).is_err() {
                    attempt.stop()
                } else if attempt.previous().len() >= 5 {
                    attempt.stop()
                } else {
                    attempt.follow()
                }
            }))
            .user_agent("mcp-gateway/2.5 capability-discovery")
            .build()
            .unwrap_or_default();
        Self { client, options }
    }

    /// Discover API specifications from a base URL.
    ///
    /// Returns generated capabilities ready to write, sorted by quality
    /// score descending. Capabilities exceeding `max_endpoints` are
    /// dropped from the tail.
    pub async fn discover(
        &self,
        base_url: &str,
    ) -> crate::Result<Vec<crate::capability::GeneratedCapability>> {
        // 1. SSRF check on base_url
        // 2. Run DiscoveryChain probes
        // 3. On first spec found: detect format, normalize to OpenAPI
        // 4. Pipe through OpenApiConverter (existing)
        // 5. Score, dedup, truncate
        todo!()
    }
}
```

```rust
// src/capability/discovery/chain.rs

use reqwest::Client;
use crate::security::ssrf::validate_url_not_ssrf;

/// Ordered chain of spec probe strategies.
pub struct DiscoveryChain<'a> {
    client: &'a Client,
    auth: Option<&'a str>,
}

/// A single probe strategy.
struct Probe {
    /// Suffix to append to the base URL.
    path: &'static str,
    /// Expected format if this probe succeeds.
    format: super::SpecFormat,
    /// HTTP method (GET for most, POST for GraphQL).
    method: ProbeMethod,
}

enum ProbeMethod {
    Get,
    /// POST with the given body (GraphQL introspection).
    Post(&'static str),
}

/// GraphQL introspection query (minimal, gets types + fields).
const GRAPHQL_INTROSPECTION: &str = r#"{"query":"{ __schema { queryType { name } mutationType { name } types { name kind fields { name description args { name description type { name kind ofType { name kind } } } } } } }"}"#;

impl<'a> DiscoveryChain<'a> {
    pub fn new(client: &'a Client, auth: Option<&'a str>) -> Self {
        Self { client, auth }
    }

    /// Probe all well-known paths in parallel, take first success.
    ///
    /// All probes are launched concurrently via `futures::future::join_all`,
    /// reducing total discovery latency from up to N * RTT (sequential) to
    /// a single network RTT (~200-500ms). Every URL is SSRF-checked before
    /// fetching.
    pub async fn probe(&self, base_url: &str) -> Option<super::DiscoveryResult> {
        let probes = Self::probes();

        // Launch all probes in parallel
        let probe_futures: Vec<_> = probes.iter()
            .map(|probe| self.probe_single(base_url, probe))
            .collect();
        let results = futures::future::join_all(probe_futures).await;

        // Take first success (preserving probe priority order)
        results.into_iter().find_map(|r| r)
    }

    /// Probe a single well-known path. Returns None on failure.
    async fn probe_single(
        &self,
        base_url: &str,
        probe: &Probe,
    ) -> Option<super::DiscoveryResult> {
        let url = format!("{}{}", base_url.trim_end_matches('/'), probe.path);

        // SSRF gate: reject private/reserved IPs
        if validate_url_not_ssrf(&url).is_err() {
            return None;
        }

        // Build request
        let mut req = match probe.method {
            ProbeMethod::Get => self.client.get(&url),
            ProbeMethod::Post(body) => self.client.post(&url)
                .header("Content-Type", "application/json")
                .body(body),
        };

        if let Some(auth) = self.auth {
            req = req.header("Authorization", auth);
        }

        match req.send().await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(body) = resp.text().await {
                    if Self::looks_like_spec(&body, probe.format) {
                        return Some(super::DiscoveryResult {
                            spec_url: url,
                            format: probe.format,
                            spec_content: body,
                            discovery_method: super::DiscoveryMethod::WellKnownPath(
                                probe.path.to_string(),
                            ),
                        });
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn probes() -> Vec<Probe> {
        vec![
            Probe { path: "/.well-known/openapi.json", format: super::SpecFormat::OpenApi3, method: ProbeMethod::Get },
            Probe { path: "/openapi.json", format: super::SpecFormat::OpenApi3, method: ProbeMethod::Get },
            Probe { path: "/openapi.yaml", format: super::SpecFormat::OpenApi3, method: ProbeMethod::Get },
            Probe { path: "/swagger.json", format: super::SpecFormat::Swagger2, method: ProbeMethod::Get },
            Probe { path: "/swagger.yaml", format: super::SpecFormat::Swagger2, method: ProbeMethod::Get },
            Probe { path: "/api-docs", format: super::SpecFormat::OpenApi3, method: ProbeMethod::Get },
            Probe { path: "/graphql", format: super::SpecFormat::GraphQL, method: ProbeMethod::Post(GRAPHQL_INTROSPECTION) },
            Probe { path: "/docs", format: super::SpecFormat::OpenApi3, method: ProbeMethod::Get },
            Probe { path: "/api/docs", format: super::SpecFormat::OpenApi3, method: ProbeMethod::Get },
            Probe { path: "/v1", format: super::SpecFormat::OpenApi3, method: ProbeMethod::Get },
            Probe { path: "/api/v1", format: super::SpecFormat::OpenApi3, method: ProbeMethod::Get },
        ]
    }

    /// Quick content sniff: does this body look like the expected format?
    fn looks_like_spec(body: &str, format: super::SpecFormat) -> bool {
        match format {
            super::SpecFormat::OpenApi3 => {
                body.contains("\"openapi\"") || body.contains("openapi:")
            }
            super::SpecFormat::Swagger2 => {
                body.contains("\"swagger\"") || body.contains("swagger:")
            }
            super::SpecFormat::GraphQL => {
                body.contains("__schema") && body.contains("queryType")
            }
        }
    }
}
```

```rust
// src/capability/discovery/detector.rs

use serde_json::Value;

/// Detects the exact spec format and version from content.
pub struct SpecDetector;

impl SpecDetector {
    /// Detect format from raw content string.
    pub fn detect(content: &str) -> Option<super::SpecFormat> {
        // Try JSON parse first
        if let Ok(json) = serde_json::from_str::<Value>(content) {
            return Self::detect_json(&json);
        }
        // Try YAML parse
        if let Ok(json) = serde_yaml::from_str::<Value>(content) {
            return Self::detect_json(&json);
        }
        // GraphQL introspection result
        if content.contains("__schema") {
            return Some(super::SpecFormat::GraphQL);
        }
        None
    }

    fn detect_json(json: &Value) -> Option<super::SpecFormat> {
        if json.get("openapi").is_some() {
            Some(super::SpecFormat::OpenApi3)
        } else if json.get("swagger").is_some() {
            Some(super::SpecFormat::Swagger2)
        } else if json.pointer("/data/__schema").is_some() {
            Some(super::SpecFormat::GraphQL)
        } else {
            None
        }
    }
}
```

```rust
// src/capability/discovery/graphql.rs

use serde_json::Value;
use std::fmt::Write;

/// Convert a GraphQL introspection result to OpenAPI 3.0 YAML.
///
/// Strategy: each Query field becomes a GET endpoint, each Mutation
/// field becomes a POST endpoint. Arguments become query/body params.
pub fn graphql_to_openapi(introspection: &Value, base_url: &str) -> crate::Result<String> {
    let schema = introspection
        .pointer("/data/__schema")
        .or_else(|| introspection.get("__schema"))
        .ok_or_else(|| crate::Error::Config("No __schema in introspection result".into()))?;

    let query_type_name = schema
        .pointer("/queryType/name")
        .and_then(Value::as_str)
        .unwrap_or("Query");

    let mutation_type_name = schema
        .pointer("/mutationType/name")
        .and_then(Value::as_str);

    let types = schema.get("types").and_then(Value::as_array)
        .ok_or_else(|| crate::Error::Config("No types in schema".into()))?;

    let mut yaml = String::new();
    writeln!(yaml, "openapi: '3.0.0'").ok();
    writeln!(yaml, "info:").ok();
    writeln!(yaml, "  title: GraphQL API").ok();
    writeln!(yaml, "  version: '1.0'").ok();
    writeln!(yaml, "servers:").ok();
    writeln!(yaml, "  - url: {base_url}").ok();
    writeln!(yaml, "paths:").ok();

    for type_def in types {
        let name = type_def.get("name").and_then(Value::as_str).unwrap_or("");
        let fields = type_def.get("fields").and_then(Value::as_array);

        let is_query = name == query_type_name;
        let is_mutation = mutation_type_name.is_some_and(|m| name == m);

        if !is_query && !is_mutation {
            continue;
        }

        if let Some(fields) = fields {
            for field in fields {
                let field_name = field.get("name").and_then(Value::as_str).unwrap_or("unknown");
                let desc = field.get("description").and_then(Value::as_str).unwrap_or("");
                let method = if is_query { "get" } else { "post" };

                writeln!(yaml, "  /graphql#{field_name}:").ok();
                writeln!(yaml, "    {method}:").ok();
                writeln!(yaml, "      operationId: {field_name}").ok();
                writeln!(yaml, "      summary: \"{desc}\"").ok();
                writeln!(yaml, "      parameters: []").ok();
                writeln!(yaml, "      responses:").ok();
                writeln!(yaml, "        '200':").ok();
                writeln!(yaml, "          description: Success").ok();

                // Add args as parameters
                if let Some(args) = field.get("args").and_then(Value::as_array) {
                    if !args.is_empty() {
                        // Rewrite parameters section
                        // (simplified: full impl would build proper schema)
                    }
                }
            }
        }
    }

    Ok(yaml)
}
```

```rust
// src/capability/discovery/html_scanner.rs

/// Scan an HTML page for links to API specifications.
///
/// Looks for:
/// 1. <link rel="api-description" href="...">
/// 2. Swagger UI / Redoc / Stoplight markers with embedded spec URLs
/// 3. <a> tags pointing to .json/.yaml files with "api"/"swagger"/"openapi" in the URL
pub fn extract_spec_links(html: &str, base_url: &str) -> Vec<String> {
    let mut links = Vec::new();

    // Pattern 1: <link rel="api-description">
    // Regex: <link[^>]+rel=["']api-description["'][^>]+href=["']([^"']+)["']
    let link_re = regex::Regex::new(
        r#"<link[^>]+rel=["']api-description["'][^>]+href=["']([^"']+)["']"#
    ).ok();

    if let Some(re) = &link_re {
        for cap in re.captures_iter(html) {
            if let Some(href) = cap.get(1) {
                links.push(resolve_url(base_url, href.as_str()));
            }
        }
    }

    // Pattern 2: Swagger UI spec URL
    // SwaggerUIBundle({ url: "..." }) or spec-url="..."
    let swagger_ui_re = regex::Regex::new(
        r#"(?:url:\s*["']|spec-url=["'])([^"']+\.(?:json|yaml))["']"#
    ).ok();

    if let Some(re) = &swagger_ui_re {
        for cap in re.captures_iter(html) {
            if let Some(href) = cap.get(1) {
                links.push(resolve_url(base_url, href.as_str()));
            }
        }
    }

    // Pattern 3: Redoc spec-url
    let redoc_re = regex::Regex::new(
        r#"<redoc\s+spec-url=["']([^"']+)["']"#
    ).ok();

    if let Some(re) = &redoc_re {
        for cap in re.captures_iter(html) {
            if let Some(href) = cap.get(1) {
                links.push(resolve_url(base_url, href.as_str()));
            }
        }
    }

    // Pattern 4: Generic <a> links to spec files
    let link_href_re = regex::Regex::new(
        r#"href=["']([^"']*(?:openapi|swagger|api-docs)[^"']*\.(?:json|yaml))["']"#
    ).ok();

    if let Some(re) = &link_href_re {
        for cap in re.captures_iter(html) {
            if let Some(href) = cap.get(1) {
                links.push(resolve_url(base_url, href.as_str()));
            }
        }
    }

    links.sort();
    links.dedup();
    links
}

/// Resolve a potentially relative URL against a base.
fn resolve_url(base: &str, href: &str) -> String {
    if href.starts_with("http://") || href.starts_with("https://") {
        href.to_string()
    } else if href.starts_with('/') {
        // Absolute path -- combine with scheme+host from base
        if let Ok(parsed) = url::Url::parse(base) {
            format!("{}://{}{}", parsed.scheme(), parsed.host_str().unwrap_or(""), href)
        } else {
            format!("{}/{}", base.trim_end_matches('/'), href.trim_start_matches('/'))
        }
    } else {
        format!("{}/{}", base.trim_end_matches('/'), href)
    }
}
```

```rust
// src/capability/discovery/quality.rs

use super::EndpointQuality;
use crate::capability::GeneratedCapability;

/// Score a generated capability for LLM usefulness.
///
/// Operates on the parsed `CapabilityDefinition` struct, not raw YAML strings,
/// for reliable and maintainable scoring.
///
/// Scoring factors (0-100):
/// - Has description: +30
/// - Has >=1 required parameter: +15
/// - Has <=5 total parameters: +15 (too many = confusing for LLM)
/// - Method is GET or POST (not OPTIONS/HEAD): +10
/// - Name is descriptive (>5 chars, not just "get_"): +10
/// - Has response schema: +10
/// - Has examples in description: +10
pub fn score_capability(cap: &GeneratedCapability) -> EndpointQuality {
    let mut score: u32 = 0;
    let mut reasons = Vec::new();
    let def = &cap.definition;

    // Score on parsed struct fields, not string matching
    if def.description.as_ref().is_some_and(|d| !d.is_empty()) {
        score += 30;
        reasons.push("has description".into());
    }

    let required_count = def.input.iter()
        .filter(|p| p.required)
        .count();
    if required_count > 0 {
        score += 15;
        reasons.push("has required params".into());
    }

    let param_count = def.input.len();
    if param_count > 0 && param_count <= 5 {
        score += 15;
        reasons.push(format!("{param_count} params (manageable)"));
    } else if param_count > 5 {
        reasons.push(format!("{param_count} params (complex)"));
    }

    let method = &def.provider.method;
    if matches!(method.as_str(), "GET" | "POST") {
        score += 10;
        reasons.push("standard method".into());
    }

    if cap.name.len() > 5 && !cap.name.starts_with("get_") {
        score += 10;
        reasons.push("descriptive name".into());
    }

    if def.output.is_some() {
        score += 10;
        reasons.push("has response schema".into());
    }

    EndpointQuality { name: cap.name.clone(), score, reasons }
}

/// Sort capabilities by quality score descending, return with scores.
pub fn rank_capabilities(
    caps: Vec<GeneratedCapability>,
) -> Vec<(GeneratedCapability, EndpointQuality)> {
    let mut scored: Vec<_> = caps.into_iter()
        .map(|c| {
            let q = score_capability(&c);
            (c, q)
        })
        .collect();
    scored.sort_by(|a, b| b.1.score.cmp(&a.1.score));
    scored
}
```

```rust
// src/capability/discovery/dedup.rs

use crate::capability::GeneratedCapability;

/// Filter out capabilities whose names match existing ones.
pub fn deduplicate(
    candidates: Vec<GeneratedCapability>,
    existing_names: &[String],
) -> Vec<GeneratedCapability> {
    candidates.into_iter()
        .filter(|cap| {
            if existing_names.contains(&cap.name) {
                tracing::info!(name = %cap.name, "Skipping: capability already exists");
                false
            } else {
                true
            }
        })
        .collect()
}
```

## Integration Points

### File: `src/cli/mod.rs`

Add new variant to `CapCommand`:

```rust
// In CapCommand enum, add after Import:

/// Auto-discover and import API capabilities from a URL
///
/// Fetches the URL, probes for API specifications (OpenAPI, Swagger),
/// and generates capability YAML files automatically.
/// Extends the `cap import <file>` pattern for remote URLs.
#[command(name = "import-url", about = "Import API capabilities from a URL")]
ImportUrl {
    /// Base URL of the API to discover
    #[arg(required = true)]
    url: String,

    /// Name prefix for generated capabilities
    #[arg(short, long)]
    prefix: Option<String>,

    /// Directory to write generated capability YAML files
    #[arg(short, long, default_value = "capabilities")]
    output: PathBuf,

    /// Authorization header (e.g., "Bearer sk_test_xxx")
    #[arg(long)]
    auth: Option<String>,

    /// Maximum endpoints to generate
    #[arg(long, default_value_t = 50)]
    max_endpoints: usize,

    /// Show what would be generated without writing files
    #[arg(long)]
    dry_run: bool,

    /// Default cost per call (USD) to set in generated capability YAML
    /// (RFC-0075 cost governance integration). Applied to all generated
    /// capabilities unless overridden in config.yaml tool_costs.
    #[arg(long)]
    cost_per_call: Option<f64>,
},
```

### File: `src/commands/cap.rs`

Add handler:

```rust
CapCommand::ImportUrl { url, prefix, output, auth, max_endpoints, dry_run, cost_per_call } => {
    cap_import_url(url, prefix, output, auth, max_endpoints, dry_run, cost_per_call).await
}
```

### File: `src/capability/mod.rs`

Add module declaration:

```rust
pub mod discovery;
```

Re-export:

```rust
pub use discovery::{DiscoveryEngine, DiscoveryOptions, DiscoveryResult};
```

### File: `src/gateway/ui/import.rs`

Extend the existing OpenAPI import UI endpoint to optionally accept a bare URL and run discovery first:

```rust
// POST /ui/api/import/discover
// Body: { "url": "https://api.stripe.com", "prefix": "stripe" }
// Returns: { "capabilities": [...], "spec_url": "...", "format": "OpenApi3" }
```

### File: `Cargo.toml`

No new dependencies. Discovery uses only:
- `reqwest` (already present)
- `futures` (already present)
- `serde_json`, `serde_yaml` (already present)
- `regex` (already present)
- `url` (already present)
- `tracing` (already present)

Feature gate addition:

```toml
[features]
default = ["webui", "discovery"]
discovery = []
```

## CLI Interface

```bash
# Basic: discover from a URL
mcp-gateway cap import-url https://api.openweathermap.org
# Discovered OpenAPI spec at /swagger.json
# Generated 3 capabilities (quality scored):
#   93  capabilities/openweathermap_current.yaml
#   87  capabilities/openweathermap_forecast.yaml
#   72  capabilities/openweathermap_onecall.yaml

# With auth and prefix
mcp-gateway cap import-url https://api.stripe.com \
  --prefix stripe \
  --output capabilities/stripe/ \
  --auth "Bearer sk_test_xxx" \
  --max-endpoints 50

# Dry run (inspect without writing)
mcp-gateway cap import-url https://api.github.com --dry-run
# Would generate 42 capabilities from OpenAPI spec at /openapi.json
# Top 10 by quality:
#   95  github_repos_list          List repositories for the authenticated user
#   92  github_issues_list         List issues assigned to the authenticated user
#   ...

# GraphQL endpoint
mcp-gateway cap import-url https://api.github.com/graphql \
  --auth "Bearer ghp_xxx" \
  --prefix github_gql
```

## Config Schema

No config changes required for v1. Discovery is a CLI command, not a runtime feature. Future versions could add:

```yaml
# (future) auto-discovery on startup
capabilities:
  auto_discover:
    - url: https://internal-api.company.com
      prefix: internal
      auth: "env:INTERNAL_API_TOKEN"
      refresh_interval: "24h"
```

## Web UI Integration

Extend the existing import tab (RFC-0060):

```
Tab: Capabilities -> Import OpenAPI -> new "Discover from URL" option

  +--------------------------------------------------+
  | Discover API from URL                            |
  |                                                  |
  | URL: [https://api.stripe.com___________] [Scan]  |
  | Prefix: [stripe_______]                          |
  | Auth: [Bearer sk_test_________________] (optional)|
  |                                                  |
  | Status: Discovered OpenAPI 3.0 at /openapi.json  |
  |                                                  |
  | [x] stripe_create_customer  (score: 95)          |
  | [x] stripe_list_charges     (score: 92)          |
  | [ ] stripe_delete_webhook   (score: 45)          |
  | ...                                              |
  |                                                  |
  | [Import Selected (8)]  [Cancel]                  |
  +--------------------------------------------------+
```

API endpoint: `POST /ui/api/import/discover`

```json
{
  "url": "https://api.stripe.com",
  "prefix": "stripe",
  "auth": "Bearer sk_test_xxx",
  "max_endpoints": 50
}
```

Response:

```json
{
  "spec_url": "https://api.stripe.com/openapi.json",
  "format": "OpenApi3",
  "capabilities": [
    { "name": "stripe_create_customer", "description": "...", "quality_score": 95, "yaml": "..." },
    ...
  ]
}
```

## Testing Strategy

### Unit Tests (~15 tests)

1. `SpecDetector::detect` -- OpenAPI 3, Swagger 2, GraphQL, unknown
2. `html_scanner::extract_spec_links` -- each pattern (link rel, Swagger UI, Redoc, generic)
3. `html_scanner::resolve_url` -- absolute, relative, path-only
4. `quality::score_capability` -- high quality, low quality, edge cases
5. `dedup::deduplicate` -- with matches, without matches, empty input
6. `graphql_to_openapi` -- valid introspection result, malformed input
7. `chain::looks_like_spec` -- true/false for each format

### Integration Tests (~5 tests)

8. `discover_openapi_json` -- mock HTTP server returning OpenAPI spec at /openapi.json
9. `discover_swagger_yaml` -- mock returning Swagger 2.0 at /swagger.yaml
10. `discover_graphql` -- mock responding to introspection query
11. `discover_ssrf_blocked` -- ensure 127.0.0.1 and 10.x URLs are rejected
12. `discover_auth_header_forwarded` -- verify auth header is sent on requests

### CLI Tests (~3 tests)

13. `cli_import_url_dry_run` -- runs with --dry-run against mock server
14. `cli_import_url_writes_files` -- verify YAML files are created in output dir
15. `cli_import_url_with_prefix` -- verify prefix is applied to all names

## Differentiators

1. **Multi-format discovery in one command.** Postman requires knowing the spec format upfront. Swagger Inspector requires browser interaction. This combines well-known path probing, HTML doc scanning, and format detection in a single CLI invocation.

2. **Quality scoring for LLM usefulness.** Discovered endpoints are scored by factors that matter for LLM tool use (description quality, parameter count, method type), filtering noise like OPTIONS endpoints.

3. **SSRF protection on every fetch.** The gateway's existing SSRF validation (RFC 5735/6890 coverage including redirect targets) is applied to every URL in the discovery chain and redirect hops.

4. **Deduplication against existing capabilities.** Running discovery twice does not produce duplicates. Hand-crafted capabilities for an endpoint cause the auto-generated one to be skipped.

5. **HTML doc page scanning.** When no spec is found at well-known paths, the engine falls back to scanning HTML for Swagger UI, Redoc, and Stoplight markers. This covers APIs that embed docs in non-standard locations.

6. **Single command to MCP tools.** The pipeline from bare URL to working MCP tool capability YAML requires one command with zero manual steps.

---

## Shared Prerequisites

**Prerequisite**: Implement session disconnect callback in `src/gateway/server.rs` that notifies all per-session state holders. All RFCs adding per-session DashMap entries MUST register a cleanup handler.

---

## ADR-0074: API Discovery Strategy

### Context

The `cap import` command requires a local spec file. Users must manually find and download API specs before they can generate capabilities. This friction contradicts the gateway's "no code" value proposition.

### Decision

Implement a `cap import-url` CLI command that probes a URL for API specifications, with a defined probe order that starts with `.well-known` paths and falls back to HTML page scanning. Reuse the existing `OpenApiConverter` for the actual YAML generation.

**Alternatives considered:**

| Option | Pros | Cons | Decision |
|--------|------|------|----------|
| A. Headless browser (chromiumoxide) | Renders SPAs, captures dynamic specs | +24MB binary, 10s startup, complex | Rejected |
| B. LLM-assisted discovery | Could understand any doc format | Requires API key, non-deterministic, slow | Rejected |
| C. Static HTTP probing (chosen) | Fast, deterministic, zero dependencies | Misses SPA-only docs | **Selected** |
| D. curl piped to `cap import` | Simple | No quality scoring, no dedup, no GraphQL | Rejected |

**Key design decisions:**

1. **Parallel probe fan-out.** All well-known paths are probed concurrently via `futures::future::join_all`. The first successful response wins (in priority order). This reduces discovery latency from sequential N * RTT (up to 6 seconds) to a single network RTT (~200-500ms) for typical APIs.

2. **GraphQL as Phase 2 target.** GraphQL-to-capability conversion requires its own design for POST body templates and variable mapping. Deferred to a follow-up RFC to keep v1 scope focused on OpenAPI/Swagger.

3. **Quality scoring is separate from generation.** The scorer runs after `OpenApiConverter`, not during. This keeps the converter pure and testable independently.

4. **Feature-gated but default-on.** The feature adds ~2KB to the binary (no new deps). Users who want a minimal binary can disable it.

### Consequences

- Users can onboard any OpenAPI/Swagger API with a single command
- GraphQL support deferred to Phase 2 (needs POST body template design)
- Quality scoring may need tuning based on real-world feedback (expose weights as constants)
- HTML scanning is regex-based and may miss unusual doc frameworks (acceptable: covers 90%+ of real APIs)

---

## Risk Register

| ID | Risk | Likelihood | Impact | Mitigation |
|----|------|-----------|--------|------------|
| R1 | SSRF via discovery URL | Medium | Critical | Every URL passes through `security::ssrf::validate_url_not_ssrf()` before fetch. Redirect chain validation for followed redirects. |
| R2 | API spec too large (100MB+) | Low | Medium | `Content-Length` check before reading body. Hard limit at 10MB. Timeout at 30s. |
| R3 | GraphQL introspection disabled on API | Medium | Low | Graceful fallback to next probe in chain. Logged as debug, not error. |
| R4 | Generated capabilities have incorrect auth | High | Low | Discovery does NOT auto-configure credentials. It sets `auth.required: true` with a TODO comment. User must fill in credential references. |
| R5 | Rate limiting by target API during probing | Medium | Low | Sequential probes with 100ms delay between attempts. Respect `Retry-After` header. |
| R6 | Duplicate capabilities overwrite hand-crafted ones | Low | High | Dedup filter checks existing names. `--dry-run` available for preview. Never overwrites existing files (appends `_2` suffix if name collision after dedup). |
| R7 | HTML scanner regex injection | Low | Medium | Regex patterns are compile-time constants, not user-controlled. Extracted URLs are SSRF-checked before use. |
| R8 | Swagger 2.0 spec not fully converted | Low | Medium | `OpenApiConverter` already handles Swagger 2.0. If it misses edge cases, those are pre-existing bugs, not new ones. |
