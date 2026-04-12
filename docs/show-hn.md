---
title: "Show HN draft: security-aware MCP gateway"
status: draft
target_post_date: TBD
---

# Show HN post draft

## Title options

1. **(Recommended)** Show HN: A security-aware MCP gateway that catches tool poisoning before your agent sees it
2. Show HN: mcp-gateway, one Rust binary, 91% token savings, tool-poisoning defenses
3. Show HN: I wrote a meta-tool MCP gateway after Invariant Labs showed N servers = N attack surfaces

Reasoning: option 1 leads with the pain (Invariant Labs, WhatsApp, Simon Willison's comment) which is the hot wedge on HN this week, and reuses the proven "Show HN: MCP server for X" pattern. Option 2 leads on numbers, which reads as ad copy. Option 3 is long.

## Body (target 500 to 800 words)

Hi HN,

I am Mikko. I wrote mcp-gateway because connecting N MCP servers to an agent is connecting N attack surfaces, and the attacks are not hypothetical.

The problem, in order of severity:

1. **Tool poisoning.** Invariant Labs showed that a malicious MCP tool description can embed `<IMPORTANT>` blocks that instruct the agent to read `~/.ssh/id_rsa` and pass it as a "sidenote" argument. The user sees an innocent `add(a, b)` tool, the agent sees the hidden instructions and follows them. PoC and writeup: https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks
2. **Rug pulls.** An MCP server that passed review on Monday can silently rewrite its tool descriptions on Tuesday. The user already clicked "trust" once.
3. **Shadowing.** A malicious server can emit a tool description that rewrites the behavior of an unrelated server's tool.
4. **WhatsApp MCP exfiltration.** Invariant Labs followed up with a working chat-history exfiltration against the WhatsApp MCP server: https://invariantlabs.ai/blog/whatsapp-mcp-exploited
5. **Prompt injection via tool results.** Simon Willison's summary: "MCP has prompt injection security problems" (https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/) The TL;DR is that any tool output the agent reads is untrusted and can redirect the agent mid-task.

These are all the same structural bug. If the agent is allowed to see every tool description from every server directly, every server becomes a supply-chain entry point, and the agent can be compromised before the user has even typed their first prompt. Locking down one server does not help, because the agent only needs one poisoned one.

mcp-gateway fixes this structurally:

- The agent never sees raw MCP servers. It sees **4 meta-tools**: `gateway_list_servers`, `gateway_list_tools`, `gateway_search_tools`, `gateway_invoke`.
- Every backend tool description flows through a validator before it ever lands in the agent's context window. Rule **AX-010** (`src/validator/rules/tool_poisoning.rs`, 19 tests) catches the Invariant Labs patterns: `<IMPORTANT>` tags, `~/.ssh`/`~/.aws`/`id_rsa`/`.env`/`/etc/passwd` paths, "sidenote" exfiltration language, curl-to-HTTP, base64 in exfil context, zero-width and bidi-override Unicode, 40+ consecutive spaces, and oversized descriptions. HIGH matches fail-closed; MEDIUM matches warn.
- Every capability YAML can be hash-pinned with `mcp-gateway cap pin <file>`. The hash is reproducible from a shell with `grep -v '^sha256:' capability.yaml | sha256sum`. At load time and on every file-watch event the loader recomputes the hash and refuses any mismatch, logging `RUG-PULL DETECTED: capability YAML sha256 pin mismatch, unloading`. Implementation: `src/capability/hash.rs` and `src/capability/backend.rs::detect_rug_pulls`.
- Capability YAMLs are the audit surface. They are small, diffable, grep-able, PR-reviewable. A compromised upstream cannot mutate them without tripping the hash.

Numbers, all reproducible from the repo:

- 4 meta-tools minimum; 14 in the README benchmark scenario (`benchmarks/public_claims.json`)
- ~91% token savings at 100 tools / 1000 requests (Claude Opus pricing, `benchmarks/token_savings.py`)
- ~8ms startup (`hyperfine` in `docs/BENCHMARKS.md`)
- 2765 tests passing, `#![deny(unsafe_code)]`, zero clippy warnings
- 101 built-in REST capabilities across 16 categories
- OpenAPI importer: the full Swagger Petstore spec becomes 19 validated capability YAMLs end-to-end with one command

Three-line usage:

```
brew tap MikkoParkkola/tap && brew install mcp-gateway
mcp-gateway cap import https://petstore3.swagger.io/api/v3/openapi.json --output capabilities/ --prefix petstore
mcp-gateway --config gateway.yaml
```

Then point Claude Code / Cursor / Windsurf at `http://localhost:39400/mcp`.

I believe this is the first open-source MCP gateway that ships structural defenses against tool poisoning, rug pulls, and centralized capability audit. I would like HN to break it.

Repo: https://github.com/MikkoParkkola/mcp-gateway
License: MIT
Stack: Rust 1.88, edition 2024, single binary, ~12MB
Blog post with the full attack walkthrough: docs/blog/security-aware-mcp-gateway.md

Happy to answer questions.
