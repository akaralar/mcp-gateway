# Enterprise Edition License (PolyForm Noncommercial)

**Status**: Active as of v2.11.0 (2026-04-25). See MIK-3034, MIK-3036.

This file describes the license terms that apply to designated **Enterprise Edition (EE)** files within the `mcp-gateway` repository. The Path C dual-license refactor landed in v2.11.0.

## Scope

Files marked with the SPDX header

```rust
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
```

are licensed under the **PolyForm Noncommercial** license (version 1.0.0). All other files remain under the existing MIT License (see `LICENSE`).

## Enterprise Edition coverage (planned, per ADR-001 / MIK-3036)

- `src/security/firewall/`
- `src/security/agent_identity.rs`
- `src/security/data_flow.rs`
- `src/security/message_signing.rs`
- `src/security/policy.rs`
- `src/security/response_inspect.rs`
- `src/security/response_scanner.rs`
- `src/security/scope_collision.rs`
- `src/security/tool_integrity.rs`
- `src/cost_accounting/`
- `src/key_server/`
- `src/transparency_log/` (new in v2.11, per MIK-3034)
- Future EE features per `docs/plans/`

## Summary of PolyForm Noncommercial terms

- **Free** for noncommercial use, modification, redistribution
- **Commercial use requires a separate commercial license** — contact the maintainer
- All other rights reserved

Full license text reference: see polyformproject.org for the canonical license document.

## Commercial licensing

For commercial use of EE-designated files, contact: mikko.parkkola@iki.fi

A pricing page will be published alongside the v2.11 release. Provisional tiers under consideration:

- Per-seat developer license
- Per-organization annual license
- Bundled with managed-service hosting

## Existing MIT-licensed releases

Versions of `mcp-gateway` released **before** v2.11 are entirely MIT-licensed and remain so forever. The PolyForm Noncommercial license applies only to v2.11+ EE-designated files.

## References

- ADR-001: `claude-elite/docs/adr/ADR-001-ip-strategy.md` (Path C decision)
- Linear: MIK-3024 (umbrella), MIK-3034, MIK-3035, MIK-3036
- PolyForm Project: search "PolyForm Noncommercial 1.0.0"
