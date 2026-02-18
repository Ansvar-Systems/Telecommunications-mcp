# Changelog

All notable changes to this project are documented in this file.

## [1.0.0] - 2026-02-18

- Expanded clause-level jurisdiction coverage to all Europe country profiles and all US states + DC.
- Added expertise quality tooling (`audit_expertise_quality`, scorecards, exact-reference backlog, override persistence).
- Added telecom expert planning tools:
  - `build_detection_playbook`
  - `build_telecom_expert_brief`
  - `build_threat_remediation_backlog`
  - `build_architecture_hardening_plan`
  - `build_compliance_evidence_matrix`
- Implemented Streamable HTTP MCP transport at `/mcp` and retained stdio transport for local clients.
- Added provenance coverage for EU legal, US legal, RFC, and ISO source families.
- Added contract fixtures (`fixtures/golden-tests.json`, `fixtures/golden-hashes.json`) and validation scripts.
- Updated STIR/SHAKEN citation URL to the correct eCFR subpart (`subpart-HH`).
- Switched SQLite journal mode to `DELETE` for serverless-safe runtime behavior.
- Upgraded `search_domain_knowledge` to FTS5-first retrieval with keyword fallback and explicit match status markers.
- Added alias-aware and shorthand-aware standards mapping for telecom expert queries.
- Added `quality:prod-ready` gate script and CI enforcement for production readiness checks.
- Added explicit search status markers (`matched`, `no_match`, `not_indexed_content_type`, `empty_query`) for agent-safe search behavior.
- Added `detail_level` control (`compact|standard|full`) for `build_telecom_expert_brief` to reduce token-heavy responses in production agents.
