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
