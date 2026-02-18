# Telecommunications MCP

Telecommunications domain intelligence MCP implementing the shared tool contract from `domain-mcp-specifications.md` (v1.0, 2026-02-18).

## Scope

Covers telecom operators, ISPs, and digital infrastructure providers across EU and US contexts, including:

- 5G security and network slicing
- NFV/SDN and cloud-native telecom infrastructure
- Lawful intercept obligations
- Subscriber, metadata, DNS, and location data handling
- NIS2 / EECC / ePrivacy / GDPR / CPNI / ECPA-SCA / CALEA mappings

## Implemented Tool Surface

Universal tools:

- `about`
- `get_knowledge_coverage`
- `list_supported_jurisdictions`
- `get_jurisdiction_clause_pack`
- `audit_expertise_quality`
- `get_jurisdiction_expertise_scorecard`
- `get_exact_reference_backlog`
- `apply_exact_reference_overrides`
- `list_sources`
- `list_architecture_patterns`
- `get_architecture_pattern`
- `classify_data`
- `get_domain_threats`
- `build_detection_playbook`
- `build_telecom_expert_brief`
- `build_threat_remediation_backlog`
- `build_architecture_hardening_plan`
- `build_compliance_evidence_matrix`
- `assess_applicability`
- `explain_obligation_conflicts`
- `map_to_technical_standards`
- `search_domain_knowledge`
- `compare_jurisdictions`
- `build_control_baseline`
- `build_evidence_plan`
- `assess_breach_obligations`
- `create_remediation_backlog`

Telecommunications-specific tools:

- `classify_telecom_entity`
- `assess_5g_security`
- `assess_lawful_intercept_compliance`
- `assess_data_retention_obligations`
- `build_detection_playbook` (operational threat detection guidance)
- `build_telecom_expert_brief` (integrated operator-ready expert package)
- `build_threat_remediation_backlog` (threat-driven prioritized engineering actions)
- `build_architecture_hardening_plan` (architecture-specific hardening blueprint)
- `build_compliance_evidence_matrix` (obligation-to-evidence/control audit mapping)

Each tool returns the shared `{ data, metadata }` response envelope including citations, confidence, dataset version and fingerprint.

`compare_jurisdictions` now prefers clause-pack-backed comparisons for mapped telecom topics (directive strength + exact/named reference quality), not only heuristic summaries.

## Applicability Engine

`assess_applicability` now uses deterministic rule resolution instead of simple first-match behavior:

- precedence levels: `country_specific` > `jurisdiction_wide` > `cross_jurisdiction`
- score-based ordering and de-duplication for stable outputs
- explicit decision trace for auditability
- cross-border support via `additional_context.countries` (for multi-country operator profiles)
- clause-level jurisdiction assertion packs (EU core + country overlays + US federal + state overlays)
- topic/directive/citation metadata on each obligation assertion
- global technical exact-reference assertions (3GPP TS 33.501, ETSI TS 103 120, RFC 7258, GSMA NESAS/SCAS, ISO 27001 A.5.33, RFC 8224, ISO 27701, NIST SP 800-61r2, RFC 9325) across all supported jurisdictions
- conflict detection across overlapping jurisdictions with strictest-directive recommendation
- optional exact-reference resolution flow for clause packs (`resolve_exact_references: true`) via foundation MCP joins
- optional persistence when resolving exact references (`persist_exact_references: true`)

## Expertise QA Gate

Run the expertise quality gate locally/CI:

```bash
npm run quality:expertise
```

Run exact-reference backlog promotion dry-run:

```bash
npm run quality:exact-backlog
```

Gate checks include:

- assertions present for every supported Europe country and every US state jurisdiction key
- citation completeness (non-empty ref + HTTPS source URL) at 100%
- named references require explicit resolution hints for exact section lookup

Use backlog tooling to prioritize exact-reference completion:

- `get_exact_reference_backlog` returns named-reference items by jurisdiction
- `get_jurisdiction_expertise_scorecard` pinpoints lowest/highest quality jurisdictions by exact refs + topic coverage
- `get_jurisdiction_clause_pack` with `resolve_exact_references=true` triggers foundation MCP resolution calls
- exact-resolution planning now reports unsupported named assertions separately when no compatible foundation law MCP is configured

## Foundation MCP Joins

Foundation joins are executed through an HTTP adapter (`POST /mcp`) with timeout and graceful fallback:

- `eu-regulations`
- `us-regulations`
- `security-controls`
- `dutch-law`

Configure endpoints with environment variables:

```bash
FOUNDATION_MCP_EU_REGULATIONS_URL=https://eu-regulations-mcp.example.com
FOUNDATION_MCP_US_REGULATIONS_URL=https://us-regulations-mcp.example.com
FOUNDATION_MCP_SECURITY_CONTROLS_URL=https://security-controls-mcp.example.com
FOUNDATION_MCP_DUTCH_LAW_URL=https://dutch-law-mcp.example.com
FOUNDATION_MCP_TIMEOUT_MS=3500
```

If an endpoint is not configured, join execution is returned as `skipped` rather than failing the local domain response.

## Data Layer

Database: SQLite + FTS5

- Shared core schema from Appendix A (`architecture_patterns`, `data_categories`, `threat_scenarios`, `technical_standards`, `applicability_rules`, `evidence_artifacts`, `db_metadata`)
- Additional table: `authoritative_sources`
- Seeded with telecommunications content from MCP 5 section of the spec

Current core knowledge coverage includes:

- 12/12 architecture patterns from the telecom spec
- 10/10 telecom data categories from the telecom spec
- 27/27 core telecom threat scenarios across 5G, NFV/SDN, lawful intercept, infrastructure, and privacy
- jurisdiction overlays for 50 European country profiles and all 50 US states + DC

## Run

Install dependencies:

```bash
npm install
```

Start stdio MCP transport:

```bash
npm run dev
```

Start HTTP transport:

```bash
npm run dev:http
```

HTTP endpoints:

- `GET /health`
- `GET /mcp` (usage metadata)
- `POST /mcp` with payload:

```json
{
  "tool": "about",
  "arguments": {}
}
```

## Tests

Tests include:

- baseline domain tests in `test/telecommunications.spec.ts`
- full 24-case telecom sampling harness aligned to MCP 5 Phase 2.3 in `test/telecommunications-sampling-24.spec.ts`

```bash
npm test
```

## Notes

- This implementation is a domain intelligence router. It does not duplicate full foundation MCP legal text.
- National legal edge cases should be finalized through foundation MCP joins and jurisdiction-specific validation.
