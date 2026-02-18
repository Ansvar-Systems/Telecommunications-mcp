import { initializeDatabase } from "../src/db/database.js";
import { TelecomDomainService } from "../src/domain/service.js";
import { architecturePatterns, authoritativeSources, technicalStandards } from "../src/domain/seedData.js";

type CheckResult = {
  name: string;
  pass: boolean;
  detail: string;
};

function main() {
  const db = initializeDatabase(":memory:");
  const service = new TelecomDomainService(db);
  const checks: CheckResult[] = [];

  const expertise = service.auditExpertiseQuality();
  checks.push({
    name: "expertise_quality_gate",
    pass: expertise.pass,
    detail: `pass=${expertise.pass}; exact_reference_pct=${expertise.summary.exact_reference_pct}`
  });

  const coverage = service.getKnowledgeCoverageReport();
  checks.push({
    name: "coverage_readiness",
    pass: coverage.readiness_score === 100,
    detail: `readiness_score=${coverage.readiness_score}`
  });

  const standardIdSet = new Set(technicalStandards.map((standard) => standard.id));
  const danglingStandardRefs = Array.from(
    new Set(
      architecturePatterns.flatMap((pattern) =>
        pattern.applicable_standards.filter((standardId) => !standardIdSet.has(standardId))
      )
    )
  );
  checks.push({
    name: "standards_reference_integrity",
    pass: danglingStandardRefs.length === 0,
    detail:
      danglingStandardRefs.length === 0
        ? "all applicable_standards references resolve to technical_standards IDs"
        : `dangling references: ${danglingStandardRefs.join(", ")}`
  });

  const nonHttpsSources = authoritativeSources.filter(
    (source) => !source.source_url || !source.source_url.startsWith("https://")
  );
  checks.push({
    name: "authoritative_source_hygiene",
    pass: authoritativeSources.length >= 16 && nonHttpsSources.length === 0,
    detail: `sources=${authoritativeSources.length}; non_https=${nonHttpsSources.length}`
  });

  const indexedSearch = service.searchDomainKnowledge("SEPP signaling protection", "architecture_patterns", 5);
  checks.push({
    name: "indexed_search_behavior",
    pass: indexedSearch.match_status === "matched" && indexedSearch.results.length > 0,
    detail: `match_status=${indexedSearch.match_status}; results=${indexedSearch.results.length}`
  });

  const unsupportedSearch = service.searchDomainKnowledge("SEPP", "evidence_artifacts", 5);
  checks.push({
    name: "search_non_indexed_marker",
    pass: unsupportedSearch.match_status === "not_indexed_content_type",
    detail: `match_status=${unsupportedSearch.match_status}`
  });

  const compactBrief = service.buildTelecomExpertBrief({
    country: "SE",
    role: "mobile_operator",
    size: "large",
    architecture_patterns: ["tc-5g-core"],
    data_types: ["subscriber_data", "traffic_metadata"],
    service_types: ["voice", "data", "5g"],
    detail_level: "compact"
  });
  const fullBrief = service.buildTelecomExpertBrief({
    country: "SE",
    role: "mobile_operator",
    size: "large",
    architecture_patterns: ["tc-5g-core"],
    data_types: ["subscriber_data", "traffic_metadata"],
    service_types: ["voice", "data", "5g"],
    detail_level: "full"
  });
  checks.push({
    name: "expert_brief_detail_levels",
    pass:
      compactBrief.profile.detail_level === "compact" &&
      fullBrief.profile.detail_level === "full" &&
      compactBrief.applicability.obligations.length <= fullBrief.applicability.obligations.length,
    detail: `compact_obligations=${compactBrief.applicability.obligations.length}; full_obligations=${fullBrief.applicability.obligations.length}`
  });

  db.close();

  const failed = checks.filter((check) => !check.pass);
  const payload = {
    pass: failed.length === 0,
    checks,
    summary: {
      total: checks.length,
      passed: checks.length - failed.length,
      failed: failed.length
    }
  };

  process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
  if (failed.length > 0) {
    process.exit(1);
  }
}

main();
