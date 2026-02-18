import { initializeDatabase } from "../src/db/database.js";
import { TelecomDomainService } from "../src/domain/service.js";
import { FoundationMcpAdapter } from "../src/foundation/adapter.js";
import { buildClauseResolutionPlanSet } from "../src/foundation/planner.js";
import { extractExactReferenceResolutionCandidates } from "../src/foundation/resolution.js";

function parseArgs(argv: string[]) {
  const getValue = (flag: string): string | undefined => {
    const index = argv.indexOf(flag);
    if (index >= 0 && index + 1 < argv.length) {
      return argv[index + 1];
    }
    return undefined;
  };

  return {
    jurisdiction: getValue("--jurisdiction"),
    limit: Number(getValue("--limit") ?? "250"),
    dryRun: argv.includes("--dry-run")
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const db = initializeDatabase(process.env.TELECOM_MCP_DB_PATH);
  const service = new TelecomDomainService(db);
  const adapter = new FoundationMcpAdapter();

  const backlog = service.getExactReferenceBacklog(args.jurisdiction);
  const scopedItems = backlog.items.slice(0, Math.max(1, args.limit));

  const grouped = new Map<
    string,
    Array<{
      assertion_id: string;
      regulation_id: string;
      article_or_section: string;
    }>
  >();

  for (const item of scopedItems) {
    if (!grouped.has(item.jurisdiction)) {
      grouped.set(item.jurisdiction, []);
    }
    grouped.get(item.jurisdiction)?.push({
      assertion_id: item.assertion_id,
      regulation_id: item.regulation_id,
      article_or_section: item.article_or_section
    });
  }

  let totalResolvedCandidates = 0;
  let totalApplied = 0;
  let totalCalls = 0;
  let totalSkippedNoResolver = 0;
  const perJurisdiction: Array<{
    jurisdiction: string;
    pending: number;
    calls: number;
    skipped_no_resolver: number;
    resolved_candidates: number;
    applied: number;
  }> = [];

  for (const [jurisdiction, assertions] of grouped.entries()) {
    const planSet = buildClauseResolutionPlanSet(jurisdiction, assertions);
    totalCalls += planSet.plans.length;
    totalSkippedNoResolver += planSet.skipped.length;
    const results = await adapter.invokeAll(planSet.plans);
    const candidates = extractExactReferenceResolutionCandidates(results);
    totalResolvedCandidates += candidates.length;

    let applied = 0;
    if (!args.dryRun && candidates.length > 0) {
      const persistence = service.applyExactReferenceOverrides(jurisdiction, candidates);
      applied = persistence.applied;
      totalApplied += applied;
    }

    perJurisdiction.push({
      jurisdiction,
      pending: assertions.length,
      calls: planSet.plans.length,
      skipped_no_resolver: planSet.skipped.length,
      resolved_candidates: candidates.length,
      applied
    });
  }

  const postAudit = service.auditExpertiseQuality();
  db.close();

  process.stdout.write(
    `${JSON.stringify(
      {
        mode: args.dryRun ? "dry-run" : "apply",
        jurisdiction_filter: args.jurisdiction ?? null,
        backlog_scanned: scopedItems.length,
        jurisdictions_processed: grouped.size,
        foundation_calls: totalCalls,
        skipped_no_supported_resolver: totalSkippedNoResolver,
        resolved_candidates: totalResolvedCandidates,
        applied_overrides: totalApplied,
        per_jurisdiction: perJurisdiction,
        post_audit: postAudit.summary
      },
      null,
      2
    )}\n`
  );
}

main().catch((error) => {
  process.stderr.write(`promote-exact-references failed: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
});
