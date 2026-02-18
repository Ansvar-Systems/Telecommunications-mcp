import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { ToolEnvelope } from "../types.js";
import { TelecomDomainService } from "../domain/service.js";
import { FoundationMcpAdapter } from "../foundation/adapter.js";
import {
  buildFoundationCallsFor5gSecurity,
  buildFoundationCallsForApplicability,
  buildClauseResolutionPlanSet,
  buildFoundationCallsForEntityClassification,
  buildFoundationCallsForLawfulIntercept,
  buildFoundationCallsForRetention
} from "../foundation/planner.js";
import { extractExactReferenceResolutionCandidates } from "../foundation/resolution.js";
import { makeToolResponse } from "../utils/metadata.js";

function mcpPayload<T>(response: ToolEnvelope<T>) {
  return {
    content: [{ type: "text", text: JSON.stringify(response, null, 2) }],
    structuredContent: response
  };
}

function withMeta<T>(
  service: TelecomDomainService,
  data: T,
  options?: {
    confidence?: "authoritative" | "inferred" | "estimated";
    rationale?: string;
    outOfScope?: string[];
    foundationCalls?: Array<{ mcp: string; tool: string; params: Record<string, unknown> }>;
  }
) {
  const metadataContext = service.metadataContext();
  return makeToolResponse(data, {
    confidence: options?.confidence,
    rationale: options?.rationale,
    outOfScope: options?.outOfScope,
    foundationCalls: options?.foundationCalls,
    datasetVersion: metadataContext.datasetVersion,
    datasetFingerprint: metadataContext.datasetFingerprint
  });
}

export function createTelecommunicationsMcpServer(
  service: TelecomDomainService,
  foundationAdapter = new FoundationMcpAdapter()
) {
  const server: any = new McpServer({
    name: "telecommunications-mcp",
    version: "1.0.0"
  });

  server.tool("about", "Server metadata, coverage, freshness, known gaps", async () =>
    mcpPayload(withMeta(service, service.about(), { confidence: "authoritative" }))
  );

  server.tool(
    "get_knowledge_coverage",
    "Knowledge completeness and readiness report for telecom domain corpus",
    async () => mcpPayload(withMeta(service, service.getKnowledgeCoverageReport(), { confidence: "authoritative" }))
  );

  server.tool(
    "list_supported_jurisdictions",
    "List covered European countries and US states with telecom/privacy overlays",
    async () =>
      mcpPayload(withMeta(service, service.getSupportedJurisdictionsCatalog(), { confidence: "authoritative" }))
  );

  server.tool(
    "get_jurisdiction_clause_pack",
    "Retrieve clause-level telecom obligation assertions for a jurisdiction (country or US-state like US-CA)",
    {
      jurisdiction: z.string(),
      resolve_exact_references: z.boolean().default(false),
      persist_exact_references: z.boolean().default(false)
    },
    async ({
      jurisdiction,
      resolve_exact_references,
      persist_exact_references
    }: {
      jurisdiction: string;
      resolve_exact_references: boolean;
      persist_exact_references: boolean;
    }) => {
      const pack = service.getJurisdictionClausePack(jurisdiction);
      if (!resolve_exact_references) {
        return mcpPayload(withMeta(service, pack, { confidence: "authoritative" }));
      }

      const namedAssertions = pack.assertions
        .filter((assertion) => assertion.reference_quality === "named")
        .map((assertion) => ({
          assertion_id: assertion.id,
          regulation_id: assertion.regulation_id,
          article_or_section: assertion.article_or_section
        }));

      const resolutionPlanSet = buildClauseResolutionPlanSet(pack.jurisdiction, namedAssertions);
      const foundationCalls = resolutionPlanSet.plans;
      const foundationJoinResults = await foundationAdapter.invokeAll(foundationCalls);
      const resolvedCandidates = extractExactReferenceResolutionCandidates(foundationJoinResults);

      let persistenceResult:
        | {
            jurisdiction: string;
            received: number;
            applied: number;
          }
        | undefined;
      if (persist_exact_references && resolvedCandidates.length > 0) {
        persistenceResult = service.applyExactReferenceOverrides(pack.jurisdiction, resolvedCandidates);
      }
      const effectivePack =
        persist_exact_references && resolvedCandidates.length > 0
          ? service.getJurisdictionClausePack(pack.jurisdiction)
          : pack;

      return mcpPayload(
        withMeta(
          service,
          {
            ...effectivePack,
            exact_reference_resolution: {
              requested: true,
              named_assertion_count: namedAssertions.length,
              foundation_call_count: foundationCalls.length,
              unsupported_named_assertion_count: resolutionPlanSet.skipped.length,
              unsupported_named_assertions: resolutionPlanSet.skipped,
              resolved_candidate_count: resolvedCandidates.length,
              foundation_join_results: foundationJoinResults,
              persisted: Boolean(persistenceResult),
              persistence_result: persistenceResult
            }
          },
          {
            confidence: "inferred",
            rationale:
              "Named references require exact-section resolution from jurisdiction-specific foundation law MCPs.",
            foundationCalls
          }
        )
      );
    }
  );

  server.tool(
    "audit_expertise_quality",
    "Run citation and reference-quality gate checks across all supported Europe and US jurisdictions",
    async () => mcpPayload(withMeta(service, service.auditExpertiseQuality(), { confidence: "authoritative" }))
  );

  server.tool(
    "get_jurisdiction_expertise_scorecard",
    "Return jurisdiction-level expertise scoring (exact refs, topic coverage, citation completeness)",
    {
      jurisdiction: z.string().optional()
    },
    async ({ jurisdiction }: { jurisdiction?: string }) =>
      mcpPayload(
        withMeta(service, service.getJurisdictionExpertiseScorecard(jurisdiction), {
          confidence: "authoritative"
        })
      )
  );

  server.tool(
    "get_exact_reference_backlog",
    "List named (non-exact) reference assertions that should be resolved to exact sections",
    {
      jurisdiction: z.string().optional()
    },
    async ({ jurisdiction }: { jurisdiction?: string }) =>
      mcpPayload(withMeta(service, service.getExactReferenceBacklog(jurisdiction), { confidence: "authoritative" }))
  );

  server.tool(
    "apply_exact_reference_overrides",
    "Persist exact-reference overrides for one jurisdiction (manual curation or batch import)",
    {
      jurisdiction: z.string(),
      overrides: z.array(
        z.object({
          assertion_id: z.string(),
          regulation_id: z.string(),
          exact_reference: z.string(),
          citations: z
            .array(
              z.object({
                type: z.enum(["CELEX", "CFR", "USC", "ISO", "IEC", "NIST", "ETSI", "3GPP", "GSMA", "RFC"]),
                ref: z.string(),
                source_url: z.string()
              })
            )
            .optional(),
          source_confidence: z.enum(["high", "medium", "low"]).optional(),
          resolved_by: z.string().optional(),
          notes: z.string().optional()
        })
      )
    },
    async ({
      jurisdiction,
      overrides
    }: {
      jurisdiction: string;
      overrides: Array<{
        assertion_id: string;
        regulation_id: string;
        exact_reference: string;
        citations?: Array<{ type: "CELEX" | "CFR" | "USC" | "ISO" | "IEC" | "NIST" | "ETSI" | "3GPP" | "GSMA" | "RFC"; ref: string; source_url: string }>;
        source_confidence?: "high" | "medium" | "low";
        resolved_by?: string;
        notes?: string;
      }>;
    }) => {
      const result = service.applyExactReferenceOverrides(jurisdiction, overrides);
      const updatedPack = service.getJurisdictionClausePack(result.jurisdiction);
      return mcpPayload(
        withMeta(
          service,
          {
            ...result,
            jurisdiction_pack: updatedPack
          },
          {
            confidence: "authoritative",
            rationale: "Exact references were persisted to local override storage and reapplied to clause assertions."
          }
        )
      );
    }
  );

  server.tool(
    "list_sources",
    "Authoritative sources used by this MCP",
    {
      source_type: z.string().optional()
    },
    async ({ source_type }: { source_type?: string }) =>
      mcpPayload(
        withMeta(
          service,
          {
            sources: service.listSources(source_type)
          },
          { confidence: "authoritative" }
        )
      )
  );

  server.tool(
    "list_architecture_patterns",
    "Available telecommunications architecture archetypes",
    {
      category: z.string().optional()
    },
    async ({ category }: { category?: string }) =>
      mcpPayload(
        withMeta(
          service,
          {
            patterns: service.listArchitecturePatterns(category)
          },
          { confidence: "authoritative" }
        )
      )
  );

  server.tool(
    "get_architecture_pattern",
    "Retrieve full pattern detail",
    {
      pattern_id: z.string()
    },
    async ({ pattern_id }: { pattern_id: string }) => {
      const pattern = service.getArchitecturePattern(pattern_id);
      if (!pattern) {
        return mcpPayload(
          withMeta(
            service,
            {
              pattern_id,
              error: `Architecture pattern not found: ${pattern_id}`
            },
            {
              confidence: "estimated",
              rationale: "No architecture pattern matched the provided ID.",
              outOfScope: ["Use list_architecture_patterns to discover supported IDs"]
            }
          )
        );
      }

      return mcpPayload(
        withMeta(
          service,
          {
            topology: {
              pattern_id: pattern.id,
              name: pattern.name,
              category: pattern.category,
              description: pattern.description,
              components: pattern.components
            },
            trust_boundaries: pattern.trust_boundaries,
            data_flows: pattern.data_flows,
            integration_points: pattern.components,
            known_weaknesses: pattern.known_weaknesses,
            applicable_standards: pattern.applicable_standards
          },
          { confidence: "authoritative" }
        )
      );
    }
  );

  server.tool(
    "classify_data",
    "Classify telecom data categories and protection tiers",
    {
      data_description: z.string(),
      jurisdictions: z.array(z.string()).default([])
    },
    async ({ data_description, jurisdictions }: { data_description: string; jurisdictions: string[] }) => {
      const result = service.classifyData(data_description, jurisdictions);
      return mcpPayload(
        withMeta(service, result, {
          confidence: result.categories.length > 0 ? "authoritative" : "estimated",
          rationale:
            result.categories.length > 0
              ? "Mapped against telecommunications data taxonomy and jurisdiction protections."
              : "No taxonomy keyword match detected.",
          outOfScope:
            result.categories.length > 0
              ? []
              : ["Input may belong to another domain MCP (e.g. Financial Services, Healthcare)."]
        })
      );
    }
  );

  server.tool(
    "get_domain_threats",
    "Threat scenarios for architecture/data/deployment context",
    {
      architecture_pattern: z.string(),
      data_types: z.array(z.string()).default([]),
      deployment_context: z.string().optional()
    },
    async ({
      architecture_pattern,
      data_types,
      deployment_context
    }: {
      architecture_pattern: string;
      data_types: string[];
      deployment_context?: string;
    }) =>
      mcpPayload(
        withMeta(
          service,
          service.getDomainThreats(architecture_pattern, data_types, deployment_context),
          {
            confidence: "inferred",
            rationale: "Threat matching based on affected patterns/data categories and context keywords."
          }
        )
      )
  );

  server.tool(
    "build_detection_playbook",
    "Build telecom threat detection playbooks with telemetry, analytics signals, and triage actions",
    {
      architecture_pattern: z.string(),
      data_types: z.array(z.string()).default([]),
      deployment_context: z.string().optional(),
      max_items: z.number().int().min(1).max(20).default(8)
    },
    async ({
      architecture_pattern,
      data_types,
      deployment_context,
      max_items
    }: {
      architecture_pattern: string;
      data_types: string[];
      deployment_context?: string;
      max_items: number;
    }) =>
      mcpPayload(
        withMeta(
          service,
          service.buildDetectionPlaybook(architecture_pattern, data_types, deployment_context, max_items),
          {
            confidence: "inferred",
            rationale:
              "Playbook items are generated from matched telecom threat scenarios, known detection indicators, and architecture telemetry mapping."
          }
        )
      )
  );

  server.tool(
    "build_telecom_expert_brief",
    "Build an integrated telecom expert brief: obligations, threats, controls, evidence, conflicts, and prioritized actions",
    {
      country: z.string(),
      role: z.string().optional(),
      architecture_patterns: z.array(z.string()).default([]),
      system_types: z.array(z.string()).default([]),
      data_types: z.array(z.string()).default([]),
      service_types: z.array(z.string()).default([]),
      size: z.enum(["small", "medium", "large"]).optional(),
      deployment_context: z.string().optional(),
      additional_context: z.record(z.unknown()).optional(),
      audit_type: z.string().optional()
    },
    async (args: {
      country: string;
      role?: string;
      architecture_patterns: string[];
      system_types: string[];
      data_types: string[];
      service_types: string[];
      size?: "small" | "medium" | "large";
      deployment_context?: string;
      additional_context?: Record<string, unknown>;
      audit_type?: string;
    }) => {
      const brief = service.buildTelecomExpertBrief(args);
      const foundationCalls = buildFoundationCallsForApplicability(
        args.country,
        brief.applicability.obligations
      );
      const foundationJoinResults = await foundationAdapter.invokeAll(foundationCalls);
      return mcpPayload(
        withMeta(
          service,
          {
            ...brief,
            foundation_join_results: foundationJoinResults
          },
          {
            confidence: "inferred",
            rationale:
              "Expert brief composes domain obligations, threat intelligence, and operational planning with foundation MCP joins for legal/control enrichment.",
            foundationCalls
          }
        )
      );
    }
  );

  server.tool(
    "build_threat_remediation_backlog",
    "Build prioritized remediation backlog from telecom threat intelligence context",
    {
      architecture_patterns: z.array(z.string()).default([]),
      data_types: z.array(z.string()).default([]),
      deployment_context: z.string().optional(),
      max_items: z.number().int().min(1).max(30).default(12)
    },
    async ({
      architecture_patterns,
      data_types,
      deployment_context,
      max_items
    }: {
      architecture_patterns: string[];
      data_types: string[];
      deployment_context?: string;
      max_items: number;
    }) =>
      mcpPayload(
        withMeta(
          service,
          service.buildThreatRemediationBacklog(
            architecture_patterns,
            data_types,
            deployment_context,
            max_items
          ),
          {
            confidence: "inferred",
            rationale:
              "Backlog items are generated from ranked telecom threat scenarios with severity and regulation linkage."
          }
        )
      )
  );

  server.tool(
    "build_architecture_hardening_plan",
    "Build architecture-specific hardening plan with obligations, threats, controls, detection, evidence, and verification checks",
    {
      architecture_pattern: z.string(),
      country: z.string(),
      role: z.string().optional(),
      data_types: z.array(z.string()).default([]),
      service_types: z.array(z.string()).default([]),
      size: z.enum(["small", "medium", "large"]).optional(),
      deployment_context: z.string().optional(),
      audit_type: z.string().optional(),
      additional_context: z.record(z.unknown()).optional()
    },
    async (args: {
      architecture_pattern: string;
      country: string;
      role?: string;
      data_types: string[];
      service_types: string[];
      size?: "small" | "medium" | "large";
      deployment_context?: string;
      audit_type?: string;
      additional_context?: Record<string, unknown>;
    }) =>
      mcpPayload(
        withMeta(
          service,
          service.buildArchitectureHardeningPlan(args),
          {
            confidence: "inferred",
            rationale:
              "Plan combines architecture-specific threats, jurisdiction obligations, and implementation controls into an actionable hardening blueprint."
          }
        )
      )
  );

  server.tool(
    "build_compliance_evidence_matrix",
    "Map obligations to evidence artifacts and control candidates for a telecom profile",
    {
      country: z.string(),
      role: z.string().optional(),
      system_types: z.array(z.string()).default([]),
      data_types: z.array(z.string()).default([]),
      service_types: z.array(z.string()).default([]),
      size: z.enum(["small", "medium", "large"]).optional(),
      audit_type: z.string().optional(),
      additional_context: z.record(z.unknown()).optional()
    },
    async (args: {
      country: string;
      role?: string;
      system_types: string[];
      data_types: string[];
      service_types: string[];
      size?: "small" | "medium" | "large";
      audit_type?: string;
      additional_context?: Record<string, unknown>;
    }) =>
      mcpPayload(
        withMeta(
          service,
          service.buildComplianceEvidenceMatrix(args),
          {
            confidence: "inferred",
            rationale:
              "Matrix links obligation outputs to evidence artifacts and controls to support audit-readiness planning."
          }
        )
      )
  );

  server.tool(
    "assess_applicability",
    "Regulatory and standards obligation map for telecom profiles",
    {
      country: z.string(),
      role: z.string().optional(),
      system_types: z.array(z.string()).default([]),
      data_types: z.array(z.string()).default([]),
      service_types: z.array(z.string()).default([]),
      size: z.enum(["small", "medium", "large"]).optional(),
      additional_context: z.record(z.unknown()).optional()
    },
    async (args: {
      country: string;
      role?: string;
      system_types?: string[];
      data_types?: string[];
      service_types?: string[];
      size?: "small" | "medium" | "large";
      additional_context?: Record<string, unknown>;
    }) => {
      const result = service.assessApplicability(args);
      const foundationCalls = buildFoundationCallsForApplicability(args.country, result.obligations);
      const foundationJoinResults = await foundationAdapter.invokeAll(foundationCalls);

      return mcpPayload(
        withMeta(
          service,
          {
            ...result,
            foundation_join_results: foundationJoinResults
          },
          {
          confidence: "inferred",
          rationale:
            "Deterministic precedence-based applicability engine with foundation MCP join execution for authoritative references.",
          foundationCalls
          }
        )
      );
    }
  );

  server.tool(
    "explain_obligation_conflicts",
    "Run applicability and return only detected obligation conflicts with strictness resolution guidance",
    {
      country: z.string(),
      role: z.string().optional(),
      system_types: z.array(z.string()).default([]),
      data_types: z.array(z.string()).default([]),
      service_types: z.array(z.string()).default([]),
      size: z.enum(["small", "medium", "large"]).optional(),
      additional_context: z.record(z.unknown()).optional()
    },
    async (args: {
      country: string;
      role?: string;
      system_types?: string[];
      data_types?: string[];
      service_types?: string[];
      size?: "small" | "medium" | "large";
      additional_context?: Record<string, unknown>;
    }) => {
      const result = service.assessApplicability(args);
      return mcpPayload(
        withMeta(
          service,
          {
            profile_summary: result.profile_summary,
            conflicts: result.conflicts,
            conflict_count: result.conflicts.length
          },
          {
            confidence: "inferred",
            rationale:
              "Conflict analysis groups obligations by topic and applies strictest-directive strategy when directives diverge."
          }
        )
      );
    }
  );

  server.tool(
    "map_to_technical_standards",
    "Map requirement/control references to telecom standards",
    {
      requirement_ref: z.string().optional(),
      control_id: z.string().optional()
    },
    async ({ requirement_ref, control_id }: { requirement_ref?: string; control_id?: string }) => {
      const result = service.mapToTechnicalStandards(requirement_ref, control_id);
      return mcpPayload(
        withMeta(service, result, {
          confidence: "inferred",
          rationale: "Mapped against telecom technical standards catalog and control crosswalk entries."
        })
      );
    }
  );

  server.tool(
    "search_domain_knowledge",
    "Search architecture, data taxonomy, threat catalog and standards",
    {
      query: z.string(),
      content_type: z.string().optional(),
      limit: z.number().int().min(1).max(25).default(10)
    },
    async ({ query, content_type, limit }: { query: string; content_type?: string; limit: number }) =>
      mcpPayload(
        withMeta(
          service,
          service.searchDomainKnowledge(query, content_type, limit),
          {
            confidence: "inferred",
            rationale: "Keyword and relevance scoring across seeded domain datasets with token-safe limits."
          }
        )
      )
  );

  server.tool(
    "compare_jurisdictions",
    "Side-by-side telecom obligation comparison across jurisdictions",
    {
      topic: z.string(),
      jurisdictions: z.array(z.string()).min(2)
    },
    async ({ topic, jurisdictions }: { topic: string; jurisdictions: string[] }) =>
      mcpPayload(withMeta(service, service.compareJurisdictions(topic, jurisdictions), { confidence: "inferred" }))
  );

  server.tool(
    "build_control_baseline",
    "Build prioritized control baseline for telecom organization profile",
    {
      org_profile: z.object({
        country: z.string(),
        role: z.string().optional(),
        system_types: z.array(z.string()).optional(),
        data_types: z.array(z.string()).optional(),
        service_types: z.array(z.string()).optional(),
        size: z.enum(["small", "medium", "large"]).optional()
      })
    },
    async ({ org_profile }: { org_profile: { country: string; role?: string; system_types?: string[]; data_types?: string[]; service_types?: string[]; size?: "small" | "medium" | "large" } }) =>
      mcpPayload(withMeta(service, service.buildControlBaseline(org_profile), { confidence: "inferred" }))
  );

  server.tool(
    "build_evidence_plan",
    "Generate audit artifact plan",
    {
      baseline: z
        .object({
          controls: z.array(z.union([z.string(), z.object({ control_id: z.string() })])).optional()
        })
        .default({}),
      audit_type: z.string().optional()
    },
    async ({ baseline, audit_type }: { baseline: { controls?: string[] | Array<{ control_id: string }> }; audit_type?: string }) =>
      mcpPayload(withMeta(service, service.buildEvidencePlan(baseline, audit_type), { confidence: "inferred" }))
  );

  server.tool(
    "assess_breach_obligations",
    "Assess telecom breach notification obligations",
    {
      incident_description: z.string(),
      jurisdictions: z.array(z.string()).min(1),
      data_types: z.array(z.string()).default([])
    },
    async ({ incident_description, jurisdictions, data_types }: { incident_description: string; jurisdictions: string[]; data_types: string[] }) =>
      mcpPayload(withMeta(service, service.assessBreachObligations(incident_description, jurisdictions, data_types), { confidence: "inferred" }))
  );

  server.tool(
    "create_remediation_backlog",
    "Create prioritized remediation backlog from current state and target baseline",
    {
      current_state: z.object({ controls_implemented: z.array(z.string()).default([]) }).default({}),
      target_baseline: z
        .object({
          controls: z.array(
            z.object({
              control_id: z.string(),
              priority: z.enum(["high", "medium", "low"]).optional()
            })
          )
        })
        .default({ controls: [] })
    },
    async ({ current_state, target_baseline }: { current_state: { controls_implemented?: string[] }; target_baseline: { controls?: Array<{ control_id: string; priority?: string }> } }) =>
      mcpPayload(withMeta(service, service.createRemediationBacklog(current_state, target_baseline), { confidence: "inferred" }))
  );

  server.tool(
    "classify_telecom_entity",
    "EECC + NIS2 telecom entity classification",
    {
      service_types: z.array(z.string()).min(1),
      size: z.enum(["small", "medium", "large"]),
      country: z.string()
    },
    async ({ service_types, size, country }: { service_types: string[]; size: "small" | "medium" | "large"; country: string }) => {
      const result = service.classifyTelecomEntity(service_types, size, country);
      const foundationCalls = buildFoundationCallsForEntityClassification(
        country,
        service_types,
        result.nis2_status
      );
      const foundationJoinResults = await foundationAdapter.invokeAll(foundationCalls);
      return mcpPayload(
        withMeta(service, { ...result, foundation_join_results: foundationJoinResults }, {
          confidence: "inferred",
          foundationCalls
        })
      );
    }
  );

  server.tool(
    "assess_5g_security",
    "Assess 5G architecture posture against EU toolbox and GSMA controls",
    {
      architecture: z.enum(["NSA", "SA"]),
      vendor_mix: z.array(z.string()).default([]),
      deployment_model: z.enum(["on-prem", "hybrid", "cloud-native"]),
      country: z.string().optional()
    },
    async ({ architecture, vendor_mix, deployment_model, country }: { architecture: "NSA" | "SA"; vendor_mix: string[]; deployment_model: "on-prem" | "hybrid" | "cloud-native"; country?: string }) => {
      const result = service.assess5gSecurity(architecture, vendor_mix, deployment_model, country);
      const foundationCalls = buildFoundationCallsFor5gSecurity(country);
      const foundationJoinResults = await foundationAdapter.invokeAll(foundationCalls);
      return mcpPayload(
        withMeta(service, { ...result, foundation_join_results: foundationJoinResults }, {
          confidence: "inferred",
          foundationCalls
        })
      );
    }
  );

  server.tool(
    "assess_lawful_intercept_compliance",
    "Assess lawful intercept obligations for technology and jurisdiction",
    {
      country: z.string(),
      service_types: z.array(z.string()).default([]),
      technology: z.string()
    },
    async ({ country, service_types, technology }: { country: string; service_types: string[]; technology: string }) => {
      const result = service.assessLawfulInterceptCompliance(country, service_types, technology);
      const foundationCalls = buildFoundationCallsForLawfulIntercept(country);
      const foundationJoinResults = await foundationAdapter.invokeAll(foundationCalls);
      return mcpPayload(
        withMeta(service, { ...result, foundation_join_results: foundationJoinResults }, {
          confidence: "inferred",
          foundationCalls
        })
      );
    }
  );

  server.tool(
    "assess_data_retention_obligations",
    "Assess data retention legality and limits",
    {
      data_type: z.string(),
      country: z.string(),
      purpose: z.string()
    },
    async ({ data_type, country, purpose }: { data_type: string; country: string; purpose: string }) => {
      const result = service.assessDataRetentionObligations(data_type, country, purpose);
      const foundationCalls = buildFoundationCallsForRetention(country);
      const foundationJoinResults = await foundationAdapter.invokeAll(foundationCalls);
      return mcpPayload(
        withMeta(service, { ...result, foundation_join_results: foundationJoinResults }, {
          confidence: "inferred",
          foundationCalls
        })
      );
    }
  );

  return server;
}
