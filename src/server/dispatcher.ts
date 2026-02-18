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

export type ToolDispatchRequest = {
  tool: string;
  arguments?: Record<string, unknown>;
};

export class TelecomToolDispatcher {
  constructor(
    private readonly service: TelecomDomainService,
    private readonly foundationAdapter = new FoundationMcpAdapter()
  ) {}

  async dispatch({ tool, arguments: args = {} }: ToolDispatchRequest) {
    const metadata = this.service.metadataContext();

    const wrap = <T>(data: T) =>
      makeToolResponse(data, {
        datasetVersion: metadata.datasetVersion,
        datasetFingerprint: metadata.datasetFingerprint,
        confidence: "inferred"
      });

    switch (tool) {
      case "about":
        return makeToolResponse(this.service.about(), {
          datasetVersion: metadata.datasetVersion,
          datasetFingerprint: metadata.datasetFingerprint,
          confidence: "authoritative"
        });
      case "get_knowledge_coverage":
        return makeToolResponse(this.service.getKnowledgeCoverageReport(), {
          datasetVersion: metadata.datasetVersion,
          datasetFingerprint: metadata.datasetFingerprint,
          confidence: "authoritative"
        });
      case "list_supported_jurisdictions":
        return makeToolResponse(this.service.getSupportedJurisdictionsCatalog(), {
          datasetVersion: metadata.datasetVersion,
          datasetFingerprint: metadata.datasetFingerprint,
          confidence: "authoritative"
        });
      case "get_jurisdiction_clause_pack":
        {
          const pack = this.service.getJurisdictionClausePack(String(args.jurisdiction ?? ""));
          const resolveExact = Boolean(args.resolve_exact_references ?? false);
          const persistExact = Boolean(args.persist_exact_references ?? false);
          if (!resolveExact) {
            return makeToolResponse(pack, {
              datasetVersion: metadata.datasetVersion,
              datasetFingerprint: metadata.datasetFingerprint,
              confidence: "authoritative"
            });
          }
          const namedAssertions = pack.assertions
            .filter((assertion) => assertion.reference_quality === "named")
            .map((assertion) => ({
              assertion_id: assertion.id,
              regulation_id: assertion.regulation_id,
              article_or_section: assertion.article_or_section
            }));
          const planSet = buildClauseResolutionPlanSet(pack.jurisdiction, namedAssertions);
          const foundation_join_results = await this.foundationAdapter.invokeAll(planSet.plans);
          const resolvedCandidates = extractExactReferenceResolutionCandidates(foundation_join_results);
          const persistence_result =
            persistExact && resolvedCandidates.length > 0
              ? this.service.applyExactReferenceOverrides(pack.jurisdiction, resolvedCandidates)
              : undefined;
          const effectivePack =
            persistExact && resolvedCandidates.length > 0
              ? this.service.getJurisdictionClausePack(pack.jurisdiction)
              : pack;
          return makeToolResponse(
            {
              ...effectivePack,
              exact_reference_resolution: {
                requested: true,
                named_assertion_count: namedAssertions.length,
                foundation_call_count: planSet.plans.length,
                unsupported_named_assertion_count: planSet.skipped.length,
                unsupported_named_assertions: planSet.skipped,
                resolved_candidate_count: resolvedCandidates.length,
                foundation_join_results,
                persisted: Boolean(persistence_result),
                persistence_result
              }
            },
            {
              datasetVersion: metadata.datasetVersion,
              datasetFingerprint: metadata.datasetFingerprint,
              confidence: "inferred"
            }
          );
        }
      case "audit_expertise_quality":
        return makeToolResponse(this.service.auditExpertiseQuality(), {
          datasetVersion: metadata.datasetVersion,
          datasetFingerprint: metadata.datasetFingerprint,
          confidence: "authoritative"
        });
      case "get_jurisdiction_expertise_scorecard":
        return makeToolResponse(this.service.getJurisdictionExpertiseScorecard(args.jurisdiction as string | undefined), {
          datasetVersion: metadata.datasetVersion,
          datasetFingerprint: metadata.datasetFingerprint,
          confidence: "authoritative"
        });
      case "get_exact_reference_backlog":
        return makeToolResponse(this.service.getExactReferenceBacklog(args.jurisdiction as string | undefined), {
          datasetVersion: metadata.datasetVersion,
          datasetFingerprint: metadata.datasetFingerprint,
          confidence: "authoritative"
        });
      case "apply_exact_reference_overrides":
        {
          const result = this.service.applyExactReferenceOverrides(
            String(args.jurisdiction ?? ""),
            Array.isArray(args.overrides)
              ? (args.overrides as Array<{
                  assertion_id: string;
                  regulation_id: string;
                  exact_reference: string;
                  citations?: Array<{ type: "CELEX" | "CFR" | "USC" | "ISO" | "IEC" | "NIST" | "ETSI" | "3GPP" | "GSMA" | "RFC"; ref: string; source_url: string }>;
                  source_confidence?: "high" | "medium" | "low";
                  resolved_by?: string;
                  notes?: string;
                }>)
              : []
          );
          return makeToolResponse(
            {
              ...result,
              jurisdiction_pack: this.service.getJurisdictionClausePack(result.jurisdiction)
            },
            {
              datasetVersion: metadata.datasetVersion,
              datasetFingerprint: metadata.datasetFingerprint,
              confidence: "authoritative"
            }
          );
        }
      case "list_sources":
        return wrap({ sources: this.service.listSources(args.source_type as string | undefined) });
      case "list_architecture_patterns":
        return wrap({ patterns: this.service.listArchitecturePatterns(args.category as string | undefined) });
      case "get_architecture_pattern": {
        const pattern = this.service.getArchitecturePattern(String(args.pattern_id ?? ""));
        if (!pattern) {
          return makeToolResponse(
            {
              error: `Pattern not found: ${String(args.pattern_id ?? "")}`
            },
            {
              datasetVersion: metadata.datasetVersion,
              datasetFingerprint: metadata.datasetFingerprint,
              confidence: "estimated",
              outOfScope: ["Use list_architecture_patterns for valid IDs"]
            }
          );
        }
        return wrap(pattern);
      }
      case "classify_data":
        return wrap(
          this.service.classifyData(
            String(args.data_description ?? ""),
            Array.isArray(args.jurisdictions) ? (args.jurisdictions as string[]) : []
          )
        );
      case "get_domain_threats":
        return wrap(
          this.service.getDomainThreats(
            String(args.architecture_pattern ?? ""),
            Array.isArray(args.data_types) ? (args.data_types as string[]) : [],
            args.deployment_context as string | undefined
          )
        );
      case "build_detection_playbook":
        return wrap(
          this.service.buildDetectionPlaybook(
            String(args.architecture_pattern ?? ""),
            Array.isArray(args.data_types) ? (args.data_types as string[]) : [],
            args.deployment_context as string | undefined,
            Number(args.max_items ?? 8)
          )
        );
      case "build_telecom_expert_brief":
        {
          const brief = this.service.buildTelecomExpertBrief({
            country: String(args.country ?? ""),
            role: args.role as string | undefined,
            architecture_patterns: Array.isArray(args.architecture_patterns)
              ? (args.architecture_patterns as string[])
              : [],
            system_types: Array.isArray(args.system_types) ? (args.system_types as string[]) : [],
            data_types: Array.isArray(args.data_types) ? (args.data_types as string[]) : [],
            service_types: Array.isArray(args.service_types) ? (args.service_types as string[]) : [],
            size: (args.size as "small" | "medium" | "large" | undefined) ?? "medium",
            deployment_context: args.deployment_context as string | undefined,
            additional_context: (args.additional_context as Record<string, unknown> | undefined) ?? {},
            audit_type: args.audit_type as string | undefined,
            detail_level:
              (args.detail_level as "compact" | "standard" | "full" | undefined) ?? "standard"
          });
          const plans = buildFoundationCallsForApplicability(String(args.country ?? ""), brief.applicability.obligations);
          const foundation_join_results = await this.foundationAdapter.invokeAll(plans);
          return wrap({ ...brief, foundation_join_results });
        }
      case "build_threat_remediation_backlog":
        return wrap(
          this.service.buildThreatRemediationBacklog(
            Array.isArray(args.architecture_patterns) ? (args.architecture_patterns as string[]) : [],
            Array.isArray(args.data_types) ? (args.data_types as string[]) : [],
            args.deployment_context as string | undefined,
            Number(args.max_items ?? 12)
          )
        );
      case "build_architecture_hardening_plan":
        return wrap(
          this.service.buildArchitectureHardeningPlan({
            architecture_pattern: String(args.architecture_pattern ?? ""),
            country: String(args.country ?? ""),
            role: args.role as string | undefined,
            data_types: Array.isArray(args.data_types) ? (args.data_types as string[]) : [],
            service_types: Array.isArray(args.service_types) ? (args.service_types as string[]) : [],
            size: (args.size as "small" | "medium" | "large" | undefined) ?? "medium",
            deployment_context: args.deployment_context as string | undefined,
            audit_type: args.audit_type as string | undefined,
            additional_context: (args.additional_context as Record<string, unknown> | undefined) ?? {}
          })
        );
      case "build_compliance_evidence_matrix":
        return wrap(
          this.service.buildComplianceEvidenceMatrix({
            country: String(args.country ?? ""),
            role: args.role as string | undefined,
            system_types: Array.isArray(args.system_types) ? (args.system_types as string[]) : [],
            data_types: Array.isArray(args.data_types) ? (args.data_types as string[]) : [],
            service_types: Array.isArray(args.service_types) ? (args.service_types as string[]) : [],
            size: (args.size as "small" | "medium" | "large" | undefined) ?? "medium",
            audit_type: args.audit_type as string | undefined,
            additional_context: (args.additional_context as Record<string, unknown> | undefined) ?? {}
          })
        );
      case "assess_applicability":
        {
          const result = this.service.assessApplicability({
            country: String(args.country ?? ""),
            role: args.role as string | undefined,
            system_types: Array.isArray(args.system_types) ? (args.system_types as string[]) : [],
            data_types: Array.isArray(args.data_types) ? (args.data_types as string[]) : [],
            service_types: Array.isArray(args.service_types) ? (args.service_types as string[]) : [],
            size: (args.size as "small" | "medium" | "large" | undefined) ?? "medium",
            additional_context: (args.additional_context as Record<string, unknown> | undefined) ?? {}
          });
          const plans = buildFoundationCallsForApplicability(String(args.country ?? ""), result.obligations);
          const foundation_join_results = await this.foundationAdapter.invokeAll(plans);
          return wrap({ ...result, foundation_join_results });
        }
      case "explain_obligation_conflicts":
        {
          const result = this.service.assessApplicability({
            country: String(args.country ?? ""),
            role: args.role as string | undefined,
            system_types: Array.isArray(args.system_types) ? (args.system_types as string[]) : [],
            data_types: Array.isArray(args.data_types) ? (args.data_types as string[]) : [],
            service_types: Array.isArray(args.service_types) ? (args.service_types as string[]) : [],
            size: (args.size as "small" | "medium" | "large" | undefined) ?? "medium",
            additional_context: (args.additional_context as Record<string, unknown> | undefined) ?? {}
          });
          return wrap({
            profile_summary: result.profile_summary,
            conflicts: result.conflicts,
            conflict_count: result.conflicts.length
          });
        }
      case "map_to_technical_standards":
        return wrap(
          this.service.mapToTechnicalStandards(
            args.requirement_ref as string | undefined,
            args.control_id as string | undefined
          )
        );
      case "search_domain_knowledge":
        return wrap(
          this.service.searchDomainKnowledge(
            String(args.query ?? ""),
            args.content_type as string | undefined,
            Number(args.limit ?? 10)
          )
        );
      case "compare_jurisdictions":
        return wrap(
          this.service.compareJurisdictions(
            String(args.topic ?? ""),
            Array.isArray(args.jurisdictions) ? (args.jurisdictions as string[]) : []
          )
        );
      case "build_control_baseline":
        return wrap(
          this.service.buildControlBaseline((args.org_profile as Parameters<TelecomDomainService["buildControlBaseline"]>[0]) ?? { country: "US" })
        );
      case "build_evidence_plan":
        return wrap(
          this.service.buildEvidencePlan(
            (args.baseline as { controls?: string[] | Array<{ control_id: string }> }) ?? {},
            args.audit_type as string | undefined
          )
        );
      case "assess_breach_obligations":
        return wrap(
          this.service.assessBreachObligations(
            String(args.incident_description ?? ""),
            Array.isArray(args.jurisdictions) ? (args.jurisdictions as string[]) : [],
            Array.isArray(args.data_types) ? (args.data_types as string[]) : []
          )
        );
      case "create_remediation_backlog":
        return wrap(
          this.service.createRemediationBacklog(
            (args.current_state as { controls_implemented?: string[] }) ?? {},
            (args.target_baseline as { controls?: Array<{ control_id: string; priority?: string }> }) ?? {}
          )
        );
      case "classify_telecom_entity":
        {
          const result = this.service.classifyTelecomEntity(
            Array.isArray(args.service_types) ? (args.service_types as string[]) : [],
            (args.size as "small" | "medium" | "large" | undefined) ?? "medium",
            String(args.country ?? "US")
          );
          const plans = buildFoundationCallsForEntityClassification(
            String(args.country ?? "US"),
            Array.isArray(args.service_types) ? (args.service_types as string[]) : [],
            result.nis2_status
          );
          const foundation_join_results = await this.foundationAdapter.invokeAll(plans);
          return wrap({ ...result, foundation_join_results });
        }
      case "assess_5g_security":
        {
          const result = this.service.assess5gSecurity(
            (args.architecture as "NSA" | "SA" | undefined) ?? "SA",
            Array.isArray(args.vendor_mix) ? (args.vendor_mix as string[]) : [],
            (args.deployment_model as "on-prem" | "hybrid" | "cloud-native" | undefined) ?? "hybrid",
            args.country as string | undefined
          );
          const plans = buildFoundationCallsFor5gSecurity(args.country as string | undefined);
          const foundation_join_results = await this.foundationAdapter.invokeAll(plans);
          return wrap({ ...result, foundation_join_results });
        }
      case "assess_lawful_intercept_compliance":
        {
          const result = this.service.assessLawfulInterceptCompliance(
            String(args.country ?? "US"),
            Array.isArray(args.service_types) ? (args.service_types as string[]) : [],
            String(args.technology ?? "5g")
          );
          const plans = buildFoundationCallsForLawfulIntercept(String(args.country ?? "US"));
          const foundation_join_results = await this.foundationAdapter.invokeAll(plans);
          return wrap({ ...result, foundation_join_results });
        }
      case "assess_data_retention_obligations":
        {
          const result = this.service.assessDataRetentionObligations(
            String(args.data_type ?? "traffic_metadata"),
            String(args.country ?? "US"),
            String(args.purpose ?? "security")
          );
          const plans = buildFoundationCallsForRetention(String(args.country ?? "US"));
          const foundation_join_results = await this.foundationAdapter.invokeAll(plans);
          return wrap({ ...result, foundation_join_results });
        }
      default:
        return makeToolResponse(
          {
            error: `Unknown tool: ${tool}`,
            available_tools: [
              "about",
              "get_knowledge_coverage",
              "list_supported_jurisdictions",
              "get_jurisdiction_clause_pack",
              "audit_expertise_quality",
              "get_jurisdiction_expertise_scorecard",
              "get_exact_reference_backlog",
              "apply_exact_reference_overrides",
              "list_sources",
              "list_architecture_patterns",
              "get_architecture_pattern",
              "classify_data",
              "get_domain_threats",
              "build_detection_playbook",
              "build_telecom_expert_brief",
              "build_threat_remediation_backlog",
              "build_architecture_hardening_plan",
              "build_compliance_evidence_matrix",
              "assess_applicability",
              "explain_obligation_conflicts",
              "map_to_technical_standards",
              "search_domain_knowledge",
              "compare_jurisdictions",
              "build_control_baseline",
              "build_evidence_plan",
              "assess_breach_obligations",
              "create_remediation_backlog",
              "classify_telecom_entity",
              "assess_5g_security",
              "assess_lawful_intercept_compliance",
              "assess_data_retention_obligations"
            ]
          },
          {
            datasetVersion: metadata.datasetVersion,
            datasetFingerprint: metadata.datasetFingerprint,
            confidence: "estimated",
            outOfScope: ["Tool not implemented"]
          }
        );
    }
  }
}
