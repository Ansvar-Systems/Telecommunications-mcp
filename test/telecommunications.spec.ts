import { describe, expect, it } from "vitest";
import { initializeDatabase } from "../src/db/database.js";
import { TelecomDomainService } from "../src/domain/service.js";
import { buildClauseResolutionPlanSet } from "../src/foundation/planner.js";

function createService() {
  const db = initializeDatabase(":memory:");
  const service = new TelecomDomainService(db);
  return { service, db };
}

describe("Telecommunications MCP domain service", () => {
  it("retrieves core architecture patterns", () => {
    const { service, db } = createService();
    const pattern = service.getArchitecturePattern("tc-5g-core");

    expect(pattern).toBeDefined();
    expect(pattern?.components).toContain("AMF");
    expect(pattern?.components).toContain("SEPP");

    db.close();
  });

  it("classifies Swedish CDR metadata correctly", () => {
    const { service, db } = createService();
    const result = service.classifyData("CDR metadata for Swedish mobile subscribers", ["SE"]);

    expect(result.categories.map((item) => item.id)).toContain("dc-traffic-metadata");
    expect(result.applicable_regimes).toContain("ePrivacy Directive");
    expect(result.applicable_regimes).toContain("GDPR");

    db.close();
  });

  it("flags location data monetization as critical", () => {
    const { service, db } = createService();
    const result = service.classifyData("subscriber location data sold to third-party analytics", ["US", "SE"]);

    expect(result.categories.map((item) => item.id)).toContain("dc-location-data");
    expect(result.protection_tier).toBe("critical");

    db.close();
  });

  it("returns SS7 signaling abuse threats with standards references", () => {
    const { service, db } = createService();
    const result = service.getDomainThreats("tc-5g-core", ["subscriber_data"], "signaling");

    const threatIds = result.threats.map((threat) => threat.threat_id);
    expect(threatIds).toContain("th-ss7-diameter-abuse");

    const ss7Threat = result.threats.find((threat) => threat.threat_id === "th-ss7-diameter-abuse");
    expect(ss7Threat?.regulation_refs.some((ref) => ref.article_or_section.includes("TS 33.117"))).toBe(true);

    db.close();
  });

  it("builds detection playbook entries for matched telecom threats", () => {
    const { service, db } = createService();
    const playbook = service.buildDetectionPlaybook("tc-5g-core", ["subscriber_data", "location_data"], "signaling", 5);

    expect(playbook.playbooks.length).toBeGreaterThan(0);
    expect(playbook.playbooks[0].telemetry_sources.length).toBeGreaterThan(0);
    expect(playbook.playbooks[0].analytic_signals.length).toBeGreaterThan(0);
    expect(playbook.playbooks[0].detection_query_hints.length).toBeGreaterThan(0);
    expect(playbook.summary.returned_playbooks).toBeLessThanOrEqual(5);

    db.close();
  });

  it("builds integrated telecom expert brief for multi-country operator profile", () => {
    const { service, db } = createService();
    const brief = service.buildTelecomExpertBrief({
      country: "SE",
      role: "mobile_operator",
      architecture_patterns: ["tc-5g-core", "tc-edge"],
      system_types: ["tc-5g-core", "tc-edge", "tc-iot-platform"],
      data_types: ["subscriber_data", "traffic_metadata", "location_data"],
      service_types: ["voice", "data", "5g", "cdn"],
      size: "large",
      additional_context: { countries: ["NL", "DE"] },
      deployment_context: "signaling",
      audit_type: "NIS2"
    });

    expect(brief.applicability.obligations.length).toBeGreaterThan(0);
    expect(brief.threat_intelligence.prioritized_threats.length).toBeGreaterThan(0);
    expect(brief.control_baseline.controls.length).toBeGreaterThan(0);
    expect(brief.evidence_plan.evidence_items.length).toBeGreaterThan(0);
    expect(brief.detection_playbooks.playbooks.length).toBeGreaterThan(0);
    expect(brief.recommended_actions.length).toBeGreaterThan(0);

    db.close();
  });

  it("builds threat remediation backlog from prioritized telecom threats", () => {
    const { service, db } = createService();
    const backlog = service.buildThreatRemediationBacklog(
      ["tc-5g-core", "tc-nfv"],
      ["subscriber_data", "traffic_metadata", "network_configuration"],
      "signaling",
      6
    );

    expect(backlog.summary.remediation_items).toBeGreaterThan(0);
    expect(backlog.backlog_items[0].action.length).toBeGreaterThan(0);
    expect(backlog.backlog_items[0].regulation_basis.length).toBeGreaterThan(0);
    expect(backlog.backlog_items.length).toBeLessThanOrEqual(6);

    db.close();
  });

  it("builds architecture hardening plan for 5G core profile", () => {
    const { service, db } = createService();
    const plan = service.buildArchitectureHardeningPlan({
      architecture_pattern: "tc-5g-core",
      country: "SE",
      role: "mobile_operator",
      data_types: ["subscriber_data", "traffic_metadata", "location_data"],
      service_types: ["voice", "data", "5g"],
      size: "large",
      deployment_context: "signaling",
      audit_type: "NIS2",
      additional_context: { countries: ["NL"] }
    });

    expect((plan as { error?: string }).error).toBeUndefined();
    expect((plan as { architecture: { id: string } }).architecture.id).toBe("tc-5g-core");
    expect((plan as { hardening_priorities: string[] }).hardening_priorities.length).toBeGreaterThan(0);
    expect((plan as { verification_checks: string[] }).verification_checks.length).toBeGreaterThan(0);

    db.close();
  });

  it("builds compliance evidence matrix with mapped obligations", () => {
    const { service, db } = createService();
    const matrix = service.buildComplianceEvidenceMatrix({
      country: "SE",
      role: "mobile_operator",
      system_types: ["tc-5g-core"],
      data_types: ["subscriber_data", "traffic_metadata"],
      service_types: ["voice", "data", "5g"],
      size: "large",
      audit_type: "NIS2",
      additional_context: { countries: ["NL"] }
    });

    expect(matrix.summary.obligations_considered).toBeGreaterThan(0);
    expect(matrix.summary.mapped_obligations).toBeGreaterThan(0);
    expect(matrix.matrix.some((row) => row.evidence_items.length > 0 || row.control_candidates.length > 0)).toBe(true);

    db.close();
  });

  it("assesses Swedish mobile operator applicability", () => {
    const { service, db } = createService();
    const result = service.assessApplicability({
      country: "SE",
      role: "mobile_operator",
      size: "large",
      service_types: ["voice", "data", "5g"]
    });

    const regulations = result.obligations.map((obligation) => obligation.regulation_id);
    expect(regulations).toContain("EECC");
    expect(regulations).toContain("NIS2");
    expect(regulations).toContain("LEK");

    db.close();
  });

  it("assesses US ISP obligations", () => {
    const { service, db } = createService();
    const result = service.assessApplicability({
      country: "US",
      role: "isp",
      size: "large",
      service_types: ["broadband", "dns"],
      data_types: ["subscriber_data", "dns_data"]
    });

    const regulations = result.obligations.map((obligation) => obligation.regulation_id);
    expect(regulations).toContain("CPNI");
    expect(regulations).toContain("ECPA/SCA");
    expect(regulations).toContain("CALEA");

    db.close();
  });

  it("maps 3GPP authentication references to technical standards", () => {
    const { service, db } = createService();
    const result = service.mapToTechnicalStandards("TS 33.501 primary authentication", undefined);

    expect(result.standard_mappings.some((mapping) => mapping.standard_id === "3gpp-ts-33-series")).toBe(true);

    db.close();
  });

  it("maps ISO 27701 privacy references to telecom standards catalog", () => {
    const { service, db } = createService();
    const result = service.mapToTechnicalStandards("ISO 27701 privacy rights handling", undefined);

    expect(result.standard_mappings.some((mapping) => mapping.standard_id === "iso-27701")).toBe(true);

    db.close();
  });

  it("maps RFC 9325 TLS recommendations to telecom standards catalog", () => {
    const { service, db } = createService();
    const result = service.mapToTechnicalStandards("RFC 9325 TLS recommendations", undefined);

    expect(result.standard_mappings.some((mapping) => mapping.standard_id === "ietf-rfc-9325")).toBe(true);

    db.close();
  });

  it("maps BGP route origin validation references to RPKI-related telecom standards", () => {
    const { service, db } = createService();
    const result = service.mapToTechnicalStandards("RPKI RFC 6811 route origin validation", undefined);

    expect(result.standard_mappings.some((mapping) => mapping.standard_id === "ietf-rfc-6811")).toBe(true);
    expect(result.standard_mappings.some((mapping) => mapping.standard_id === "ietf-rfc-6480")).toBe(true);

    db.close();
  });

  it("maps DNSSEC hardening references to DNS security standards", () => {
    const { service, db } = createService();
    const result = service.mapToTechnicalStandards("DNSSEC RFC 4035 validation and signing", undefined);

    expect(result.standard_mappings.some((mapping) => mapping.standard_id === "ietf-rfc-dnssec-core")).toBe(true);

    db.close();
  });

  it("maps GSMA FS.19 interconnect references to telecom standards catalog", () => {
    const { service, db } = createService();
    const result = service.mapToTechnicalStandards("GSMA FS.19 interconnect security controls", undefined);

    expect(result.standard_mappings.some((mapping) => mapping.standard_id === "gsma-fs19")).toBe(true);

    db.close();
  });

  it("maps 3GPP TS 33.126 lawful interception references to expanded 3GPP LI standards", () => {
    const { service, db } = createService();
    const result = service.mapToTechnicalStandards("3GPP TS 33.126 lawful interception requirements", undefined);

    expect(result.standard_mappings.some((mapping) => mapping.standard_id === "3gpp-ts-33-li")).toBe(true);

    db.close();
  });

  it("maps ITU-T X.805 security architecture references", () => {
    const { service, db } = createService();
    const result = service.mapToTechnicalStandards("ITU-T X.805 telecom security architecture model", undefined);

    expect(result.standard_mappings.some((mapping) => mapping.standard_id === "itu-t-x805")).toBe(true);

    db.close();
  });

  it("maps RFC 3704 ingress filtering references to anti-spoofing routing standards", () => {
    const { service, db } = createService();
    const result = service.mapToTechnicalStandards("RFC 3704 BCP 38 ingress filtering at ISP edge", undefined);

    expect(result.standard_mappings.some((mapping) => mapping.standard_id === "ietf-rfc-3704")).toBe(true);

    db.close();
  });

  it("maps RFC 9234 route leak prevention references", () => {
    const { service, db } = createService();
    const result = service.mapToTechnicalStandards("RFC 9234 route leak prevention and OTC validation", undefined);

    expect(result.standard_mappings.some((mapping) => mapping.standard_id === "ietf-rfc-9234")).toBe(true);

    db.close();
  });

  it("maps RFC 8210 RPKI-to-router references", () => {
    const { service, db } = createService();
    const result = service.mapToTechnicalStandards("RFC 8210 cache to router protocol for RPKI", undefined);

    expect(result.standard_mappings.some((mapping) => mapping.standard_id === "ietf-rfc-8210")).toBe(true);

    db.close();
  });

  it("maps ETSI EN 303 645 IoT security references", () => {
    const { service, db } = createService();
    const result = service.mapToTechnicalStandards("ETSI EN 303 645 consumer IoT cybersecurity baseline", undefined);

    expect(result.standard_mappings.some((mapping) => mapping.standard_id === "etsi-en-303-645")).toBe(true);

    db.close();
  });

  it("maps ETSI TS 103 701 IoT conformance references", () => {
    const { service, db } = createService();
    const result = service.mapToTechnicalStandards("ETSI TS 103 701 conformance assessment methods", undefined);

    expect(result.standard_mappings.some((mapping) => mapping.standard_id === "etsi-ts-103-701")).toBe(true);

    db.close();
  });

  it("maps RFC 8588 SHAKEN PASSporT extension references", () => {
    const { service, db } = createService();
    const result = service.mapToTechnicalStandards("RFC 8588 SHAKEN PASSporT extension", undefined);

    expect(result.standard_mappings.some((mapping) => mapping.standard_id === "ietf-rfc-8588")).toBe(true);

    db.close();
  });

  it("maps RFC 9060 rich call data references", () => {
    const { service, db } = createService();
    const result = service.mapToTechnicalStandards("RFC 9060 rich call data PASSporT", undefined);

    expect(result.standard_mappings.some((mapping) => mapping.standard_id === "ietf-rfc-9060")).toBe(true);

    db.close();
  });

  it("maps ITU-T X.1051 telecom ISMS references", () => {
    const { service, db } = createService();
    const result = service.mapToTechnicalStandards("ITU-T X.1051 telecom ISMS guidance", undefined);

    expect(result.standard_mappings.some((mapping) => mapping.standard_id === "itu-t-x1051")).toBe(true);

    db.close();
  });

  it("compares EU vs US metadata obligations", () => {
    const { service, db } = createService();
    const result = service.compareJurisdictions("metadata retention/access", ["SE", "US"]);

    expect(result.comparison_matrix).toHaveLength(2);
    expect(result.comparison_matrix[0].obligations.join(" ")).toMatch(/ePrivacy|GDPR/i);
    expect(result.comparison_matrix[1].obligations.join(" ")).toMatch(/ECPA|CPNI/i);

    db.close();
  });

  it("compares lawful intercept topic via clause assertions with quality markers", () => {
    const { service, db } = createService();
    const result = service.compareJurisdictions("lawful intercept", ["SE", "US-CA"]);

    expect(result.normalized_topic).toBe("lawful_intercept");
    expect(result.comparison_matrix).toHaveLength(2);
    expect(result.comparison_matrix[0].obligations.join(" ")).toMatch(/ETSI|LEK|lawful/i);
    expect(result.comparison_matrix[1].obligations.join(" ")).toMatch(/CALEA|lawful/i);
    expect(result.comparison_matrix[0].notes).toMatch(/exact references|named references/i);

    db.close();
  });

  it("returns graceful fallback for out-of-scope financial query", () => {
    const { service, db } = createService();
    const result = service.classifyData("SWIFT CSP payment card scoping", ["US"]);

    expect(result.categories).toHaveLength(0);
    expect(result.handling_requirements[0]).toMatch(/Out of telecommunications scope|Unable to classify/);

    db.close();
  });

  it("handles pan-european edge profile with 5G SA, edge and IoT", () => {
    const { service, db } = createService();
    const baseline = service.buildControlBaseline({
      country: "SE",
      role: "mobile_operator",
      size: "large",
      service_types: ["5g", "voice", "data", "cdn"],
      system_types: ["tc-5g-core", "tc-edge", "tc-iot-platform"],
      data_types: ["subscriber_data", "location_data", "iot_m2m_data"]
    });

    expect(baseline.controls.length).toBeGreaterThan(0);
    expect(baseline.controls.map((control) => control.control_id)).toContain("ctrl-risk-mgmt");
    expect(baseline.controls.map((control) => control.control_id)).toContain("ctrl-privacy-governance");

    db.close();
  });

  it("reports full core telecom knowledge coverage", () => {
    const { service, db } = createService();
    const report = service.getKnowledgeCoverageReport();

    expect(report.gaps.missing_architecture_patterns).toHaveLength(0);
    expect(report.gaps.missing_data_categories).toHaveLength(0);
    expect(report.gaps.missing_core_threats).toHaveLength(0);
    expect(report.coverage.threat_scenarios.present).toBeGreaterThanOrEqual(27);
    expect(report.readiness_score).toBeGreaterThanOrEqual(95);

    db.close();
  });

  it("covers all Europe countries and all US states in jurisdiction catalog", () => {
    const { service, db } = createService();
    const catalog = service.getSupportedJurisdictionsCatalog();

    expect(catalog.summary.europe_country_count).toBeGreaterThanOrEqual(50);
    expect(catalog.summary.us_state_count).toBe(51);
    expect(catalog.europe_countries.some((entry) => entry.code === "FR")).toBe(true);
    expect(catalog.europe_countries.some((entry) => entry.code === "GB")).toBe(true);
    expect(catalog.us_states.some((entry) => entry.code === "CA")).toBe(true);
    expect(catalog.us_states.some((entry) => entry.code === "NY")).toBe(true);

    db.close();
  });

  it("applies France national telecom overlays in applicability output", () => {
    const { service, db } = createService();
    const result = service.assessApplicability({
      country: "FR",
      role: "mobile_operator",
      size: "large",
      service_types: ["voice", "data", "5g"],
      data_types: ["subscriber_data", "traffic_metadata"]
    });

    const regulations = result.obligations.map((obligation) => obligation.regulation_id);
    expect(regulations).toContain("Code des postes et des communications electroniques (CPCE)");
    expect(regulations).toContain("EECC");
    expect(regulations).toContain("NIS2");

    db.close();
  });

  it("applies US state overlays when state code is provided", () => {
    const { service, db } = createService();
    const result = service.assessApplicability({
      country: "US-CA",
      role: "isp",
      size: "large",
      service_types: ["broadband", "dns"],
      data_types: ["subscriber_data", "traffic_metadata", "dns_data"]
    });

    const regulations = result.obligations.map((obligation) => obligation.regulation_id);
    expect(regulations).toContain("California comprehensive consumer privacy law");
    expect(regulations).toContain("California data breach notification statute");
    expect(regulations).toContain("CPNI");
    expect(regulations).toContain("ECPA/SCA");

    db.close();
  });

  it("provides clause-level jurisdiction pack for US-CA with federal and state assertions", () => {
    const { service, db } = createService();
    const pack = service.getJurisdictionClausePack("US-CA");

    expect(pack.assertions.some((entry) => entry.regulation_id === "CPNI")).toBe(true);
    expect(pack.assertions.some((entry) => entry.regulation_id.includes("California"))).toBe(true);
    expect(pack.assertions.some((entry) => entry.article_or_section.includes("47 CFR 64.2001"))).toBe(true);

    db.close();
  });

  it("detects cross-jurisdiction directive conflicts and recommends strictest baseline", () => {
    const { service, db } = createService();
    const result = service.assessApplicability({
      country: "SE",
      role: "mobile_operator",
      size: "large",
      service_types: ["voice", "data", "5g"],
      data_types: ["subscriber_data", "traffic_metadata", "dns_data"],
      additional_context: {
        countries: ["US-CA"]
      }
    });

    expect(result.conflicts.length).toBeGreaterThan(0);
    const privacyConflict = result.conflicts.find((conflict) => conflict.topic === "subscriber_privacy");
    expect(privacyConflict).toBeDefined();
    expect(privacyConflict?.resolution.recommended_directive).toBe("restricted");

    db.close();
  });

  it("passes expertise quality gate across Europe and US jurisdictions", () => {
    const { service, db } = createService();
    const report = service.auditExpertiseQuality();

    expect(report.pass).toBe(true);
    expect(report.summary.jurisdiction_count).toBe(101);
    expect(report.summary.citation_completeness_pct).toBe(100);
    expect(report.gaps.jurisdictions_without_assertions).toHaveLength(0);

    db.close();
  });

  it("returns exact-reference backlog for named assertions", () => {
    const { service, db } = createService();
    const backlog = service.getExactReferenceBacklog();

    expect(backlog.summary.jurisdictions_scanned).toBe(101);
    expect(backlog.summary.named_reference_items).toBeGreaterThan(0);
    expect(backlog.top_jurisdiction_backlog.length).toBeGreaterThan(0);
    expect(backlog.items[0].resolution_hint).toBeDefined();

    db.close();
  });

  it("returns jurisdiction expertise scorecard and scoped drilldown", () => {
    const { service, db } = createService();
    const globalScorecard = service.getJurisdictionExpertiseScorecard();
    const scopedScorecard = service.getJurisdictionExpertiseScorecard("US-CA");

    expect(globalScorecard.scope.jurisdictions_scanned).toBe(101);
    expect(globalScorecard.summary.average_score).toBeGreaterThan(0);
    expect(globalScorecard.lowest_quality.length).toBeGreaterThan(0);
    expect(globalScorecard.highest_quality.length).toBeGreaterThan(0);

    expect(scopedScorecard.scope.requested_jurisdiction).toBe("US-CA");
    expect(scopedScorecard.entries?.length).toBe(1);
    expect(scopedScorecard.entries?.[0].jurisdiction).toBe("US-CA");
    expect(scopedScorecard.entries?.[0].missing_topics).toHaveLength(0);

    db.close();
  });

  it("builds exact-resolution plans only for supported resolver MCPs", () => {
    const { service, db } = createService();
    const seBacklog = service.getExactReferenceBacklog("SE").items;
    const usBacklog = service.getExactReferenceBacklog("US-CA").items;

    const sePlanSet = buildClauseResolutionPlanSet(
      "SE",
      seBacklog.map((item) => ({
        assertion_id: item.assertion_id,
        regulation_id: item.regulation_id,
        article_or_section: item.article_or_section
      }))
    );
    const usPlanSet = buildClauseResolutionPlanSet(
      "US-CA",
      usBacklog.map((item) => ({
        assertion_id: item.assertion_id,
        regulation_id: item.regulation_id,
        article_or_section: item.article_or_section
      }))
    );

    expect(sePlanSet.plans.length).toBe(0);
    expect(sePlanSet.skipped.length).toBeGreaterThan(0);
    expect(usPlanSet.plans.length).toBeGreaterThan(0);

    db.close();
  });

  it("applies exact-reference override and upgrades assertion quality to exact", () => {
    const { service, db } = createService();
    const beforePack = service.getJurisdictionClausePack("SE");
    const target = beforePack.assertions.find((entry) => entry.id === "country-telecom-SE");
    expect(target).toBeDefined();
    expect(target?.reference_quality).toBe("named");

    const beforeBacklog = service.getExactReferenceBacklog("SE").summary.named_reference_items;
    const beforeExactPct = service.auditExpertiseQuality().summary.exact_reference_pct;

    const applyResult = service.applyExactReferenceOverrides("SE", [
      {
        assertion_id: "country-telecom-SE",
        regulation_id: target?.regulation_id ?? "LEK",
        exact_reference: "LEK (2022:482) 8 kap. 1 §",
        citations: [
          {
            type: "CELEX",
            ref: "LEK (2022:482) 8 kap. 1 §",
            source_url: "https://lagen.nu/2022:482"
          }
        ],
        source_confidence: "medium",
        resolved_by: "test-suite",
        notes: "Regression test override"
      }
    ]);

    expect(applyResult.applied).toBe(1);

    const afterPack = service.getJurisdictionClausePack("SE");
    const afterTarget = afterPack.assertions.find((entry) => entry.id === "country-telecom-SE");
    expect(afterTarget?.reference_quality).toBe("exact");
    expect(afterTarget?.article_or_section).toBe("LEK (2022:482) 8 kap. 1 §");
    expect(afterTarget?.citations[0].source_url).toBe("https://lagen.nu/2022:482");

    const afterBacklog = service.getExactReferenceBacklog("SE").summary.named_reference_items;
    const afterExactPct = service.auditExpertiseQuality().summary.exact_reference_pct;
    expect(afterBacklog).toBe(beforeBacklog - 1);
    expect(afterExactPct).toBeGreaterThan(beforeExactPct);

    db.close();
  });
});
