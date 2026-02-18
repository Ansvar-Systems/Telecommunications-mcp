import type Database from "better-sqlite3";
import {
  getApplicabilityRules,
  getArchitecturePatterns,
  getAuthoritativeSources,
  getDataCategories,
  getEvidenceArtifacts,
  getExactReferenceOverrides,
  getMetadataValue,
  getTechnicalStandards,
  getThreatScenarios,
  upsertExactReferenceOverrides
} from "../db/database.js";
import type {
  ApplicabilityAssessment,
  ApplicabilityRule,
  ArchitecturePattern,
  AssessedObligation,
  DataCategory,
  EvidenceArtifact,
  ExactReferenceOverrideInput,
  ObligationConflict,
  OrgProfile,
  TechnicalStandard,
  ThreatScenario
} from "../types.js";
import {
  getEuropeJurisdictionProfile,
  getUsStateProfile,
  isEuCountryCode,
  parseJurisdiction,
  listEuropeCountryCodes,
  listUsStateCodes
} from "./jurisdictions.js";
import { getJurisdictionClauseAssertions } from "./regimePacks.js";

const SIZE_ORDER: Record<"small" | "medium" | "large", number> = {
  small: 1,
  medium: 2,
  large: 3
};

const DATA_CATEGORY_KEYWORDS: Array<{ id: string; keywords: string[] }> = [
  { id: "dc-subscriber-data", keywords: ["subscriber", "imsi", "msisdn", "billing", "cpni"] },
  { id: "dc-traffic-metadata", keywords: ["cdr", "metadata", "traffic", "connection", "session"] },
  { id: "dc-content-data", keywords: ["voice", "message", "payload", "content", "call recording"] },
  { id: "dc-lawful-intercept", keywords: ["lawful intercept", "warrant", "intercept", "mediation"] },
  { id: "dc-network-configuration", keywords: ["routing", "topology", "configuration", "peering"] },
  { id: "dc-spectrum-data", keywords: ["spectrum", "frequency", "interference"] },
  { id: "dc-location-data", keywords: ["location", "cell tower", "gps", "triangulation"] },
  { id: "dc-dns-data", keywords: ["dns", "resolver", "query log"] },
  { id: "dc-iot-m2m-data", keywords: ["iot", "m2m", "telemetry", "sim ota"] },
  { id: "dc-roaming-data", keywords: ["roaming", "tap", "inter-operator"] }
];

const SPEC_ARCHITECTURE_PATTERN_IDS = [
  "tc-5g-core",
  "tc-ran",
  "tc-nfv",
  "tc-ims",
  "tc-transport",
  "tc-edge",
  "tc-bss",
  "tc-oss",
  "tc-li",
  "tc-dns",
  "tc-isp",
  "tc-iot-platform"
] as const;

const SPEC_DATA_CATEGORY_IDS = [
  "dc-subscriber-data",
  "dc-traffic-metadata",
  "dc-content-data",
  "dc-lawful-intercept",
  "dc-network-configuration",
  "dc-spectrum-data",
  "dc-location-data",
  "dc-dns-data",
  "dc-iot-m2m-data",
  "dc-roaming-data"
] as const;

const SPEC_THREAT_CORE_IDS = [
  "th-5g-sba-compromise",
  "th-slice-isolation-failure",
  "th-sepp-exploitation",
  "th-ss7-diameter-abuse",
  "th-ric-manipulation",
  "th-fake-base-station-imsi",
  "th-sim-swap-esim",
  "th-roaming-exploitation",
  "th-nfv-hypervisor-breakout",
  "th-sdn-controller-compromise",
  "th-mano-orchestrator-manipulation",
  "th-vnf-supply-chain",
  "th-east-west-interception",
  "th-li-unauthorized-access",
  "th-li-target-tipping",
  "th-li-warrant-system-compromise",
  "th-li-overcollection-retention",
  "th-bgp-hijack",
  "th-ddos-dns",
  "th-physical-infrastructure-sabotage",
  "th-submarine-cable-tapping",
  "th-sync-spoofing",
  "th-mass-subscriber-exfiltration",
  "th-location-surveillance",
  "th-metadata-analysis-surveillance",
  "th-dns-surveillance",
  "th-content-interception"
] as const;

const DOMAIN_TOPICS = [
  "security_risk_management",
  "incident_reporting",
  "subscriber_privacy",
  "traffic_location_privacy",
  "lawful_intercept",
  "data_retention",
  "supply_chain",
  "caller_id_authentication"
] as const;

const TECHNICAL_STANDARD_ALIAS_HINTS: Record<string, string[]> = {
  "3gpp-ts-33-series": ["ts 33.501", "sba security", "5g authentication", "5g key hierarchy"],
  "3gpp-ts-33-interconnect": ["ts 33.210", "ts 33.310", "interconnect security", "network domain security"],
  "3gpp-ts-33-li": ["ts 33.126", "ts 33.127", "ts 33.128", "3gpp lawful intercept"],
  "nist-sp-800-53": ["nist 800-53", "sc-7", "au-9", "ac-6"],
  "iec-62443": ["iec 62443", "security levels", "zones and conduits", "iacs security"],
  nis2: ["nis2", "art.21", "art.23", "directive eu 2022/2555"],
  gdpr: ["gdpr", "art.5", "art.32", "regulation eu 2016/679"],
  "fcc-cpni": ["cpni", "47 cfr 64.2001", "47 cfr 64.2011"],
  cra: ["cyber resilience act", "eu cra", "regulation eu 2024/2847"],
  "etsi-li": ["ts 103 120", "etsi lawful intercept", "li handover interface"],
  "gsma-fs11": ["ss7 security", "diameter security", "signaling firewall"],
  "gsma-fs19": ["interconnect security monitoring", "operator interconnect threat monitoring"],
  "gsma-sgp-22": ["consumer esim", "rsp consumer esim"],
  "gsma-sgp-02": ["m2m esim", "m2m rsp"],
  "gsma-sgp-32": ["iot esim", "iot rsp", "euicc iot provisioning"],
  "ietf-rfc-3704": ["bcp38", "bcp 38", "bcp84", "bcp 84", "urpf", "ingress filtering", "anti-spoofing"],
  "ietf-rfc-7454": ["bgp operations", "routing security operations", "prefix filtering"],
  "ietf-rfc-8210": ["rpki-to-router", "rpki to router", "rtr protocol", "cache to router"],
  "ietf-rfc-6480": ["rpki framework", "resource public key infrastructure"],
  "ietf-rfc-6811": ["route origin validation", "rov", "origin validation"],
  "ietf-rfc-8205": ["bgpsec", "path validation"],
  "ietf-rfc-9234": ["route leak", "otc", "only-to-customer"],
  "ietf-rfc-dnssec-core": ["dnssec", "zone signing", "rrsig", "dns validation"],
  "ietf-rfc-7858": ["dot", "dns over tls"],
  "ietf-rfc-8484": ["doh", "dns over https"],
  "ietf-rfc-9156": ["qname minimisation", "qname minimization", "query name minimisation", "query name minimization"],
  "ietf-rfc-8446": ["tls 1.3"],
  "ietf-rfc-8588": ["shaken passport extension", "oob shaken", "out-of-band shaken"],
  "ietf-rfc-8946": ["div passport", "diversion passport", "diverted calls stir"],
  "ietf-rfc-9060": ["rich call data", "rcd passport", "branded calling"],
  "stir-shaken": ["caller id authentication", "robocall mitigation", "passport", "attestation"],
  "etsi-en-303-645": ["consumer iot baseline", "no default password", "iot vulnerability disclosure"],
  "etsi-ts-103-701": ["iot conformity assessment", "en 303 645 conformance"],
  "itu-t-x805": ["security dimensions", "security layers and planes"],
  "itu-t-x1051": ["telecom isms", "telecommunications information security management"],
  "itu-t-x1053": ["telecom threat information sharing", "csp cybersecurity information exchange"]
};

function intersection<T>(a: T[], b: T[]): T[] {
  const right = new Set(b);
  return a.filter((item) => right.has(item));
}

function normalizeCountry(input: string): string {
  return parseJurisdiction(input).country;
}

function isEuCountry(country: string): boolean {
  return isEuCountryCode(normalizeCountry(country));
}

function getJurisdictionBucket(country: string): "EU" | "US" | "OTHER" {
  const normalized = normalizeCountry(country);
  if (normalized === "US") {
    return "US";
  }
  if (isEuCountry(normalized)) {
    return "EU";
  }
  return "OTHER";
}

function normalizeDataType(input: string): string {
  const value = input.trim().toLowerCase();
  if (value.includes("cdr") || value.includes("metadata") || value.includes("traffic")) {
    return "traffic_metadata";
  }
  if (value.includes("location")) {
    return "location_data";
  }
  if (value.includes("dns")) {
    return "dns_data";
  }
  if (value.includes("subscriber") || value.includes("imsi") || value.includes("cpni") || value.includes("msisdn")) {
    return "subscriber_data";
  }
  if (value.includes("content") || value.includes("voice") || value.includes("message") || value.includes("payload")) {
    return "content_data";
  }
  if (value.includes("intercept") || value.includes("warrant")) {
    return "lawful_intercept_data";
  }
  if (value.includes("network") || value.includes("routing") || value.includes("topology")) {
    return "network_configuration";
  }
  if (value.includes("spectrum") || value.includes("frequency")) {
    return "spectrum_data";
  }
  if (value.includes("roaming") || value.includes("tap")) {
    return "roaming_data";
  }
  if (value.includes("iot") || value.includes("m2m") || value.includes("telemetry")) {
    return "iot_m2m_data";
  }
  return value.replace(/\s+/g, "_");
}

function includesAny(haystack: string[], needles: string[]): boolean {
  return intersection(
    haystack.map((x) => x.toLowerCase()),
    needles.map((x) => x.toLowerCase())
  ).length > 0;
}

type DomainTopic =
  | "security_risk_management"
  | "incident_reporting"
  | "subscriber_privacy"
  | "traffic_location_privacy"
  | "lawful_intercept"
  | "data_retention"
  | "supply_chain"
  | "caller_id_authentication";

function inferNationalDataRegimes(country: string, matchedCategoryIds: string[]): string[] {
  const parsed = parseJurisdiction(country);
  const normalized = parsed.country;
  const usState = parsed.state;
  const overlays = new Set<string>();
  const hasTrafficLike = matchedCategoryIds.some((id) =>
    ["dc-traffic-metadata", "dc-location-data", "dc-dns-data", "dc-roaming-data"].includes(id)
  );
  const hasLawfulIntercept = matchedCategoryIds.includes("dc-lawful-intercept");

  if (normalized === "SE" && hasTrafficLike) {
    overlays.add("LEK");
    overlays.add("PTS requirements");
  }
  if (normalized === "NL") {
    if (hasTrafficLike) {
      overlays.add("Telecommunicatiewet");
      overlays.add("Wbni");
    }
    if (hasLawfulIntercept) {
      overlays.add("Telecommunicatiewet");
      overlays.add("WIV");
    }
  }
  if (normalized === "DE" && hasTrafficLike) {
    overlays.add("TKG");
    overlays.add("BNetzA security requirements");
  }
  if (normalized === "US") {
    if (hasTrafficLike) {
      overlays.add("ECPA/SCA");
      overlays.add("state privacy laws");
    }
    if (matchedCategoryIds.includes("dc-subscriber-data")) {
      overlays.add("CPNI");
    }
    if (hasLawfulIntercept) {
      overlays.add("CALEA");
    }
    if (usState) {
      const stateProfile = getUsStateProfile(usState);
      if (stateProfile) {
        overlays.add(stateProfile.privacy_regime);
        overlays.add(stateProfile.breach_notification_law);
      }
    }
  }

  const europeProfile = getEuropeJurisdictionProfile(normalized);
  if (europeProfile) {
    overlays.add(europeProfile.telecom_law);
    if (hasLawfulIntercept || matchedCategoryIds.includes("dc-content-data")) {
      overlays.add(europeProfile.lawful_intercept_law);
    }
    if (!europeProfile.eu_member && hasTrafficLike) {
      europeProfile.privacy_regimes.forEach((regime) => overlays.add(regime));
    }
  }

  return Array.from(overlays);
}

function severityRank(value: string): number {
  switch (value) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    default:
      return 1;
  }
}

export class TelecomDomainService {
  private readonly patterns: ArchitecturePattern[];
  private readonly categories: DataCategory[];
  private readonly threats: ThreatScenario[];
  private readonly standards: TechnicalStandard[];
  private readonly rules: ApplicabilityRule[];
  private readonly evidence: EvidenceArtifact[];
  private readonly sources: ReturnType<typeof getAuthoritativeSources>;
  private readonly datasetVersion: string;
  private readonly datasetFingerprint: string;

  constructor(private readonly db: Database.Database) {
    this.patterns = getArchitecturePatterns(db);
    this.categories = getDataCategories(db);
    this.threats = getThreatScenarios(db);
    this.standards = getTechnicalStandards(db);
    this.rules = getApplicabilityRules(db);
    this.evidence = getEvidenceArtifacts(db);
    this.sources = getAuthoritativeSources(db);
    this.datasetVersion = getMetadataValue(db, "dataset_version") ?? "1.0.0";
    this.datasetFingerprint = getMetadataValue(db, "dataset_fingerprint") ?? "sha256:unknown";
  }

  metadataContext() {
    return {
      datasetVersion: this.datasetVersion,
      datasetFingerprint: this.datasetFingerprint
    };
  }

  about() {
    return {
      name: "telecommunications-mcp",
      version: "1.0.0",
      domain: "telecommunications",
      description:
        "Domain intelligence router for telecom operators, ISPs and digital infrastructure providers (5G, NFV, lawful intercept, ePrivacy/NIS2/US telecom).",
      coverage_summary: {
        architecture_patterns: this.patterns.length,
        data_categories: this.categories.length,
        threat_scenarios: this.threats.length,
        technical_standards: this.standards.length,
        applicability_rules: this.rules.length,
        evidence_artifacts: this.evidence.length,
        authoritative_sources: this.sources.length,
        europe_country_profiles: listEuropeCountryCodes().length,
        us_state_profiles: listUsStateCodes().length
      },
      last_updated: "2026-02-18",
      sources: this.sources.map((source) => ({
        source_name: source.source_name,
        source_url: source.source_url,
        refresh_cadence: source.refresh_cadence
      })),
      known_limitations: [
        "Not a substitute for legal counsel or regulator-specific binding interpretations.",
        "National lawful intercept implementation details vary and require local law MCP joins for final determinations.",
        "Retention constraints in EU contexts are represented as baseline guidance and should be validated for current national jurisprudence.",
        "Country/state overlays provide broad telecom coverage across Europe and US states, with varying depth by jurisdiction."
      ]
    };
  }

  getSupportedJurisdictionsCatalog() {
    const europe = listEuropeCountryCodes().map((code) => {
      const profile = getEuropeJurisdictionProfile(code);
      return {
        code,
        name: profile?.name ?? code,
        eu_member: profile?.eu_member ?? false,
        telecom_law: profile?.telecom_law ?? `${code} national telecom framework`,
        regulator: profile?.regulator ?? `${code} telecom regulator`
      };
    });

    const usStates = listUsStateCodes().map((code) => {
      const profile = getUsStateProfile(code);
      return {
        code,
        name: profile?.name ?? code,
        privacy_regime: profile?.privacy_regime ?? `${code} state privacy framework`
      };
    });

    return {
      europe_countries: europe,
      us_states: usStates,
      summary: {
        europe_country_count: europe.length,
        us_state_count: usStates.length
      }
    };
  }

  private allJurisdictionKeys() {
    const europeJurisdictions = listEuropeCountryCodes();
    const usJurisdictions = listUsStateCodes().map((code) => `US-${code}`);
    return [...europeJurisdictions, ...usJurisdictions];
  }

  getJurisdictionClausePack(jurisdiction: string) {
    const parsed = parseJurisdiction(jurisdiction);
    const baseAssertions = getJurisdictionClauseAssertions(parsed.key);
    const overrideMap = new Map(
      getExactReferenceOverrides(this.db, parsed.key).map((entry) => [entry.assertion_id, entry])
    );
    const assertions = baseAssertions.map((assertion) => {
      const override = overrideMap.get(assertion.id);
      if (!override) {
        return assertion;
      }
      return {
        ...assertion,
        regulation_id: override.regulation_id || assertion.regulation_id,
        article_or_section: override.exact_reference,
        citations: override.citations ?? assertion.citations,
        confidence: override.source_confidence ?? assertion.confidence,
        reference_quality: "exact" as const,
        resolution_hint: undefined
      };
    });

    return {
      jurisdiction: parsed.key,
      country: parsed.country,
      state: parsed.state,
      assertions
    };
  }

  applyExactReferenceOverrides(
    jurisdiction: string,
    overrides: Array<Omit<ExactReferenceOverrideInput, "jurisdiction">>
  ) {
    const parsed = parseJurisdiction(jurisdiction);
    const prepared = overrides
      .map((override) => ({
        ...override,
        jurisdiction: parsed.key,
        assertion_id: override.assertion_id.trim(),
        regulation_id: override.regulation_id.trim(),
        exact_reference: override.exact_reference.trim()
      }))
      .filter(
        (override) =>
          override.assertion_id.length > 0 &&
          override.regulation_id.length > 0 &&
          override.exact_reference.length > 0
      );

    const result = upsertExactReferenceOverrides(this.db, prepared);
    return {
      jurisdiction: parsed.key,
      received: overrides.length,
      applied: result.upserted
    };
  }

  getExactReferenceBacklog(jurisdiction?: string) {
    const scope = jurisdiction ? [parseJurisdiction(jurisdiction).key] : this.allJurisdictionKeys();
    const items: Array<{
      jurisdiction: string;
      assertion_id: string;
      regulation_id: string;
      article_or_section: string;
      resolution_hint?: string;
    }> = [];

    for (const key of scope) {
      const assertions = this.getJurisdictionClausePack(key).assertions;
      for (const assertion of assertions) {
        if (assertion.reference_quality !== "named") {
          continue;
        }
        items.push({
          jurisdiction: key,
          assertion_id: assertion.id,
          regulation_id: assertion.regulation_id,
          article_or_section: assertion.article_or_section,
          resolution_hint: assertion.resolution_hint
        });
      }
    }

    const byJurisdiction = new Map<string, number>();
    for (const item of items) {
      byJurisdiction.set(item.jurisdiction, (byJurisdiction.get(item.jurisdiction) ?? 0) + 1);
    }

    const topJurisdictions = Array.from(byJurisdiction.entries())
      .map(([jurisdiction_key, named_reference_count]) => ({ jurisdiction_key, named_reference_count }))
      .sort((a, b) => b.named_reference_count - a.named_reference_count)
      .slice(0, 20);

    return {
      summary: {
        jurisdictions_scanned: scope.length,
        named_reference_items: items.length
      },
      top_jurisdiction_backlog: topJurisdictions,
      items
    };
  }

  getJurisdictionExpertiseScorecard(jurisdiction?: string) {
    const requested = jurisdiction ? parseJurisdiction(jurisdiction).key : undefined;
    const scope = requested ? [requested] : this.allJurisdictionKeys();

    const entries = scope.map((key) => {
      const assertions = this.getJurisdictionClausePack(key).assertions;
      const exact = assertions.filter((assertion) => assertion.reference_quality === "exact").length;
      const named = assertions.length - exact;
      const namedWithHint = assertions.filter(
        (assertion) => assertion.reference_quality === "named" && typeof assertion.resolution_hint === "string" && assertion.resolution_hint.trim().length > 0
      ).length;
      const topicsCovered = new Set(assertions.map((assertion) => assertion.topic));
      const missingTopics = DOMAIN_TOPICS.filter((topic) => !topicsCovered.has(topic));
      const citationComplete = assertions.filter(
        (assertion) =>
          assertion.citations.length > 0 &&
          assertion.citations.every(
            (citation) =>
              typeof citation.ref === "string" &&
              citation.ref.trim().length > 0 &&
              typeof citation.source_url === "string" &&
              citation.source_url.startsWith("https://")
          )
      ).length;

      const exactPct = assertions.length === 0 ? 0 : Math.round((exact / assertions.length) * 10000) / 100;
      const citationPct = assertions.length === 0 ? 0 : Math.round((citationComplete / assertions.length) * 10000) / 100;
      const topicCoveragePct = Math.round((topicsCovered.size / DOMAIN_TOPICS.length) * 10000) / 100;
      const score = Math.round(exactPct * 0.45 + citationPct * 0.2 + topicCoveragePct * 0.35);

      return {
        jurisdiction: key,
        assertion_count: assertions.length,
        exact_reference_count: exact,
        named_reference_count: named,
        exact_reference_pct: exactPct,
        named_hint_coverage_pct: named === 0 ? 100 : Math.round((namedWithHint / named) * 10000) / 100,
        citation_completeness_pct: citationPct,
        topics_covered: topicsCovered.size,
        topic_coverage_pct: topicCoveragePct,
        missing_topics: missingTopics,
        score
      };
    });

    const sortedByScore = [...entries].sort((a, b) => b.score - a.score || a.jurisdiction.localeCompare(b.jurisdiction));
    const averageScore =
      entries.length === 0 ? 0 : Math.round((entries.reduce((sum, entry) => sum + entry.score, 0) / entries.length) * 100) / 100;

    return {
      scope: {
        requested_jurisdiction: requested ?? null,
        jurisdictions_scanned: entries.length
      },
      summary: {
        average_score: averageScore,
        average_exact_reference_pct:
          entries.length === 0
            ? 0
            : Math.round((entries.reduce((sum, entry) => sum + entry.exact_reference_pct, 0) / entries.length) * 100) / 100
      },
      highest_quality: sortedByScore.slice(0, 10),
      lowest_quality: [...sortedByScore].reverse().slice(0, 10),
      entries: requested ? sortedByScore : undefined
    };
  }

  auditExpertiseQuality() {
    const europeJurisdictions = listEuropeCountryCodes();
    const usJurisdictions = listUsStateCodes().map((code) => `US-${code}`);
    const allJurisdictions = this.allJurisdictionKeys();

    let assertionCount = 0;
    let citationCompleteCount = 0;
    let exactReferenceCount = 0;
    let namedReferenceCount = 0;
    let namedWithHintCount = 0;
    const jurisdictionsWithoutAssertions: string[] = [];
    const citationGaps: Array<{ jurisdiction: string; assertion_id: string }> = [];

    const topicCoverage = new Map<string, number>();

    for (const jurisdiction of allJurisdictions) {
      const assertions = this.getJurisdictionClausePack(jurisdiction).assertions;
      if (assertions.length === 0) {
        jurisdictionsWithoutAssertions.push(jurisdiction);
        continue;
      }

      for (const assertion of assertions) {
        assertionCount += 1;
        topicCoverage.set(assertion.topic, (topicCoverage.get(assertion.topic) ?? 0) + 1);

        const citationComplete =
          assertion.citations.length > 0 &&
          assertion.citations.every(
            (citation) =>
              typeof citation.ref === "string" &&
              citation.ref.trim().length > 0 &&
              typeof citation.source_url === "string" &&
              citation.source_url.startsWith("https://")
          );
        if (citationComplete) {
          citationCompleteCount += 1;
        } else {
          citationGaps.push({ jurisdiction, assertion_id: assertion.id });
        }

        if (assertion.reference_quality === "exact") {
          exactReferenceCount += 1;
        } else {
          namedReferenceCount += 1;
          if (assertion.resolution_hint && assertion.resolution_hint.trim().length > 0) {
            namedWithHintCount += 1;
          }
        }
      }
    }

    const citationCompletenessPct =
      assertionCount === 0 ? 0 : Math.round((citationCompleteCount / assertionCount) * 10000) / 100;
    const exactReferencePct =
      assertionCount === 0 ? 0 : Math.round((exactReferenceCount / assertionCount) * 10000) / 100;
    const namedReferenceHintCoveragePct =
      namedReferenceCount === 0 ? 100 : Math.round((namedWithHintCount / namedReferenceCount) * 10000) / 100;

    const pass =
      jurisdictionsWithoutAssertions.length === 0 &&
      citationCompletenessPct === 100 &&
      namedReferenceHintCoveragePct >= 100;

    const jurisdictionQuality = this.getJurisdictionExpertiseScorecard();

    return {
      pass,
      summary: {
        jurisdiction_count: allJurisdictions.length,
        assertion_count: assertionCount,
        citation_completeness_pct: citationCompletenessPct,
        exact_reference_pct: exactReferencePct,
        named_reference_pct: Math.round((namedReferenceCount / Math.max(1, assertionCount)) * 10000) / 100,
        named_reference_hint_coverage_pct: namedReferenceHintCoveragePct
      },
      coverage: {
        europe_jurisdictions: europeJurisdictions.length,
        us_state_jurisdictions: usJurisdictions.length,
        topics: Array.from(topicCoverage.entries()).map(([topic, count]) => ({ topic, count }))
      },
      gaps: {
        jurisdictions_without_assertions: jurisdictionsWithoutAssertions,
        citation_gaps: citationGaps
      },
      quality_gate: {
        citation_completeness_required_pct: 100,
        named_reference_hint_required_pct: 100,
        jurisdictions_without_assertions_required: 0
      },
      jurisdiction_quality_snapshot: {
        average_score: jurisdictionQuality.summary.average_score,
        average_exact_reference_pct: jurisdictionQuality.summary.average_exact_reference_pct,
        lowest_quality: jurisdictionQuality.lowest_quality,
        highest_quality: jurisdictionQuality.highest_quality
      }
    };
  }

  getKnowledgeCoverageReport() {
    const patternIds = new Set(this.patterns.map((pattern) => pattern.id));
    const dataCategoryIds = new Set(this.categories.map((category) => category.id));
    const threatIds = new Set(this.threats.map((threat) => threat.id));

    const missingPatterns = SPEC_ARCHITECTURE_PATTERN_IDS.filter((id) => !patternIds.has(id));
    const missingDataCategories = SPEC_DATA_CATEGORY_IDS.filter((id) => !dataCategoryIds.has(id));
    const missingCoreThreats = SPEC_THREAT_CORE_IDS.filter((id) => !threatIds.has(id));

    const patternCoverage = Math.round(
      ((SPEC_ARCHITECTURE_PATTERN_IDS.length - missingPatterns.length) / SPEC_ARCHITECTURE_PATTERN_IDS.length) * 100
    );
    const dataCoverage = Math.round(
      ((SPEC_DATA_CATEGORY_IDS.length - missingDataCategories.length) / SPEC_DATA_CATEGORY_IDS.length) * 100
    );
    const threatCoverage = Math.round(
      ((SPEC_THREAT_CORE_IDS.length - missingCoreThreats.length) / SPEC_THREAT_CORE_IDS.length) * 100
    );

    const applicabilityBreadth = new Set(this.rules.map((rule) => rule.obligation.regulation_id)).size;
    const standardsBreadth = this.standards.length;
    const supportedEuropeCountries = listEuropeCountryCodes().length;
    const supportedUsStates = listUsStateCodes().length;
    const jurisdictionCoverage = Math.round(
      ((supportedEuropeCountries / 50) * 100 + (supportedUsStates / 51) * 100) / 2
    );
    const readinessScore = Math.max(
      0,
      Math.min(
        100,
        Math.round(
          patternCoverage * 0.18 +
            dataCoverage * 0.18 +
            threatCoverage * 0.3 +
            Math.min(100, applicabilityBreadth * 8) * 0.12 +
            Math.min(100, standardsBreadth * 6) * 0.1 +
            jurisdictionCoverage * 0.12
        )
      )
    );

    return {
      readiness_score: readinessScore,
      coverage: {
        architecture_patterns: {
          present: this.patterns.length,
          expected_core: SPEC_ARCHITECTURE_PATTERN_IDS.length,
          core_coverage_pct: patternCoverage
        },
        data_categories: {
          present: this.categories.length,
          expected_core: SPEC_DATA_CATEGORY_IDS.length,
          core_coverage_pct: dataCoverage
        },
        threat_scenarios: {
          present: this.threats.length,
          expected_core: SPEC_THREAT_CORE_IDS.length,
          core_coverage_pct: threatCoverage
        },
        technical_standards: {
          present: this.standards.length
        },
        applicability_rules: {
          present: this.rules.length,
          unique_regimes: applicabilityBreadth
        },
        jurisdictions: {
          europe_countries_supported: supportedEuropeCountries,
          us_states_supported: supportedUsStates,
          coverage_pct: jurisdictionCoverage
        }
      },
      gaps: {
        missing_architecture_patterns: missingPatterns,
        missing_data_categories: missingDataCategories,
        missing_core_threats: missingCoreThreats
      },
      improvement_focus: [
        "Increase clause-level precision for each European country profile and each US state overlay.",
        "Add regulator bulletin ingestion for real-time updates from ARCEP, BNetzA, Ofcom, FCC and state authorities.",
        "Increase threat intelligence linkage to real incident references and ATT&CK coverage updates."
      ]
    };
  }

  listSources(sourceType?: string) {
    if (!sourceType) {
      return this.sources;
    }

    return this.sources.filter((source) => source.source_type.toLowerCase() === sourceType.toLowerCase());
  }

  listArchitecturePatterns(category?: string) {
    if (!category) {
      return this.patterns.map((pattern) => ({
        pattern_id: pattern.id,
        name: pattern.name,
        category: pattern.category,
        description: pattern.description
      }));
    }

    const normalizedCategory = category.toLowerCase();
    return this.patterns
      .filter(
        (pattern) =>
          pattern.category.toLowerCase() === normalizedCategory ||
          pattern.name.toLowerCase().includes(normalizedCategory)
      )
      .map((pattern) => ({
        pattern_id: pattern.id,
        name: pattern.name,
        category: pattern.category,
        description: pattern.description
      }));
  }

  getArchitecturePattern(patternId: string) {
    return this.patterns.find((pattern) => pattern.id === patternId);
  }

  classifyData(dataDescription: string, jurisdictions: string[]) {
    const lower = dataDescription.toLowerCase();
    const matchedCategoryIds = DATA_CATEGORY_KEYWORDS.filter((entry) =>
      entry.keywords.some((keyword) => lower.includes(keyword))
    ).map((entry) => entry.id);

    const matchedCategories = this.categories.filter((category) => matchedCategoryIds.includes(category.id));

    if (matchedCategories.length === 0) {
      const lowerDescription = dataDescription.toLowerCase();
      const financialSignal =
        lowerDescription.includes("swift") ||
        lowerDescription.includes("pci") ||
        lowerDescription.includes("payment card");
      return {
        categories: [],
        applicable_regimes: [],
        protection_tier: "baseline",
        handling_requirements: [
          financialSignal
            ? "Out of telecommunications scope. Route to Financial Services MCP for payment network and SWIFT compliance analysis."
            : "Unable to classify from current telecom taxonomy. Provide more specific telecom context or route to another domain MCP."
        ],
        recommended_mcp: financialSignal ? "financial-services-mcp" : undefined
      };
    }

    const normalizedJurisdictions = jurisdictions.length === 0 ? ["EU", "US"] : jurisdictions.map(normalizeCountry);

    const applicableRegimes = new Set<string>();
    const handlingRequirements = new Set<string>();
    let maxTierRank = 1;
    let maxTier: "baseline" | "elevated" | "high" | "critical" = "baseline";

    for (const category of matchedCategories) {
      for (const jurisdiction of normalizedJurisdictions) {
        const bucket = getJurisdictionBucket(jurisdiction);
        if (bucket === "OTHER") {
          continue;
        }

        const protections = category.jurisdiction_protections[bucket];
        if (!protections) {
          continue;
        }

        protections.regime.forEach((regime) => applicableRegimes.add(regime));
        protections.controls.forEach((control) => handlingRequirements.add(control));

        const tierRank = severityRank(protections.tier);
        if (tierRank > maxTierRank) {
          maxTierRank = tierRank;
          maxTier = protections.tier;
        }
      }

      category.deidentification_requirements.forEach((requirement) => handlingRequirements.add(requirement));
      category.cross_border_constraints.forEach((constraint) => handlingRequirements.add(constraint));
    }

    for (const jurisdiction of normalizedJurisdictions) {
      inferNationalDataRegimes(jurisdiction, matchedCategoryIds).forEach((regime) => applicableRegimes.add(regime));
    }

    return {
      categories: matchedCategories.map((category) => ({ id: category.id, name: category.name })),
      applicable_regimes: Array.from(applicableRegimes),
      protection_tier: maxTier,
      handling_requirements: Array.from(handlingRequirements)
    };
  }

  getDomainThreats(
    architecturePattern: string,
    dataTypes: string[],
    deploymentContext?: string
  ) {
    const normalizedDataTypes = dataTypes.map(normalizeDataType);
    const normalizedPattern = architecturePattern.toLowerCase();

    const matched = this.threats.filter((threat) => {
      const matchesPattern =
        threat.affected_patterns.includes(architecturePattern) ||
        threat.affected_patterns.some((patternId) => patternId.toLowerCase().includes(normalizedPattern));

      const matchesData =
        normalizedDataTypes.length === 0 ||
        threat.affected_data_categories.some((categoryId) =>
          normalizedDataTypes.some((dataType) => categoryId.includes(dataType.split("_")[0]))
        );

      const matchesContext =
        !deploymentContext ||
        threat.name.toLowerCase().includes(deploymentContext.toLowerCase()) ||
        threat.description.toLowerCase().includes(deploymentContext.toLowerCase()) ||
        threat.attack_narrative.toLowerCase().includes(deploymentContext.toLowerCase()) ||
        threat.category.toLowerCase().includes(deploymentContext.toLowerCase());

      return matchesPattern && matchesData && matchesContext;
    });

    return {
      threats: matched.map((threat) => ({
        threat_id: threat.id,
        name: threat.name,
        category: threat.category,
        description: threat.description,
        mitre_mapping: threat.mitre_mapping,
        regulation_refs: threat.regulation_refs,
        severity: this.computeThreatSeverity(threat),
        likelihood_factors: threat.likelihood_factors,
        detection_indicators: threat.detection_indicators
      }))
    };
  }

  buildDetectionPlaybook(
    architecturePattern: string,
    dataTypes: string[],
    deploymentContext?: string,
    maxItems = 8
  ) {
    const max = Math.max(1, Math.min(maxItems, 20));
    const matchedThreats = this.getDomainThreats(architecturePattern, dataTypes, deploymentContext).threats;
    const threatById = new Map(this.threats.map((threat) => [threat.id, threat]));

    const ranked = [...matchedThreats].sort(
      (a, b) =>
        severityRank(b.severity) - severityRank(a.severity) ||
        b.detection_indicators.length - a.detection_indicators.length
    );

    const playbookItems = ranked.slice(0, max).map((threat) => {
      const fullThreat = threatById.get(threat.threat_id);
      const telemetry = Array.from(
        new Set(
          (fullThreat?.affected_patterns ?? [])
            .flatMap((patternId) => this.telemetrySourcesForPattern(patternId))
            .concat(["SIEM correlation events", "identity provider audit logs"])
        )
      );
      const queryHints = this.detectionQueryHintsForThreat(threat.threat_id, threat.category);

      return {
        playbook_id: `dp-${threat.threat_id}`,
        threat_id: threat.threat_id,
        threat_name: threat.name,
        category: threat.category,
        severity: threat.severity,
        mitre_mapping: threat.mitre_mapping,
        telemetry_sources: telemetry,
        analytic_signals: threat.detection_indicators.slice(0, 6),
        detection_query_hints: queryHints,
        triage_steps: [
          "Confirm affected network domains, subscriber scope, and service impact.",
          "Validate whether behavior is tied to approved maintenance windows or legal workflows.",
          "Escalate to telecom SOC and domain SMEs for containment decision."
        ],
        response_actions: [
          "Contain compromised accounts, functions, or interfaces.",
          "Apply targeted blocking, policy rollback, or route control actions.",
          "Document regulator-notification decision points and evidence trail."
        ],
        compliance_links: threat.regulation_refs,
        operational_confidence:
          threat.severity === "critical" || threat.severity === "high" ? "high" : "medium"
      };
    });

    return {
      context: {
        architecture_pattern: architecturePattern,
        data_types: dataTypes.map(normalizeDataType),
        deployment_context: deploymentContext ?? null
      },
      summary: {
        matched_threats: matchedThreats.length,
        returned_playbooks: playbookItems.length
      },
      playbooks: playbookItems
    };
  }

  buildTelecomExpertBrief(input: {
    country: string;
    role?: string;
    architecture_patterns?: string[];
    system_types?: string[];
    data_types?: string[];
    service_types?: string[];
    size?: "small" | "medium" | "large";
    deployment_context?: string;
    additional_context?: Record<string, unknown>;
    audit_type?: string;
    detail_level?: "compact" | "standard" | "full";
  }) {
    const countryKey = parseJurisdiction(input.country).key;
    const detailLevel = input.detail_level ?? "standard";
    const dataTypes = input.data_types ?? [];
    const serviceTypes = input.service_types ?? [];
    const systemTypes = input.system_types ?? [];
    const architecturePatterns = input.architecture_patterns ?? systemTypes;
    const size = input.size ?? "medium";
    const role = input.role ?? this.inferRoleFromServices(serviceTypes);

    const applicability = this.assessApplicability({
      country: countryKey,
      role,
      size,
      system_types: systemTypes,
      data_types: dataTypes,
      service_types: serviceTypes,
      additional_context: input.additional_context ?? {}
    });

    const entityClassification =
      serviceTypes.length > 0
        ? this.classifyTelecomEntity(serviceTypes, size, countryKey)
        : undefined;

    const threatMap = new Map<
      string,
      {
        threat_id: string;
        name: string;
        category: string;
        severity: "critical" | "high" | "medium";
        mitigation_contexts: string[];
        regulation_refs: Array<{ regulation_id: string; article_or_section: string; foundation_mcp: string }>;
      }
    >();

    for (const pattern of architecturePatterns) {
      const threats = this.getDomainThreats(pattern, dataTypes, input.deployment_context).threats;
      for (const threat of threats) {
        const existing = threatMap.get(threat.threat_id);
        if (!existing) {
          threatMap.set(threat.threat_id, {
            threat_id: threat.threat_id,
            name: threat.name,
            category: threat.category,
            severity: threat.severity,
            mitigation_contexts: [pattern],
            regulation_refs: threat.regulation_refs
          });
          continue;
        }
        if (!existing.mitigation_contexts.includes(pattern)) {
          existing.mitigation_contexts.push(pattern);
        }
      }
    }

    const prioritizedThreats = Array.from(threatMap.values())
      .sort(
        (a, b) =>
          severityRank(b.severity) - severityRank(a.severity) ||
          b.mitigation_contexts.length - a.mitigation_contexts.length ||
          a.name.localeCompare(b.name)
      )
      .slice(0, 12);

    const controlBaseline = this.buildControlBaseline({
      country: countryKey,
      role,
      size,
      system_types: systemTypes,
      data_types: dataTypes,
      service_types: serviceTypes
    });
    const evidencePlan = this.buildEvidencePlan(
      { controls: controlBaseline.controls.map((control) => ({ control_id: control.control_id })) },
      input.audit_type
    );

    const primaryPattern = architecturePatterns[0];
    const detectionMaxItems = detailLevel === "compact" ? 4 : detailLevel === "full" ? 10 : 6;
    const detectionPlaybooks = primaryPattern
      ? this.buildDetectionPlaybook(primaryPattern, dataTypes, input.deployment_context, detectionMaxItems)
      : { context: {}, summary: { matched_threats: 0, returned_playbooks: 0 }, playbooks: [] as Array<unknown> };

    const scorecard = this.getJurisdictionExpertiseScorecard(countryKey);
    const backlog = this.getExactReferenceBacklog(countryKey);

    const recommendedActions: string[] = [];
    if (applicability.conflicts.length > 0) {
      recommendedActions.push(
        "Apply strictest directive for conflicted topics and segment processing by jurisdiction where needed."
      );
    }
    if (backlog.summary.named_reference_items > 0) {
      recommendedActions.push(
        `Resolve ${backlog.summary.named_reference_items} named legal references for ${countryKey} to exact section-level citations.`
      );
    }
    if (controlBaseline.controls.some((control) => control.priority === "high")) {
      recommendedActions.push("Prioritize implementation of high-priority controls before medium/low maturity uplift.");
    }
    if (recommendedActions.length === 0) {
      recommendedActions.push("Maintain continuous control validation and regulator-update monitoring cadence.");
    }

    const obligationLimit = detailLevel === "compact" ? 12 : detailLevel === "full" ? 50 : 25;
    const threatLimit = detailLevel === "compact" ? 6 : detailLevel === "full" ? 20 : 12;
    const controlLimit = detailLevel === "compact" ? 12 : detailLevel === "full" ? controlBaseline.controls.length : 20;
    const evidenceLimit = detailLevel === "compact" ? 10 : detailLevel === "full" ? evidencePlan.evidence_items.length : 20;

    return {
      profile: {
        country: countryKey,
        role,
        size,
        architecture_patterns: architecturePatterns,
        deployment_context: input.deployment_context ?? null,
        detail_level: detailLevel
      },
      entity_classification: entityClassification,
      applicability: {
        obligations: applicability.obligations.slice(0, obligationLimit),
        conflicts: applicability.conflicts,
        matched_rule_count: applicability.matched_rule_count
      },
      threat_intelligence: {
        prioritized_threats: prioritizedThreats.slice(0, threatLimit)
      },
      control_baseline: {
        ...controlBaseline,
        controls: controlBaseline.controls.slice(0, controlLimit)
      },
      evidence_plan: {
        ...evidencePlan,
        evidence_items: evidencePlan.evidence_items.slice(0, evidenceLimit)
      },
      detection_playbooks: detectionPlaybooks,
      expertise_quality: {
        jurisdiction_scorecard:
          detailLevel === "compact"
            ? {
                summary: scorecard.summary,
                lowest_quality: scorecard.lowest_quality,
                highest_quality: scorecard.highest_quality
              }
            : scorecard,
        exact_reference_backlog: backlog.summary
      },
      recommended_actions: recommendedActions
    };
  }

  buildThreatRemediationBacklog(
    architecturePatterns: string[],
    dataTypes: string[],
    deploymentContext?: string,
    maxItems = 12
  ) {
    const patterns = architecturePatterns.length > 0 ? architecturePatterns : ["tc-5g-core"];
    const threatMap = new Map<
      string,
      {
        threat_id: string;
        name: string;
        severity: "critical" | "high" | "medium";
        category: string;
        regulation_refs: Array<{ regulation_id: string; article_or_section: string; foundation_mcp: string }>;
      }
    >();

    for (const pattern of patterns) {
      for (const threat of this.getDomainThreats(pattern, dataTypes, deploymentContext).threats) {
        if (!threatMap.has(threat.threat_id)) {
          threatMap.set(threat.threat_id, {
            threat_id: threat.threat_id,
            name: threat.name,
            severity: threat.severity,
            category: threat.category,
            regulation_refs: threat.regulation_refs
          });
        }
      }
    }

    const items = Array.from(threatMap.values())
      .sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.name.localeCompare(b.name))
      .slice(0, Math.max(1, Math.min(maxItems, 30)))
      .map((threat, index) => {
        const priority: "high" | "medium" | "low" =
          threat.severity === "critical" || threat.severity === "high" ? "high" : "medium";
        const effort = threat.severity === "critical" ? "L" : threat.severity === "high" ? "M" : "S";
        return {
          id: `trb-${index + 1}`,
          threat_id: threat.threat_id,
          action: this.remediationActionForThreat(threat.threat_id, threat.category),
          priority,
          effort_estimate: effort,
          risk_reduction: priority === "high" ? "high" : "medium",
          regulation_basis: threat.regulation_refs.map((ref) => `${ref.regulation_id} ${ref.article_or_section}`).slice(0, 5)
        };
      });

    return {
      context: {
        architecture_patterns: patterns,
        data_types: dataTypes.map(normalizeDataType),
        deployment_context: deploymentContext ?? null
      },
      summary: {
        candidate_threats: threatMap.size,
        remediation_items: items.length
      },
      backlog_items: items
    };
  }

  buildArchitectureHardeningPlan(input: {
    architecture_pattern: string;
    country: string;
    role?: string;
    data_types?: string[];
    service_types?: string[];
    size?: "small" | "medium" | "large";
    deployment_context?: string;
    audit_type?: string;
    additional_context?: Record<string, unknown>;
  }) {
    const pattern = this.getArchitecturePattern(input.architecture_pattern);
    if (!pattern) {
      return {
        architecture_pattern: input.architecture_pattern,
        error: `Architecture pattern not found: ${input.architecture_pattern}`,
        available_patterns: this.listArchitecturePatterns().map((entry) => entry.pattern_id)
      };
    }

    const countryKey = parseJurisdiction(input.country).key;
    const dataTypes = input.data_types ?? [];
    const serviceTypes = input.service_types ?? [];
    const size = input.size ?? "medium";
    const role = input.role ?? this.inferRoleFromServices(serviceTypes);

    const applicability = this.assessApplicability({
      country: countryKey,
      role,
      size,
      system_types: [pattern.id],
      data_types: dataTypes,
      service_types: serviceTypes,
      additional_context: input.additional_context ?? {}
    });

    const threats = this.getDomainThreats(pattern.id, dataTypes, input.deployment_context).threats
      .sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.name.localeCompare(b.name))
      .slice(0, 12);

    const controlBaseline = this.buildControlBaseline({
      country: countryKey,
      role,
      size,
      system_types: [pattern.id],
      data_types: dataTypes,
      service_types: serviceTypes
    });

    const threatBacklog = this.buildThreatRemediationBacklog(
      [pattern.id],
      dataTypes,
      input.deployment_context,
      10
    );
    const detectionPlan = this.buildDetectionPlaybook(pattern.id, dataTypes, input.deployment_context, 8);
    const evidencePlan = this.buildEvidencePlan(
      { controls: controlBaseline.controls.map((control) => ({ control_id: control.control_id })) },
      input.audit_type
    );

    const verificationChecks = this.verificationChecksForPattern(pattern.id);
    const hardeningPriorities = Array.from(
      new Set([
        ...controlBaseline.controls
          .filter((control) => control.priority === "high")
          .map((control) => `Implement ${control.control_id} (${control.name}).`),
        ...threatBacklog.backlog_items.slice(0, 6).map((item) => item.action)
      ])
    ).slice(0, 12);

    return {
      profile: {
        country: countryKey,
        role,
        size,
        architecture_pattern: pattern.id,
        deployment_context: input.deployment_context ?? null
      },
      architecture: {
        id: pattern.id,
        name: pattern.name,
        category: pattern.category,
        trust_boundaries: pattern.trust_boundaries,
        known_weaknesses: pattern.known_weaknesses,
        applicable_standards: pattern.applicable_standards
      },
      applicability: {
        obligations: applicability.obligations.slice(0, 20),
        conflicts: applicability.conflicts
      },
      threat_landscape: {
        top_threats: threats
      },
      hardening_priorities: hardeningPriorities,
      control_baseline: controlBaseline,
      threat_remediation_backlog: threatBacklog,
      detection_plan: detectionPlan,
      evidence_plan: evidencePlan,
      verification_checks: verificationChecks
    };
  }

  buildComplianceEvidenceMatrix(input: {
    country: string;
    role?: string;
    system_types?: string[];
    data_types?: string[];
    service_types?: string[];
    size?: "small" | "medium" | "large";
    audit_type?: string;
    additional_context?: Record<string, unknown>;
  }) {
    const countryKey = parseJurisdiction(input.country).key;
    const role = input.role ?? this.inferRoleFromServices(input.service_types ?? []);
    const size = input.size ?? "medium";
    const systemTypes = input.system_types ?? [];
    const dataTypes = input.data_types ?? [];
    const serviceTypes = input.service_types ?? [];

    const applicability = this.assessApplicability({
      country: countryKey,
      role,
      size,
      system_types: systemTypes,
      data_types: dataTypes,
      service_types: serviceTypes,
      additional_context: input.additional_context ?? {}
    });
    const controlBaseline = this.buildControlBaseline({
      country: countryKey,
      role,
      size,
      system_types: systemTypes,
      data_types: dataTypes,
      service_types: serviceTypes
    });
    const evidencePlan = this.buildEvidencePlan(
      { controls: controlBaseline.controls.map((control) => ({ control_id: control.control_id })) },
      input.audit_type
    );

    const rows = applicability.obligations.slice(0, 40).map((obligation) => {
      const evidenceItems = evidencePlan.evidence_items.filter((item) =>
        item.regulation_basis.some((basis) =>
          basis.regulation_id.toLowerCase().includes(obligation.regulation_id.toLowerCase()) ||
          obligation.regulation_id.toLowerCase().includes(basis.regulation_id.toLowerCase())
        )
      );
      const controls = controlBaseline.controls.filter((control) =>
        control.regulation_basis.some((basis) =>
          basis.toLowerCase().includes(obligation.regulation_id.toLowerCase()) ||
          obligation.regulation_id.toLowerCase().includes(basis.toLowerCase())
        )
      );

      return {
        regulation_id: obligation.regulation_id,
        article_or_section: obligation.article_or_section ?? "general",
        directive: obligation.directive ?? "required",
        jurisdiction_scope: obligation.jurisdiction_scope ?? obligation.basis.matched_country,
        evidence_items: evidenceItems.map((item) => ({
          artifact_name: item.artifact_name,
          template_ref: item.template_ref,
          retention_period: item.retention_period,
          mandatory: item.mandatory
        })),
        control_candidates: controls.map((control) => ({
          control_id: control.control_id,
          name: control.name,
          priority: control.priority
        })),
        coverage_status:
          evidenceItems.length > 0 || controls.length > 0 ? "mapped" : "needs_custom_evidence_mapping"
      };
    });

    const mappedCount = rows.filter((row) => row.coverage_status === "mapped").length;
    const missing = rows.filter((row) => row.coverage_status !== "mapped");

    return {
      profile: {
        country: countryKey,
        role,
        size,
        audit_type: input.audit_type ?? null
      },
      summary: {
        obligations_considered: rows.length,
        mapped_obligations: mappedCount,
        unmapped_obligations: rows.length - mappedCount
      },
      matrix: rows,
      unmapped: missing
    };
  }

  assessApplicability(input: OrgProfile & { additional_context?: Record<string, unknown> }): ApplicabilityAssessment {
    const primaryJurisdiction = parseJurisdiction(input.country);
    const primaryCountry = primaryJurisdiction.country;
    const size = input.size ?? "medium";
    const dataTypes = (input.data_types ?? []).map(normalizeDataType);
    const systemTypes = (input.system_types ?? []).map((entry) => entry.toLowerCase());
    const serviceTypes = (input.service_types ?? []).map((entry) => entry.toLowerCase());
    const role = (input.role ?? this.inferRoleFromServices(serviceTypes)).toLowerCase();

    const additionalCountries =
      Array.isArray(input.additional_context?.countries) &&
      input.additional_context?.countries.every((value) => typeof value === "string")
        ? (input.additional_context.countries as string[])
        : [];

    const crossBorderJurisdictions = Array.from(
      new Map(
        [primaryJurisdiction, ...additionalCountries.map((country) => parseJurisdiction(country))].map((entry) => [
          entry.key,
          entry
        ])
      ).values()
    );

    const crossBorderCountries = Array.from(new Set(crossBorderJurisdictions.map((entry) => entry.country)));

    const rankedMatches: Array<{
      rule: ApplicabilityRule;
      country: string;
      score: number;
      precedence_level: "country_specific" | "jurisdiction_wide" | "cross_jurisdiction";
      matched_conditions: string[];
    }> = [];

    for (const jurisdiction of crossBorderJurisdictions) {
      const country = jurisdiction.country;
      for (const rule of this.rules) {
        const match = this.ruleMatchInfo(rule, country, role, size, dataTypes, systemTypes, serviceTypes);
        if (!match.matched) {
          continue;
        }

        rankedMatches.push({
          rule,
          country,
          score: this.computeRuleScore(rule, country, match.matched_conditions),
          precedence_level: this.resolvePrecedenceLevel(rule, country),
          matched_conditions: match.matched_conditions
        });
      }
    }

    rankedMatches.sort((a, b) => b.score - a.score || a.rule.id.localeCompare(b.rule.id));

    const obligationMap = new Map<
      string,
      {
        obligation: AssessedObligation;
        supporting_rule_ids: Set<string>;
      }
    >();

    for (const match of rankedMatches) {
      const obligation = match.rule.obligation;
      const countryScoped = match.precedence_level === "country_specific";
      const key = [
        obligation.regulation_id,
        obligation.article_or_section ?? "",
        obligation.standard_id ?? "",
        countryScoped ? match.country : "*"
      ].join("|");

      const candidate: AssessedObligation = {
        regulation_id: obligation.regulation_id,
        standard_id: obligation.standard_id,
        article_or_section: obligation.article_or_section,
        confidence: obligation.confidence,
        topic: this.inferObligationTopic(obligation.regulation_id),
        directive: this.inferObligationDirective(obligation.regulation_id),
        jurisdiction_scope: match.country,
        assertion_citations: this.inferObligationCitations(obligation.regulation_id, obligation.article_or_section),
        source_confidence: obligation.confidence,
        precedence_level: match.precedence_level,
        match_score: match.score,
        basis: {
          rule_id: match.rule.id,
          rationale: match.rule.rationale,
          matched_country: match.country,
          matched_conditions: match.matched_conditions
        }
      };

      const existing = obligationMap.get(key);
      if (!existing) {
        obligationMap.set(key, {
          obligation: candidate,
          supporting_rule_ids: new Set<string>()
        });
        continue;
      }

      if (candidate.match_score > existing.obligation.match_score) {
        existing.supporting_rule_ids.add(existing.obligation.basis.rule_id);
        existing.obligation = candidate;
      } else {
        existing.supporting_rule_ids.add(candidate.basis.rule_id);
      }
    }

    for (const jurisdiction of crossBorderJurisdictions) {
      const overlays = this.buildJurisdictionOverlayObligations(jurisdiction.key, role, size, serviceTypes, dataTypes);
      for (const overlay of overlays) {
        const countryScoped = overlay.precedence_level === "country_specific";
        const key = [
          overlay.regulation_id,
          overlay.article_or_section ?? "",
          overlay.standard_id ?? "",
          countryScoped ? overlay.basis.matched_country : "*"
        ].join("|");

        const existing = obligationMap.get(key);
        if (!existing) {
          obligationMap.set(key, {
            obligation: overlay,
            supporting_rule_ids: new Set<string>()
          });
          continue;
        }

        if (overlay.match_score > existing.obligation.match_score) {
          existing.supporting_rule_ids.add(existing.obligation.basis.rule_id);
          existing.obligation = overlay;
        } else {
          existing.supporting_rule_ids.add(overlay.basis.rule_id);
        }
      }
    }

    const obligations = Array.from(obligationMap.values())
      .map((entry) => {
        if (entry.supporting_rule_ids.size > 0) {
          entry.obligation.basis.supporting_rule_ids = Array.from(entry.supporting_rule_ids).sort();
        }
        return entry.obligation;
      })
      .sort((a, b) => b.match_score - a.match_score || a.regulation_id.localeCompare(b.regulation_id));

    const conflicts = this.detectObligationConflicts(obligations);

    const decisionTrace = rankedMatches.map((match) => ({
      rule_id: match.rule.id,
      regulation_id: match.rule.obligation.regulation_id,
      score: match.score,
      precedence_level: match.precedence_level,
      country: match.country
    }));

    for (const obligation of obligations) {
      if (obligation.basis.rule_id.startsWith("overlay-")) {
        decisionTrace.push({
          rule_id: obligation.basis.rule_id,
          regulation_id: obligation.regulation_id,
          score: obligation.match_score,
          precedence_level: obligation.precedence_level,
          country: obligation.basis.matched_country
        });
      }
    }

    return {
      obligations,
      conflicts,
      matched_rule_count: decisionTrace.length,
      profile_summary: {
        country: primaryJurisdiction.key,
        role,
        size,
        system_types: systemTypes,
        data_types: dataTypes,
        service_types: serviceTypes,
        cross_border_countries: crossBorderJurisdictions.map((entry) => entry.key)
      },
      decision_trace: decisionTrace
    };
  }

  mapToTechnicalStandards(requirementRef?: string, controlId?: string) {
    const requirement = (requirementRef ?? "").toLowerCase().trim();
    const control = (controlId ?? "").toLowerCase().trim();
    const combinedInput = `${requirement} ${control}`.trim();
    const requirementTokens = requirement
      .split(/[^a-z0-9.]+/)
      .map((token) => token.trim())
      .filter((token) => token.length >= 3);

    const matchesTokens = (value: string) => {
      if (requirementTokens.length === 0) {
        return false;
      }
      const normalizedValue = value.toLowerCase();
      const numericTokenMatch = requirementTokens
        .filter((token) => /\d/.test(token))
        .some((token) => normalizedValue.includes(token));
      if (numericTokenMatch) {
        return true;
      }
      const matched = requirementTokens.filter((token) => normalizedValue.includes(token)).length;
      return matched >= Math.min(2, requirementTokens.length);
    };

    const ranked = this.standards
      .map((standard) => {
        const scopeText = `${standard.name} ${standard.scope} ${standard.implementation_guidance}`.toLowerCase();
        const aliases = TECHNICAL_STANDARD_ALIAS_HINTS[standard.id] ?? [];
        const aliasMatch = combinedInput.length > 0 && aliases.some((alias) => combinedInput.includes(alias.toLowerCase()));

        const clauseMatch =
          requirement.length > 0 &&
          standard.key_clauses.some((clause) => {
            const clauseText = `${clause.clause} ${clause.summary}`.toLowerCase();
            return clauseText.includes(requirement) || matchesTokens(clauseText);
          });

        const controlMatch =
          control.length > 0 &&
          standard.control_mappings.some((mapping) => `${mapping.framework} ${mapping.control}`.toLowerCase().includes(control));

        const regulationMatch =
          requirement.length > 0 &&
          standard.regulation_mappings.some((mapping) => {
            const regulationText = `${mapping.regulation_id} ${mapping.article_or_section}`.toLowerCase();
            return regulationText.includes(requirement) || matchesTokens(regulationText);
          });

        const scopeExactMatch = requirement.length > 0 && scopeText.includes(requirement);
        const scopeTokenMatch = requirement.length > 0 && matchesTokens(scopeText);

        let score = 0;
        if (aliasMatch) {
          score += 6;
        }
        if (scopeExactMatch) {
          score += 4;
        }
        if (scopeTokenMatch) {
          score += 3;
        }
        if (clauseMatch) {
          score += 4;
        }
        if (regulationMatch) {
          score += 3;
        }
        if (controlMatch) {
          score += 4;
        }

        if (combinedInput.length === 0 || score === 0) {
          return null;
        }

        const relevance = score >= 8 ? "high" : "medium";
        return { standard, score, relevance };
      })
      .filter((entry): entry is { standard: TechnicalStandard; score: number; relevance: "high" | "medium" } => entry !== null)
      .sort((a, b) => b.score - a.score || a.standard.name.localeCompare(b.standard.name));

    return {
      standard_mappings: ranked.map((entry) => ({
        standard_id: entry.standard.id,
        standard_name: entry.standard.name,
        clauses: entry.standard.key_clauses,
        relevance: entry.relevance,
        implementation_guidance: entry.standard.implementation_guidance
      }))
    };
  }

  searchDomainKnowledge(query: string, contentType?: string, limit = 10) {
    const cappedLimit = Math.max(1, Math.min(limit, 25));
    const normalized = query.trim().toLowerCase();
    const requestedContentType = contentType?.trim().toLowerCase();
    const indexedContentTypes = [
      "architecture_patterns",
      "data_categories",
      "threat_scenarios",
      "technical_standards"
    ] as const;

    if (normalized.length === 0) {
      return {
        results: [],
        search_backend: "fts5+keyword-fallback",
        match_status: "empty_query",
        indexed_content_types: indexedContentTypes
      };
    }

    if (requestedContentType && !indexedContentTypes.includes(requestedContentType as (typeof indexedContentTypes)[number])) {
      return {
        results: [],
        search_backend: "fts5+keyword-fallback",
        match_status: "not_indexed_content_type",
        unsupported_content_type: contentType,
        indexed_content_types: indexedContentTypes
      };
    }

    type SearchResult = {
      content_type: string;
      id: string;
      title: string;
      snippet: string;
      relevance_score: number;
      source_ref: string;
    };

    const results: SearchResult[] = [];
    const seen = new Set<string>();
    let fallbackUsed = false;

    const pushResult = (entry: SearchResult) => {
      const key = `${entry.content_type}:${entry.id}`;
      if (seen.has(key)) {
        return;
      }
      seen.add(key);
      results.push(entry);
    };

    const tokenizeForFts = (value: string): string[] =>
      value
        .split(/[^a-z0-9]+/)
        .map((token) => token.trim())
        .filter((token) => token.length >= 2);

    const tokens = tokenizeForFts(normalized);
    const ftsQuery = tokens.length === 0 ? null : tokens.map((token) => `"${token}"*`).join(" OR ");

    if (ftsQuery) {
      const runFts = (
        table: "architecture_patterns_fts" | "data_categories_fts" | "threat_scenarios_fts" | "technical_standards_fts",
        baseTable: "architecture_patterns" | "data_categories" | "threat_scenarios" | "technical_standards",
        snippetColumn: "description" | "scope",
        content_type: SearchResult["content_type"],
        source_ref: string
      ) => {
        if (requestedContentType && requestedContentType !== content_type) {
          return;
        }
        const querySql = `
          SELECT b.id AS id, b.name AS title, b.${snippetColumn} AS snippet, bm25(${table}) AS rank
          FROM ${table}
          JOIN ${baseTable} b ON b.id = ${table}.id
          WHERE ${table} MATCH ?
          ORDER BY rank
          LIMIT ?
        `;
        const rows = this.db.prepare(querySql).all(ftsQuery, cappedLimit) as Array<{
          id: string;
          title: string;
          snippet: string;
          rank: number;
        }>;

        for (const row of rows) {
          const score = 1 / (1 + Math.max(0, Number.isFinite(row.rank) ? row.rank : 0));
          pushResult({
            content_type,
            id: row.id,
            title: row.title,
            snippet: row.snippet,
            relevance_score: Number(score.toFixed(4)),
            source_ref
          });
        }
      };

      try {
        runFts("architecture_patterns_fts", "architecture_patterns", "description", "architecture_patterns", "3GPP/ETSI");
        runFts("data_categories_fts", "data_categories", "description", "data_categories", "EECC/ePrivacy/GDPR/ECPA");
        runFts("threat_scenarios_fts", "threat_scenarios", "description", "threat_scenarios", "Threat catalog");
        runFts("technical_standards_fts", "technical_standards", "scope", "technical_standards", "Standards catalog");
      } catch {
        // Fallback path handles malformed FTS expressions and any runtime FTS issues.
      }
    }

    const addIfMatched = (
      content_type: string,
      id: string,
      title: string,
      searchable: string,
      snippet: string,
      source_ref: string
    ) => {
      if (requestedContentType && requestedContentType !== content_type.toLowerCase()) {
        return;
      }
      const haystack = searchable.toLowerCase();
      const position = haystack.indexOf(normalized);
      if (position < 0) {
        return;
      }
      const relevance = 1 / (position + 1) + Math.min(1, normalized.length / Math.max(1, haystack.length));
      pushResult({ content_type, id, title, snippet, relevance_score: Number(relevance.toFixed(4)), source_ref });
    };

    if (results.length < cappedLimit) {
      fallbackUsed = true;
      for (const pattern of this.patterns) {
        addIfMatched(
          "architecture_patterns",
          pattern.id,
          pattern.name,
          `${pattern.name} ${pattern.description} ${pattern.components.join(" ")}`,
          pattern.description,
          "3GPP/ETSI"
        );
      }

      for (const category of this.categories) {
        addIfMatched(
          "data_categories",
          category.id,
          category.name,
          `${category.name} ${category.description} ${category.boundary_conditions}`,
          category.description,
          "EECC/ePrivacy/GDPR/ECPA"
        );
      }

      for (const threat of this.threats) {
        addIfMatched(
          "threat_scenarios",
          threat.id,
          threat.name,
          `${threat.name} ${threat.description} ${threat.attack_narrative}`,
          threat.attack_narrative,
          "Threat catalog"
        );
      }

      for (const standard of this.standards) {
        addIfMatched(
          "technical_standards",
          standard.id,
          standard.name,
          `${standard.name} ${standard.scope} ${standard.implementation_guidance}`,
          standard.scope,
          standard.publisher
        );
      }
    }

    const topResults = results
      .sort((a, b) => b.relevance_score - a.relevance_score)
      .slice(0, cappedLimit)
      .map((result) => ({
        ...result,
        snippets: [result.snippet]
      }));

    return {
      results: topResults,
      search_backend: fallbackUsed ? "fts5+keyword-fallback" : "fts5",
      match_status: topResults.length > 0 ? "matched" : "no_match",
      indexed_content_types: indexedContentTypes
    };
  }

  compareJurisdictions(topic: string, jurisdictions: string[]) {
    const normalizedTopic = topic.toLowerCase();
    const normalizedJurisdictions = jurisdictions.map((entry) => parseJurisdiction(entry).key);
    const mappedTopic = this.mapInputTopic(normalizedTopic);

    const matrix: Array<{ jurisdiction: string; obligations: string[]; notes: string }> = [];
    const directiveStrictness: Record<"required" | "restricted" | "prohibited" | "conditional", number> = {
      prohibited: 4,
      restricted: 3,
      required: 2,
      conditional: 1
    };

    if (mappedTopic) {
      for (const jurisdictionKey of normalizedJurisdictions) {
        const pack = this.getJurisdictionClausePack(jurisdictionKey);
        const assertions = pack.assertions
          .filter((assertion) => assertion.topic === mappedTopic)
          .sort((a, b) => {
            const directiveRank = directiveStrictness[b.directive] - directiveStrictness[a.directive];
            if (directiveRank !== 0) {
              return directiveRank;
            }
            const exactRank =
              Number(b.reference_quality === "exact") - Number(a.reference_quality === "exact");
            if (exactRank !== 0) {
              return exactRank;
            }
            return a.regulation_id.localeCompare(b.regulation_id);
          });

        const exactCount = assertions.filter((assertion) => assertion.reference_quality === "exact").length;
        const namedCount = assertions.length - exactCount;

        if (assertions.length === 0) {
          matrix.push({
            jurisdiction: jurisdictionKey,
            obligations: ["No mapped telecom assertions for this topic in current dataset."],
            notes: "Add jurisdiction-specific overlays or standard mappings for this topic."
          });
          continue;
        }

        const obligations = assertions.slice(0, 8).map((assertion) => {
          const quality =
            assertion.reference_quality === "exact"
              ? "exact"
              : `named${assertion.resolution_hint ? " (needs resolution)" : ""}`;
          return `${assertion.regulation_id}: ${assertion.article_or_section} [${assertion.directive}; ${quality}]`;
        });

        matrix.push({
          jurisdiction: jurisdictionKey,
          obligations,
          notes: `${exactCount}/${assertions.length} exact references; ${namedCount} named references for topic ${mappedTopic}.`
        });
      }

      return {
        topic,
        normalized_topic: mappedTopic,
        comparison_matrix: matrix
      };
    }

    for (const jurisdictionKey of normalizedJurisdictions) {
      const bucket = getJurisdictionBucket(jurisdictionKey);

      if (normalizedTopic.includes("metadata") || normalizedTopic.includes("retention") || normalizedTopic.includes("privacy")) {
        if (bucket === "EU") {
          matrix.push({
            jurisdiction: jurisdictionKey,
            obligations: [
              "ePrivacy traffic/location confidentiality",
              "GDPR lawful basis and minimization",
              "Retention must be necessary and proportionate (CJEU constraints)"
            ],
            notes: "EU model strongly limits blanket retention and broad metadata reuse."
          });
        } else if (bucket === "US") {
          matrix.push({
            jurisdiction: jurisdictionKey,
            obligations: [
              "ECPA/SCA lawful process requirements",
              "CPNI restrictions for telecom carriers",
              "State privacy and location laws (varies by state)"
            ],
            notes: "US model is sectoral and state-fragmented, with different legal process thresholds."
          });
        } else {
          matrix.push({
            jurisdiction: jurisdictionKey,
            obligations: ["Jurisdiction-specific telecom privacy review required"],
            notes: "No curated baseline in this dataset."
          });
        }
        continue;
      }

      if (normalizedTopic.includes("5g") || normalizedTopic.includes("vendor")) {
        if (bucket === "EU") {
          matrix.push({
            jurisdiction: jurisdictionKey,
            obligations: [
              "EU 5G Toolbox strategic and technical measures",
              "NIS2 Art.21 risk management and supply chain controls",
              "National telecom authority implementation specifics"
            ],
            notes: "EU uses a coordinated risk-based high-risk vendor restriction model."
          });
        } else if (bucket === "US") {
          matrix.push({
            jurisdiction: jurisdictionKey,
            obligations: [
              "Section 889 federal procurement restrictions",
              "FCC rip-and-replace program conditions",
              "Carrier-specific supply chain risk obligations"
            ],
            notes: "US model uses targeted restrictions and federal program overlays."
          });
        } else {
          matrix.push({
            jurisdiction: jurisdictionKey,
            obligations: ["National telecom security screening obligations"],
            notes: "Country-specific telecom vendor security regime needed."
          });
        }
        continue;
      }

      if (normalizedTopic.includes("caller") || normalizedTopic.includes("robocall") || normalizedTopic.includes("spoof")) {
        if (bucket === "EU") {
          matrix.push({
            jurisdiction: jurisdictionKey,
            obligations: [
              "EECC consumer protection and security obligations",
              "National telecom authority CLI spoofing and nuisance-call controls",
              "STIR/PASSporT-style interoperability controls where deployed"
            ],
            notes: "EU obligations are implemented through national telecom frameworks and regulator anti-spoofing programs."
          });
        } else if (bucket === "US") {
          matrix.push({
            jurisdiction: jurisdictionKey,
            obligations: [
              "FCC STIR/SHAKEN implementation requirements (47 CFR 64.6300)",
              "Robocall mitigation program and traceback cooperation duties",
              "Caller authentication certificate governance and attestation controls"
            ],
            notes: "US model is explicit and rule-based with FCC enforcement focus."
          });
        } else {
          matrix.push({
            jurisdiction: jurisdictionKey,
            obligations: ["National caller-ID integrity and anti-fraud telecom rules"],
            notes: "Country-specific telecom regulator guidance required."
          });
        }
        continue;
      }

      const sample = this.rules
        .filter((rule) => this.ruleMatches(rule, jurisdictionKey, "telecom_operator", "medium", [], [], []))
        .slice(0, 4)
        .map((rule) => `${rule.obligation.regulation_id}: ${rule.obligation.article_or_section ?? "general obligations"}`);

      matrix.push({
        jurisdiction: jurisdictionKey,
        obligations: sample.length > 0 ? sample : ["No direct matches in baseline rule set."],
        notes: "Generated from applicability rule matches for baseline telecom operator profile."
      });
    }

    return {
      topic,
      normalized_topic: null,
      comparison_matrix: matrix
    };
  }

  buildControlBaseline(profile: OrgProfile) {
    const applicability = this.assessApplicability(profile);

    const controls = new Map<
      string,
      {
        control_id: string;
        name: string;
        priority: "high" | "medium" | "low";
        rationale: string;
        regulation_basis: string[];
        standard_basis: string[];
      }
    >();

    const ensureControl = (
      id: string,
      name: string,
      priority: "high" | "medium" | "low",
      rationale: string,
      regulationBasis: string,
      standardBasis: string
    ) => {
      const existing = controls.get(id);
      if (!existing) {
        controls.set(id, {
          control_id: id,
          name,
          priority,
          rationale,
          regulation_basis: [regulationBasis],
          standard_basis: [standardBasis]
        });
        return;
      }

      if (severityRank(priority) > severityRank(existing.priority)) {
        existing.priority = priority;
      }
      if (!existing.regulation_basis.includes(regulationBasis)) {
        existing.regulation_basis.push(regulationBasis);
      }
      if (!existing.standard_basis.includes(standardBasis)) {
        existing.standard_basis.push(standardBasis);
      }
    };

    for (const obligation of applicability.obligations) {
      if (obligation.regulation_id.includes("NIS2")) {
        ensureControl(
          "ctrl-risk-mgmt",
          "Risk management program for network and information security",
          "high",
          "NIS2 telecom and digital infrastructure obligations.",
          obligation.regulation_id,
          "enisa-5g-toolbox"
        );
        ensureControl(
          "ctrl-supply-chain",
          "Supplier and vendor risk governance",
          "high",
          "Supply chain is an explicit NIS2 and 5G toolbox control area.",
          obligation.regulation_id,
          "gsma-nesas-scas"
        );
      }

      if (obligation.regulation_id.includes("ePrivacy") || obligation.regulation_id.includes("GDPR")) {
        ensureControl(
          "ctrl-privacy-governance",
          "Traffic/location privacy governance and minimization",
          "high",
          "Traffic and location processing constraints must be enforced.",
          obligation.regulation_id,
          "rfc-7258"
        );
      }

      if (obligation.regulation_id.includes("EECC") || obligation.regulation_id.includes("CPNI")) {
        ensureControl(
          "ctrl-subscriber-access",
          "Subscriber data access hardening",
          "high",
          "Subscriber data confidentiality is central in telecom regulations.",
          obligation.regulation_id,
          "3gpp-ts-33-series"
        );
      }

      if (obligation.regulation_id.includes("CALEA")) {
        ensureControl(
          "ctrl-lawful-intercept-security",
          "Lawful intercept workflow security",
          "high",
          "CALEA and national LI laws require secure and auditable intercept capability.",
          obligation.regulation_id,
          "etsi-li"
        );
      }

      if (obligation.regulation_id.includes("FCC STIR/SHAKEN")) {
        ensureControl(
          "ctrl-caller-auth",
          "Caller identity authentication",
          "medium",
          "Voice providers should prevent spoofed caller identity and robocall abuse.",
          obligation.regulation_id,
          "stir-shaken"
        );
      }
    }

    if ((profile.system_types ?? []).some((system) => system.toLowerCase().includes("nfv"))) {
      ensureControl(
        "ctrl-nfv-isolation",
        "NFV tenant and workload isolation",
        "high",
        "NFV workloads need strong isolation, image trust and orchestration security.",
        "NFV risk",
        "etsi-nfv-sec"
      );
    }

    if ((profile.service_types ?? []).some((service) => ["dns", "broadband", "transit"].includes(service.toLowerCase()))) {
      ensureControl(
        "ctrl-routing-security",
        "Routing security and anti-hijack controls",
        "high",
        "ISP and transport environments require route integrity controls.",
        "NIS2/FCC resilience",
        "manrs"
      );
    }

    return {
      controls: Array.from(controls.values()).sort((a, b) => severityRank(b.priority) - severityRank(a.priority))
    };
  }

  buildEvidencePlan(baseline: { controls?: string[] | Array<{ control_id: string }> }, auditType?: string) {
    const normalizedAuditType = auditType?.toLowerCase();

    const selected = this.evidence.filter((artifact) => {
      if (!normalizedAuditType) {
        return artifact.mandatory;
      }
      return (
        artifact.audit_type.toLowerCase().includes(normalizedAuditType) ||
        artifact.artifact_name.toLowerCase().includes(normalizedAuditType)
      );
    });

    const fallback = selected.length > 0 ? selected : this.evidence.filter((artifact) => artifact.mandatory);

    return {
      evidence_items: fallback.map((artifact) => ({
        artifact_name: artifact.artifact_name,
        description: artifact.description,
        template_ref: artifact.template_ref,
        retention_period: artifact.retention_period,
        mandatory: artifact.mandatory,
        regulation_basis: artifact.regulation_basis
      })),
      baseline_controls_considered: baseline.controls ?? []
    };
  }

  assessBreachObligations(incidentDescription: string, jurisdictions: string[], dataTypes: string[]) {
    const notifications = jurisdictions.map((jurisdictionRaw) => {
      const jurisdiction = normalizeCountry(jurisdictionRaw);
      const bucket = getJurisdictionBucket(jurisdiction);
      const normalizedDataTypes = dataTypes.map(normalizeDataType);

      if (bucket === "EU") {
        const recipients = ["Relevant national telecom authority", "Data protection authority (if personal data impact)"];
        const deadlines = ["NIS2 early warning within 24 hours for significant incidents", "GDPR notification within 72 hours if personal data breach"];
        return {
          jurisdiction,
          recipient: recipients.join("; "),
          deadline: deadlines.join("; "),
          content_requirements: [
            "Incident nature and operational impact",
            "Affected telecom services and subscriber scope",
            "Mitigation status and containment timeline",
            "Potential cross-border effects"
          ],
          penalties: "Administrative fines and supervisory measures under NIS2/GDPR/national telecom law"
        };
      }

      if (bucket === "US") {
        const hasCpni = normalizedDataTypes.some((type) => type.includes("subscriber") || type.includes("traffic"));
        return {
          jurisdiction,
          recipient: hasCpni
            ? "FCC CPNI breach process + applicable state authorities"
            : "Applicable state breach notification authorities",
          deadline: hasCpni
            ? "CPNI breach law enforcement notification and waiting period before customer notice"
            : "State-specific deadlines (often 30-45 days)",
          content_requirements: [
            "Breach vector and compromised data classes",
            "Estimated affected individuals",
            "Containment and remediation actions",
            "Consumer protection actions"
          ],
          penalties: "FCC enforcement actions and state attorney general penalties"
        };
      }

      return {
        jurisdiction,
        recipient: "National telecom and data protection authorities",
        deadline: "Country-specific statutory timelines",
        content_requirements: ["Incident details", "Impact assessment", "Remediation plan"],
        penalties: "Country-specific"
      };
    });

    return {
      incident_summary: incidentDescription,
      notifications
    };
  }

  createRemediationBacklog(currentState: { controls_implemented?: string[] }, targetBaseline: { controls?: Array<{ control_id: string; priority?: string }> }) {
    const implemented = new Set((currentState.controls_implemented ?? []).map((control) => control.toLowerCase()));

    const missing = (targetBaseline.controls ?? []).filter(
      (control) => !implemented.has(control.control_id.toLowerCase())
    );

    return {
      backlog_items: missing.map((control, index) => ({
        id: `rb-${index + 1}`,
        action: `Implement ${control.control_id}`,
        priority: control.priority ?? "medium",
        effort_estimate: control.priority === "high" ? "M" : "S",
        risk_reduction: control.priority === "high" ? "high" : "medium",
        regulation_basis: ["Derived from target baseline obligations"]
      }))
    };
  }

  classifyTelecomEntity(serviceTypes: string[], size: "small" | "medium" | "large", country: string) {
    const normalizedServices = serviceTypes.map((service) => service.toLowerCase());
    const normalizedCountry = normalizeCountry(country);
    const eu = isEuCountry(normalizedCountry);

    let eeccCategory = "out_of_scope";
    if (eu) {
      if (includesAny(normalizedServices, ["mobile", "voice", "data", "broadband", "5g"])) {
        eeccCategory = "provider_of_electronic_communications_networks_or_services";
      } else if (includesAny(normalizedServices, ["messaging", "chat", "communications_app"])) {
        eeccCategory = "number_independent_interpersonal_communications";
      } else {
        eeccCategory = "associated_facility_provider";
      }
    }

    let nis2Status = "likely_out_of_scope";
    if (includesAny(normalizedServices, ["mobile", "voice", "data", "5g", "broadband"]) && size !== "small") {
      nis2Status = "essential";
    } else if (includesAny(normalizedServices, ["dns", "tld", "iaas", "cdn", "data-center"])) {
      nis2Status = size === "small" ? "important" : "essential_digital_infrastructure";
    } else if (eu) {
      nis2Status = "important";
    }

    const applicability = this.assessApplicability({
      country: normalizedCountry,
      role: includesAny(normalizedServices, ["mobile", "voice", "data", "5g", "broadband"]) ? "telecom_operator" : "provider",
      size,
      service_types: normalizedServices
    });

    return {
      eecc_category: eeccCategory,
      nis2_status: nis2Status,
      applicable_obligations: applicability.obligations
    };
  }

  assess5gSecurity(
    architecture: "NSA" | "SA",
    vendorMix: string[],
    deploymentModel: "on-prem" | "hybrid" | "cloud-native",
    country?: string
  ) {
    const riskAreas: Array<{ area: string; severity: "high" | "medium" | "low"; rationale: string }> = [];

    if (architecture === "SA") {
      riskAreas.push({
        area: "SBA API exposure",
        severity: "high",
        rationale: "Standalone 5G core relies heavily on API security and service mesh policy controls."
      });
      riskAreas.push({
        area: "Network slicing isolation",
        severity: "high",
        rationale: "Slice misconfiguration can cause cross-tenant impact and confidentiality breaches."
      });
    } else {
      riskAreas.push({
        area: "Legacy interworking (4G/SS7/Diameter)",
        severity: "high",
        rationale: "NSA deployments inherit legacy signaling risks and transition complexity."
      });
    }

    if (vendorMix.length <= 1) {
      riskAreas.push({
        area: "Vendor concentration",
        severity: "medium",
        rationale: "Low supplier diversity raises systemic and geopolitical supply-chain risk."
      });
    }

    if (deploymentModel === "cloud-native") {
      riskAreas.push({
        area: "Container and orchestration hardening",
        severity: "high",
        rationale: "Cloud-native CNFs require strong workload isolation, admission control and signing."
      });
    }

    const euToolboxMeasures = [
      "Vendor risk profile and high-risk vendor restrictions",
      "Supplier diversification strategy",
      "Critical network function hardening",
      "Enhanced incident response and monitoring for 5G"
    ];

    const gsmaControls = [
      "GSMA FS.31 identity and key management controls",
      "GSMA FS.31 network function hardening",
      "NESAS/SCAS vendor assurance checkpoints"
    ];

    const nationalRequirements = [] as string[];
    if (country) {
      const normalizedCountry = normalizeCountry(country);
      if (isEuCountry(normalizedCountry)) {
        nationalRequirements.push("National implementation of EU 5G Toolbox");
        nationalRequirements.push("NIS2 supervisory authority expectations for telecom entities");
      } else if (normalizedCountry === "US") {
        nationalRequirements.push("FCC and federal supply-chain restrictions where applicable");
        nationalRequirements.push("NIST 5G security implementation alignment");
      }
    }

    return {
      risk_areas: riskAreas,
      eu_toolbox_measures: euToolboxMeasures,
      gsma_controls: gsmaControls,
      national_requirements: nationalRequirements
    };
  }

  assessLawfulInterceptCompliance(country: string, serviceTypes: string[], technology: string) {
    const normalizedCountry = normalizeCountry(country);

    const liStandards = isEuCountry(normalizedCountry)
      ? ["ETSI TS 103 120", "National lawful intercept implementation law"]
      : normalizedCountry === "US"
        ? ["CALEA", "FCC lawful intercept obligations", "Carrier-specific lawful access procedures"]
        : ["Country-specific lawful intercept standards"];

    const warrantHandlingRequirements = [
      "Validate warrant scope and legal authority before activation",
      "Enforce dual control for intercept activation and export",
      "Maintain immutable audit trail for warrant lifecycle",
      "Restrict target-identifying information to authorized personnel"
    ];

    if (technology.toLowerCase().includes("5g")) {
      warrantHandlingRequirements.push("Confirm 5G core and interworking intercept coverage for requested services");
    }

    const retentionObligations = isEuCountry(normalizedCountry)
      ? [
          "Retention must be legally authorized, necessary and proportionate",
          "National implementations may impose strict limits after CJEU rulings"
        ]
      : normalizedCountry === "US"
        ? [
            "Preserve records per lawful process requirements",
            "Apply CPNI and evidence handling controls for retained intercept outputs"
          ]
        : ["Country-specific retention obligations require local legal mapping"];

    return {
      li_standards: liStandards,
      warrant_handling_requirements: warrantHandlingRequirements,
      retention_obligations: retentionObligations,
      service_types: serviceTypes
    };
  }

  assessDataRetentionObligations(dataType: string, country: string, purpose: string) {
    const normalizedType = normalizeDataType(dataType);
    const normalizedCountry = normalizeCountry(country);
    const normalizedPurpose = purpose.toLowerCase();

    if (isEuCountry(normalizedCountry)) {
      const legalBasis =
        normalizedPurpose.includes("security") || normalizedPurpose.includes("fraud")
          ? "Targeted security and fraud prevention basis may apply under national law."
          : normalizedPurpose.includes("law enforcement") || normalizedPurpose.includes("lawful")
            ? "Lawful intercept and criminal procedure basis may apply with strict safeguards."
            : "General analytics/monetization purposes typically require strong necessity/proportionality and may be prohibited.";

      const retentionPermitted =
        normalizedPurpose.includes("security") ||
        normalizedPurpose.includes("fraud") ||
        normalizedPurpose.includes("law enforcement") ||
        normalizedPurpose.includes("lawful");

      return {
        retention_permitted: retentionPermitted,
        legal_basis: legalBasis,
        maximum_period: retentionPermitted
          ? "No blanket EU-wide period; use national telecom law with strict necessity and proportionality checks"
          : "Not permitted in baseline guidance",
        cjeu_relevant_rulings: [
          "Digital Rights Ireland (C-293/12)",
          "Tele2 Sverige / Watson (C-203/15 and C-698/15)",
          "La Quadrature du Net (C-511/18, C-512/18, C-520/18)"
        ],
        data_type_normalized: normalizedType
      };
    }

    if (normalizedCountry === "US") {
      return {
        retention_permitted: true,
        legal_basis:
          "Sectoral model: ECPA/SCA, CPNI and state law define process and retention boundaries; law enforcement preservation requests may apply.",
        maximum_period: "State and sector specific; establish policy aligned to legal holds and customer notice obligations",
        cjeu_relevant_rulings: [],
        data_type_normalized: normalizedType
      };
    }

    return {
      retention_permitted: false,
      legal_basis: "No curated legal baseline for this jurisdiction in current dataset.",
      maximum_period: "Unknown",
      cjeu_relevant_rulings: [],
      data_type_normalized: normalizedType
    };
  }

  private buildJurisdictionOverlayObligations(
    jurisdictionKey: string,
    role: string,
    size: "small" | "medium" | "large",
    serviceTypes: string[],
    dataTypes: string[]
  ): AssessedObligation[] {
    const jurisdiction = parseJurisdiction(jurisdictionKey);
    const overlays: AssessedObligation[] = [];
    const clauseAssertions = getJurisdictionClauseAssertions(jurisdiction.key);
    const hasTelecomService =
      serviceTypes.length === 0 ||
      includesAny(serviceTypes, [
        "voice",
        "data",
        "mobile",
        "5g",
        "broadband",
        "dns",
        "tld",
        "iaas",
        "cdn",
        "data-center"
      ]);
    const hasPersonalData = dataTypes.some((dataType) =>
      [
        "subscriber_data",
        "traffic_metadata",
        "location_data",
        "dns_data",
        "content_data",
        "lawful_intercept_data",
        "roaming_data"
      ].includes(dataType)
    );
    const hasLiContext =
      dataTypes.includes("lawful_intercept_data") ||
      dataTypes.includes("content_data") ||
      includesAny(serviceTypes, ["voice", "mobile", "5g"]);

    const minSizeSatisfied = (required?: "small" | "medium" | "large"): boolean => {
      if (!required) {
        return true;
      }
      return SIZE_ORDER[size] >= SIZE_ORDER[required];
    };

    const voiceContext = includesAny(serviceTypes, ["voice", "mobile"]);

    const topicBaseScore: Record<string, number> = {
      security_risk_management: 240,
      incident_reporting: 232,
      subscriber_privacy: 236,
      traffic_location_privacy: 234,
      lawful_intercept: 238,
      data_retention: 230,
      supply_chain: 228,
      caller_id_authentication: 226
    };

    for (const assertion of clauseAssertions) {
      if (assertion.trigger.requires_telecom_service && !hasTelecomService) {
        continue;
      }
      if (assertion.trigger.requires_personal_data && !hasPersonalData) {
        continue;
      }
      if (assertion.trigger.requires_li_context && !hasLiContext) {
        continue;
      }
      if (assertion.trigger.requires_voice_service && !voiceContext) {
        continue;
      }
      if (!minSizeSatisfied(assertion.trigger.min_size)) {
        continue;
      }

      const score =
        (topicBaseScore[assertion.topic] ?? 220) +
        (assertion.confidence === "high" ? 14 : assertion.confidence === "medium" ? 9 : 5) +
        (assertion.directive === "prohibited"
          ? 12
          : assertion.directive === "restricted"
            ? 9
            : assertion.directive === "required"
              ? 8
              : 6);

      overlays.push({
        regulation_id: assertion.regulation_id,
        standard_id: assertion.standard_id,
        article_or_section: assertion.article_or_section,
        confidence: assertion.confidence,
        topic: assertion.topic,
        directive: assertion.directive,
        jurisdiction_scope: jurisdiction.key,
        reference_quality: assertion.reference_quality,
        resolution_hint: assertion.resolution_hint,
        assertion_citations: assertion.citations,
        source_confidence: assertion.confidence,
        precedence_level: "country_specific",
        match_score: score,
        basis: {
          rule_id: `overlay-${assertion.id}`,
          rationale: assertion.summary,
          matched_country: jurisdiction.key,
          matched_conditions: [
            "jurisdiction_overlay",
            role,
            size,
            ...(assertion.trigger.requires_personal_data ? ["personal_data"] : []),
            ...(assertion.trigger.requires_li_context ? ["li_context"] : []),
            ...(assertion.trigger.requires_voice_service ? ["voice_context"] : [])
          ]
        }
      });
    }

    return overlays;
  }

  private inferObligationTopic(regulationId: string):
    | "security_risk_management"
    | "incident_reporting"
    | "subscriber_privacy"
    | "traffic_location_privacy"
    | "lawful_intercept"
    | "data_retention"
    | "supply_chain"
    | "caller_id_authentication"
    | "general" {
    const value = regulationId.toLowerCase();
    if (value.includes("nis2")) {
      return "security_risk_management";
    }
    if (value.includes("eecc")) {
      return "security_risk_management";
    }
    if (value.includes("gdpr") || value.includes("cpni")) {
      return "subscriber_privacy";
    }
    if (value.includes("eprivacy") || value.includes("ecpa")) {
      return "traffic_location_privacy";
    }
    if (value.includes("calea") || value.includes("intercept") || value.includes("wiv")) {
      return "lawful_intercept";
    }
    if (value.includes("stir") || value.includes("robocall")) {
      return "caller_id_authentication";
    }
    if (value.includes("state privacy")) {
      return "subscriber_privacy";
    }
    if (value.includes("breach")) {
      return "incident_reporting";
    }
    return "general";
  }

  private inferObligationDirective(regulationId: string): "required" | "restricted" | "prohibited" | "conditional" {
    const value = regulationId.toLowerCase();
    if (value.includes("eprivacy") || value.includes("gdpr")) {
      return "restricted";
    }
    if (value.includes("ecpa") || value.includes("cpni")) {
      return "conditional";
    }
    return "required";
  }

  private inferObligationCitations(regulationId: string, reference?: string) {
    const value = regulationId.toLowerCase();
    if (value.includes("nis2")) {
      return [
        {
          type: "CELEX" as const,
          ref: reference ? `NIS2 ${reference}` : "Directive (EU) 2022/2555",
          source_url: "https://eur-lex.europa.eu/eli/dir/2022/2555/oj"
        }
      ];
    }
    if (value.includes("eecc")) {
      return [
        {
          type: "CELEX" as const,
          ref: reference ? `EECC ${reference}` : "Directive (EU) 2018/1972",
          source_url: "https://eur-lex.europa.eu/eli/dir/2018/1972/oj"
        }
      ];
    }
    if (value.includes("gdpr")) {
      return [
        {
          type: "CELEX" as const,
          ref: reference ? `GDPR ${reference}` : "Regulation (EU) 2016/679",
          source_url: "https://eur-lex.europa.eu/eli/reg/2016/679/oj"
        }
      ];
    }
    if (value.includes("cpni")) {
      return [
        {
          type: "CFR" as const,
          ref: reference ?? "47 CFR 64.2001",
          source_url: "https://www.ecfr.gov/current/title-47/part-64/subpart-U"
        }
      ];
    }
    if (value.includes("ecpa") || value.includes("sca")) {
      return [
        {
          type: "USC" as const,
          ref: reference ?? "18 USC 2510 et seq / 18 USC 2701 et seq",
          source_url: "https://uscode.house.gov/"
        }
      ];
    }
    if (value.includes("calea")) {
      return [
        {
          type: "USC" as const,
          ref: reference ?? "47 USC 1001",
          source_url: "https://uscode.house.gov/"
        }
      ];
    }
    return undefined;
  }

  private detectObligationConflicts(obligations: AssessedObligation[]): ObligationConflict[] {
    const byTopic = new Map<string, AssessedObligation[]>();
    for (const obligation of obligations) {
      const topic = obligation.topic ?? "general";
      if (!byTopic.has(topic)) {
        byTopic.set(topic, []);
      }
      byTopic.get(topic)?.push(obligation);
    }

    const directiveStrictness: Record<"required" | "restricted" | "prohibited" | "conditional", number> = {
      prohibited: 4,
      restricted: 3,
      required: 2,
      conditional: 1
    };

    const conflicts: ObligationConflict[] = [];

    for (const [topic, entries] of byTopic.entries()) {
      const withDirective = entries.filter(
        (entry): entry is AssessedObligation & { directive: "required" | "restricted" | "prohibited" | "conditional" } =>
          Boolean(entry.directive)
      );

      if (withDirective.length < 2) {
        continue;
      }

      const directives = Array.from(new Set(withDirective.map((entry) => entry.directive)));
      const hasHardConflict =
        directives.includes("prohibited") &&
        (directives.includes("required") || directives.includes("conditional"));
      const hasMaterialVariance = directives.length >= 3 || hasHardConflict;

      if (!hasMaterialVariance) {
        continue;
      }

      const recommendedDirective = withDirective.reduce(
        (strictest, entry) =>
          directiveStrictness[entry.directive] > directiveStrictness[strictest]
            ? entry.directive
            : strictest,
        withDirective[0].directive
      );

      conflicts.push({
        topic,
        directives: withDirective.map((entry) => ({
          regulation_id: entry.regulation_id,
          directive: entry.directive,
          jurisdiction_scope: entry.jurisdiction_scope ?? entry.basis.matched_country,
          match_score: entry.match_score
        })),
        resolution: {
          recommended_directive: recommendedDirective,
          strategy:
            recommendedDirective === "prohibited" || recommendedDirective === "restricted"
              ? "Apply strictest-jurisdiction baseline and segment data processing by jurisdiction."
              : "Apply harmonized baseline controls with jurisdiction-specific implementation flags.",
          rationale:
            "Conflicting directive strengths detected for the same topic across jurisdictions and regimes."
        }
      });
    }

    return conflicts.sort((a, b) => b.directives.length - a.directives.length || a.topic.localeCompare(b.topic));
  }

  private inferRoleFromServices(serviceTypes: string[]): string {
    if (includesAny(serviceTypes, ["voice", "data", "mobile", "5g"])) {
      return "mobile_operator";
    }
    if (includesAny(serviceTypes, ["broadband", "dns", "transit"])) {
      return "isp";
    }
    if (includesAny(serviceTypes, ["iaas", "cdn", "data-center"])) {
      return "cloud_provider";
    }
    return "telecom_operator";
  }

  private isCountrySpecificRegulation(country: string, regulationId: string): boolean {
    const normalizedCountry = normalizeCountry(country);
    const value = regulationId.toLowerCase();
    if (normalizedCountry === "SE") {
      return value.includes("lek") || value.includes("pts");
    }
    if (normalizedCountry === "NL") {
      return value.includes("wbni") || value.includes("telecommunicatiewet") || value.includes("wiv");
    }
    if (normalizedCountry === "DE") {
      return value.includes("tkg");
    }
    if (normalizedCountry === "US") {
      return value.includes("cpni") || value.includes("ecpa") || value.includes("calea") || value.includes("fcc");
    }
    return false;
  }

  private resolvePrecedenceLevel(
    rule: ApplicabilityRule,
    country: string
  ): "country_specific" | "jurisdiction_wide" | "cross_jurisdiction" {
    const normalizedCountry = normalizeCountry(country);
    const countries = rule.condition.countries ?? [];
    const hasExactCountry = countries.some((candidate) => normalizeCountry(candidate) === normalizedCountry);

    if (hasExactCountry || this.isCountrySpecificRegulation(country, rule.obligation.regulation_id)) {
      return "country_specific";
    }

    const hasJurisdictionWide =
      (countries.includes("EU") && isEuCountry(normalizedCountry)) || countries.includes("US");
    if (hasJurisdictionWide) {
      return "jurisdiction_wide";
    }

    return "cross_jurisdiction";
  }

  private computeRuleScore(rule: ApplicabilityRule, country: string, matchedConditions: string[]): number {
    let score = 0;
    const normalizedCountry = normalizeCountry(country);
    const conditionCountries = rule.condition.countries ?? [];

    if (conditionCountries.some((candidate) => normalizeCountry(candidate) === normalizedCountry)) {
      score += 120;
    } else if (conditionCountries.includes("EU") && isEuCountry(normalizedCountry)) {
      score += 90;
    } else if (conditionCountries.includes("US") && normalizedCountry === "US") {
      score += 90;
    } else if (conditionCountries.length === 0) {
      score += 20;
    }

    if (this.isCountrySpecificRegulation(country, rule.obligation.regulation_id)) {
      score += 120;
    } else if (
      ["EECC", "NIS2", "ePrivacy", "GDPR", "NIS2 Digital Infrastructure"].some((tag) =>
        rule.obligation.regulation_id.includes(tag)
      )
    ) {
      score += 80;
    } else {
      score += 50;
    }

    score += matchedConditions.length * 8;

    if (rule.condition.roles && rule.condition.roles.length > 0) {
      score += 20;
    }
    if (rule.condition.service_types && rule.condition.service_types.length > 0) {
      score += 12 + rule.condition.service_types.length;
    }
    if (rule.condition.data_types && rule.condition.data_types.length > 0) {
      score += 10 + rule.condition.data_types.length;
    }
    if (rule.condition.system_types && rule.condition.system_types.length > 0) {
      score += 8 + rule.condition.system_types.length;
    }
    if (rule.condition.min_size) {
      score += 6 + SIZE_ORDER[rule.condition.min_size];
    }

    if (rule.obligation.confidence === "high") {
      score += 10;
    } else if (rule.obligation.confidence === "medium") {
      score += 6;
    } else {
      score += 3;
    }

    return score;
  }

  private ruleMatchInfo(
    rule: ApplicabilityRule,
    country: string,
    role: string,
    size: "small" | "medium" | "large",
    dataTypes: string[],
    systemTypes: string[],
    serviceTypes: string[]
  ): { matched: boolean; matched_conditions: string[] } {
    const matchedConditions: string[] = [];
    const normalizedCountry = normalizeCountry(country);

    if (rule.condition.countries && rule.condition.countries.length > 0) {
      const countryMatch = rule.condition.countries.some((candidate) => {
        const normalizedCandidate = normalizeCountry(candidate);
        if (normalizedCandidate === "EU") {
          return isEuCountry(normalizedCountry);
        }
        return normalizedCandidate === normalizedCountry;
      });
      if (!countryMatch) {
        return { matched: false, matched_conditions: matchedConditions };
      }
      matchedConditions.push("country");
    }

    if (
      rule.condition.roles &&
      rule.condition.roles.length > 0 &&
      !rule.condition.roles.map((entry) => entry.toLowerCase()).includes(role.toLowerCase())
    ) {
      return { matched: false, matched_conditions: matchedConditions };
    }
    if (rule.condition.roles && rule.condition.roles.length > 0) {
      matchedConditions.push("role");
    }

    if (
      rule.condition.data_types &&
      rule.condition.data_types.length > 0 &&
      !includesAny(dataTypes, rule.condition.data_types)
    ) {
      return { matched: false, matched_conditions: matchedConditions };
    }
    if (rule.condition.data_types && rule.condition.data_types.length > 0) {
      matchedConditions.push("data_types");
    }

    if (
      rule.condition.system_types &&
      rule.condition.system_types.length > 0 &&
      !includesAny(systemTypes, rule.condition.system_types)
    ) {
      return { matched: false, matched_conditions: matchedConditions };
    }
    if (rule.condition.system_types && rule.condition.system_types.length > 0) {
      matchedConditions.push("system_types");
    }

    if (
      rule.condition.service_types &&
      rule.condition.service_types.length > 0 &&
      !includesAny(serviceTypes, rule.condition.service_types)
    ) {
      return { matched: false, matched_conditions: matchedConditions };
    }
    if (rule.condition.service_types && rule.condition.service_types.length > 0) {
      matchedConditions.push("service_types");
    }

    if (rule.condition.min_size && SIZE_ORDER[size] < SIZE_ORDER[rule.condition.min_size]) {
      return { matched: false, matched_conditions: matchedConditions };
    }
    if (rule.condition.min_size) {
      matchedConditions.push("size");
    }

    return { matched: true, matched_conditions: matchedConditions };
  }

  private ruleMatches(
    rule: ApplicabilityRule,
    country: string,
    role: string,
    size: "small" | "medium" | "large",
    dataTypes: string[],
    systemTypes: string[],
    serviceTypes: string[]
  ): boolean {
    return this.ruleMatchInfo(rule, country, role, size, dataTypes, systemTypes, serviceTypes).matched;
  }

  private computeThreatSeverity(threat: ThreatScenario): "critical" | "high" | "medium" {
    const impactValues = Object.values(threat.impact_dimensions);
    if (impactValues.some((value) => value.toLowerCase() === "critical")) {
      return "critical";
    }
    if (impactValues.some((value) => value.toLowerCase() === "high")) {
      return "high";
    }
    return "medium";
  }

  private mapInputTopic(topic: string): DomainTopic | undefined {
    if (topic.includes("5g") || topic.includes("vendor")) {
      return undefined;
    }
    if (
      topic.includes("security") ||
      topic.includes("risk") ||
      topic.includes("routing") ||
      topic.includes("route leak") ||
      topic.includes("rpki") ||
      topic.includes("rov") ||
      topic.includes("bgp")
    ) {
      return "security_risk_management";
    }
    if (topic.includes("incident") || topic.includes("breach")) {
      return "incident_reporting";
    }
    if (topic.includes("subscriber") || topic.includes("cpni")) {
      return "subscriber_privacy";
    }
    if (
      topic.includes("traffic") ||
      topic.includes("location") ||
      topic.includes("metadata") ||
      topic.includes("dns") ||
      topic.includes("doh") ||
      topic.includes("dot") ||
      topic.includes("qname")
    ) {
      return "traffic_location_privacy";
    }
    if (topic.includes("intercept") || topic.includes("lawful")) {
      return "lawful_intercept";
    }
    if (topic.includes("retention")) {
      return "data_retention";
    }
    if (topic.includes("supply")) {
      return "supply_chain";
    }
    if (
      topic.includes("caller") ||
      topic.includes("robocall") ||
      topic.includes("spoof") ||
      topic.includes("stir") ||
      topic.includes("shaken") ||
      topic.includes("passport")
    ) {
      return "caller_id_authentication";
    }
    return undefined;
  }

  private telemetrySourcesForPattern(patternId: string): string[] {
    switch (patternId) {
      case "tc-5g-core":
        return ["SBA API gateway logs", "AMF/SMF/UPF audit events", "SEPP interconnect telemetry"];
      case "tc-ran":
        return ["gNB/CU/DU alarms", "RIC policy and xApp audit logs", "RF anomaly detection feeds"];
      case "tc-nfv":
        return ["MANO orchestration logs", "VIM and hypervisor security events", "Container runtime events"];
      case "tc-ims":
        return ["SIP session border controller logs", "Diameter/HSS access logs", "Voice fraud analytics"];
      case "tc-transport":
        return ["BGP route monitoring", "RPKI validation telemetry", "Router NetFlow/IPFIX"];
      case "tc-edge":
        return ["Edge workload runtime telemetry", "Local API gateway logs", "Remote attestation status events"];
      case "tc-bss":
        return ["CRM/billing API audit logs", "Subscriber export job traces", "Helpdesk authentication events"];
      case "tc-oss":
        return ["Provisioning workflow audit events", "Configuration change history", "Privileged admin sessions"];
      case "tc-li":
        return ["Warrant workflow system logs", "LI admin function audit trail", "Handover interface transfer logs"];
      case "tc-dns":
        return ["Resolver query logs", "DNSSEC validation failures", "DDoS scrubbing telemetry"];
      case "tc-isp":
        return ["Peering and transit flow telemetry", "Abuse desk case logs", "DDoS edge telemetry"];
      case "tc-iot-platform":
        return ["Device onboarding logs", "SIM OTA change history", "IoT API access logs"];
      default:
        return ["Core network telemetry"];
    }
  }

  private detectionQueryHintsForThreat(threatId: string, category: string): string[] {
    if (threatId.includes("bgp")) {
      return [
        "Detect route origin ASN changes for protected prefixes with invalid/unknown RPKI state.",
        "Alert on abrupt path-length or next-hop changes outside maintenance windows."
      ];
    }
    if (threatId.includes("li-")) {
      return [
        "Alert on intercept activation events without linked warrant IDs and dual-approval metadata.",
        "Detect export/download actions from LI environments outside approved agency handover paths."
      ];
    }
    if (category.includes("subscriber") || threatId.includes("exfiltration")) {
      return [
        "Detect unusual high-volume subscriber read/export activity by user, API key, or partner integration.",
        "Alert when low-frequency identities access diverse subscriber cohorts in short windows."
      ];
    }
    if (category.includes("5g") || threatId.includes("sba")) {
      return [
        "Alert on anomalous NF registration, token scope escalation, or NEF policy updates.",
        "Detect failed mutual-authentication spikes across control-plane interfaces."
      ];
    }
    return [
      "Detect baseline deviations in privileged actions and network control-plane changes.",
      "Correlate identity, configuration, and flow anomalies into threat-specific investigations."
    ];
  }

  private remediationActionForThreat(threatId: string, category: string): string {
    if (threatId.includes("bgp")) {
      return "Implement RPKI route validation, strict prefix filtering, and route-monitoring auto-escalation.";
    }
    if (threatId.includes("li-")) {
      return "Harden lawful intercept administration with dual control, immutable auditing, and strict segmentation.";
    }
    if (threatId.includes("sba") || category.includes("5g")) {
      return "Enforce 5G control-plane API least privilege, strong service identity, and continuous policy validation.";
    }
    if (category.includes("nfv")) {
      return "Apply signed artifact pipeline, orchestration RBAC hardening, and workload/runtime isolation controls.";
    }
    if (category.includes("subscriber")) {
      return "Tighten subscriber data access governance, DLP monitoring, and privacy-purpose enforcement controls.";
    }
    if (category.includes("infrastructure")) {
      return "Increase network resilience with segmentation, redundancy, and high-fidelity anomaly detection coverage.";
    }
    return "Implement focused compensating controls and monitoring for this threat scenario with regulator-aligned evidence.";
  }

  private verificationChecksForPattern(patternId: string): string[] {
    switch (patternId) {
      case "tc-5g-core":
        return [
          "Validate SBA mutual authentication and authorization policy enforcement across NF interfaces.",
          "Run SEPP roaming signaling abuse simulations and alert tuning checks.",
          "Verify network slicing isolation controls under failover and scaling scenarios."
        ];
      case "tc-nfv":
        return [
          "Verify signed image enforcement and reject unsigned/tampered artifacts in orchestration pipeline.",
          "Test hypervisor and container isolation with lateral-movement simulations.",
          "Validate MANO privileged access controls and emergency break-glass auditing."
        ];
      case "tc-ran":
        return [
          "Execute rogue base station detection validation and response drills.",
          "Validate RIC app admission controls and policy integrity monitoring.",
          "Test timing-source anomaly detection for GNSS/PTP drift events."
        ];
      case "tc-li":
        return [
          "Validate dual-approval requirement for intercept activation and export operations.",
          "Test warrant scope enforcement to prevent over-collection.",
          "Verify immutable audit retention and regular integrity checks."
        ];
      case "tc-dns":
        return [
          "Run DNSSEC validation failure and cache poisoning detection tests.",
          "Exercise DDoS scrubbing and resolver failover procedures.",
          "Verify privacy-safe query log retention and access controls."
        ];
      case "tc-isp":
      case "tc-transport":
        return [
          "Run BGP route leak/hijack tabletop and automated response validation.",
          "Verify RPKI origin validation and prefix filtering policy coverage.",
          "Test backbone resiliency and failover under link-loss and congestion conditions."
        ];
      default:
        return [
          "Validate least-privilege administration and privileged action auditing.",
          "Run incident response tabletop for top two architecture threats.",
          "Verify evidence retention and control-effectiveness review cadence."
        ];
    }
  }

}
