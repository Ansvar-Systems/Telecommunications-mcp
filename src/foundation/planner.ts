import type { AssessedObligation } from "../types.js";
import { isEuCountryCode, parseJurisdiction } from "../domain/jurisdictions.js";
import type { FoundationCallPlan, FoundationMcpName } from "./adapter.js";

const EU_REGULATION_IDS = new Set([
  "EECC",
  "NIS2",
  "ePrivacy",
  "GDPR",
  "NIS2 Digital Infrastructure"
]);

const US_REGULATION_IDS = new Set(["CPNI", "ECPA/SCA", "CALEA", "FCC STIR/SHAKEN", "FCC rules"]);

const DUTCH_REGULATION_MARKERS = ["Wbni", "Telecommunicatiewet", "WIV", "Dutch"];
const EU_LEVEL_REGULATION_MARKERS = ["EECC", "NIS2", "ePrivacy", "GDPR"];
const US_REGULATION_MARKERS = ["CPNI", "ECPA", "SCA", "CALEA", "FCC", "USC", "CFR", "state", "privacy", "breach"];

function normalizeCountry(country: string): string {
  return country.trim().toUpperCase();
}

function toMcpForRegulation(regulationId: string, country: string): FoundationMcpName {
  if (DUTCH_REGULATION_MARKERS.some((marker) => regulationId.includes(marker)) || normalizeCountry(country) === "NL") {
    return "dutch-law";
  }
  if (US_REGULATION_IDS.has(regulationId) || regulationId.startsWith("US")) {
    return "us-regulations";
  }
  if (EU_REGULATION_IDS.has(regulationId) || regulationId.includes("NIS2") || regulationId.includes("EECC")) {
    return "eu-regulations";
  }
  return "security-controls";
}

function dedupePlans(plans: FoundationCallPlan[]): FoundationCallPlan[] {
  const seen = new Set<string>();
  const output: FoundationCallPlan[] = [];
  for (const plan of plans) {
    const key = `${plan.mcp}|${plan.tool}|${JSON.stringify(plan.params)}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    output.push(plan);
  }
  return output;
}

export function buildFoundationCallsForApplicability(
  country: string,
  obligations: AssessedObligation[]
): FoundationCallPlan[] {
  const plans: FoundationCallPlan[] = [];

  for (const obligation of obligations) {
    const mcp = toMcpForRegulation(obligation.regulation_id, country);

    plans.push({
      mcp,
      tool: "lookup_regulation",
      params: {
        regulation_id: obligation.regulation_id,
        reference: obligation.article_or_section ?? "general",
        country
      }
    });

    if (obligation.standard_id) {
      plans.push({
        mcp: "security-controls",
        tool: "map_standard",
        params: {
          standard_id: obligation.standard_id,
          regulation_id: obligation.regulation_id
        }
      });
    }
  }

  return dedupePlans(plans);
}

export function buildFoundationCallsForEntityClassification(
  country: string,
  serviceTypes: string[],
  nis2Status: string
): FoundationCallPlan[] {
  const normalizedCountry = normalizeCountry(country);
  const plans: FoundationCallPlan[] = [];

  if (["SE", "NL", "DE", "EU"].includes(normalizedCountry) || nis2Status.includes("essential") || nis2Status.includes("important")) {
    plans.push({
      mcp: "eu-regulations",
      tool: "get_articles",
      params: {
        regulations: ["EECC", "NIS2"],
        service_types: serviceTypes,
        country
      }
    });
  }

  if (normalizedCountry === "NL") {
    plans.push({
      mcp: "dutch-law",
      tool: "lookup_provision",
      params: {
        document: "Telecommunicatiewet",
        topic: "operator classification"
      }
    });
  }

  if (normalizedCountry === "US") {
    plans.push({
      mcp: "us-regulations",
      tool: "lookup_regulation",
      params: {
        regulations: ["CPNI", "CALEA"],
        service_types: serviceTypes,
        country
      }
    });
  }

  return dedupePlans(plans);
}

export function buildFoundationCallsFor5gSecurity(country?: string): FoundationCallPlan[] {
  const plans: FoundationCallPlan[] = [
    {
      mcp: "security-controls",
      tool: "map_controls",
      params: {
        profile: "5g",
        standards: ["3gpp-ts-33-series", "gsma-fs31", "enisa-5g-toolbox", "o-ran-security"]
      }
    }
  ];

  const normalizedCountry = normalizeCountry(country ?? "");
  if (normalizedCountry === "US") {
    plans.push({
      mcp: "us-regulations",
      tool: "lookup_regulation",
      params: {
        regulations: ["Section 889", "FCC rip-and-replace"],
        topic: "5g vendor restrictions"
      }
    });
  } else if (normalizedCountry.length > 0) {
    plans.push({
      mcp: "eu-regulations",
      tool: "lookup_regulation",
      params: {
        regulations: ["NIS2"],
        topic: "5g toolbox alignment",
        country
      }
    });
  }

  return dedupePlans(plans);
}

export function buildFoundationCallsForLawfulIntercept(country: string): FoundationCallPlan[] {
  const normalizedCountry = normalizeCountry(country);

  if (normalizedCountry === "US") {
    return [
      {
        mcp: "us-regulations",
        tool: "lookup_regulation",
        params: {
          regulations: ["CALEA"],
          topic: "lawful intercept"
        }
      }
    ];
  }

  if (normalizedCountry === "NL") {
    return [
      {
        mcp: "dutch-law",
        tool: "lookup_provision",
        params: {
          document: "Telecommunicatiewet",
          topic: "lawful intercept"
        }
      },
      {
        mcp: "dutch-law",
        tool: "lookup_provision",
        params: {
          document: "WIV",
          topic: "interception authority"
        }
      }
    ];
  }

  return [
    {
      mcp: "eu-regulations",
      tool: "lookup_regulation",
      params: {
        regulations: ["EECC", "ePrivacy"],
        topic: "lawful intercept",
        country
      }
    }
  ];
}

export function buildFoundationCallsForRetention(country: string): FoundationCallPlan[] {
  const normalizedCountry = normalizeCountry(country);

  if (normalizedCountry === "US") {
    return [
      {
        mcp: "us-regulations",
        tool: "lookup_regulation",
        params: {
          regulations: ["ECPA/SCA", "CPNI"],
          topic: "data retention"
        }
      }
    ];
  }

  if (normalizedCountry === "NL") {
    return [
      {
        mcp: "dutch-law",
        tool: "lookup_provision",
        params: {
          document: "Telecommunicatiewet",
          topic: "retention"
        }
      },
      {
        mcp: "eu-regulations",
        tool: "lookup_case_law",
        params: {
          cases: ["C-293/12", "C-203/15", "C-511/18"],
          topic: "retention proportionality"
        }
      }
    ];
  }

  return [
    {
      mcp: "eu-regulations",
      tool: "lookup_regulation",
      params: {
        regulations: ["ePrivacy", "GDPR"],
        topic: "data retention",
        country
      }
    }
  ];
}

export function buildFoundationCallsForClauseResolution(
  jurisdiction: string,
  assertions: Array<{
    assertion_id: string;
    regulation_id: string;
    article_or_section: string;
  }>
): FoundationCallPlan[] {
  return buildClauseResolutionPlanSet(jurisdiction, assertions).plans;
}

export interface ClauseResolutionPlanSkip {
  jurisdiction: string;
  assertion_id: string;
  regulation_id: string;
  reason: "no_supported_resolver_for_regulation";
}

export interface ClauseResolutionPlanSet {
  plans: FoundationCallPlan[];
  skipped: ClauseResolutionPlanSkip[];
}

function isEuLevelRegulation(regulationId: string): boolean {
  return EU_LEVEL_REGULATION_MARKERS.some((marker) => regulationId.includes(marker));
}

function isDutchRegulation(regulationId: string): boolean {
  return DUTCH_REGULATION_MARKERS.some((marker) => regulationId.includes(marker));
}

function isUsRegulation(regulationId: string): boolean {
  const normalized = regulationId.toLowerCase();
  return US_REGULATION_MARKERS.some((marker) => normalized.includes(marker.toLowerCase()));
}

export function buildClauseResolutionPlanSet(
  jurisdiction: string,
  assertions: Array<{
    assertion_id: string;
    regulation_id: string;
    article_or_section: string;
  }>
): ClauseResolutionPlanSet {
  const parsed = parseJurisdiction(jurisdiction);
  const isUs = parsed.country === "US";
  const isDutch = parsed.country === "NL";
  const isEuMember = isEuCountryCode(parsed.country);

  const plans: FoundationCallPlan[] = [];
  const skipped: ClauseResolutionPlanSkip[] = [];

  for (const assertion of assertions) {
    let resolverMcp: FoundationMcpName | undefined;
    if (isUs && isUsRegulation(assertion.regulation_id)) {
      resolverMcp = "us-regulations";
    } else if (isDutch && isDutchRegulation(assertion.regulation_id)) {
      resolverMcp = "dutch-law";
    } else if (isEuMember && isEuLevelRegulation(assertion.regulation_id)) {
      resolverMcp = "eu-regulations";
    }

    if (!resolverMcp) {
      skipped.push({
        jurisdiction: parsed.key,
        assertion_id: assertion.assertion_id,
        regulation_id: assertion.regulation_id,
        reason: "no_supported_resolver_for_regulation"
      });
      continue;
    }

    plans.push({
      mcp: resolverMcp,
      tool: "resolve_exact_reference",
      params: {
        jurisdiction: parsed.key,
        regulation_id: assertion.regulation_id,
        current_reference: assertion.article_or_section,
        assertion_id: assertion.assertion_id
      }
    });
  }

  return {
    plans: dedupePlans(plans),
    skipped
  };
}
