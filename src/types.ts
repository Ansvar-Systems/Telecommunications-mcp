export type ConfidenceLevel = "authoritative" | "inferred" | "estimated";

export interface Citation {
  type: "CELEX" | "CFR" | "USC" | "ISO" | "IEC" | "NIST" | "ETSI" | "3GPP" | "GSMA" | "RFC";
  ref: string;
  source_url: string;
}

export interface FoundationMcpCall {
  mcp: string;
  tool: string;
  params: Record<string, unknown>;
}

export interface ResponseMetadata {
  citations: Citation[];
  effective_date: string;
  confidence: ConfidenceLevel;
  inference_rationale: string;
  last_verified: string;
  dataset_version: string;
  dataset_fingerprint: string;
  out_of_scope: string[];
  foundation_mcp_calls: FoundationMcpCall[];
}

export interface ToolEnvelope<T> {
  data: T;
  metadata: ResponseMetadata;
}

export interface ArchitecturePattern {
  id: string;
  name: string;
  category: string;
  description: string;
  components: string[];
  trust_boundaries: string[];
  data_flows: Array<{
    data_type: string;
    source: string;
    destination: string;
    protocol: string;
    encryption_state: string;
  }>;
  known_weaknesses: string[];
  applicable_standards: string[];
  last_updated: string;
}

export interface DataCategory {
  id: string;
  name: string;
  description: string;
  boundary_conditions: string;
  jurisdiction_protections: Record<
    string,
    {
      regime: string[];
      tier: "baseline" | "elevated" | "high" | "critical";
      controls: string[];
    }
  >;
  deidentification_requirements: string[];
  cross_border_constraints: string[];
  last_updated: string;
}

export interface ThreatScenario {
  id: string;
  name: string;
  category: string;
  description: string;
  attack_narrative: string;
  mitre_mapping: string[];
  affected_patterns: string[];
  affected_data_categories: string[];
  likelihood_factors: string[];
  impact_dimensions: {
    availability: string;
    integrity: string;
    confidentiality: string;
    safety?: string;
    regulatory: string;
  };
  regulation_refs: Array<{
    regulation_id: string;
    article_or_section: string;
    foundation_mcp: string;
  }>;
  control_refs: string[];
  detection_indicators: string[];
  historical_incidents: string[];
  last_updated: string;
}

export interface TechnicalStandard {
  id: string;
  name: string;
  version: string;
  publisher: string;
  scope: string;
  key_clauses: Array<{ clause: string; summary: string }>;
  control_mappings: Array<{ framework: string; control: string }>;
  regulation_mappings: Array<{ regulation_id: string; article_or_section: string }>;
  implementation_guidance: string;
  licensing_restrictions: string;
  last_updated: string;
}

export interface ApplicabilityRule {
  id: string;
  condition: {
    countries?: string[];
    roles?: string[];
    system_types?: string[];
    data_types?: string[];
    service_types?: string[];
    min_size?: "small" | "medium" | "large";
  };
  obligation: {
    regulation_id: string;
    standard_id?: string;
    article_or_section?: string;
    confidence: "high" | "medium" | "low";
  };
  rationale: string;
  last_updated: string;
}

export interface EvidenceArtifact {
  id: string;
  audit_type: string;
  artifact_name: string;
  description: string;
  mandatory: boolean;
  retention_period: string;
  template_ref: string;
  regulation_basis: Array<{ regulation_id: string; article_or_section?: string }>;
  last_updated: string;
}

export interface AuthoritativeSource {
  id: string;
  source_name: string;
  content: string;
  license: string;
  refresh_cadence: string;
  source_type: string;
  source_url: string;
  last_updated: string;
}

export interface OrgProfile {
  country: string;
  role?: string;
  system_types?: string[];
  data_types?: string[];
  service_types?: string[];
  size?: "small" | "medium" | "large";
}

export interface AssessedObligation {
  regulation_id: string;
  standard_id?: string;
  article_or_section?: string;
  confidence: "high" | "medium" | "low";
  topic?: string;
  directive?: "required" | "restricted" | "prohibited" | "conditional";
  jurisdiction_scope?: string;
  reference_quality?: "exact" | "named";
  resolution_hint?: string;
  assertion_citations?: Citation[];
  source_confidence?: "high" | "medium" | "low";
  precedence_level: "country_specific" | "jurisdiction_wide" | "cross_jurisdiction";
  match_score: number;
  basis: {
    rule_id: string;
    rationale: string;
    matched_country: string;
    matched_conditions: string[];
    supporting_rule_ids?: string[];
  };
}

export interface ObligationConflict {
  topic: string;
  directives: Array<{
    regulation_id: string;
    directive: "required" | "restricted" | "prohibited" | "conditional";
    jurisdiction_scope: string;
    match_score: number;
  }>;
  resolution: {
    recommended_directive: "required" | "restricted" | "prohibited" | "conditional";
    strategy: string;
    rationale: string;
  };
}

export interface ApplicabilityAssessment {
  obligations: AssessedObligation[];
  conflicts: ObligationConflict[];
  matched_rule_count: number;
  profile_summary: {
    country: string;
    role: string;
    size: "small" | "medium" | "large";
    system_types: string[];
    data_types: string[];
    service_types: string[];
    cross_border_countries: string[];
  };
  decision_trace: Array<{
    rule_id: string;
    regulation_id: string;
    score: number;
    precedence_level: "country_specific" | "jurisdiction_wide" | "cross_jurisdiction";
    country: string;
  }>;
}

export interface ExactReferenceOverrideInput {
  jurisdiction: string;
  assertion_id: string;
  regulation_id: string;
  exact_reference: string;
  citations?: Citation[];
  source_confidence?: "high" | "medium" | "low";
  resolved_by?: string;
  notes?: string;
}

export interface ExactReferenceOverrideRecord extends ExactReferenceOverrideInput {
  resolved_at: string;
}
