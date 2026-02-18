import Database from "better-sqlite3";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  applicabilityRules,
  architecturePatterns,
  authoritativeSources,
  dataCategories,
  evidenceArtifacts,
  technicalStandards,
  threatScenarios
} from "../domain/seedData.js";
import type {
  ApplicabilityRule,
  ArchitecturePattern,
  AuthoritativeSource,
  DataCategory,
  EvidenceArtifact,
  ExactReferenceOverrideInput,
  ExactReferenceOverrideRecord,
  TechnicalStandard,
  ThreatScenario
} from "../types.js";
import { computeDatasetFingerprint } from "../utils/metadata.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const bundledSchemaPath = resolve(__dirname, "schema.sql");
const sourceSchemaPath = resolve(process.cwd(), "src", "db", "schema.sql");
const schemaPath = existsSync(bundledSchemaPath) ? bundledSchemaPath : sourceSchemaPath;

export const defaultDbPath = resolve(process.cwd(), "data", "telecommunications.db");

const asJson = (value: unknown): string => JSON.stringify(value);

export function initializeDatabase(dbPath = defaultDbPath): Database.Database {
  const db = new Database(dbPath);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");

  const schemaSql = readFileSync(schemaPath, "utf8");
  db.exec(schemaSql);

  seedDatabase(db);

  return db;
}

export function seedDatabase(db: Database.Database): void {
  const upsertArchitecture = db.prepare(`
    INSERT INTO architecture_patterns (
      id, name, category, description, components, trust_boundaries,
      data_flows, known_weaknesses, applicable_standards, last_updated
    ) VALUES (
      @id, @name, @category, @description, @components, @trust_boundaries,
      @data_flows, @known_weaknesses, @applicable_standards, @last_updated
    )
    ON CONFLICT(id) DO UPDATE SET
      name=excluded.name,
      category=excluded.category,
      description=excluded.description,
      components=excluded.components,
      trust_boundaries=excluded.trust_boundaries,
      data_flows=excluded.data_flows,
      known_weaknesses=excluded.known_weaknesses,
      applicable_standards=excluded.applicable_standards,
      last_updated=excluded.last_updated
  `);

  const upsertCategory = db.prepare(`
    INSERT INTO data_categories (
      id, name, description, boundary_conditions, jurisdiction_protections,
      deidentification_requirements, cross_border_constraints, last_updated
    ) VALUES (
      @id, @name, @description, @boundary_conditions, @jurisdiction_protections,
      @deidentification_requirements, @cross_border_constraints, @last_updated
    )
    ON CONFLICT(id) DO UPDATE SET
      name=excluded.name,
      description=excluded.description,
      boundary_conditions=excluded.boundary_conditions,
      jurisdiction_protections=excluded.jurisdiction_protections,
      deidentification_requirements=excluded.deidentification_requirements,
      cross_border_constraints=excluded.cross_border_constraints,
      last_updated=excluded.last_updated
  `);

  const upsertThreat = db.prepare(`
    INSERT INTO threat_scenarios (
      id, name, category, description, attack_narrative, mitre_mapping,
      affected_patterns, affected_data_categories, likelihood_factors,
      impact_dimensions, regulation_refs, control_refs, detection_indicators,
      historical_incidents, last_updated
    ) VALUES (
      @id, @name, @category, @description, @attack_narrative, @mitre_mapping,
      @affected_patterns, @affected_data_categories, @likelihood_factors,
      @impact_dimensions, @regulation_refs, @control_refs, @detection_indicators,
      @historical_incidents, @last_updated
    )
    ON CONFLICT(id) DO UPDATE SET
      name=excluded.name,
      category=excluded.category,
      description=excluded.description,
      attack_narrative=excluded.attack_narrative,
      mitre_mapping=excluded.mitre_mapping,
      affected_patterns=excluded.affected_patterns,
      affected_data_categories=excluded.affected_data_categories,
      likelihood_factors=excluded.likelihood_factors,
      impact_dimensions=excluded.impact_dimensions,
      regulation_refs=excluded.regulation_refs,
      control_refs=excluded.control_refs,
      detection_indicators=excluded.detection_indicators,
      historical_incidents=excluded.historical_incidents,
      last_updated=excluded.last_updated
  `);

  const upsertStandard = db.prepare(`
    INSERT INTO technical_standards (
      id, name, version, publisher, scope, key_clauses, control_mappings,
      regulation_mappings, implementation_guidance, licensing_restrictions, last_updated
    ) VALUES (
      @id, @name, @version, @publisher, @scope, @key_clauses, @control_mappings,
      @regulation_mappings, @implementation_guidance, @licensing_restrictions, @last_updated
    )
    ON CONFLICT(id) DO UPDATE SET
      name=excluded.name,
      version=excluded.version,
      publisher=excluded.publisher,
      scope=excluded.scope,
      key_clauses=excluded.key_clauses,
      control_mappings=excluded.control_mappings,
      regulation_mappings=excluded.regulation_mappings,
      implementation_guidance=excluded.implementation_guidance,
      licensing_restrictions=excluded.licensing_restrictions,
      last_updated=excluded.last_updated
  `);

  const upsertRule = db.prepare(`
    INSERT INTO applicability_rules (id, condition, obligation, rationale, last_updated)
    VALUES (@id, @condition, @obligation, @rationale, @last_updated)
    ON CONFLICT(id) DO UPDATE SET
      condition=excluded.condition,
      obligation=excluded.obligation,
      rationale=excluded.rationale,
      last_updated=excluded.last_updated
  `);

  const upsertEvidence = db.prepare(`
    INSERT INTO evidence_artifacts (
      id, audit_type, artifact_name, description, mandatory, retention_period,
      template_ref, regulation_basis, last_updated
    ) VALUES (
      @id, @audit_type, @artifact_name, @description, @mandatory, @retention_period,
      @template_ref, @regulation_basis, @last_updated
    )
    ON CONFLICT(id) DO UPDATE SET
      audit_type=excluded.audit_type,
      artifact_name=excluded.artifact_name,
      description=excluded.description,
      mandatory=excluded.mandatory,
      retention_period=excluded.retention_period,
      template_ref=excluded.template_ref,
      regulation_basis=excluded.regulation_basis,
      last_updated=excluded.last_updated
  `);

  const upsertSource = db.prepare(`
    INSERT INTO authoritative_sources (
      id, source_name, content, license, refresh_cadence, source_type, source_url, last_updated
    ) VALUES (
      @id, @source_name, @content, @license, @refresh_cadence, @source_type, @source_url, @last_updated
    )
    ON CONFLICT(id) DO UPDATE SET
      source_name=excluded.source_name,
      content=excluded.content,
      license=excluded.license,
      refresh_cadence=excluded.refresh_cadence,
      source_type=excluded.source_type,
      source_url=excluded.source_url,
      last_updated=excluded.last_updated
  `);

  const upsertMeta = db.prepare(`
    INSERT INTO db_metadata (key, value)
    VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
  `);

  const seedTx = db.transaction(() => {
    for (const row of architecturePatterns) {
      upsertArchitecture.run({
        ...row,
        components: asJson(row.components),
        trust_boundaries: asJson(row.trust_boundaries),
        data_flows: asJson(row.data_flows),
        known_weaknesses: asJson(row.known_weaknesses),
        applicable_standards: asJson(row.applicable_standards)
      });
    }

    for (const row of dataCategories) {
      upsertCategory.run({
        ...row,
        jurisdiction_protections: asJson(row.jurisdiction_protections),
        deidentification_requirements: asJson(row.deidentification_requirements),
        cross_border_constraints: asJson(row.cross_border_constraints)
      });
    }

    for (const row of threatScenarios) {
      upsertThreat.run({
        ...row,
        mitre_mapping: asJson(row.mitre_mapping),
        affected_patterns: asJson(row.affected_patterns),
        affected_data_categories: asJson(row.affected_data_categories),
        likelihood_factors: asJson(row.likelihood_factors),
        impact_dimensions: asJson(row.impact_dimensions),
        regulation_refs: asJson(row.regulation_refs),
        control_refs: asJson(row.control_refs),
        detection_indicators: asJson(row.detection_indicators),
        historical_incidents: asJson(row.historical_incidents)
      });
    }

    for (const row of technicalStandards) {
      upsertStandard.run({
        ...row,
        key_clauses: asJson(row.key_clauses),
        control_mappings: asJson(row.control_mappings),
        regulation_mappings: asJson(row.regulation_mappings)
      });
    }

    for (const row of applicabilityRules) {
      upsertRule.run({
        ...row,
        condition: asJson(row.condition),
        obligation: asJson(row.obligation)
      });
    }

    for (const row of evidenceArtifacts) {
      upsertEvidence.run({
        ...row,
        mandatory: row.mandatory ? 1 : 0,
        regulation_basis: asJson(row.regulation_basis)
      });
    }

    for (const row of authoritativeSources) {
      upsertSource.run(row);
    }

    const fingerprint = computeDatasetFingerprint({
      architecturePatterns,
      dataCategories,
      threatScenarios,
      technicalStandards,
      applicabilityRules,
      evidenceArtifacts,
      authoritativeSources
    });

    upsertMeta.run("schema_version", "1.0.0");
    upsertMeta.run("domain", "telecommunications");
    upsertMeta.run("dataset_version", "1.0.0");
    upsertMeta.run("dataset_fingerprint", fingerprint);
    upsertMeta.run("last_updated", "2026-02-18");
    upsertMeta.run(
      "coverage_notes",
      "Covers core telecom architecture patterns, primary regulatory regimes and canonical threat catalog from domain-mcp-specifications.md v1.0"
    );

    refreshFtsTables(db);
  });

  seedTx();
}

function refreshFtsTables(db: Database.Database): void {
  db.exec("DELETE FROM architecture_patterns_fts;");
  db.exec("DELETE FROM threat_scenarios_fts;");
  db.exec("DELETE FROM technical_standards_fts;");
  db.exec("DELETE FROM data_categories_fts;");

  const insertArchitectureFts = db.prepare(
    "INSERT INTO architecture_patterns_fts (id, name, description, components) VALUES (?, ?, ?, ?)"
  );
  const insertThreatFts = db.prepare(
    "INSERT INTO threat_scenarios_fts (id, name, description, attack_narrative) VALUES (?, ?, ?, ?)"
  );
  const insertStandardFts = db.prepare(
    "INSERT INTO technical_standards_fts (id, name, scope, key_clauses) VALUES (?, ?, ?, ?)"
  );
  const insertDataFts = db.prepare(
    "INSERT INTO data_categories_fts (id, name, description, boundary_conditions) VALUES (?, ?, ?, ?)"
  );

  const archRows = db
    .prepare("SELECT id, name, description, components FROM architecture_patterns")
    .all() as Array<{ id: string; name: string; description: string; components: string }>;
  for (const row of archRows) {
    insertArchitectureFts.run(row.id, row.name, row.description, row.components);
  }

  const threatRows = db
    .prepare("SELECT id, name, description, attack_narrative FROM threat_scenarios")
    .all() as Array<{ id: string; name: string; description: string; attack_narrative: string }>;
  for (const row of threatRows) {
    insertThreatFts.run(row.id, row.name, row.description, row.attack_narrative);
  }

  const standardRows = db
    .prepare("SELECT id, name, scope, key_clauses FROM technical_standards")
    .all() as Array<{ id: string; name: string; scope: string; key_clauses: string }>;
  for (const row of standardRows) {
    insertStandardFts.run(row.id, row.name, row.scope, row.key_clauses);
  }

  const dataRows = db
    .prepare("SELECT id, name, description, boundary_conditions FROM data_categories")
    .all() as Array<{ id: string; name: string; description: string; boundary_conditions: string }>;
  for (const row of dataRows) {
    insertDataFts.run(row.id, row.name, row.description, row.boundary_conditions);
  }
}

const parseJson = <T>(input: string): T => JSON.parse(input) as T;

export function getArchitecturePatterns(db: Database.Database): ArchitecturePattern[] {
  const rows = db
    .prepare("SELECT * FROM architecture_patterns ORDER BY id")
    .all() as Array<Record<string, string>>;

  return rows.map((row) => ({
    id: row.id,
    name: row.name,
    category: row.category,
    description: row.description,
    components: parseJson<string[]>(row.components),
    trust_boundaries: parseJson<string[]>(row.trust_boundaries),
    data_flows: parseJson<ArchitecturePattern["data_flows"]>(row.data_flows),
    known_weaknesses: parseJson<string[]>(row.known_weaknesses),
    applicable_standards: parseJson<string[]>(row.applicable_standards),
    last_updated: row.last_updated
  }));
}

export function getDataCategories(db: Database.Database): DataCategory[] {
  const rows = db
    .prepare("SELECT * FROM data_categories ORDER BY id")
    .all() as Array<Record<string, string>>;

  return rows.map((row) => ({
    id: row.id,
    name: row.name,
    description: row.description,
    boundary_conditions: row.boundary_conditions,
    jurisdiction_protections: parseJson<DataCategory["jurisdiction_protections"]>(row.jurisdiction_protections),
    deidentification_requirements: parseJson<string[]>(row.deidentification_requirements),
    cross_border_constraints: parseJson<string[]>(row.cross_border_constraints),
    last_updated: row.last_updated
  }));
}

export function getThreatScenarios(db: Database.Database): ThreatScenario[] {
  const rows = db
    .prepare("SELECT * FROM threat_scenarios ORDER BY id")
    .all() as Array<Record<string, string>>;

  return rows.map((row) => ({
    id: row.id,
    name: row.name,
    category: row.category,
    description: row.description,
    attack_narrative: row.attack_narrative,
    mitre_mapping: parseJson<string[]>(row.mitre_mapping),
    affected_patterns: parseJson<string[]>(row.affected_patterns),
    affected_data_categories: parseJson<string[]>(row.affected_data_categories),
    likelihood_factors: parseJson<string[]>(row.likelihood_factors),
    impact_dimensions: parseJson<ThreatScenario["impact_dimensions"]>(row.impact_dimensions),
    regulation_refs: parseJson<ThreatScenario["regulation_refs"]>(row.regulation_refs),
    control_refs: parseJson<string[]>(row.control_refs),
    detection_indicators: parseJson<string[]>(row.detection_indicators),
    historical_incidents: parseJson<string[]>(row.historical_incidents),
    last_updated: row.last_updated
  }));
}

export function getTechnicalStandards(db: Database.Database): TechnicalStandard[] {
  const rows = db
    .prepare("SELECT * FROM technical_standards ORDER BY id")
    .all() as Array<Record<string, string>>;

  return rows.map((row) => ({
    id: row.id,
    name: row.name,
    version: row.version,
    publisher: row.publisher,
    scope: row.scope,
    key_clauses: parseJson<TechnicalStandard["key_clauses"]>(row.key_clauses),
    control_mappings: parseJson<TechnicalStandard["control_mappings"]>(row.control_mappings),
    regulation_mappings: parseJson<TechnicalStandard["regulation_mappings"]>(row.regulation_mappings),
    implementation_guidance: row.implementation_guidance,
    licensing_restrictions: row.licensing_restrictions,
    last_updated: row.last_updated
  }));
}

export function getApplicabilityRules(db: Database.Database): ApplicabilityRule[] {
  const rows = db
    .prepare("SELECT * FROM applicability_rules ORDER BY id")
    .all() as Array<Record<string, string>>;

  return rows.map((row) => ({
    id: row.id,
    condition: parseJson<ApplicabilityRule["condition"]>(row.condition),
    obligation: parseJson<ApplicabilityRule["obligation"]>(row.obligation),
    rationale: row.rationale,
    last_updated: row.last_updated
  }));
}

export function getEvidenceArtifacts(db: Database.Database): EvidenceArtifact[] {
  const rows = db
    .prepare("SELECT * FROM evidence_artifacts ORDER BY id")
    .all() as Array<Record<string, string | number>>;

  return rows.map((row) => ({
    id: String(row.id),
    audit_type: String(row.audit_type),
    artifact_name: String(row.artifact_name),
    description: String(row.description),
    mandatory: Number(row.mandatory) === 1,
    retention_period: String(row.retention_period),
    template_ref: String(row.template_ref),
    regulation_basis: parseJson<EvidenceArtifact["regulation_basis"]>(String(row.regulation_basis)),
    last_updated: String(row.last_updated)
  }));
}

export function getAuthoritativeSources(db: Database.Database): AuthoritativeSource[] {
  return db
    .prepare("SELECT * FROM authoritative_sources ORDER BY source_name")
    .all() as AuthoritativeSource[];
}

export function getMetadataValue(db: Database.Database, key: string): string | undefined {
  const row = db.prepare("SELECT value FROM db_metadata WHERE key = ?").get(key) as { value?: string } | undefined;
  return row?.value;
}

export function getExactReferenceOverrides(
  db: Database.Database,
  jurisdiction?: string
): ExactReferenceOverrideRecord[] {
  const rows = jurisdiction
    ? db
        .prepare(
          `SELECT jurisdiction, assertion_id, regulation_id, exact_reference, citations, source_confidence, resolved_by, notes, resolved_at
           FROM exact_reference_overrides
           WHERE jurisdiction = ?
           ORDER BY assertion_id`
        )
        .all(jurisdiction)
    : db
        .prepare(
          `SELECT jurisdiction, assertion_id, regulation_id, exact_reference, citations, source_confidence, resolved_by, notes, resolved_at
           FROM exact_reference_overrides
           ORDER BY jurisdiction, assertion_id`
        )
        .all();

  return (rows as Array<Record<string, string | null>>).map((row) => ({
    jurisdiction: String(row.jurisdiction),
    assertion_id: String(row.assertion_id),
    regulation_id: String(row.regulation_id),
    exact_reference: String(row.exact_reference),
    citations: row.citations ? parseJson(row.citations) : undefined,
    source_confidence: (row.source_confidence as "high" | "medium" | "low" | null) ?? undefined,
    resolved_by: row.resolved_by ?? undefined,
    notes: row.notes ?? undefined,
    resolved_at: String(row.resolved_at)
  }));
}

export function upsertExactReferenceOverrides(
  db: Database.Database,
  overrides: ExactReferenceOverrideInput[]
): { upserted: number } {
  if (overrides.length === 0) {
    return { upserted: 0 };
  }

  const stmt = db.prepare(`
    INSERT INTO exact_reference_overrides (
      jurisdiction, assertion_id, regulation_id, exact_reference, citations,
      source_confidence, resolved_by, notes, resolved_at
    ) VALUES (
      @jurisdiction, @assertion_id, @regulation_id, @exact_reference, @citations,
      @source_confidence, @resolved_by, @notes, @resolved_at
    )
    ON CONFLICT(jurisdiction, assertion_id) DO UPDATE SET
      regulation_id=excluded.regulation_id,
      exact_reference=excluded.exact_reference,
      citations=excluded.citations,
      source_confidence=excluded.source_confidence,
      resolved_by=excluded.resolved_by,
      notes=excluded.notes,
      resolved_at=excluded.resolved_at
  `);

  const runTx = db.transaction((rows: ExactReferenceOverrideInput[]) => {
    for (const row of rows) {
      stmt.run({
        jurisdiction: row.jurisdiction,
        assertion_id: row.assertion_id,
        regulation_id: row.regulation_id,
        exact_reference: row.exact_reference,
        citations: row.citations ? asJson(row.citations) : null,
        source_confidence: row.source_confidence ?? null,
        resolved_by: row.resolved_by ?? null,
        notes: row.notes ?? null,
        resolved_at: new Date().toISOString()
      });
    }
  });

  runTx(overrides);
  return { upserted: overrides.length };
}
