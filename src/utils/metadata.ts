import { createHash } from "node:crypto";
import type { Citation, ConfidenceLevel, FoundationMcpCall, ToolEnvelope } from "../types.js";

const DEFAULT_EFFECTIVE_DATE = "2026-02-18";
const DEFAULT_LAST_VERIFIED = "2026-02-18";
const DEFAULT_DATASET_VERSION = "1.0.0";

const BASE_CITATIONS: Citation[] = [
  {
    type: "3GPP",
    ref: "TS 33.xxx",
    source_url: "https://www.3gpp.org/specifications-technologies/specifications-by-series"
  },
  {
    type: "ETSI",
    ref: "TS 103 120",
    source_url: "https://www.etsi.org/"
  },
  {
    type: "NIST",
    ref: "SP 1800-33",
    source_url: "https://www.nist.gov/publications"
  }
];

export function computeDatasetFingerprint(input: unknown): string {
  const payload = typeof input === "string" ? input : JSON.stringify(input);
  return `sha256:${createHash("sha256").update(payload).digest("hex")}`;
}

export function makeToolResponse<T>(
  data: T,
  options?: {
    confidence?: ConfidenceLevel;
    rationale?: string;
    citations?: Citation[];
    outOfScope?: string[];
    foundationCalls?: FoundationMcpCall[];
    datasetVersion?: string;
    datasetFingerprint?: string;
    effectiveDate?: string;
    lastVerified?: string;
  }
): ToolEnvelope<T> {
  const mergedCitations = options?.citations && options.citations.length > 0 ? options.citations : BASE_CITATIONS;

  return {
    data,
    metadata: {
      citations: mergedCitations,
      effective_date: options?.effectiveDate ?? DEFAULT_EFFECTIVE_DATE,
      confidence: options?.confidence ?? "inferred",
      inference_rationale: options?.rationale ?? "Derived from domain routing rules and seeded telecommunications catalog.",
      last_verified: options?.lastVerified ?? DEFAULT_LAST_VERIFIED,
      dataset_version: options?.datasetVersion ?? DEFAULT_DATASET_VERSION,
      dataset_fingerprint: options?.datasetFingerprint ?? computeDatasetFingerprint(data),
      out_of_scope: options?.outOfScope ?? [],
      foundation_mcp_calls: options?.foundationCalls ?? []
    }
  };
}
