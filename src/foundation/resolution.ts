import type { Citation, ExactReferenceOverrideInput } from "../types.js";
import type { FoundationCallResult } from "./adapter.js";

type CitationType = Citation["type"];

function normalizeCitationType(input: unknown, mcp: FoundationCallResult["mcp"]): CitationType {
  const value = typeof input === "string" ? input.toUpperCase() : "";
  const allowed: CitationType[] = ["CELEX", "CFR", "USC", "ISO", "IEC", "NIST", "ETSI", "3GPP", "GSMA", "RFC"];
  if (allowed.includes(value as CitationType)) {
    return value as CitationType;
  }

  if (mcp === "us-regulations") {
    return "USC";
  }
  if (mcp === "security-controls") {
    return "NIST";
  }
  if (mcp === "dutch-law") {
    return "CELEX";
  }
  return "CELEX";
}

function asObject(value: unknown): Record<string, unknown> | undefined {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return undefined;
}

function extractPayload(response: unknown): Record<string, unknown> {
  const base = asObject(response) ?? {};
  const structured = asObject(base.structuredContent);
  const dataFromStructured = asObject(structured?.data);
  if (dataFromStructured) {
    return dataFromStructured;
  }
  const data = asObject(base.data);
  if (data) {
    return data;
  }
  return base;
}

function collectCandidateObjects(payload: Record<string, unknown>): Array<Record<string, unknown>> {
  const candidates: Array<Record<string, unknown>> = [payload];
  const arrayKeys = ["candidates", "results", "items", "resolutions", "matches", "records"];

  for (const key of arrayKeys) {
    const value = payload[key];
    if (!Array.isArray(value)) {
      continue;
    }
    for (const entry of value) {
      const asObj = asObject(entry);
      if (asObj) {
        candidates.push(asObj);
      }
    }
  }

  const nestedData = asObject(payload.data);
  if (nestedData) {
    candidates.push(...collectCandidateObjects(nestedData));
  }

  return candidates;
}

function toCitationArray(
  payload: Record<string, unknown>,
  fallbackRef: string,
  fallbackUrl: string,
  mcp: FoundationCallResult["mcp"]
): Citation[] | undefined {
  const raw = payload.citations;
  if (Array.isArray(raw)) {
    const mapped = raw
      .map((entry) => {
        const item = asObject(entry);
        if (!item) {
          return undefined;
        }
        const ref = typeof item.ref === "string" ? item.ref : fallbackRef;
        const sourceUrl =
          typeof item.source_url === "string"
            ? item.source_url
            : typeof item.url === "string"
              ? item.url
              : fallbackUrl;
        return {
          type: normalizeCitationType(item.type, mcp),
          ref,
          source_url: sourceUrl
        } as Citation;
      })
      .filter((entry): entry is Citation => Boolean(entry));
    if (mapped.length > 0) {
      return mapped;
    }
  }

  const citation = asObject(payload.citation);
  if (citation) {
    const ref = typeof citation.ref === "string" ? citation.ref : fallbackRef;
    const sourceUrl =
      typeof citation.source_url === "string"
        ? citation.source_url
        : typeof citation.url === "string"
          ? citation.url
          : fallbackUrl;
    return [
      {
        type: normalizeCitationType(citation.type, mcp),
        ref,
        source_url: sourceUrl
      }
    ];
  }

  return [
    {
      type: normalizeCitationType(undefined, mcp),
      ref: fallbackRef,
      source_url: fallbackUrl
    }
  ];
}

export type ExactReferenceResolutionCandidate = Omit<ExactReferenceOverrideInput, "jurisdiction">;

export function extractExactReferenceResolutionCandidates(
  results: FoundationCallResult[]
): ExactReferenceResolutionCandidate[] {
  const candidates: ExactReferenceResolutionCandidate[] = [];
  const seen = new Set<string>();

  for (const result of results) {
    if (result.status !== "success") {
      continue;
    }

    const payload = extractPayload(result.response);
    const candidateObjects = collectCandidateObjects(payload);

    for (const candidatePayload of candidateObjects) {
      const assertionId =
        typeof candidatePayload.assertion_id === "string"
          ? candidatePayload.assertion_id
          : typeof payload.assertion_id === "string"
            ? payload.assertion_id
            : typeof result.params.assertion_id === "string"
              ? (result.params.assertion_id as string)
              : undefined;

      const regulationId =
        typeof candidatePayload.regulation_id === "string"
          ? candidatePayload.regulation_id
          : typeof payload.regulation_id === "string"
            ? payload.regulation_id
            : typeof result.params.regulation_id === "string"
              ? (result.params.regulation_id as string)
              : undefined;

      const exactReferenceCandidates = [
        candidatePayload.exact_reference,
        candidatePayload.resolved_reference,
        candidatePayload.article_or_section,
        candidatePayload.reference,
        payload.exact_reference,
        payload.resolved_reference,
        payload.article_or_section,
        payload.reference
      ];

      const exactReference = exactReferenceCandidates.find(
        (value): value is string => typeof value === "string" && value.trim().length > 0
      );

      if (!assertionId || !regulationId || !exactReference) {
        continue;
      }

      const dedupeKey = `${assertionId}|${regulationId}|${exactReference}`;
      if (seen.has(dedupeKey)) {
        continue;
      }
      seen.add(dedupeKey);

      const sourceConfidence =
        candidatePayload.source_confidence === "high" ||
        candidatePayload.source_confidence === "medium" ||
        candidatePayload.source_confidence === "low"
          ? candidatePayload.source_confidence
          : payload.source_confidence === "high" || payload.source_confidence === "medium" || payload.source_confidence === "low"
            ? payload.source_confidence
            : candidatePayload.confidence === "high" ||
                candidatePayload.confidence === "medium" ||
                candidatePayload.confidence === "low"
              ? candidatePayload.confidence
              : payload.confidence === "high" || payload.confidence === "medium" || payload.confidence === "low"
                ? payload.confidence
                : "medium";

      const citations = toCitationArray(
        candidatePayload,
        exactReference,
        result.endpoint ?? "https://example.com",
        result.mcp
      );

      candidates.push({
        assertion_id: assertionId,
        regulation_id: regulationId,
        exact_reference: exactReference,
        citations,
        source_confidence: sourceConfidence,
        resolved_by: `foundation:${result.mcp}/${result.tool}`,
        notes: "Resolved via foundation MCP exact reference lookup"
      });
    }
  }

  return candidates;
}
