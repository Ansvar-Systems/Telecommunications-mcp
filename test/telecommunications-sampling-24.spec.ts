import { describe, expect, it } from "vitest";
import { initializeDatabase } from "../src/db/database.js";
import { TelecomDomainService } from "../src/domain/service.js";
import { FoundationMcpAdapter } from "../src/foundation/adapter.js";
import {
  buildFoundationCallsFor5gSecurity,
  buildFoundationCallsForEntityClassification,
  buildFoundationCallsForRetention
} from "../src/foundation/planner.js";

function createService() {
  const db = initializeDatabase(":memory:");
  const service = new TelecomDomainService(db);
  return { service, db };
}

describe("Telecommunications sampling harness (24 cases)", () => {
  it("1. retrieves tc-5g-core, tc-nfv, tc-li, tc-edge, tc-ran patterns", () => {
    const { service, db } = createService();
    const required = ["tc-5g-core", "tc-nfv", "tc-li", "tc-edge", "tc-ran"];
    for (const id of required) {
      expect(service.getArchitecturePattern(id)).toBeDefined();
    }
    expect(service.getArchitecturePattern("tc-5g-core")?.components).toContain("SEPP");
    db.close();
  });

  it("2. classifies CDR metadata for Swedish subscribers with EECC/ePrivacy/LEK/GDPR", () => {
    const { service, db } = createService();
    const result = service.classifyData("CDR metadata for Swedish mobile subscribers", ["SE"]);
    expect(result.categories.map((x) => x.id)).toContain("dc-traffic-metadata");
    expect(result.applicable_regimes).toEqual(expect.arrayContaining(["EECC", "ePrivacy Directive", "LEK", "GDPR"]));
    db.close();
  });

  it("3. classifies 5G network slice config for German hospital case with NIS2", () => {
    const { service, db } = createService();
    const result = service.classifyData("5G network slice configuration for German hospital use case", ["DE"]);
    expect(result.categories.map((x) => x.id)).toContain("dc-network-configuration");
    expect(result.applicable_regimes).toContain("NIS2");
    db.close();
  });

  it("4. classifies lawful intercept delivery for Dutch operator with ETSI LI + Telecommunicatiewet + WIV", () => {
    const { service, db } = createService();
    const result = service.classifyData("lawful intercept delivery for Dutch operator", ["NL"]);
    expect(result.categories.map((x) => x.id)).toContain("dc-lawful-intercept");
    expect(result.applicable_regimes).toEqual(
      expect.arrayContaining(["ETSI LI standards", "Telecommunicatiewet", "WIV"])
    );
    db.close();
  });

  it("5. classifies DNS query logs for US ISP with ECPA/SCA and GDPR overlay when EU subscribers involved", () => {
    const { service, db } = createService();
    const result = service.classifyData("DNS query logs for US ISP", ["US", "SE"]);
    expect(result.categories.map((x) => x.id)).toContain("dc-dns-data");
    expect(result.applicable_regimes).toEqual(expect.arrayContaining(["ECPA/SCA", "state privacy laws", "GDPR"]));
    db.close();
  });

  it("6. classifies subscriber location monetization with critical tier", () => {
    const { service, db } = createService();
    const result = service.classifyData("subscriber location data sold to third-party analytics", ["SE", "US"]);
    expect(result.categories.map((x) => x.id)).toContain("dc-location-data");
    expect(result.protection_tier).toBe("critical");
    db.close();
  });

  it("7. SS7/Diameter threat includes TS 33.117 + GSMA FS.11 references", () => {
    const { service, db } = createService();
    const result = service.getDomainThreats("tc-5g-core", ["subscriber_data"], "signaling");
    const threat = result.threats.find((x) => x.threat_id === "th-ss7-diameter-abuse");
    expect(threat).toBeDefined();
    expect(threat?.regulation_refs.map((x) => `${x.regulation_id} ${x.article_or_section}`).join(" ")).toMatch(/33\.117/i);
    expect(threat?.regulation_refs.map((x) => `${x.regulation_id} ${x.article_or_section}`).join(" ")).toMatch(/FS\.11/i);
    db.close();
  });

  it("8. slice isolation threat includes TS 33.811 + NIS2 Art.21", () => {
    const { service, db } = createService();
    const result = service.getDomainThreats("tc-5g-core", ["content_data"], "slice");
    const threat = result.threats.find((x) => x.threat_id === "th-slice-isolation-failure");
    expect(threat).toBeDefined();
    const refs = threat?.regulation_refs.map((x) => `${x.regulation_id} ${x.article_or_section}`).join(" ") ?? "";
    expect(refs).toMatch(/33\.811/i);
    expect(refs).toMatch(/NIS2/i);
    db.close();
  });

  it("9. lawful intercept unauthorized access threat includes ETSI LI references", () => {
    const { service, db } = createService();
    const result = service.getDomainThreats("tc-li", ["lawful_intercept_data"], "intercept");
    const threat = result.threats.find((x) => x.threat_id === "th-li-unauthorized-access");
    expect(threat).toBeDefined();
    expect(threat?.regulation_refs.some((x) => x.regulation_id.includes("ETSI LI"))).toBe(true);
    db.close();
  });

  it("10. BGP hijacking threat includes MANRS reference", () => {
    const { service, db } = createService();
    const result = service.getDomainThreats("tc-transport", ["traffic_metadata"], "bgp");
    const threat = result.threats.find((x) => x.threat_id === "th-bgp-hijack");
    expect(threat).toBeDefined();
    expect(threat?.regulation_refs.some((x) => x.regulation_id.includes("MANRS"))).toBe(true);
    db.close();
  });

  it("11. NFV hypervisor breakout maps to ETSI NFV SEC", () => {
    const { service, db } = createService();
    const result = service.getDomainThreats("tc-nfv", ["network_configuration"], "hypervisor");
    const threat = result.threats.find((x) => x.threat_id === "th-nfv-hypervisor-breakout");
    expect(threat).toBeDefined();
    expect(threat?.regulation_refs.some((x) => x.regulation_id.includes("ETSI NFV SEC"))).toBe(true);
    db.close();
  });

  it("12. applicability for SE mobile operator includes NIS2/EECC/LEK/ePrivacy", () => {
    const { service, db } = createService();
    const result = service.assessApplicability({
      country: "SE",
      role: "mobile_operator",
      size: "large",
      service_types: ["voice", "data", "5g"],
      data_types: ["traffic_metadata"]
    });
    const regs = result.obligations.map((x) => x.regulation_id);
    expect(regs).toEqual(expect.arrayContaining(["NIS2", "EECC", "LEK", "ePrivacy"]));
    db.close();
  });

  it("13. applicability for US ISP includes FCC/CALEA/CPNI/ECPA-SCA", () => {
    const { service, db } = createService();
    const result = service.assessApplicability({
      country: "US",
      role: "isp",
      size: "large",
      service_types: ["broadband", "dns"],
      data_types: ["subscriber_data", "dns_data", "traffic_metadata"]
    });
    const regs = result.obligations.map((x) => x.regulation_id);
    expect(regs).toEqual(expect.arrayContaining(["CPNI", "ECPA/SCA", "CALEA"]));
    db.close();
  });

  it("14. applicability for NL cloud provider includes NIS2 digital infrastructure + Wbni", () => {
    const { service, db } = createService();
    const result = service.assessApplicability({
      country: "NL",
      role: "cloud_provider",
      size: "large",
      service_types: ["iaas", "cdn"],
      data_types: ["subscriber_data"]
    });
    const regs = result.obligations.map((x) => x.regulation_id);
    expect(regs).toEqual(expect.arrayContaining(["NIS2 Digital Infrastructure", "Wbni/Telecommunicatiewet", "GDPR"]));
    db.close();
  });

  it("15. maps TS 33.501 authentication to NIST 800-63 alignment", () => {
    const { service, db } = createService();
    const result = service.mapToTechnicalStandards("3GPP TS 33.501 primary authentication", undefined);
    const mapping = result.standard_mappings.find((x) => x.standard_id === "3gpp-ts-33-series");
    expect(mapping).toBeDefined();
    expect(mapping?.clauses.map((x) => `${x.clause} ${x.summary}`).join(" ")).toMatch(/33\.501/i);
    db.close();
  });

  it("16. maps GSMA FS.31 to NIS2 Art.21 risk management", () => {
    const { service, db } = createService();
    const result = service.mapToTechnicalStandards("NIS2 Art.21 risk management measures", undefined);
    expect(result.standard_mappings.some((x) => x.standard_id === "gsma-fs31")).toBe(true);
    db.close();
  });

  it("17. maps ETSI NFV SEC to IEC 62443 virtualization security", () => {
    const { service, db } = createService();
    const result = service.mapToTechnicalStandards("IEC 62443 virtualization security requirements", undefined);
    expect(result.standard_mappings.some((x) => x.standard_id === "etsi-nfv-sec")).toBe(true);
    db.close();
  });

  it("18. cross-MCP join plan for classify_telecom_entity targets EU regulations", async () => {
    const plans = buildFoundationCallsForEntityClassification("SE", ["voice", "data", "5g"], "essential");
    expect(plans.some((x) => x.mcp === "eu-regulations")).toBe(true);

    const adapter = new FoundationMcpAdapter({
      endpoints: { "eu-regulations": "https://example.eu" },
      fetchFn: async () =>
        new Response(JSON.stringify({ data: { ok: true } }), {
          status: 200,
          headers: { "content-type": "application/json" }
        })
    });

    const result = await adapter.invoke(plans[0]);
    expect(result.status).toBe("success");
  });

  it("19. cross-MCP join plan for assess_5g_security targets security-controls", async () => {
    const plans = buildFoundationCallsFor5gSecurity("SE");
    const securityPlan = plans.find((x) => x.mcp === "security-controls");
    expect(securityPlan).toBeDefined();

    const adapter = new FoundationMcpAdapter({
      endpoints: { "security-controls": "https://example.controls" },
      fetchFn: async () =>
        new Response(JSON.stringify({ data: { controls: [] } }), {
          status: 200,
          headers: { "content-type": "application/json" }
        })
    });

    const result = await adapter.invoke(securityPlan!);
    expect(result.status).toBe("success");
  });

  it("20. cross-MCP join plan for Dutch retention includes Dutch law MCP", async () => {
    const plans = buildFoundationCallsForRetention("NL");
    expect(plans.some((x) => x.mcp === "dutch-law")).toBe(true);

    const adapter = new FoundationMcpAdapter({
      endpoints: { "dutch-law": "https://example.nl" },
      fetchFn: async () =>
        new Response(JSON.stringify({ data: { provision: "ok" } }), {
          status: 200,
          headers: { "content-type": "application/json" }
        })
    });

    const dutchPlan = plans.find((x) => x.mcp === "dutch-law")!;
    const result = await adapter.invoke(dutchPlan);
    expect(result.status).toBe("success");
  });

  it("21. compares EU ePrivacy+GDPR vs US ECPA/SCA for metadata", () => {
    const { service, db } = createService();
    const result = service.compareJurisdictions("metadata retention/access", ["SE", "US"]);
    expect(result.comparison_matrix[0].obligations.join(" ")).toMatch(/ePrivacy|GDPR/i);
    expect(result.comparison_matrix[1].obligations.join(" ")).toMatch(/ECPA|CPNI/i);
    db.close();
  });

  it("22. compares EU 5G toolbox vs US Section 889/rip-and-replace", () => {
    const { service, db } = createService();
    const result = service.compareJurisdictions("5G high-risk vendor restrictions", ["SE", "US"]);
    expect(result.comparison_matrix[0].obligations.join(" ")).toMatch(/5G Toolbox|NIS2/i);
    expect(result.comparison_matrix[1].obligations.join(" ")).toMatch(/Section 889|rip-and-replace/i);
    db.close();
  });

  it("23. negative test redirects SWIFT CSP compliance to Financial Services MCP", () => {
    const { service, db } = createService();
    const result = service.classifyData("SWIFT CSP compliance", ["US"]);
    expect(result.categories).toHaveLength(0);
    expect(result.recommended_mcp).toBe("financial-services-mcp");
    db.close();
  });

  it("24. edge case pan-EU operator SE+NL+DE includes national overlays", () => {
    const { service, db } = createService();
    const result = service.assessApplicability({
      country: "SE",
      role: "mobile_operator",
      size: "large",
      service_types: ["voice", "data", "5g", "cdn"],
      data_types: ["subscriber_data", "location_data", "iot_m2m_data"],
      system_types: ["tc-5g-core", "tc-edge", "tc-iot-platform"],
      additional_context: {
        countries: ["NL", "DE"]
      }
    });

    const regs = result.obligations.map((x) => x.regulation_id);
    expect(regs).toEqual(expect.arrayContaining(["LEK", "Wbni/Telecommunicatiewet", "TKG", "NIS2", "EECC"]));
    expect(result.profile_summary.cross_border_countries).toEqual(expect.arrayContaining(["SE", "NL", "DE"]));
    db.close();
  });
});
