import type { Citation } from "../types.js";
import {
  getEuropeJurisdictionProfile,
  getUsStateProfile,
  isEuCountryCode,
  parseJurisdiction
} from "./jurisdictions.js";

export interface ClauseAssertion {
  id: string;
  regulation_id: string;
  article_or_section: string;
  topic:
    | "security_risk_management"
    | "incident_reporting"
    | "subscriber_privacy"
    | "traffic_location_privacy"
    | "lawful_intercept"
    | "data_retention"
    | "supply_chain"
    | "caller_id_authentication";
  directive: "required" | "restricted" | "prohibited" | "conditional";
  summary: string;
  confidence: "high" | "medium" | "low";
  reference_quality: "exact" | "named";
  resolution_hint?: string;
  citations: Citation[];
  standard_id?: string;
  trigger: {
    requires_telecom_service?: boolean;
    requires_personal_data?: boolean;
    requires_li_context?: boolean;
    requires_voice_service?: boolean;
    min_size?: "small" | "medium" | "large";
  };
}

const EU_COUNTRY_REFERENCE_OVERRIDES: Record<
  string,
  {
    telecom: string;
    lawful_intercept: string;
    incident: string;
    quality: "exact" | "named";
  }
> = {
  SE: {
    telecom: "LEK (2022:482) Chapter 8 security and integrity provisions",
    lawful_intercept: "LEK lawful intercept provisions + Swedish criminal procedure authorization framework",
    incident: "LEK incident obligations and PTS supervisory reporting requirements",
    quality: "named"
  },
  NL: {
    telecom: "Telecommunicatiewet security and continuity provisions",
    lawful_intercept: "Telecommunicatiewet lawful intercept provisions + Wiv 2017 powers",
    incident: "Wbni incident and supervisory notification obligations",
    quality: "named"
  },
  DE: {
    telecom: "TKG security and integrity obligations",
    lawful_intercept: "TKG lawful intercept implementation + German criminal procedure framework",
    incident: "NIS2 transposition and telecom supervisory reporting obligations",
    quality: "named"
  },
  FR: {
    telecom: "CPCE network security obligations",
    lawful_intercept: "French lawful intercept implementation provisions",
    incident: "ANSSI/sector supervisory incident notification obligations",
    quality: "named"
  },
  ES: {
    telecom: "Ley General de Telecomunicaciones security obligations",
    lawful_intercept: "Spanish lawful intercept implementation provisions",
    incident: "National cyber incident and telecom supervisory reporting obligations",
    quality: "named"
  },
  IT: {
    telecom: "Codice delle comunicazioni elettroniche security obligations",
    lawful_intercept: "Italian lawful intercept implementation provisions",
    incident: "National telecom supervisory and CSIRT reporting obligations",
    quality: "named"
  },
  GB: {
    telecom: "Communications Act and Telecom Security Act duties",
    lawful_intercept: "Investigatory Powers Act 2016",
    incident: "Ofcom and UK NIS reporting obligations",
    quality: "named"
  }
};

const US_STATE_REFERENCE_OVERRIDES: Record<
  string,
  {
    privacy: string;
    breach: string;
    quality: "exact" | "named";
  }
> = {
  CA: {
    privacy: "California CCPA/CPRA (consumer rights and business obligations provisions)",
    breach: "California breach notification statute",
    quality: "named"
  },
  CO: {
    privacy: "Colorado Privacy Act controller and processor duties",
    breach: "Colorado breach notification statute",
    quality: "named"
  },
  CT: {
    privacy: "Connecticut Data Privacy Act controller and processor duties",
    breach: "Connecticut breach notification statute",
    quality: "named"
  },
  VA: {
    privacy: "Virginia Consumer Data Protection Act obligations",
    breach: "Virginia breach notification statute",
    quality: "named"
  },
  UT: {
    privacy: "Utah Consumer Privacy Act obligations",
    breach: "Utah breach notification statute",
    quality: "named"
  },
  TX: {
    privacy: "Texas Data Privacy and Security Act obligations",
    breach: "Texas breach notification statute",
    quality: "named"
  }
};

const CITATIONS = {
  eecc: {
    type: "CELEX" as const,
    ref: "Directive (EU) 2018/1972",
    source_url: "https://eur-lex.europa.eu/eli/dir/2018/1972/oj"
  },
  nis2: {
    type: "CELEX" as const,
    ref: "Directive (EU) 2022/2555",
    source_url: "https://eur-lex.europa.eu/eli/dir/2022/2555/oj"
  },
  gdpr: {
    type: "CELEX" as const,
    ref: "Regulation (EU) 2016/679",
    source_url: "https://eur-lex.europa.eu/eli/reg/2016/679/oj"
  },
  eprivacy: {
    type: "CELEX" as const,
    ref: "Directive 2002/58/EC",
    source_url: "https://eur-lex.europa.eu/eli/dir/2002/58/oj"
  },
  ecpa: {
    type: "USC" as const,
    ref: "18 USC 2510 et seq",
    source_url: "https://uscode.house.gov/view.xhtml?path=/prelim@title18/part1/chapter119"
  },
  sca: {
    type: "USC" as const,
    ref: "18 USC 2701 et seq",
    source_url: "https://uscode.house.gov/view.xhtml?path=/prelim@title18/part1/chapter121"
  },
  cpni: {
    type: "CFR" as const,
    ref: "47 CFR 64.2001",
    source_url: "https://www.ecfr.gov/current/title-47/part-64/subpart-U"
  },
  calea: {
    type: "USC" as const,
    ref: "47 USC 1001",
    source_url: "https://uscode.house.gov/view.xhtml?path=/prelim@title47/chapter9/subchapterI"
  },
  stirShaken: {
    type: "CFR" as const,
    ref: "47 CFR 64.6300",
    source_url: "https://www.ecfr.gov/current/title-47/part-64/subpart-II"
  },
  gpp33501: {
    type: "3GPP" as const,
    ref: "3GPP TS 33.501",
    source_url: "https://www.3gpp.org/"
  },
  etsiLi: {
    type: "ETSI" as const,
    ref: "ETSI TS 103 120",
    source_url: "https://www.etsi.org/"
  },
  rfc7258: {
    type: "RFC" as const,
    ref: "RFC 7258",
    source_url: "https://www.rfc-editor.org/rfc/rfc7258"
  },
  gsmaNesas: {
    type: "GSMA" as const,
    ref: "GSMA NESAS/SCAS",
    source_url: "https://www.gsma.com/security/network-equipment-security-assurance-scheme/"
  },
  iso27001Records: {
    type: "ISO" as const,
    ref: "ISO/IEC 27001:2022 A.5.33",
    source_url: "https://www.iso.org/standard/27001"
  },
  rfc8224: {
    type: "RFC" as const,
    ref: "RFC 8224",
    source_url: "https://www.rfc-editor.org/rfc/rfc8224"
  },
  iso27701: {
    type: "ISO" as const,
    ref: "ISO/IEC 27701:2019 Clause 7.3.2",
    source_url: "https://www.iso.org/standard/71670.html"
  },
  nist80061: {
    type: "NIST" as const,
    ref: "NIST SP 800-61r2 Section 3.2",
    source_url: "https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final"
  },
  rfc9325: {
    type: "RFC" as const,
    ref: "RFC 9325",
    source_url: "https://www.rfc-editor.org/rfc/rfc9325"
  }
};

function globalTechnicalAssertions(jurisdictionKey: string): ClauseAssertion[] {
  const safeKey = jurisdictionKey.replace(/[^A-Z0-9]/g, "-");
  return [
    {
      id: `std-3gpp-security-${safeKey}`,
      regulation_id: "3GPP TS 33.501",
      article_or_section: "Clause 6 (Security architecture and procedures)",
      topic: "security_risk_management",
      directive: "required",
      summary:
        "5G deployments should implement 3GPP security architecture controls for authentication, key hierarchy, and SBA protection.",
      confidence: "high",
      reference_quality: "exact",
      citations: [CITATIONS.gpp33501],
      standard_id: "3gpp-ts-33-series",
      trigger: {
        requires_telecom_service: true
      }
    },
    {
      id: `std-etsi-li-${safeKey}`,
      regulation_id: "ETSI TS 103 120",
      article_or_section: "Clause 6 (Handover interface security requirements)",
      topic: "lawful_intercept",
      directive: "required",
      summary:
        "Lawful intercept interfaces should enforce strong transport security, integrity protection, and operational safeguards.",
      confidence: "medium",
      reference_quality: "exact",
      citations: [CITATIONS.etsiLi],
      standard_id: "etsi-li",
      trigger: {
        requires_li_context: true
      }
    },
    {
      id: `std-rfc7258-privacy-${safeKey}`,
      regulation_id: "RFC 7258",
      article_or_section: "Section 1 (Pervasive monitoring is an attack)",
      topic: "traffic_location_privacy",
      directive: "restricted",
      summary:
        "Traffic and metadata handling should minimize surveillance exposure and treat pervasive monitoring as an active attack vector.",
      confidence: "medium",
      reference_quality: "exact",
      citations: [CITATIONS.rfc7258],
      standard_id: "rfc-7258",
      trigger: {
        requires_personal_data: true
      }
    },
    {
      id: `std-gsma-nesas-supply-chain-${safeKey}`,
      regulation_id: "GSMA NESAS/SCAS",
      article_or_section: "NESAS security assurance framework requirements",
      topic: "supply_chain",
      directive: "required",
      summary:
        "Network equipment procurement should enforce telecom vendor assurance checks and secure development/process evidence.",
      confidence: "medium",
      reference_quality: "exact",
      citations: [CITATIONS.gsmaNesas],
      standard_id: "gsma-nesas-scas",
      trigger: {
        requires_telecom_service: true
      }
    },
    {
      id: `std-iso27001-retention-${safeKey}`,
      regulation_id: "ISO/IEC 27001:2022 A.5.33",
      article_or_section: "A.5.33 Protection of records",
      topic: "data_retention",
      directive: "required",
      summary:
        "Telecom data retention workflows should define record protection, retention periods, and controlled disposal with auditability.",
      confidence: "medium",
      reference_quality: "exact",
      citations: [CITATIONS.iso27001Records],
      standard_id: "iso-27001",
      trigger: {
        requires_telecom_service: true
      }
    },
    {
      id: `std-rfc8224-caller-id-${safeKey}`,
      regulation_id: "RFC 8224",
      article_or_section: "Section 4 Identity Header and PASSporT validation",
      topic: "caller_id_authentication",
      directive: "conditional",
      summary:
        "IP voice domains should implement caller identity signing and verification to reduce spoofing and robocall abuse.",
      confidence: "medium",
      reference_quality: "exact",
      citations: [CITATIONS.rfc8224],
      standard_id: "stir-shaken",
      trigger: {
        requires_voice_service: true
      }
    },
    {
      id: `std-iso27701-privacy-${safeKey}`,
      regulation_id: "ISO/IEC 27701",
      article_or_section: "Clause 7.3.2 (PII principals rights support)",
      topic: "subscriber_privacy",
      directive: "required",
      summary:
        "PII processing operations should enforce privacy governance, rights handling support, and accountable processing controls.",
      confidence: "medium",
      reference_quality: "exact",
      citations: [CITATIONS.iso27701],
      standard_id: "iso-27701",
      trigger: {
        requires_personal_data: true
      }
    },
    {
      id: `std-nist80061-incident-${safeKey}`,
      regulation_id: "NIST SP 800-61r2",
      article_or_section: "Section 3.2 (Incident handling lifecycle)",
      topic: "incident_reporting",
      directive: "required",
      summary:
        "Telecom incident response should follow detection, analysis, containment, eradication, recovery, and post-incident reporting disciplines.",
      confidence: "medium",
      reference_quality: "exact",
      citations: [CITATIONS.nist80061],
      standard_id: "nist-sp-800-61r2",
      trigger: {
        requires_telecom_service: true
      }
    },
    {
      id: `std-rfc9325-tls-${safeKey}`,
      regulation_id: "RFC 9325",
      article_or_section: "Section 4 (Recommendations for use of TLS/DTLS)",
      topic: "security_risk_management",
      directive: "required",
      summary:
        "Telecom control and management interfaces should apply modern TLS/DTLS configurations and deprecate insecure cipher suites and protocol versions.",
      confidence: "medium",
      reference_quality: "exact",
      citations: [CITATIONS.rfc9325],
      standard_id: "ietf-rfc-9325",
      trigger: {
        requires_telecom_service: true
      }
    }
  ];
}

function euCoreAssertions(country: string): ClauseAssertion[] {
  return [
    {
      id: `eu-eecc-security-${country}`,
      regulation_id: "EECC",
      article_or_section: "Art.40",
      topic: "security_risk_management",
      directive: "required",
      summary: "Providers must take technical and organizational measures to manage security risks.",
      confidence: "high",
      reference_quality: "exact",
      citations: [CITATIONS.eecc],
      trigger: {
        requires_telecom_service: true
      }
    },
    {
      id: `eu-nis2-risk-${country}`,
      regulation_id: "NIS2",
      article_or_section: "Art.21",
      topic: "security_risk_management",
      directive: "required",
      summary: "Essential/important entities must implement cybersecurity risk management measures.",
      confidence: "high",
      reference_quality: "exact",
      citations: [CITATIONS.nis2],
      standard_id: "enisa-5g-toolbox",
      trigger: {
        requires_telecom_service: true,
        min_size: "medium"
      }
    },
    {
      id: `eu-nis2-incidents-${country}`,
      regulation_id: "NIS2",
      article_or_section: "Art.23",
      topic: "incident_reporting",
      directive: "required",
      summary: "Significant incidents require staged notifications to competent authorities.",
      confidence: "high",
      reference_quality: "exact",
      citations: [CITATIONS.nis2],
      trigger: {
        requires_telecom_service: true,
        min_size: "medium"
      }
    },
    {
      id: `eu-gdpr-security-${country}`,
      regulation_id: "GDPR",
      article_or_section: "Art.5/6/32/33",
      topic: "subscriber_privacy",
      directive: "required",
      summary: "Personal data processing must have lawful basis, security controls, and breach notification handling.",
      confidence: "high",
      reference_quality: "exact",
      citations: [CITATIONS.gdpr],
      trigger: {
        requires_personal_data: true
      }
    },
    {
      id: `eu-eprivacy-confidentiality-${country}`,
      regulation_id: "ePrivacy",
      article_or_section: "Art.5",
      topic: "traffic_location_privacy",
      directive: "restricted",
      summary: "Confidentiality of communications limits interception and surveillance without legal basis.",
      confidence: "high",
      reference_quality: "exact",
      citations: [CITATIONS.eprivacy],
      trigger: {
        requires_personal_data: true
      }
    },
    {
      id: `eu-eprivacy-traffic-${country}`,
      regulation_id: "ePrivacy",
      article_or_section: "Art.6/9",
      topic: "data_retention",
      directive: "restricted",
      summary: "Traffic and location data retention/use is constrained and purpose-bound.",
      confidence: "high",
      reference_quality: "exact",
      citations: [CITATIONS.eprivacy],
      trigger: {
        requires_personal_data: true
      }
    }
  ];
}

function euCountryAssertion(country: string): ClauseAssertion[] {
  const profile = getEuropeJurisdictionProfile(country);
  if (!profile) {
    return [];
  }
  const reference = EU_COUNTRY_REFERENCE_OVERRIDES[country] ?? {
    telecom: `${profile.telecom_law} security and integrity provisions`,
    lawful_intercept: `${profile.lawful_intercept_law} authorization and handover provisions`,
    incident: `${profile.regulator} incident and supervisory reporting expectations`,
    quality: "named" as const
  };

  return [
    {
      id: `country-telecom-${country}`,
      regulation_id: profile.telecom_law,
      article_or_section: reference.telecom,
      topic: "security_risk_management",
      directive: "required",
      summary: `${profile.name} telecom law security and integrity obligations for electronic communications providers.`,
      confidence: isEuCountryCode(country) ? "high" : "medium",
      reference_quality: reference.quality,
      resolution_hint:
        reference.quality === "named"
          ? "Resolve exact national article numbers via country law MCP join."
          : undefined,
      citations: [
        {
          type: "CELEX",
          ref: profile.telecom_law,
          source_url: "https://www.berec.europa.eu/"
        }
      ],
      trigger: {
        requires_telecom_service: true
      }
    },
    {
      id: `country-li-${country}`,
      regulation_id: profile.lawful_intercept_law,
      article_or_section: reference.lawful_intercept,
      topic: "lawful_intercept",
      directive: "required",
      summary: `${profile.name} lawful intercept implementation controls, authorization workflow, and handover security.`,
      confidence: "medium",
      reference_quality: reference.quality,
      resolution_hint:
        reference.quality === "named"
          ? "Resolve exact lawful intercept article references through national law MCP."
          : undefined,
      citations: [
        {
          type: "ETSI",
          ref: "TS 103 120",
          source_url: "https://www.etsi.org/"
        }
      ],
      trigger: {
        requires_li_context: true
      }
    },
    {
      id: `country-regulator-${country}`,
      regulation_id: `${profile.regulator} supervisory requirements`,
      article_or_section: reference.incident,
      topic: "incident_reporting",
      directive: "required",
      summary: `${profile.regulator} supervisory notification and security oversight requirements.`,
      confidence: "medium",
      reference_quality: reference.quality,
      resolution_hint:
        reference.quality === "named"
          ? "Resolve exact supervisory notice clauses from regulator notices and national implementation acts."
          : undefined,
      citations: [
        {
          type: "CELEX",
          ref: profile.regulator,
          source_url: "https://www.berec.europa.eu/"
        }
      ],
      trigger: {
        requires_telecom_service: true
      }
    }
  ];
}

function usFederalAssertions(): ClauseAssertion[] {
  return [
    {
      id: "us-cpni",
      regulation_id: "CPNI",
      article_or_section: "47 CFR 64.2001",
      topic: "subscriber_privacy",
      directive: "required",
      summary: "Carrier handling of customer proprietary network information requires safeguards and limits.",
      confidence: "high",
      reference_quality: "exact",
      citations: [CITATIONS.cpni],
      trigger: {
        requires_personal_data: true,
        requires_telecom_service: true
      }
    },
    {
      id: "us-ecpa-sca",
      regulation_id: "ECPA/SCA",
      article_or_section: "18 USC 2510+ / 18 USC 2701+",
      topic: "traffic_location_privacy",
      directive: "required",
      summary: "Access to communications content and metadata is constrained by federal legal process requirements.",
      confidence: "high",
      reference_quality: "exact",
      citations: [CITATIONS.ecpa, CITATIONS.sca],
      trigger: {
        requires_personal_data: true
      }
    },
    {
      id: "us-calea",
      regulation_id: "CALEA",
      article_or_section: "47 USC 1001",
      topic: "lawful_intercept",
      directive: "required",
      summary: "Covered providers must ensure lawful intercept capability with secure implementation and controls.",
      confidence: "high",
      reference_quality: "exact",
      citations: [CITATIONS.calea],
      trigger: {
        requires_li_context: true,
        requires_telecom_service: true
      }
    },
    {
      id: "us-stir-shaken",
      regulation_id: "FCC STIR/SHAKEN",
      article_or_section: "47 CFR 64.6300",
      topic: "caller_id_authentication",
      directive: "required",
      summary: "Voice providers must implement caller ID authentication and robocall mitigation measures.",
      confidence: "high",
      reference_quality: "exact",
      citations: [CITATIONS.stirShaken],
      trigger: {
        requires_voice_service: true
      }
    }
  ];
}

function usStateAssertions(stateCode: string): ClauseAssertion[] {
  const profile = getUsStateProfile(stateCode);
  if (!profile) {
    return [];
  }
  const reference = US_STATE_REFERENCE_OVERRIDES[stateCode] ?? {
    privacy: `${profile.privacy_regime} core obligations`,
    breach: `${profile.breach_notification_law} notice and timing provisions`,
    quality: "named" as const
  };

  return [
    {
      id: `us-state-privacy-${stateCode}`,
      regulation_id: profile.privacy_regime,
      article_or_section: reference.privacy,
      topic: "subscriber_privacy",
      directive: "required",
      summary: `${profile.name} privacy obligations for consumer data processing and rights handling.`,
      confidence: "medium",
      reference_quality: reference.quality,
      resolution_hint:
        reference.quality === "named"
          ? "Resolve exact state code sections via state law MCP for this jurisdiction."
          : undefined,
      citations: [
        {
          type: "CFR",
          ref: profile.privacy_regime,
          source_url: "https://www.ncsl.org/telecommunications-and-information-technology/consumer-data-privacy-legislation"
        }
      ],
      trigger: {
        requires_personal_data: true
      }
    },
    {
      id: `us-state-breach-${stateCode}`,
      regulation_id: profile.breach_notification_law,
      article_or_section: reference.breach,
      topic: "incident_reporting",
      directive: "required",
      summary: `${profile.name} breach notification and consumer notice timing requirements.`,
      confidence: "medium",
      reference_quality: reference.quality,
      resolution_hint:
        reference.quality === "named"
          ? "Resolve exact breach-notification sections via state law MCP for this jurisdiction."
          : undefined,
      citations: [
        {
          type: "CFR",
          ref: profile.breach_notification_law,
          source_url: "https://www.ncsl.org/technology-and-communication/security-breach-notification-laws"
        }
      ],
      trigger: {
        requires_personal_data: true
      }
    },
    {
      id: `us-state-telecom-${stateCode}`,
      regulation_id: profile.telecom_consumer_protection,
      article_or_section: "State telecom/consumer protection provisions",
      topic: "subscriber_privacy",
      directive: "required",
      summary: `${profile.name} telecom and consumer protection baseline obligations for subscriber handling.`,
      confidence: "low",
      reference_quality: "named",
      resolution_hint:
        "State telecom consumer-protection section references vary; resolve exact provisions through state regulator/law MCP.",
      citations: [
        {
          type: "CFR",
          ref: profile.telecom_consumer_protection,
          source_url: "https://www.fcc.gov/general/state-telecommunications-regulators"
        }
      ],
      trigger: {
        requires_telecom_service: true
      }
    }
  ];
}

export function getJurisdictionClauseAssertions(jurisdictionRaw: string): ClauseAssertion[] {
  const jurisdiction = parseJurisdiction(jurisdictionRaw);
  const standards = globalTechnicalAssertions(jurisdiction.key);

  if (jurisdiction.country === "US") {
    return [...standards, ...usFederalAssertions(), ...(jurisdiction.state ? usStateAssertions(jurisdiction.state) : [])];
  }

  const europeProfile = getEuropeJurisdictionProfile(jurisdiction.country);
  if (!europeProfile) {
    return [];
  }

  if (europeProfile.eu_member) {
    return [...standards, ...euCoreAssertions(jurisdiction.country), ...euCountryAssertion(jurisdiction.country)];
  }

  return [...standards, ...euCountryAssertion(jurisdiction.country)];
}
