import type {
  ApplicabilityRule,
  ArchitecturePattern,
  AuthoritativeSource,
  DataCategory,
  EvidenceArtifact,
  TechnicalStandard,
  ThreatScenario
} from "../types.js";

const LAST_UPDATED = "2026-02-18";

export const architecturePatterns: ArchitecturePattern[] = [
  {
    id: "tc-5g-core",
    name: "5G Core Network (SA)",
    category: "mobile-core",
    description:
      "Service-based architecture for standalone 5G with control and user plane separation, roaming interconnect and policy-driven exposure.",
    components: ["AMF", "SMF", "UPF", "NRF", "NSSF", "AUSF", "UDM", "PCF", "NEF", "SEPP"],
    trust_boundaries: [
      "Subscriber and SIM/eSIM identity boundary",
      "Inter-PLMN boundary at SEPP",
      "Control plane vs user plane boundary",
      "Exposure boundary at NEF/API gateway"
    ],
    data_flows: [
      {
        data_type: "subscriber_data",
        source: "UDM",
        destination: "AUSF/AMF",
        protocol: "HTTP/2 SBA",
        encryption_state: "TLS in transit"
      },
      {
        data_type: "traffic_metadata",
        source: "SMF",
        destination: "UPF",
        protocol: "PFCP",
        encryption_state: "Operator controlled"
      },
      {
        data_type: "roaming_data",
        source: "SEPP",
        destination: "Partner PLMN",
        protocol: "N32",
        encryption_state: "Application layer security required"
      }
    ],
    known_weaknesses: [
      "SBA API authorization drift",
      "Interworking exposure to SS7/Diameter legacy systems",
      "Slice policy misconfiguration"
    ],
    applicable_standards: ["3gpp-ts-33-series", "gsma-fs31", "enisa-5g-toolbox"],
    last_updated: LAST_UPDATED
  },
  {
    id: "tc-ran",
    name: "Radio Access Network",
    category: "radio-access",
    description: "5G and mixed-generation radio access architecture including O-RAN options and transport synchronization.",
    components: ["gNB", "CU", "DU", "RU", "fronthaul", "midhaul", "backhaul", "RIC"],
    trust_boundaries: [
      "Physical site boundary",
      "Fronthaul transport boundary",
      "RIC application boundary"
    ],
    data_flows: [
      {
        data_type: "location_data",
        source: "gNB",
        destination: "AMF",
        protocol: "NGAP",
        encryption_state: "5G NAS/AS protection"
      },
      {
        data_type: "network_configuration",
        source: "OSS",
        destination: "CU/DU",
        protocol: "NETCONF/gNMI",
        encryption_state: "Mutual TLS"
      }
    ],
    known_weaknesses: ["RIC app supply chain", "Site tampering", "Timing spoofing impacts"],
    applicable_standards: ["o-ran-security", "3gpp-ts-33-series"],
    last_updated: LAST_UPDATED
  },
  {
    id: "tc-nfv",
    name: "NFV Infrastructure",
    category: "virtualization",
    description: "Virtualized network function stack with orchestration and software-defined networking control planes.",
    components: ["VNF", "CNF", "NFVI", "MANO", "VIM", "hypervisor", "SDN controller"],
    trust_boundaries: [
      "Tenant workload boundary",
      "Orchestrator privileged boundary",
      "East-west service mesh boundary"
    ],
    data_flows: [
      {
        data_type: "network_configuration",
        source: "MANO",
        destination: "VNF/CNF",
        protocol: "REST/gRPC",
        encryption_state: "Mutual TLS and signed artifacts"
      },
      {
        data_type: "traffic_metadata",
        source: "VNF",
        destination: "Telemetry pipeline",
        protocol: "IPFIX/Streaming telemetry",
        encryption_state: "TLS"
      }
    ],
    known_weaknesses: ["Hypervisor breakout", "Unsigned VNF images", "SDN controller compromise"],
    applicable_standards: ["etsi-nfv-sec", "nist-sp-800-53", "iec-62443"],
    last_updated: LAST_UPDATED
  },
  {
    id: "tc-ims",
    name: "IP Multimedia Subsystem",
    category: "voice-core",
    description: "VoLTE and voice service core components with SIP signaling and border controls.",
    components: ["P-CSCF", "I-CSCF", "S-CSCF", "HSS", "Media Gateway", "SBC"],
    trust_boundaries: ["Subscriber access boundary", "SIP peering boundary", "Lawful intercept mediation boundary"],
    data_flows: [
      {
        data_type: "content_data",
        source: "UE",
        destination: "Media Gateway",
        protocol: "RTP/SRTP",
        encryption_state: "SRTP recommended"
      },
      {
        data_type: "subscriber_data",
        source: "HSS",
        destination: "S-CSCF",
        protocol: "Diameter",
        encryption_state: "IPsec/TLS"
      }
    ],
    known_weaknesses: ["SIP spoofing", "Fraud via weak interconnect filtering"],
    applicable_standards: ["3gpp-ts-33-series", "stir-shaken"],
    last_updated: LAST_UPDATED
  },
  {
    id: "tc-transport",
    name: "Transport Network",
    category: "transport",
    description: "High-capacity optical and IP/MPLS transport carrying mobile and fixed backhaul traffic.",
    components: ["DWDM", "IP/MPLS routers", "segment routing", "PTP/GNSS sync", "OAM"],
    trust_boundaries: ["Peering boundary", "Backbone control plane boundary", "Timing source boundary"],
    data_flows: [
      {
        data_type: "traffic_metadata",
        source: "edge routers",
        destination: "core routers",
        protocol: "BGP/MPLS",
        encryption_state: "Control plane hardening required"
      }
    ],
    known_weaknesses: ["BGP route leaks", "Timing spoofing", "Fiber cut single points of failure"],
    applicable_standards: ["manrs", "rfc-7258"],
    last_updated: LAST_UPDATED
  },
  {
    id: "tc-edge",
    name: "Multi-Access Edge Computing",
    category: "edge",
    description: "Edge compute platform with local breakout and low-latency workloads integrated to 5G core.",
    components: ["MEC platform", "edge apps", "local breakout", "API exposure gateway"],
    trust_boundaries: ["Edge site boundary", "Workload isolation boundary", "Local API exposure boundary"],
    data_flows: [
      {
        data_type: "iot_m2m_data",
        source: "IoT devices",
        destination: "Edge application",
        protocol: "MQTT/HTTP",
        encryption_state: "TLS with cert-based auth"
      }
    ],
    known_weaknesses: ["Weaker physical controls at remote sites", "API abuse through exposed local services"],
    applicable_standards: ["etsi-mec", "3gpp-ts-33-series"],
    last_updated: LAST_UPDATED
  },
  {
    id: "tc-bss",
    name: "Business Support Systems",
    category: "it-systems",
    description: "CRM, billing and order management stack handling subscriber lifecycle and charging records.",
    components: ["CRM", "billing", "product catalog", "order management", "partner management"],
    trust_boundaries: ["Customer portal boundary", "Partner API boundary", "Payment/data warehouse boundary"],
    data_flows: [
      {
        data_type: "subscriber_data",
        source: "CRM",
        destination: "Billing",
        protocol: "API/ETL",
        encryption_state: "TLS in transit and encryption at rest"
      }
    ],
    known_weaknesses: ["Privilege sprawl", "Partner API token leakage"],
    applicable_standards: ["nis2", "gdpr"],
    last_updated: LAST_UPDATED
  },
  {
    id: "tc-oss",
    name: "Operations Support Systems",
    category: "it-systems",
    description: "Operational control plane for provisioning, inventory and fault management across telecom infrastructure.",
    components: ["fault management", "performance monitoring", "provisioning", "inventory"],
    trust_boundaries: ["Operational admin boundary", "Managed element boundary"],
    data_flows: [
      {
        data_type: "network_configuration",
        source: "OSS",
        destination: "network elements",
        protocol: "SSH/NETCONF/SNMP",
        encryption_state: "Encrypted channels with role-based access"
      }
    ],
    known_weaknesses: ["Overprivileged service accounts", "Lateral movement through management plane"],
    applicable_standards: ["nis2", "iso-27001"],
    last_updated: LAST_UPDATED
  },
  {
    id: "tc-li",
    name: "Lawful Intercept",
    category: "lawful-intercept",
    description: "Lawful intercept mediation, handover and warrant administration infrastructure.",
    components: ["mediation", "handover interface", "administration function", "warrant management"],
    trust_boundaries: ["Judicial request boundary", "Intercept data boundary", "Agency handover boundary"],
    data_flows: [
      {
        data_type: "lawful_intercept_data",
        source: "network probes",
        destination: "handover interface",
        protocol: "ETSI HI interfaces",
        encryption_state: "Strong transport security and integrity checks"
      }
    ],
    known_weaknesses: ["Unauthorized intercept activation", "Tipping-off via audit trail leakage"],
    applicable_standards: ["etsi-li", "calea"],
    last_updated: LAST_UPDATED
  },
  {
    id: "tc-dns",
    name: "DNS Infrastructure",
    category: "digital-infrastructure",
    description: "Recursive and authoritative DNS infrastructure with anti-DDoS and DNSSEC controls.",
    components: ["authoritative DNS", "recursive resolvers", "DDoS protection", "DNSSEC"],
    trust_boundaries: ["Resolver client boundary", "Authoritative management boundary"],
    data_flows: [
      {
        data_type: "dns_data",
        source: "subscriber resolver query",
        destination: "recursive resolver",
        protocol: "DNS/DoT/DoH",
        encryption_state: "DoT/DoH preferred"
      }
    ],
    known_weaknesses: ["Resolver abuse", "Cache poisoning if DNSSEC validation absent"],
    applicable_standards: ["manrs", "rfc-7258", "nis2"],
    last_updated: LAST_UPDATED
  },
  {
    id: "tc-isp",
    name: "Internet Service Provider",
    category: "digital-infrastructure",
    description: "Fixed/mobile ISP architecture with edge routing, peering, abuse and DDoS operations.",
    components: ["edge routers", "peering", "transit", "DDoS mitigation", "abuse management"],
    trust_boundaries: ["Customer edge boundary", "Internet peering boundary", "Abuse operations boundary"],
    data_flows: [
      {
        data_type: "traffic_metadata",
        source: "broadband access network",
        destination: "abuse analytics",
        protocol: "NetFlow/IPFIX",
        encryption_state: "Internal secure transport"
      }
    ],
    known_weaknesses: ["BGP hijack impact", "DDoS saturation"],
    applicable_standards: ["manrs", "nis2", "fcc-cpni"],
    last_updated: LAST_UPDATED
  },
  {
    id: "tc-iot-platform",
    name: "IoT/M2M Platform",
    category: "iot",
    description: "Device and connectivity management platform for large-scale IoT SIM fleets and telemetry pipelines.",
    components: ["device management", "connectivity management", "SIM OTA", "data routing", "API exposure"],
    trust_boundaries: ["Device identity boundary", "Tenant API boundary", "SIM OTA update boundary"],
    data_flows: [
      {
        data_type: "iot_m2m_data",
        source: "connected device",
        destination: "telemetry processing",
        protocol: "MQTT/CoAP/HTTP",
        encryption_state: "Mutual TLS recommended"
      }
    ],
    known_weaknesses: ["Weak device credentials", "Unsafe OTA pipeline"],
    applicable_standards: ["cra", "etsi-mec", "gsma-fs31"],
    last_updated: LAST_UPDATED
  }
];

export const dataCategories: DataCategory[] = [
  {
    id: "dc-subscriber-data",
    name: "Subscriber data",
    description: "Personal and account-linked subscriber data including identity, billing and SIM-linked identifiers.",
    boundary_conditions: "Includes IMSI/MSISDN and account records; excludes anonymized aggregate metrics.",
    jurisdiction_protections: {
      EU: {
        regime: ["EECC", "GDPR", "ePrivacy Directive"],
        tier: "high",
        controls: ["purpose limitation", "access logging", "data minimization", "encryption at rest"]
      },
      US: {
        regime: ["CPNI", "FCC telecom privacy rules", "state privacy laws"],
        tier: "high",
        controls: ["role-based access", "customer notice", "retention policy", "breach notification"]
      }
    },
    deidentification_requirements: [
      "Tokenize persistent subscriber identifiers for analytics reuse.",
      "Separate direct identifiers from usage datasets by key management boundary."
    ],
    cross_border_constraints: ["GDPR transfer mechanisms required for EU-origin personal data."],
    last_updated: LAST_UPDATED
  },
  {
    id: "dc-traffic-metadata",
    name: "Traffic/metadata",
    description: "CDR, session records, connection logs, routing traces and associated metadata.",
    boundary_conditions: "Metadata only; excludes payload content unless combined in same record.",
    jurisdiction_protections: {
      EU: {
        regime: ["ePrivacy Directive", "GDPR", "NIS2 incident handling"],
        tier: "high",
        controls: ["strict purpose binding", "short retention windows", "lawful basis tracking"]
      },
      US: {
        regime: ["ECPA", "SCA", "state privacy and location laws"],
        tier: "elevated",
        controls: ["lawful process verification", "chain of custody", "query audit trail"]
      }
    },
    deidentification_requirements: ["Aggregate session-level records before external analytics exposure."],
    cross_border_constraints: [
      "Cross-border metadata sharing requires transfer assessment and proportionality review in EU contexts."
    ],
    last_updated: LAST_UPDATED
  },
  {
    id: "dc-content-data",
    name: "Content data",
    description: "Voice/message content and user payload captured or processed by telecom systems.",
    boundary_conditions: "Includes media and payload, excluding signaling-only metadata.",
    jurisdiction_protections: {
      EU: {
        regime: ["ePrivacy confidentiality of communications", "GDPR"],
        tier: "critical",
        controls: ["strong encryption", "strict interception controls", "judicial authorization checks"]
      },
      US: {
        regime: ["Wiretap Act", "CALEA", "4th Amendment constraints"],
        tier: "critical",
        controls: ["warrant validation", "least privilege", "tamper-evident audit logs"]
      }
    },
    deidentification_requirements: ["Content should be redacted or transformed before use outside lawful and operational purposes."],
    cross_border_constraints: ["International content transfer is high risk and requires country-specific legal review."],
    last_updated: LAST_UPDATED
  },
  {
    id: "dc-lawful-intercept",
    name: "Lawful intercept data",
    description: "Warranted intercept outputs, related metadata and judicial workflow artifacts.",
    boundary_conditions: "Only data tied to valid legal process and strict authorization chain.",
    jurisdiction_protections: {
      EU: {
        regime: ["ETSI LI standards", "national lawful intercept acts"],
        tier: "critical",
        controls: ["dual control", "immutable logs", "warrant lifecycle management"]
      },
      US: {
        regime: ["CALEA", "federal/state lawful intercept orders"],
        tier: "critical",
        controls: ["agency handover controls", "separation of duties", "target confidentiality"]
      }
    },
    deidentification_requirements: ["No repurposing outside authorized legal scope."],
    cross_border_constraints: ["International handover is generally prohibited without treaty/legal basis."],
    last_updated: LAST_UPDATED
  },
  {
    id: "dc-network-configuration",
    name: "Network configuration",
    description: "Topology, routing policies, interconnect settings, signaling rules and security policy configuration.",
    boundary_conditions: "Operational data that can expose critical infrastructure posture.",
    jurisdiction_protections: {
      EU: {
        regime: ["NIS2", "national critical infrastructure security laws"],
        tier: "high",
        controls: ["configuration integrity", "change approval", "secrets management"]
      },
      US: {
        regime: ["CISA telecom guidance", "FCC resilience expectations"],
        tier: "high",
        controls: ["segmentation", "admin MFA", "configuration backup and attestation"]
      }
    },
    deidentification_requirements: ["Mask sensitive peering and security policy details in external disclosures."],
    cross_border_constraints: ["Sharing with foreign vendors may trigger export and national security review."],
    last_updated: LAST_UPDATED
  },
  {
    id: "dc-spectrum-data",
    name: "Spectrum data",
    description: "Frequency assignments, utilization metrics and interference management data.",
    boundary_conditions: "Includes regulator-facing frequency coordination records.",
    jurisdiction_protections: {
      EU: {
        regime: ["National spectrum authority regulations", "ITU radio regulations"],
        tier: "elevated",
        controls: ["integrity of allocation records", "authorized disclosure only"]
      },
      US: {
        regime: ["FCC licensing rules", "ITU coordination"],
        tier: "elevated",
        controls: ["record authenticity", "license-condition traceability"]
      }
    },
    deidentification_requirements: ["Public reporting should strip site-level precision where security sensitive."],
    cross_border_constraints: ["Cross-border interference datasets require regulator coordination."],
    last_updated: LAST_UPDATED
  },
  {
    id: "dc-location-data",
    name: "Location data",
    description: "Cell-site and derived geolocation information for subscribers or devices.",
    boundary_conditions: "Fine-grained location is treated as highly sensitive personal data in many jurisdictions.",
    jurisdiction_protections: {
      EU: {
        regime: ["ePrivacy location rules", "GDPR"],
        tier: "critical",
        controls: ["explicit purpose and consent where required", "strict retention", "aggregation"]
      },
      US: {
        regime: ["ECPA", "state location privacy laws", "FCC enforcement precedents"],
        tier: "critical",
        controls: ["warrant/legal process checks", "opt-out/notice controls", "query approvals"]
      }
    },
    deidentification_requirements: ["Apply k-anonymity or coarse geohash aggregation before analytics sharing."],
    cross_border_constraints: ["Cross-border location processing requires transfer impact assessment under GDPR."],
    last_updated: LAST_UPDATED
  },
  {
    id: "dc-dns-data",
    name: "DNS data",
    description: "DNS query/response logs and resolver behavior datasets.",
    boundary_conditions: "Can reveal communications habits and inferred interests.",
    jurisdiction_protections: {
      EU: {
        regime: ["GDPR", "ePrivacy", "NIS2 for critical DNS"],
        tier: "high",
        controls: ["pseudonymization", "retention minimization", "resolver privacy features"]
      },
      US: {
        regime: ["ECPA", "state privacy laws"],
        tier: "elevated",
        controls: ["access controls", "legal process checks", "anti-surveillance safeguards"]
      }
    },
    deidentification_requirements: ["Strip direct subscriber identifiers where operationally feasible."],
    cross_border_constraints: ["EU DNS log export requires lawful transfer mechanism and necessity basis."],
    last_updated: LAST_UPDATED
  },
  {
    id: "dc-iot-m2m-data",
    name: "IoT/M2M data",
    description: "Device telemetry, SIM provisioning and machine communication records.",
    boundary_conditions: "Includes industrial and consumer IoT profiles linked to network connectivity.",
    jurisdiction_protections: {
      EU: {
        regime: ["CRA", "GDPR", "NIS2 (where critical)"],
        tier: "high",
        controls: ["device identity assurance", "secure OTA", "telemetry minimization"]
      },
      US: {
        regime: ["sectoral IoT rules", "state privacy laws"],
        tier: "elevated",
        controls: ["device lifecycle control", "credential rotation", "tenant separation"]
      }
    },
    deidentification_requirements: ["Remove stable device IDs in cross-tenant analytics outputs."],
    cross_border_constraints: ["Cross-border telemetry can trigger sectoral restrictions for critical sectors."],
    last_updated: LAST_UPDATED
  },
  {
    id: "dc-roaming-data",
    name: "Roaming data",
    description: "Inter-operator roaming clearing and settlement data including TAP records.",
    boundary_conditions: "Data exchanged across operators and jurisdictions under roaming agreements.",
    jurisdiction_protections: {
      EU: {
        regime: ["BEREC roaming regulation", "GDPR", "ePrivacy"],
        tier: "high",
        controls: ["inter-operator contract controls", "transfer safeguards", "fraud monitoring"]
      },
      US: {
        regime: ["Contractual telecom obligations", "CPNI where applicable"],
        tier: "elevated",
        controls: ["settlement data segregation", "partner assurance checks"]
      }
    },
    deidentification_requirements: ["Use pseudonymous settlement identifiers for non-operational analysis."],
    cross_border_constraints: ["Must honor both home and visited network legal obligations."],
    last_updated: LAST_UPDATED
  }
];

export const threatScenarios: ThreatScenario[] = [
  {
    id: "th-5g-sba-compromise",
    name: "5G SBA network function compromise",
    category: "5g-mobile-network",
    description: "Compromise of service-based 5G core APIs leading to identity, policy or session manipulation.",
    attack_narrative:
      "An attacker obtains privileged API credentials and invokes core network functions to reroute traffic and access subscriber context.",
    mitre_mapping: ["T1078", "T1550", "T1190"],
    affected_patterns: ["tc-5g-core", "tc-edge"],
    affected_data_categories: ["dc-subscriber-data", "dc-traffic-metadata", "dc-location-data"],
    likelihood_factors: ["Weak API auth", "Overprivileged service accounts", "Unsegmented management plane"],
    impact_dimensions: {
      availability: "high",
      integrity: "high",
      confidentiality: "high",
      regulatory: "high"
    },
    regulation_refs: [
      { regulation_id: "NIS2", article_or_section: "Art.21", foundation_mcp: "eu-regulations" },
      { regulation_id: "EECC", article_or_section: "Art.40", foundation_mcp: "eu-regulations" }
    ],
    control_refs: ["NIST-800-53-AC-6", "ISO-27001-A.8.24", "SCF-NET-01"],
    detection_indicators: ["Unexpected NEF/API token usage", "Abnormal policy updates", "Unauthorized NF registration"],
    historical_incidents: ["Public telecom breach reports involving control-plane exposure"],
    last_updated: LAST_UPDATED
  },
  {
    id: "th-slice-isolation-failure",
    name: "Network slicing isolation failure",
    category: "5g-mobile-network",
    description: "Tenant or service slice isolation breaks enabling lateral data access across slices.",
    attack_narrative:
      "Misconfigured slice policies and shared resources allow one slice workload to infer or access another slice's data path.",
    mitre_mapping: ["T1537", "T1499"],
    affected_patterns: ["tc-5g-core", "tc-nfv"],
    affected_data_categories: ["dc-traffic-metadata", "dc-content-data"],
    likelihood_factors: ["Complex policy orchestration", "Incomplete validation testing"],
    impact_dimensions: {
      availability: "medium",
      integrity: "medium",
      confidentiality: "high",
      regulatory: "high"
    },
    regulation_refs: [
      { regulation_id: "NIS2", article_or_section: "Art.21", foundation_mcp: "eu-regulations" },
      { regulation_id: "3GPP", article_or_section: "TS 33.811", foundation_mcp: "security-controls" }
    ],
    control_refs: ["SCF-SEG-02", "NIST-800-53-SC-7"],
    detection_indicators: ["Cross-slice traffic anomalies", "Policy conflicts in orchestrator"],
    historical_incidents: ["Multi-tenant telecom cloud isolation failures (industry advisories)"],
    last_updated: LAST_UPDATED
  },
  {
    id: "th-sepp-exploitation",
    name: "SEPP inter-PLMN signaling exploitation",
    category: "5g-mobile-network",
    description: "Abuse of roaming interconnect signaling to extract or manipulate subscriber context.",
    attack_narrative:
      "A malicious roaming partner or attacker controlling partner credentials sends crafted signaling requests through SEPP interfaces.",
    mitre_mapping: ["T1040", "T1190"],
    affected_patterns: ["tc-5g-core", "tc-transport"],
    affected_data_categories: ["dc-roaming-data", "dc-subscriber-data"],
    likelihood_factors: ["Trust assumptions in roaming partner integration"],
    impact_dimensions: {
      availability: "medium",
      integrity: "medium",
      confidentiality: "high",
      regulatory: "high"
    },
    regulation_refs: [
      { regulation_id: "EECC", article_or_section: "Security obligations", foundation_mcp: "eu-regulations" }
    ],
    control_refs: ["SCF-NET-09", "NIST-800-53-SC-8"],
    detection_indicators: ["Anomalous roaming requests", "Unexpected partner signaling patterns"],
    historical_incidents: ["Legacy interconnect signaling abuses in mobile ecosystems"],
    last_updated: LAST_UPDATED
  },
  {
    id: "th-ss7-diameter-abuse",
    name: "SS7/Diameter signaling abuse",
    category: "5g-mobile-network",
    description: "Legacy signaling exploitation for location tracking or session hijack in interworking environments.",
    attack_narrative:
      "An attacker abuses insecure signaling messages to request location updates or reroute communication flows.",
    mitre_mapping: ["T1040", "T1571"],
    affected_patterns: ["tc-5g-core", "tc-ims"],
    affected_data_categories: ["dc-location-data", "dc-subscriber-data"],
    likelihood_factors: ["Legacy protocol exposure", "Weak signaling firewall rules"],
    impact_dimensions: {
      availability: "medium",
      integrity: "medium",
      confidentiality: "high",
      regulatory: "high"
    },
    regulation_refs: [
      { regulation_id: "3GPP", article_or_section: "TS 33.117", foundation_mcp: "security-controls" },
      { regulation_id: "GSMA", article_or_section: "FS.11", foundation_mcp: "security-controls" }
    ],
    control_refs: ["SCF-NET-12", "NIST-800-53-SC-7"],
    detection_indicators: ["Signaling anomalies", "Unexpected location update request volume"],
    historical_incidents: ["Published SS7 exploitation campaigns"],
    last_updated: LAST_UPDATED
  },
  {
    id: "th-ric-manipulation",
    name: "RAN Intelligent Controller manipulation",
    category: "5g-mobile-network",
    description: "Malicious xApp/rApp logic injection or policy manipulation in RIC environments.",
    attack_narrative:
      "A compromised RIC application alters radio optimization behavior causing service disruption and potential surveillance vectors.",
    mitre_mapping: ["T1608", "T1059"],
    affected_patterns: ["tc-ran"],
    affected_data_categories: ["dc-network-configuration", "dc-location-data"],
    likelihood_factors: ["Insufficient app vetting", "Weak runtime isolation"],
    impact_dimensions: {
      availability: "high",
      integrity: "high",
      confidentiality: "medium",
      regulatory: "medium"
    },
    regulation_refs: [{ regulation_id: "NIS2", article_or_section: "Art.21", foundation_mcp: "eu-regulations" }],
    control_refs: ["SCF-SUP-04", "NIST-800-53-SA-12"],
    detection_indicators: ["Unexpected RIC policy drift", "Unapproved xApp deployment"],
    historical_incidents: ["O-RAN security advisories"],
    last_updated: LAST_UPDATED
  },
  {
    id: "th-sim-swap-esim",
    name: "SIM swap and eSIM provisioning attacks",
    category: "subscriber-privacy",
    description: "Identity takeover through social engineering or provisioning workflow compromise.",
    attack_narrative:
      "Attackers trigger unauthorized SIM re-provisioning and take over subscriber sessions and authentication channels.",
    mitre_mapping: ["T1110", "T1078"],
    affected_patterns: ["tc-bss", "tc-5g-core"],
    affected_data_categories: ["dc-subscriber-data"],
    likelihood_factors: ["Weak helpdesk verification", "Insecure provisioning APIs"],
    impact_dimensions: {
      availability: "medium",
      integrity: "medium",
      confidentiality: "high",
      regulatory: "high"
    },
    regulation_refs: [
      { regulation_id: "CPNI", article_or_section: "47 CFR 64.2001", foundation_mcp: "us-regulations" }
    ],
    control_refs: ["NIST-800-63B", "SCF-IAM-07"],
    detection_indicators: ["Burst of SIM replacement requests", "Failed high-assurance checks"],
    historical_incidents: ["Well-documented SIM swap fraud campaigns"],
    last_updated: LAST_UPDATED
  },
  {
    id: "th-nfv-hypervisor-breakout",
    name: "NFV hypervisor breakout",
    category: "nfv-sdn",
    description: "Compromise of host virtualization layer enabling access to multiple VNFs/CNFs.",
    attack_narrative:
      "A vulnerable VNF is exploited to execute on the host and pivot laterally into adjacent tenant workloads.",
    mitre_mapping: ["T1068", "T1611"],
    affected_patterns: ["tc-nfv", "tc-edge"],
    affected_data_categories: ["dc-traffic-metadata", "dc-network-configuration"],
    likelihood_factors: ["Delayed patching", "Unhardened hypervisor configuration"],
    impact_dimensions: {
      availability: "high",
      integrity: "high",
      confidentiality: "high",
      regulatory: "high"
    },
    regulation_refs: [
      { regulation_id: "ETSI NFV SEC", article_or_section: "Virtualization hardening", foundation_mcp: "security-controls" }
    ],
    control_refs: ["NIST-800-53-SI-2", "SCF-CLOUD-02"],
    detection_indicators: ["Hypervisor integrity alert", "Cross-tenant traffic anomalies"],
    historical_incidents: ["Cloud hypervisor CVE exploitation patterns"],
    last_updated: LAST_UPDATED
  },
  {
    id: "th-sdn-controller-compromise",
    name: "SDN controller compromise",
    category: "nfv-sdn",
    description: "Takeover of SDN control plane allowing malicious traffic engineering and outage creation.",
    attack_narrative:
      "Adversaries with controller access modify flow rules across large infrastructure segments in near real-time.",
    mitre_mapping: ["T1098", "T1485"],
    affected_patterns: ["tc-nfv", "tc-transport"],
    affected_data_categories: ["dc-network-configuration"],
    likelihood_factors: ["Controller exposed to IT network", "Weak admin control"],
    impact_dimensions: {
      availability: "high",
      integrity: "high",
      confidentiality: "medium",
      regulatory: "high"
    },
    regulation_refs: [{ regulation_id: "NIS2", article_or_section: "Art.21", foundation_mcp: "eu-regulations" }],
    control_refs: ["SCF-NET-15", "NIST-800-53-AC-17"],
    detection_indicators: ["Unexpected flow table changes", "Admin login anomalies"],
    historical_incidents: ["SDN controller compromise simulations and incident reports"],
    last_updated: LAST_UPDATED
  },
  {
    id: "th-li-unauthorized-access",
    name: "Unauthorized access to lawful intercept infrastructure",
    category: "lawful-intercept",
    description: "Compromise of LI systems enabling unauthorized surveillance or data disclosure.",
    attack_narrative:
      "Attackers breach LI administration interfaces and activate or export intercept outputs outside authorized process.",
    mitre_mapping: ["T1078", "T1005"],
    affected_patterns: ["tc-li"],
    affected_data_categories: ["dc-lawful-intercept", "dc-content-data"],
    likelihood_factors: ["Insufficient dual control", "Weak segmentation from corporate IT"],
    impact_dimensions: {
      availability: "medium",
      integrity: "high",
      confidentiality: "critical",
      regulatory: "critical"
    },
    regulation_refs: [
      { regulation_id: "ETSI LI", article_or_section: "TS 103 120", foundation_mcp: "security-controls" },
      { regulation_id: "CALEA", article_or_section: "47 USC 1001", foundation_mcp: "us-regulations" }
    ],
    control_refs: ["SCF-LOG-05", "NIST-800-53-AU-9"],
    detection_indicators: ["Intercept activation outside warrant workflow", "Handover endpoint anomalies"],
    historical_incidents: ["Telecom lawful intercept abuse cases"],
    last_updated: LAST_UPDATED
  },
  {
    id: "th-bgp-hijack",
    name: "BGP hijacking and route leaks",
    category: "infrastructure",
    description: "Route manipulation causes traffic interception, blackholing or service outages.",
    attack_narrative:
      "Adversary announces unauthorized prefixes and diverts traffic through malicious or unstable paths.",
    mitre_mapping: ["T1583", "T1498"],
    affected_patterns: ["tc-transport", "tc-isp"],
    affected_data_categories: ["dc-traffic-metadata", "dc-content-data"],
    likelihood_factors: ["Incomplete RPKI coverage", "Weak route filtering"],
    impact_dimensions: {
      availability: "critical",
      integrity: "high",
      confidentiality: "high",
      regulatory: "high"
    },
    regulation_refs: [
      { regulation_id: "NIS2", article_or_section: "Art.21", foundation_mcp: "eu-regulations" },
      { regulation_id: "MANRS", article_or_section: "Routing security actions", foundation_mcp: "security-controls" }
    ],
    control_refs: ["SCF-NET-20", "NIST-800-53-SC-5"],
    detection_indicators: ["RPKI invalid route announcements", "Prefix origin changes"],
    historical_incidents: ["Large-scale route leak events affecting global operators"],
    last_updated: LAST_UPDATED
  },
  {
    id: "th-ddos-dns",
    name: "DDoS against DNS and network infrastructure",
    category: "infrastructure",
    description: "Volumetric and protocol attacks overwhelm critical name resolution and service edge systems.",
    attack_narrative:
      "Botnets target recursive resolvers and peering edges, causing cascading telecom and enterprise outages.",
    mitre_mapping: ["T1498"],
    affected_patterns: ["tc-dns", "tc-isp", "tc-transport"],
    affected_data_categories: ["dc-dns-data", "dc-traffic-metadata"],
    likelihood_factors: ["Inadequate scrubbing capacity", "No anycast resiliency"],
    impact_dimensions: {
      availability: "critical",
      integrity: "low",
      confidentiality: "low",
      regulatory: "medium"
    },
    regulation_refs: [{ regulation_id: "NIS2", article_or_section: "Incident reporting", foundation_mcp: "eu-regulations" }],
    control_refs: ["SCF-IR-03", "NIST-800-53-CP-2"],
    detection_indicators: ["Query per second spikes", "Resolver saturation", "Traffic entropy anomalies"],
    historical_incidents: ["Multiple major DNS outage incidents"],
    last_updated: LAST_UPDATED
  },
  {
    id: "th-location-surveillance",
    name: "Location tracking through network data misuse",
    category: "subscriber-privacy",
    description: "Unauthorized correlation and exploitation of location metadata for surveillance.",
    attack_narrative:
      "Insiders or compromised analytics environments correlate fine-grained location data with subscriber identities.",
    mitre_mapping: ["T1087", "T1567"],
    affected_patterns: ["tc-bss", "tc-5g-core", "tc-ran"],
    affected_data_categories: ["dc-location-data", "dc-subscriber-data"],
    likelihood_factors: ["Weak segregation", "Excessive analytics access"],
    impact_dimensions: {
      availability: "low",
      integrity: "medium",
      confidentiality: "critical",
      regulatory: "critical"
    },
    regulation_refs: [
      { regulation_id: "ePrivacy", article_or_section: "Location data provisions", foundation_mcp: "eu-regulations" },
      { regulation_id: "GDPR", article_or_section: "Art.5/6", foundation_mcp: "eu-regulations" }
    ],
    control_refs: ["SCF-DAT-03", "NIST-800-53-AR-4"],
    detection_indicators: ["Unusual location query patterns", "Identity linkage outside approved workflows"],
    historical_incidents: ["Telecom location data sharing enforcement actions"],
    last_updated: LAST_UPDATED
  },
  {
    id: "th-dns-surveillance",
    name: "DNS query surveillance and profiling",
    category: "subscriber-privacy",
    description: "DNS logs are misused to infer user behavior without legal basis or governance controls.",
    attack_narrative:
      "High-volume DNS data is correlated with subscriber profiles and shared beyond permissible operational purposes.",
    mitre_mapping: ["T1040", "T1087"],
    affected_patterns: ["tc-dns", "tc-isp"],
    affected_data_categories: ["dc-dns-data", "dc-subscriber-data"],
    likelihood_factors: ["Broad analyst access", "Lack of pseudonymization"],
    impact_dimensions: {
      availability: "low",
      integrity: "low",
      confidentiality: "high",
      regulatory: "high"
    },
    regulation_refs: [
      { regulation_id: "GDPR", article_or_section: "Art.5", foundation_mcp: "eu-regulations" },
      { regulation_id: "ECPA", article_or_section: "Stored communications", foundation_mcp: "us-regulations" }
    ],
    control_refs: ["SCF-PRIV-02", "NIST-800-53-AC-6"],
    detection_indicators: ["Bulk DNS exports", "Unauthorized downstream processing"],
    historical_incidents: ["Resolver privacy controversies"],
    last_updated: LAST_UPDATED
  },
  {
    id: "th-fake-base-station-imsi",
    name: "Fake base station and IMSI catcher exploitation",
    category: "5g-mobile-network",
    description: "Rogue base stations force downgrade or lure device attachment for identity and location harvesting.",
    attack_narrative:
      "Adversaries deploy rogue radio equipment near high-value locations, collecting identifiers and enabling selective interception.",
    mitre_mapping: ["T1040", "T1595"],
    affected_patterns: ["tc-ran", "tc-5g-core"],
    affected_data_categories: ["dc-subscriber-data", "dc-location-data", "dc-content-data"],
    likelihood_factors: ["NSA interworking exposure", "Weak base station anomaly detection", "Limited radio monitoring"],
    impact_dimensions: {
      availability: "medium",
      integrity: "medium",
      confidentiality: "high",
      regulatory: "high"
    },
    regulation_refs: [
      { regulation_id: "3GPP", article_or_section: "TS 33.501", foundation_mcp: "security-controls" },
      { regulation_id: "ePrivacy", article_or_section: "Confidentiality of communications", foundation_mcp: "eu-regulations" }
    ],
    control_refs: ["SCF-NET-18", "NIST-800-53-SC-7"],
    detection_indicators: ["Unexpected cell reselection patterns", "Abnormal attach reject behavior", "Rogue RF signatures"],
    historical_incidents: ["Public IMSI catcher investigations in urban centers"],
    last_updated: LAST_UPDATED
  },
  {
    id: "th-roaming-exploitation",
    name: "Roaming trust exploitation",
    category: "5g-mobile-network",
    description: "Abuse of inter-operator roaming trust relationships for fraud, data exfiltration, or signaling manipulation.",
    attack_narrative:
      "A compromised or malicious roaming partner submits crafted signaling and settlement events to abuse trust assumptions.",
    mitre_mapping: ["T1190", "T1040"],
    affected_patterns: ["tc-5g-core", "tc-transport"],
    affected_data_categories: ["dc-roaming-data", "dc-subscriber-data", "dc-traffic-metadata"],
    likelihood_factors: ["Weak partner assurance", "Incomplete interconnect policy validation"],
    impact_dimensions: {
      availability: "medium",
      integrity: "high",
      confidentiality: "high",
      regulatory: "high"
    },
    regulation_refs: [
      { regulation_id: "EECC", article_or_section: "Network security obligations", foundation_mcp: "eu-regulations" },
      { regulation_id: "BEREC roaming rules", article_or_section: "Roaming compliance obligations", foundation_mcp: "eu-regulations" }
    ],
    control_refs: ["SCF-NET-09", "SCF-SUP-03"],
    detection_indicators: ["Roaming signaling volume anomalies", "Unexpected TAP settlement spikes"],
    historical_incidents: ["Inter-operator roaming abuse and fraud investigations"],
    last_updated: LAST_UPDATED
  },
  {
    id: "th-mano-orchestrator-manipulation",
    name: "MANO/orchestrator manipulation",
    category: "nfv-sdn",
    description: "Attackers compromise orchestration systems to alter network function lifecycle and policy enforcement.",
    attack_narrative:
      "By obtaining orchestrator privileges, adversaries deploy tampered VNFs and reconfigure policy and routing behavior.",
    mitre_mapping: ["T1078", "T1098", "T1608"],
    affected_patterns: ["tc-nfv", "tc-edge"],
    affected_data_categories: ["dc-network-configuration", "dc-traffic-metadata"],
    likelihood_factors: ["Weak RBAC in orchestrator", "Unsigned deployment artifacts"],
    impact_dimensions: {
      availability: "high",
      integrity: "high",
      confidentiality: "high",
      regulatory: "high"
    },
    regulation_refs: [
      { regulation_id: "ETSI NFV SEC", article_or_section: "MANO security hardening", foundation_mcp: "security-controls" },
      { regulation_id: "NIS2", article_or_section: "Art.21", foundation_mcp: "eu-regulations" }
    ],
    control_refs: ["SCF-CLOUD-03", "NIST-800-53-AC-6"],
    detection_indicators: ["Unauthorized VNF lifecycle actions", "Unexpected orchestrator API token usage"],
    historical_incidents: ["Cloud orchestration compromise patterns adapted to NFV"],
    last_updated: LAST_UPDATED
  },
  {
    id: "th-vnf-supply-chain",
    name: "Compromised VNF/CNF supply chain artifacts",
    category: "nfv-sdn",
    description: "Tampered network function images and dependencies introduce backdoors into telecom environments.",
    attack_narrative:
      "Adversaries poison CI/CD or supplier repositories, leading operators to deploy compromised network functions.",
    mitre_mapping: ["T1195", "T1608"],
    affected_patterns: ["tc-nfv", "tc-5g-core", "tc-edge"],
    affected_data_categories: ["dc-network-configuration", "dc-subscriber-data"],
    likelihood_factors: ["Insufficient artifact signing", "Weak supplier SBOM governance"],
    impact_dimensions: {
      availability: "high",
      integrity: "critical",
      confidentiality: "high",
      regulatory: "high"
    },
    regulation_refs: [
      { regulation_id: "GSMA NESAS", article_or_section: "Assurance baseline", foundation_mcp: "security-controls" },
      { regulation_id: "NIS2", article_or_section: "Art.21(2)(d)", foundation_mcp: "eu-regulations" }
    ],
    control_refs: ["SCF-SUP-04", "NIST-800-53-SA-12"],
    detection_indicators: ["Unexpected binary hash drift", "Unsigned artifacts in production registries"],
    historical_incidents: ["Supply-chain compromises in network appliance software"],
    last_updated: LAST_UPDATED
  },
  {
    id: "th-east-west-interception",
    name: "East-west interception inside NFV fabric",
    category: "nfv-sdn",
    description: "Traffic interception between virtualized network functions due to segmentation or keying failures.",
    attack_narrative:
      "Adversaries position malicious workloads in shared NFVI and capture plaintext or weakly protected east-west service traffic.",
    mitre_mapping: ["T1040", "T1557"],
    affected_patterns: ["tc-nfv", "tc-edge"],
    affected_data_categories: ["dc-traffic-metadata", "dc-content-data", "dc-subscriber-data"],
    likelihood_factors: ["Flat service mesh topology", "Missing workload identity enforcement"],
    impact_dimensions: {
      availability: "medium",
      integrity: "medium",
      confidentiality: "high",
      regulatory: "high"
    },
    regulation_refs: [
      { regulation_id: "ETSI NFV SEC", article_or_section: "Isolation controls", foundation_mcp: "security-controls" }
    ],
    control_refs: ["SCF-NET-14", "NIST-800-53-SC-8"],
    detection_indicators: ["Unexpected mirrored traffic", "Certificate mismatch in service mesh"],
    historical_incidents: ["Virtualized environment lateral interception case studies"],
    last_updated: LAST_UPDATED
  },
  {
    id: "th-li-target-tipping",
    name: "Lawful intercept target notification (tipping)",
    category: "lawful-intercept",
    description: "Leakage of intercept target information compromises investigations and legal process integrity.",
    attack_narrative:
      "Insiders or compromised workflow systems disclose active intercept status to monitored subjects.",
    mitre_mapping: ["T1005", "T1530"],
    affected_patterns: ["tc-li", "tc-bss"],
    affected_data_categories: ["dc-lawful-intercept", "dc-subscriber-data"],
    likelihood_factors: ["Excessive admin visibility", "Weak case access controls"],
    impact_dimensions: {
      availability: "low",
      integrity: "high",
      confidentiality: "critical",
      regulatory: "critical"
    },
    regulation_refs: [
      { regulation_id: "ETSI LI", article_or_section: "Operational security controls", foundation_mcp: "security-controls" },
      { regulation_id: "CALEA", article_or_section: "Confidentiality obligations", foundation_mcp: "us-regulations" }
    ],
    control_refs: ["SCF-LOG-05", "NIST-800-53-AU-12"],
    detection_indicators: ["Case access anomalies", "Unusual exports of intercept target metadata"],
    historical_incidents: ["Judicially documented tipping incidents"],
    last_updated: LAST_UPDATED
  },
  {
    id: "th-li-warrant-system-compromise",
    name: "Warrant management system compromise",
    category: "lawful-intercept",
    description: "Compromise of warrant workflow systems leads to forged authorizations or unauthorized activations.",
    attack_narrative:
      "Attackers alter warrant records and approval metadata to trigger unauthorized lawful intercept operations.",
    mitre_mapping: ["T1078", "T1565"],
    affected_patterns: ["tc-li"],
    affected_data_categories: ["dc-lawful-intercept"],
    likelihood_factors: ["Weak integrity checks", "No dual control on warrant lifecycle changes"],
    impact_dimensions: {
      availability: "medium",
      integrity: "critical",
      confidentiality: "high",
      regulatory: "critical"
    },
    regulation_refs: [
      { regulation_id: "ETSI LI", article_or_section: "Administration function security", foundation_mcp: "security-controls" }
    ],
    control_refs: ["SCF-IAM-09", "NIST-800-53-IA-2"],
    detection_indicators: ["Retroactive warrant edits", "Approval sequence anomalies"],
    historical_incidents: ["Court-disclosed irregularities in intercept management systems"],
    last_updated: LAST_UPDATED
  },
  {
    id: "th-li-overcollection-retention",
    name: "Lawful intercept over-collection and retention violations",
    category: "lawful-intercept",
    description: "LI systems collect beyond warrant scope or retain data longer than legally permitted.",
    attack_narrative:
      "Configuration errors and poor governance create persistent excess collection and retention of intercepted data.",
    mitre_mapping: ["T1005"],
    affected_patterns: ["tc-li"],
    affected_data_categories: ["dc-lawful-intercept", "dc-content-data", "dc-traffic-metadata"],
    likelihood_factors: ["Broad default filters", "No automated warrant scope enforcement"],
    impact_dimensions: {
      availability: "low",
      integrity: "medium",
      confidentiality: "critical",
      regulatory: "critical"
    },
    regulation_refs: [
      { regulation_id: "ETSI LI", article_or_section: "Scope-constrained interception", foundation_mcp: "security-controls" },
      { regulation_id: "ePrivacy", article_or_section: "Confidentiality constraints", foundation_mcp: "eu-regulations" }
    ],
    control_refs: ["SCF-DAT-06", "NIST-800-53-DM-2"],
    detection_indicators: ["Collection set exceeds warrant parameters", "Retention period overruns"],
    historical_incidents: ["Regulatory findings on over-collection in lawful intercept programs"],
    last_updated: LAST_UPDATED
  },
  {
    id: "th-physical-infrastructure-sabotage",
    name: "Physical telecom infrastructure sabotage",
    category: "infrastructure",
    description: "Deliberate fiber cuts, tower site tampering, and power disruption affect network availability.",
    attack_narrative:
      "Adversaries target critical physical points to trigger large-scale service outages and emergency communications impact.",
    mitre_mapping: ["T1499", "T1485"],
    affected_patterns: ["tc-transport", "tc-ran", "tc-isp"],
    affected_data_categories: ["dc-network-configuration"],
    likelihood_factors: ["Single-path dependencies", "Insufficient physical redundancy"],
    impact_dimensions: {
      availability: "critical",
      integrity: "medium",
      confidentiality: "low",
      regulatory: "high"
    },
    regulation_refs: [
      { regulation_id: "NIS2", article_or_section: "Resilience obligations", foundation_mcp: "eu-regulations" }
    ],
    control_refs: ["SCF-BCP-02", "NIST-800-53-PE-3"],
    detection_indicators: ["Simultaneous regional link failures", "Unexpected tower site access events"],
    historical_incidents: ["Coordinated fiber sabotage events"],
    last_updated: LAST_UPDATED
  },
  {
    id: "th-submarine-cable-tapping",
    name: "Submarine cable tapping and interception",
    category: "infrastructure",
    description: "Interception or tampering of subsea cable traffic affects confidentiality and integrity of international data flows.",
    attack_narrative:
      "State-grade actors target subsea landing and in-line infrastructure to collect and manipulate cross-border traffic.",
    mitre_mapping: ["T1040", "T1583"],
    affected_patterns: ["tc-transport", "tc-isp"],
    affected_data_categories: ["dc-content-data", "dc-traffic-metadata"],
    likelihood_factors: ["Long transnational trust chains", "Limited visibility on subsea segments"],
    impact_dimensions: {
      availability: "medium",
      integrity: "high",
      confidentiality: "critical",
      regulatory: "high"
    },
    regulation_refs: [
      { regulation_id: "NIS2", article_or_section: "Critical infrastructure risk management", foundation_mcp: "eu-regulations" }
    ],
    control_refs: ["SCF-NET-20", "NIST-800-53-SC-7"],
    detection_indicators: ["Anomalous latency patterns", "Unexpected route shifts on subsea paths"],
    historical_incidents: ["Public allegations and investigations into subsea interception"],
    last_updated: LAST_UPDATED
  },
  {
    id: "th-sync-spoofing",
    name: "Synchronization attacks (GPS/PTP spoofing)",
    category: "infrastructure",
    description: "Timing source spoofing destabilizes RAN/transport synchronization and can cascade into service outages.",
    attack_narrative:
      "Attackers spoof GNSS/PTP timing inputs to cause drift in time-sensitive network components and degrade service quality.",
    mitre_mapping: ["T1499", "T1557"],
    affected_patterns: ["tc-transport", "tc-ran"],
    affected_data_categories: ["dc-network-configuration"],
    likelihood_factors: ["Insecure timing source trust", "No holdover and anomaly detection controls"],
    impact_dimensions: {
      availability: "high",
      integrity: "high",
      confidentiality: "low",
      regulatory: "medium"
    },
    regulation_refs: [
      { regulation_id: "NIS2", article_or_section: "Operational resilience", foundation_mcp: "eu-regulations" }
    ],
    control_refs: ["SCF-OPS-07", "NIST-800-53-SI-4"],
    detection_indicators: ["Clock drift alarms", "PTP offset spikes", "Unexpected handover failures"],
    historical_incidents: ["Timing spoofing demonstrations against critical networks"],
    last_updated: LAST_UPDATED
  },
  {
    id: "th-mass-subscriber-exfiltration",
    name: "Mass subscriber data exfiltration",
    category: "subscriber-privacy",
    description: "Bulk theft of subscriber identity and account data from BSS/CRM and adjacent systems.",
    attack_narrative:
      "Compromised privileged access and API endpoints are used to extract large subscriber datasets for fraud and resale.",
    mitre_mapping: ["T1005", "T1078"],
    affected_patterns: ["tc-bss", "tc-oss", "tc-isp"],
    affected_data_categories: ["dc-subscriber-data", "dc-traffic-metadata"],
    likelihood_factors: ["Weak privileged access governance", "Inadequate data exfiltration monitoring"],
    impact_dimensions: {
      availability: "medium",
      integrity: "medium",
      confidentiality: "critical",
      regulatory: "critical"
    },
    regulation_refs: [
      { regulation_id: "CPNI", article_or_section: "47 CFR 64.2001", foundation_mcp: "us-regulations" },
      { regulation_id: "GDPR", article_or_section: "Art.32/33", foundation_mcp: "eu-regulations" }
    ],
    control_refs: ["SCF-IAM-04", "NIST-800-53-AC-6"],
    detection_indicators: ["Unusual bulk exports from CRM", "High-volume API read anomalies"],
    historical_incidents: ["Large telecom customer data breaches across multiple regions"],
    last_updated: LAST_UPDATED
  },
  {
    id: "th-metadata-analysis-surveillance",
    name: "Metadata analysis and surveillance misuse",
    category: "subscriber-privacy",
    description: "Aggregation and correlation of metadata enables persistent surveillance beyond lawful purpose.",
    attack_narrative:
      "Data lakes correlate CDR, DNS, and location metadata to infer behavior patterns without adequate legal basis and controls.",
    mitre_mapping: ["T1087", "T1567"],
    affected_patterns: ["tc-bss", "tc-dns", "tc-5g-core"],
    affected_data_categories: ["dc-traffic-metadata", "dc-location-data", "dc-dns-data"],
    likelihood_factors: ["Overbroad analytics permissions", "Weak purpose limitation enforcement"],
    impact_dimensions: {
      availability: "low",
      integrity: "medium",
      confidentiality: "critical",
      regulatory: "critical"
    },
    regulation_refs: [
      { regulation_id: "ePrivacy", article_or_section: "Traffic and location data constraints", foundation_mcp: "eu-regulations" },
      { regulation_id: "ECPA/SCA", article_or_section: "Access constraints for communications metadata", foundation_mcp: "us-regulations" }
    ],
    control_refs: ["SCF-PRIV-01", "NIST-800-53-AR-4"],
    detection_indicators: ["Cross-domain profiling jobs without legal tag", "Excessive analyst joins over metadata stores"],
    historical_incidents: ["Regulatory enforcement actions for unlawful telecom metadata monetization"],
    last_updated: LAST_UPDATED
  },
  {
    id: "th-content-interception",
    name: "Unauthorized content interception",
    category: "subscriber-privacy",
    description: "Unauthorized interception of voice/message/content payload through compromised network elements.",
    attack_narrative:
      "Compromised edge and signaling infrastructure is abused to mirror or terminate encrypted sessions for data capture.",
    mitre_mapping: ["T1040", "T1557"],
    affected_patterns: ["tc-ims", "tc-5g-core", "tc-li"],
    affected_data_categories: ["dc-content-data", "dc-lawful-intercept"],
    likelihood_factors: ["Weak interconnect security", "Improper LI boundary controls"],
    impact_dimensions: {
      availability: "medium",
      integrity: "high",
      confidentiality: "critical",
      regulatory: "critical"
    },
    regulation_refs: [
      { regulation_id: "Wiretap Act", article_or_section: "18 USC 2511", foundation_mcp: "us-regulations" },
      { regulation_id: "ePrivacy", article_or_section: "Confidentiality of communications", foundation_mcp: "eu-regulations" }
    ],
    control_refs: ["SCF-NET-11", "NIST-800-53-SC-8"],
    detection_indicators: ["Unexplained media path duplication", "Unexpected interception trigger events"],
    historical_incidents: ["Lawful intercept platform abuse and unauthorized interception cases"],
    last_updated: LAST_UPDATED
  }
];

export const technicalStandards: TechnicalStandard[] = [
  {
    id: "iso-27001",
    name: "ISO/IEC 27001:2022",
    version: "2022",
    publisher: "ISO/IEC",
    scope: "Information security management baseline with controls relevant to telecom data governance and record retention.",
    key_clauses: [
      { clause: "A.5.33", summary: "Protection of records and retention governance." },
      { clause: "A.8.24", summary: "Use of cryptography." }
    ],
    control_mappings: [
      { framework: "NIST 800-53", control: "MP-6 media sanitization and retention controls" },
      { framework: "NIS2", control: "Art.21 governance and risk management support" }
    ],
    regulation_mappings: [{ regulation_id: "NIS2", article_or_section: "Art.21" }],
    implementation_guidance:
      "Define telecom data retention schedules, record protection, and secure disposal workflows with auditable approvals.",
    licensing_restrictions: "ISO text is licensed.",
    last_updated: LAST_UPDATED
  },
  {
    id: "iso-27701",
    name: "ISO/IEC 27701:2019",
    version: "2019",
    publisher: "ISO/IEC",
    scope: "Privacy information management extension for controlling and processing PII in regulated environments.",
    key_clauses: [
      { clause: "7.3.2", summary: "Support PII principal rights handling processes." },
      { clause: "7.4.1", summary: "PII processing records and accountability controls." }
    ],
    control_mappings: [
      { framework: "GDPR", control: "Art.5/12-23 accountability and rights operations support" },
      { framework: "NIST Privacy Framework", control: "CT-P and GV-P outcomes" }
    ],
    regulation_mappings: [{ regulation_id: "GDPR", article_or_section: "Art.5/12-23/30" }],
    implementation_guidance:
      "Align subscriber and metadata privacy programs with documented rights workflows, lawful basis tracking, and processing records.",
    licensing_restrictions: "ISO text is licensed.",
    last_updated: LAST_UPDATED
  },
  {
    id: "nist-sp-800-61r2",
    name: "NIST SP 800-61 Revision 2",
    version: "Rev.2",
    publisher: "NIST",
    scope: "Computer security incident handling guide with lifecycle and coordination practices.",
    key_clauses: [
      { clause: "Section 3.2", summary: "Incident handling lifecycle from preparation through lessons learned." }
    ],
    control_mappings: [
      { framework: "NIS2", control: "Art.21 incident handling and reporting maturity support" },
      { framework: "ISO 27035", control: "Incident response process alignment" }
    ],
    regulation_mappings: [{ regulation_id: "NIS2", article_or_section: "Art.21/23" }],
    implementation_guidance:
      "Use as telecom SOC process baseline for triage, escalation, reporting triggers, and post-incident remediation loops.",
    licensing_restrictions: "Public domain.",
    last_updated: LAST_UPDATED
  },
  {
    id: "3gpp-ts-33-series",
    name: "3GPP Security TS 33.xxx",
    version: "Release 17+",
    publisher: "3GPP",
    scope: "5G security architecture, authentication, key management and interconnect protection.",
    key_clauses: [
      { clause: "TS 33.501", summary: "5G system security architecture and procedures." },
      { clause: "TS 33.811", summary: "Network slicing security aspects." },
      { clause: "TS 33.117", summary: "Signaling security for legacy interworking." }
    ],
    control_mappings: [
      { framework: "NIST 800-63", control: "AAL/IAL alignment for subscriber auth" },
      { framework: "ISO 27001:2022", control: "A.8.24 use of cryptography" }
    ],
    regulation_mappings: [{ regulation_id: "NIS2", article_or_section: "Art.21" }],
    implementation_guidance: "Implement mutual authentication, robust key hierarchy, SBA API security and roaming protections.",
    licensing_restrictions: "Free access via 3GPP portal.",
    last_updated: LAST_UPDATED
  },
  {
    id: "etsi-nfv-sec",
    name: "ETSI NFV SEC",
    version: "Current publications",
    publisher: "ETSI",
    scope: "Security guidance for virtualization, orchestration and NFV lifecycle controls.",
    key_clauses: [
      { clause: "NFV-SEC baseline", summary: "Isolation and hardening for NFVI and MANO." }
    ],
    control_mappings: [
      { framework: "IEC 62443", control: "Virtualization and secure zones" },
      { framework: "NIST 800-53", control: "SC-2 and SC-3 process isolation" }
    ],
    regulation_mappings: [{ regulation_id: "NIS2", article_or_section: "Art.21" }],
    implementation_guidance: "Apply image signing, runtime attestation and orchestration least privilege.",
    licensing_restrictions: "Free access via ETSI.",
    last_updated: LAST_UPDATED
  },
  {
    id: "etsi-li",
    name: "ETSI Lawful Intercept (TS 103 120 etc.)",
    version: "Current",
    publisher: "ETSI",
    scope: "Technical handover interfaces and security expectations for lawful intercept implementations.",
    key_clauses: [
      { clause: "TS 103 120", summary: "Handover interface and interception security requirements." }
    ],
    control_mappings: [
      { framework: "ISO 27001:2022", control: "A.5.34 privacy and PII protection" },
      { framework: "NIST 800-53", control: "AU-9 tamper resistance" }
    ],
    regulation_mappings: [{ regulation_id: "National LI laws", article_or_section: "Implementation-specific" }],
    implementation_guidance: "Separate intercept admin from operator IT, enforce dual control, and keep immutable logs.",
    licensing_restrictions: "Free access via ETSI.",
    last_updated: LAST_UPDATED
  },
  {
    id: "calea",
    name: "CALEA",
    version: "Current",
    publisher: "US Congress / FCC",
    scope: "US lawful intercept technical capability obligations.",
    key_clauses: [
      { clause: "47 USC 1001", summary: "Carrier obligations to support lawful intercept capability." }
    ],
    control_mappings: [{ framework: "NIST 800-53", control: "AC/AU controls for lawful access workflows" }],
    regulation_mappings: [{ regulation_id: "US telecom law", article_or_section: "CALEA sections" }],
    implementation_guidance: "Maintain documented intercept capability and protect intercept workflows against misuse.",
    licensing_restrictions: "Public domain text and rules.",
    last_updated: LAST_UPDATED
  },
  {
    id: "gsma-nesas-scas",
    name: "GSMA NESAS/SCAS",
    version: "Current",
    publisher: "GSMA",
    scope: "Network equipment security assurance for telecom vendors and operators.",
    key_clauses: [
      { clause: "NESAS baseline", summary: "Vendor development and product security assurance model." }
    ],
    control_mappings: [{ framework: "NIS2", control: "Supply chain risk management" }],
    regulation_mappings: [{ regulation_id: "NIS2", article_or_section: "Art.21(2)(d)" }],
    implementation_guidance: "Require vendor attestation and test evidence in procurement and acceptance workflows.",
    licensing_restrictions: "Public summaries, full content may require GSMA membership.",
    last_updated: LAST_UPDATED
  },
  {
    id: "gsma-fs31",
    name: "GSMA FS.31",
    version: "Current",
    publisher: "GSMA",
    scope: "Baseline security controls for 5G deployment and operation.",
    key_clauses: [
      { clause: "Control families", summary: "5G security controls spanning identity, transport and operations." }
    ],
    control_mappings: [{ framework: "NIS2", control: "Art.21 risk management controls" }],
    regulation_mappings: [{ regulation_id: "NIS2", article_or_section: "Art.21" }],
    implementation_guidance: "Map FS.31 control families to operator implementation tracks and maturity levels.",
    licensing_restrictions: "Membership may be required for full text.",
    last_updated: LAST_UPDATED
  },
  {
    id: "o-ran-security",
    name: "O-RAN Security WG11",
    version: "Current",
    publisher: "O-RAN Alliance",
    scope: "Security requirements for disaggregated radio and RIC ecosystem.",
    key_clauses: [
      { clause: "WG11 security profile", summary: "RIC and O-Cloud security expectations." }
    ],
    control_mappings: [{ framework: "NIST 800-53", control: "Supply chain and software integrity" }],
    regulation_mappings: [{ regulation_id: "NIS2", article_or_section: "Art.21" }],
    implementation_guidance: "Harden xApp onboarding, image validation and runtime policy enforcement.",
    licensing_restrictions: "Public summaries; full material may require membership.",
    last_updated: LAST_UPDATED
  },
  {
    id: "enisa-5g-toolbox",
    name: "ENISA 5G Toolbox",
    version: "Current",
    publisher: "ENISA / EU",
    scope: "EU 5G cybersecurity mitigation measures and vendor risk strategies.",
    key_clauses: [
      { clause: "Strategic measures", summary: "Vendor risk profiles and supply chain diversification." },
      { clause: "Technical measures", summary: "Network security controls and resilience measures." }
    ],
    control_mappings: [{ framework: "NIS2", control: "Entity risk management and resilience" }],
    regulation_mappings: [{ regulation_id: "NIS2", article_or_section: "Art.21" }],
    implementation_guidance: "Integrate toolbox measures into procurement and national telecom security programs.",
    licensing_restrictions: "Free EU publication.",
    last_updated: LAST_UPDATED
  },
  {
    id: "nist-sp-1800-33",
    name: "NIST SP 1800-33",
    version: "1.0",
    publisher: "NIST",
    scope: "Practical guide for securing 5G networks and components.",
    key_clauses: [{ clause: "Reference architecture", summary: "Implementation examples for enterprise and operator 5G security." }],
    control_mappings: [{ framework: "NIST CSF 2.0", control: "Govern/protect/detect outcomes" }],
    regulation_mappings: [{ regulation_id: "US federal guidance", article_or_section: "5G security best practices" }],
    implementation_guidance: "Use as implementation profile to validate controls across 5G stack layers.",
    licensing_restrictions: "Public domain.",
    last_updated: LAST_UPDATED
  },
  {
    id: "ietf-rfc-8224",
    name: "RFC 8224 SIP Identity",
    version: "2018",
    publisher: "IETF",
    scope: "SIP Identity and PASSporT mechanisms underpinning STIR/SHAKEN caller authentication.",
    key_clauses: [
      { clause: "Section 4", summary: "Identity header construction and verification behavior." }
    ],
    control_mappings: [{ framework: "FCC", control: "Caller authentication implementation support" }],
    regulation_mappings: [{ regulation_id: "FCC rules", article_or_section: "47 CFR 64.6300" }],
    implementation_guidance:
      "Implement identity signing, verification, and certificate trust governance across voice interconnect boundaries.",
    licensing_restrictions: "Open RFC.",
    last_updated: LAST_UPDATED
  },
  {
    id: "ietf-rfc-9325",
    name: "RFC 9325 TLS/DTLS Recommendations",
    version: "2022",
    publisher: "IETF",
    scope: "Best current practice recommendations for secure TLS and DTLS usage.",
    key_clauses: [
      { clause: "Section 4", summary: "Recommended protocol versions, cipher suites, and configuration practices." }
    ],
    control_mappings: [{ framework: "NIS2", control: "Art.21 encryption and network security hardening support" }],
    regulation_mappings: [{ regulation_id: "NIS2", article_or_section: "Art.21(2)(h)" }],
    implementation_guidance:
      "Use modern TLS baselines for telecom APIs, management planes, and interconnect interfaces; remove weak cipher and legacy protocol support.",
    licensing_restrictions: "Open RFC.",
    last_updated: LAST_UPDATED
  },
  {
    id: "stir-shaken",
    name: "STIR/SHAKEN",
    version: "Current",
    publisher: "ATIS/SIP Forum/FCC",
    scope: "Caller identity authentication for IP-based voice networks.",
    key_clauses: [{ clause: "Identity header signing", summary: "Authenticate caller identity across interconnects." }],
    control_mappings: [{ framework: "FCC", control: "Robocall mitigation program" }],
    regulation_mappings: [{ regulation_id: "FCC rules", article_or_section: "47 CFR 64.6300" }],
    implementation_guidance: "Deploy certificate governance, attestation handling and analytics for spoofing detection.",
    licensing_restrictions: "Standards access varies by publisher.",
    last_updated: LAST_UPDATED
  },
  {
    id: "etsi-mec",
    name: "ETSI MEC",
    version: "Current",
    publisher: "ETSI",
    scope: "Security and platform guidance for multi-access edge computing.",
    key_clauses: [{ clause: "MEC security", summary: "Edge workload isolation and API security." }],
    control_mappings: [{ framework: "NIS2", control: "Operational resilience at distributed sites" }],
    regulation_mappings: [{ regulation_id: "NIS2", article_or_section: "Art.21" }],
    implementation_guidance: "Apply zero-trust access and remote attestation for edge clusters.",
    licensing_restrictions: "Free access.",
    last_updated: LAST_UPDATED
  },
  {
    id: "rfc-7258",
    name: "RFC 7258",
    version: "2014",
    publisher: "IETF",
    scope: "Treat pervasive monitoring as an attack and design privacy-preserving network operations.",
    key_clauses: [{ clause: "Section 1", summary: "Pervasive monitoring is a technical attack." }],
    control_mappings: [{ framework: "Privacy engineering", control: "Encrypt and minimize telemetry" }],
    regulation_mappings: [{ regulation_id: "GDPR", article_or_section: "Art.25" }],
    implementation_guidance: "Use by-design privacy principles for metadata collection and exposure.",
    licensing_restrictions: "Open RFC.",
    last_updated: LAST_UPDATED
  },
  {
    id: "manrs",
    name: "MANRS",
    version: "Current",
    publisher: "Internet Society",
    scope: "Routing security norms for operators including filtering, anti-spoofing, and coordination.",
    key_clauses: [{ clause: "MANRS actions", summary: "Filtering, anti-spoofing, coordination and global validation." }],
    control_mappings: [{ framework: "NIS2", control: "Network resilience and incident prevention" }],
    regulation_mappings: [{ regulation_id: "NIS2", article_or_section: "Art.21" }],
    implementation_guidance: "Adopt RPKI validation, route filtering and coordinated incident response workflows.",
    licensing_restrictions: "Open guidance.",
    last_updated: LAST_UPDATED
  }
];

export const applicabilityRules: ApplicabilityRule[] = [
  {
    id: "ar-eecc-telecom-provider",
    condition: {
      countries: ["SE", "NL", "DE", "EU"],
      service_types: ["voice", "data", "mobile", "5g", "broadband"]
    },
    obligation: {
      regulation_id: "EECC",
      article_or_section: "Security obligations for electronic communications providers",
      confidence: "high"
    },
    rationale: "Telecom network/service providers in EU member states fall under EECC security and integrity obligations.",
    last_updated: LAST_UPDATED
  },
  {
    id: "ar-nis2-essential-telecom",
    condition: {
      countries: ["SE", "NL", "DE", "EU"],
      roles: ["mobile_operator", "telecom_operator", "isp"],
      min_size: "medium"
    },
    obligation: {
      regulation_id: "NIS2",
      article_or_section: "Art.21",
      standard_id: "enisa-5g-toolbox",
      confidence: "high"
    },
    rationale: "Medium/large telecom operators are generally in-scope as essential or important entities under NIS2.",
    last_updated: LAST_UPDATED
  },
  {
    id: "ar-eprivacy-traffic-location",
    condition: {
      countries: ["SE", "NL", "DE", "EU"],
      data_types: ["traffic_metadata", "location_data", "dns_data"]
    },
    obligation: {
      regulation_id: "ePrivacy",
      article_or_section: "Traffic/location processing and confidentiality rules",
      confidence: "high"
    },
    rationale: "EU traffic and location processing is constrained by ePrivacy confidentiality and purpose requirements.",
    last_updated: LAST_UPDATED
  },
  {
    id: "ar-gdpr-personal-data",
    condition: {
      countries: ["SE", "NL", "DE", "EU"],
      data_types: ["subscriber_data", "location_data", "dns_data", "roaming_data"]
    },
    obligation: {
      regulation_id: "GDPR",
      article_or_section: "Art.5/6/32",
      confidence: "high"
    },
    rationale: "Most telecom subscriber and metadata sets are personal data under GDPR in EU contexts.",
    last_updated: LAST_UPDATED
  },
  {
    id: "ar-sweden-lek",
    condition: {
      countries: ["SE"],
      service_types: ["voice", "data", "mobile", "5g", "broadband"]
    },
    obligation: {
      regulation_id: "LEK",
      article_or_section: "Swedish Electronic Communications Act",
      confidence: "high"
    },
    rationale: "Swedish operators must satisfy LEK and PTS security requirements in addition to EU obligations.",
    last_updated: LAST_UPDATED
  },
  {
    id: "ar-netherlands-telecom-wbni",
    condition: {
      countries: ["NL"],
      service_types: ["voice", "data", "mobile", "5g", "iaas", "cdn", "dns"]
    },
    obligation: {
      regulation_id: "Wbni/Telecommunicatiewet",
      article_or_section: "National NIS and telecom implementation requirements",
      confidence: "medium"
    },
    rationale: "Dutch operators and digital infrastructure providers must align with Wbni and telecom law obligations.",
    last_updated: LAST_UPDATED
  },
  {
    id: "ar-germany-tkg",
    condition: {
      countries: ["DE"],
      service_types: ["voice", "data", "mobile", "5g", "broadband"]
    },
    obligation: {
      regulation_id: "TKG",
      article_or_section: "German Telecommunications Act security obligations",
      confidence: "medium"
    },
    rationale: "German telecom law adds national security and incident handling obligations on top of EU regimes.",
    last_updated: LAST_UPDATED
  },
  {
    id: "ar-us-cpni",
    condition: {
      countries: ["US"],
      data_types: ["subscriber_data", "traffic_metadata"]
    },
    obligation: {
      regulation_id: "CPNI",
      article_or_section: "47 CFR 64.2001",
      confidence: "high"
    },
    rationale: "US telecom carriers handling customer network information must satisfy CPNI privacy obligations.",
    last_updated: LAST_UPDATED
  },
  {
    id: "ar-us-ecpa-sca",
    condition: {
      countries: ["US"],
      data_types: ["traffic_metadata", "content_data", "dns_data", "location_data"]
    },
    obligation: {
      regulation_id: "ECPA/SCA",
      article_or_section: "18 USC 2510+, 18 USC 2701+",
      confidence: "high"
    },
    rationale: "US stored communications and intercept access are governed by ECPA/SCA and related legal process standards.",
    last_updated: LAST_UPDATED
  },
  {
    id: "ar-us-calea",
    condition: {
      countries: ["US"],
      roles: ["mobile_operator", "telecom_operator", "isp"],
      service_types: ["voice", "data", "mobile", "broadband"]
    },
    obligation: {
      regulation_id: "CALEA",
      article_or_section: "47 USC 1001",
      standard_id: "calea",
      confidence: "high"
    },
    rationale: "US telecom providers may need to provide lawful intercept capabilities under CALEA.",
    last_updated: LAST_UPDATED
  },
  {
    id: "ar-us-stir-shaken",
    condition: {
      countries: ["US"],
      service_types: ["voice", "mobile"]
    },
    obligation: {
      regulation_id: "FCC STIR/SHAKEN",
      article_or_section: "47 CFR 64.6300",
      standard_id: "stir-shaken",
      confidence: "high"
    },
    rationale: "US voice providers are generally required to implement STIR/SHAKEN caller authentication.",
    last_updated: LAST_UPDATED
  },
  {
    id: "ar-eu-digital-infrastructure",
    condition: {
      countries: ["SE", "NL", "DE", "EU"],
      service_types: ["dns", "tld", "iaas", "cdn", "data-center"]
    },
    obligation: {
      regulation_id: "NIS2 Digital Infrastructure",
      article_or_section: "Annexes and Art.21",
      confidence: "high"
    },
    rationale: "DNS, cloud and CDN operators are in-scope as digital infrastructure under NIS2.",
    last_updated: LAST_UPDATED
  }
];

export const evidenceArtifacts: EvidenceArtifact[] = [
  {
    id: "ea-nis2-risk-program",
    audit_type: "NIS2 (telecom essential entity)",
    artifact_name: "NIS2 risk management measures register",
    description:
      "Documented risk controls, incident handling workflows, supply chain controls, vulnerability handling and encryption assessments.",
    mandatory: true,
    retention_period: "6 years",
    template_ref: "templates/nis2-risk-register.md",
    regulation_basis: [{ regulation_id: "NIS2", article_or_section: "Art.21" }],
    last_updated: LAST_UPDATED
  },
  {
    id: "ea-eecc-security-measures",
    audit_type: "EECC Compliance",
    artifact_name: "Network security measures dossier",
    description: "Technical and organizational measures, incident notification process and resilience controls for telecom services.",
    mandatory: true,
    retention_period: "6 years",
    template_ref: "templates/eecc-security-dossier.md",
    regulation_basis: [{ regulation_id: "EECC", article_or_section: "Security obligations" }],
    last_updated: LAST_UPDATED
  },
  {
    id: "ea-nesas-evidence",
    audit_type: "GSMA NESAS",
    artifact_name: "Vendor and product security assurance evidence",
    description: "Vendor security assessment records, product testing evidence and secure development audit outputs.",
    mandatory: true,
    retention_period: "Product lifecycle + 5 years",
    template_ref: "templates/nesas-evidence-checklist.md",
    regulation_basis: [{ regulation_id: "GSMA NESAS", article_or_section: "Assurance model" }],
    last_updated: LAST_UPDATED
  },
  {
    id: "ea-eprivacy-processing-records",
    audit_type: "ePrivacy",
    artifact_name: "Traffic and location data processing records",
    description: "Consent/legal basis evidence, retention schedules, breach notification procedures and DPIA outputs.",
    mandatory: true,
    retention_period: "6 years",
    template_ref: "templates/eprivacy-processing-register.md",
    regulation_basis: [{ regulation_id: "ePrivacy", article_or_section: "Traffic/location confidentiality" }],
    last_updated: LAST_UPDATED
  },
  {
    id: "ea-calea-certification",
    audit_type: "CALEA",
    artifact_name: "CALEA technical capability certification pack",
    description: "System security plan, intercept delivery documentation and control assurance evidence.",
    mandatory: true,
    retention_period: "7 years",
    template_ref: "templates/calea-certification-pack.md",
    regulation_basis: [{ regulation_id: "CALEA", article_or_section: "47 USC 1001" }],
    last_updated: LAST_UPDATED
  },
  {
    id: "ea-5g-toolbox-vendor-risk",
    audit_type: "5G Toolbox (national)",
    artifact_name: "Vendor risk and diversification evidence",
    description: "Supplier risk scoring, diversification decisions, screening controls and compensating mitigation documentation.",
    mandatory: true,
    retention_period: "5 years",
    template_ref: "templates/5g-toolbox-vendor-risk.md",
    regulation_basis: [{ regulation_id: "EU 5G Toolbox", article_or_section: "Strategic measures" }],
    last_updated: LAST_UPDATED
  }
];

export const authoritativeSources: AuthoritativeSource[] = [
  {
    id: "src-3gpp",
    source_name: "3GPP",
    content: "5G security specifications (TS 33.xxx)",
    license: "Free access",
    refresh_cadence: "Per release",
    source_type: "standards",
    source_url: "https://www.3gpp.org/",
    last_updated: LAST_UPDATED
  },
  {
    id: "src-etsi",
    source_name: "ETSI",
    content: "NFV security, LI standards, MEC",
    license: "Free access",
    refresh_cadence: "Per publication",
    source_type: "standards",
    source_url: "https://www.etsi.org/",
    last_updated: LAST_UPDATED
  },
  {
    id: "src-gsma",
    source_name: "GSMA",
    content: "NESAS/SCAS, FS.31, security guidelines",
    license: "Membership (public summaries)",
    refresh_cadence: "Per update",
    source_type: "industry",
    source_url: "https://www.gsma.com/",
    last_updated: LAST_UPDATED
  },
  {
    id: "src-enisa",
    source_name: "ENISA",
    content: "5G threat landscape and EU 5G toolbox",
    license: "Free access",
    refresh_cadence: "Per publication",
    source_type: "regulatory-guidance",
    source_url: "https://www.enisa.europa.eu/",
    last_updated: LAST_UPDATED
  },
  {
    id: "src-berec",
    source_name: "BEREC",
    content: "EECC implementation guidance and roaming regulation",
    license: "Free access",
    refresh_cadence: "Per publication",
    source_type: "regulatory-guidance",
    source_url: "https://www.berec.europa.eu/",
    last_updated: LAST_UPDATED
  },
  {
    id: "src-fcc",
    source_name: "FCC",
    content: "CALEA, STIR/SHAKEN, telecom privacy and resilience rules",
    license: "Public domain",
    refresh_cadence: "Per publication",
    source_type: "regulation",
    source_url: "https://www.fcc.gov/",
    last_updated: LAST_UPDATED
  },
  {
    id: "src-oran",
    source_name: "O-RAN Alliance",
    content: "Open RAN security specifications",
    license: "Membership (public summaries)",
    refresh_cadence: "Per release",
    source_type: "standards",
    source_url: "https://www.o-ran.org/",
    last_updated: LAST_UPDATED
  },
  {
    id: "src-nist",
    source_name: "NIST",
    content: "SP 1800-33 (5G), SP 800-187 (LTE)",
    license: "Public domain",
    refresh_cadence: "Per revision",
    source_type: "standards",
    source_url: "https://www.nist.gov/",
    last_updated: LAST_UPDATED
  }
];
