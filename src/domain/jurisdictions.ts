export interface ParsedJurisdiction {
  raw: string;
  country: string;
  state?: string;
  key: string;
}

export interface EuropeJurisdictionProfile {
  code: string;
  name: string;
  eu_member: boolean;
  telecom_law: string;
  privacy_regimes: string[];
  lawful_intercept_law: string;
  regulator: string;
}

export interface UsStateProfile {
  code: string;
  name: string;
  privacy_regime: string;
  breach_notification_law: string;
  telecom_consumer_protection: string;
}

const EU27_CODES = [
  "AT",
  "BE",
  "BG",
  "HR",
  "CY",
  "CZ",
  "DK",
  "EE",
  "FI",
  "FR",
  "DE",
  "GR",
  "HU",
  "IE",
  "IT",
  "LV",
  "LT",
  "LU",
  "MT",
  "NL",
  "PL",
  "PT",
  "RO",
  "SK",
  "SI",
  "ES",
  "SE"
] as const;

const EUROPE_OTHER_CODES = [
  "AL",
  "AD",
  "AM",
  "AZ",
  "BA",
  "BY",
  "CH",
  "GB",
  "GE",
  "IS",
  "LI",
  "MD",
  "MC",
  "ME",
  "MK",
  "NO",
  "RS",
  "RU",
  "SM",
  "TR",
  "UA",
  "VA",
  "XK"
] as const;

const COUNTRY_NAMES: Record<string, string> = {
  AL: "Albania",
  AD: "Andorra",
  AM: "Armenia",
  AT: "Austria",
  AZ: "Azerbaijan",
  BA: "Bosnia and Herzegovina",
  BE: "Belgium",
  BG: "Bulgaria",
  BY: "Belarus",
  CH: "Switzerland",
  CY: "Cyprus",
  CZ: "Czech Republic",
  DE: "Germany",
  DK: "Denmark",
  EE: "Estonia",
  ES: "Spain",
  FI: "Finland",
  FR: "France",
  GB: "United Kingdom",
  GE: "Georgia",
  GR: "Greece",
  HR: "Croatia",
  HU: "Hungary",
  IE: "Ireland",
  IS: "Iceland",
  IT: "Italy",
  LI: "Liechtenstein",
  LT: "Lithuania",
  LU: "Luxembourg",
  LV: "Latvia",
  MC: "Monaco",
  MD: "Moldova",
  ME: "Montenegro",
  MK: "North Macedonia",
  MT: "Malta",
  NL: "Netherlands",
  NO: "Norway",
  PL: "Poland",
  PT: "Portugal",
  RO: "Romania",
  RS: "Serbia",
  RU: "Russia",
  SE: "Sweden",
  SI: "Slovenia",
  SK: "Slovakia",
  SM: "San Marino",
  TR: "Turkey",
  UA: "Ukraine",
  VA: "Vatican City",
  XK: "Kosovo"
};

const TELECOM_LAW_OVERRIDES: Record<string, string> = {
  AT: "Telekommunikationsgesetz (TKG 2021)",
  BE: "Belgian Electronic Communications Act",
  BG: "Bulgarian Electronic Communications Act",
  CY: "Cyprus Electronic Communications and Postal Services Law",
  CZ: "Act No. 127/2005 on Electronic Communications",
  DE: "TKG (Telekommunikationsgesetz)",
  DK: "Danish Electronic Communications Act",
  EE: "Estonian Electronic Communications Act",
  ES: "Ley General de Telecomunicaciones (Law 11/2022)",
  FI: "Information Society Code",
  FR: "Code des postes et des communications electroniques (CPCE)",
  GB: "Communications Act 2003 and telecom security legislation",
  GR: "Greek Electronic Communications framework",
  HR: "Croatian Electronic Communications Act",
  HU: "Act C of 2003 on Electronic Communications",
  IE: "Irish Communications Regulation framework",
  IT: "Codice delle comunicazioni elettroniche",
  LT: "Lithuanian Law on Electronic Communications",
  LU: "Law of 27 February 2011 on electronic communications networks and services",
  LV: "Latvian Electronic Communications Law",
  MT: "Maltese Electronic Communications Networks and Services framework",
  NL: "Telecommunicatiewet",
  NO: "Electronic Communications Act (Ekomloven)",
  PL: "Prawo komunikacji elektronicznej",
  PT: "Lei das Comunicacoes Eletronicas",
  RO: "Romanian electronic communications framework",
  SE: "LEK (Swedish Electronic Communications Act)",
  SI: "ZEKom-2",
  SK: "Slovak Electronic Communications Act",
  CH: "Federal Act on Telecommunications",
  TR: "Electronic Communications Law No. 5809",
  UA: "Law on Electronic Communications of Ukraine",
  RS: "Law on Electronic Communications",
  IS: "Icelandic Electronic Communications framework",
  LI: "Liechtenstein Communications framework"
};

const LI_LAW_OVERRIDES: Record<string, string> = {
  GB: "Investigatory Powers Act 2016",
  CH: "Swiss Surveillance of Post and Telecommunications Act",
  NL: "WIV and Telecommunicatiewet lawful intercept provisions",
  DE: "German lawful intercept implementation under TKG and criminal procedure",
  FR: "French lawful interception framework under security and criminal procedure law",
  SE: "Swedish lawful interception implementation under LEK and procedural law"
};

const REGULATOR_OVERRIDES: Record<string, string> = {
  AT: "RTR/TKK",
  BE: "BIPT",
  CH: "OFCOM (Switzerland)",
  DE: "Bundesnetzagentur",
  DK: "Danish Business Authority telecom supervision",
  ES: "CNMC",
  FI: "Traficom",
  FR: "ARCEP",
  GB: "Ofcom",
  IE: "ComReg",
  IT: "AGCOM",
  NL: "RDI/ACM",
  NO: "Nkom",
  PL: "UKE",
  PT: "ANACOM",
  SE: "PTS"
};

const US_STATE_NAMES: Record<string, string> = {
  AL: "Alabama",
  AK: "Alaska",
  AZ: "Arizona",
  AR: "Arkansas",
  CA: "California",
  CO: "Colorado",
  CT: "Connecticut",
  DE: "Delaware",
  FL: "Florida",
  GA: "Georgia",
  HI: "Hawaii",
  ID: "Idaho",
  IL: "Illinois",
  IN: "Indiana",
  IA: "Iowa",
  KS: "Kansas",
  KY: "Kentucky",
  LA: "Louisiana",
  ME: "Maine",
  MD: "Maryland",
  MA: "Massachusetts",
  MI: "Michigan",
  MN: "Minnesota",
  MS: "Mississippi",
  MO: "Missouri",
  MT: "Montana",
  NE: "Nebraska",
  NV: "Nevada",
  NH: "New Hampshire",
  NJ: "New Jersey",
  NM: "New Mexico",
  NY: "New York",
  NC: "North Carolina",
  ND: "North Dakota",
  OH: "Ohio",
  OK: "Oklahoma",
  OR: "Oregon",
  PA: "Pennsylvania",
  RI: "Rhode Island",
  SC: "South Carolina",
  SD: "South Dakota",
  TN: "Tennessee",
  TX: "Texas",
  UT: "Utah",
  VT: "Vermont",
  VA: "Virginia",
  WA: "Washington",
  WV: "West Virginia",
  WI: "Wisconsin",
  WY: "Wyoming",
  DC: "District of Columbia"
};

const US_COMPREHENSIVE_PRIVACY_STATE_CODES = new Set([
  "CA",
  "CO",
  "CT",
  "DE",
  "IA",
  "IN",
  "KY",
  "MD",
  "MN",
  "MT",
  "NE",
  "NH",
  "NJ",
  "OR",
  "RI",
  "TN",
  "TX",
  "UT",
  "VA"
]);

const EU27 = new Set<string>(EU27_CODES);
const EUROPE_CODES = new Set<string>([...EU27_CODES, ...EUROPE_OTHER_CODES]);
const US_STATE_CODES = Object.keys(US_STATE_NAMES);

function asTelecomLaw(code: string, name: string): string {
  return TELECOM_LAW_OVERRIDES[code] ?? `${name} national electronic communications law`;
}

function asLiLaw(code: string, name: string): string {
  return LI_LAW_OVERRIDES[code] ?? `${name} lawful intercept implementation law`;
}

function asRegulator(code: string, name: string): string {
  return REGULATOR_OVERRIDES[code] ?? `${name} telecom regulator`;
}

function privacyRegimesFor(code: string): string[] {
  if (EU27.has(code)) {
    return ["GDPR", "ePrivacy Directive", "NIS2 national implementation"]; 
  }
  if (["NO", "IS", "LI"].includes(code)) {
    return ["GDPR (EEA incorporation)", "national electronic communications privacy rules"];
  }
  if (code === "GB") {
    return ["UK GDPR", "PECR", "NIS Regulations (as amended)"];
  }
  if (code === "CH") {
    return ["Swiss FADP", "Swiss telecom confidentiality rules"];
  }
  return ["National privacy and telecom confidentiality laws"];
}

export function parseJurisdiction(input: string): ParsedJurisdiction {
  const trimmed = input.trim().toUpperCase();
  const compact = trimmed.replace(/\s+/g, "");
  const dashNormalized = compact.replace(/_/g, "-");

  if (dashNormalized === "US-FED" || dashNormalized === "USFED" || dashNormalized === "USA") {
    return { raw: input, country: "US", key: "US" };
  }

  const usStateMatch = dashNormalized.match(/^US-([A-Z]{2})$/);
  if (usStateMatch) {
    const state = usStateMatch[1];
    return { raw: input, country: "US", state, key: `US-${state}` };
  }

  if (dashNormalized === "UK") {
    return { raw: input, country: "GB", key: "GB" };
  }

  if (dashNormalized.length === 2) {
    return { raw: input, country: dashNormalized, key: dashNormalized };
  }

  return { raw: input, country: dashNormalized, key: dashNormalized };
}

export function listEuropeCountryCodes(): string[] {
  return Array.from(EUROPE_CODES).sort();
}

export function listUsStateCodes(): string[] {
  return [...US_STATE_CODES].sort();
}

export function isEuCountryCode(code: string): boolean {
  return EU27.has(code);
}

export function isEuropeanCountryCode(code: string): boolean {
  return EUROPE_CODES.has(code);
}

export function getEuropeJurisdictionProfile(code: string): EuropeJurisdictionProfile | undefined {
  const normalized = code.trim().toUpperCase();
  if (!EUROPE_CODES.has(normalized)) {
    return undefined;
  }

  const name = COUNTRY_NAMES[normalized] ?? normalized;
  return {
    code: normalized,
    name,
    eu_member: EU27.has(normalized),
    telecom_law: asTelecomLaw(normalized, name),
    privacy_regimes: privacyRegimesFor(normalized),
    lawful_intercept_law: asLiLaw(normalized, name),
    regulator: asRegulator(normalized, name)
  };
}

export function getUsStateProfile(stateCode: string): UsStateProfile | undefined {
  const normalized = stateCode.trim().toUpperCase();
  const name = US_STATE_NAMES[normalized];
  if (!name) {
    return undefined;
  }

  const privacyRegime = US_COMPREHENSIVE_PRIVACY_STATE_CODES.has(normalized)
    ? `${name} comprehensive consumer privacy law`
    : `${name} state privacy and consumer data law framework`;

  return {
    code: normalized,
    name,
    privacy_regime: privacyRegime,
    breach_notification_law: `${name} data breach notification statute`,
    telecom_consumer_protection: `${name} telecom and consumer protection obligations`
  };
}
