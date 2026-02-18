import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const sourceFile = resolve(process.cwd(), "sources.yml");
const sourceYaml = readFileSync(sourceFile, "utf8");

const maxSourceAgeDays = Number(process.env.TELECOM_MAX_SOURCE_AGE_DAYS ?? "30");
const dateMatch = sourceYaml.match(/^last_updated:\s*(\d{4}-\d{2}-\d{2})$/m);
if (!dateMatch) {
  console.error("sources.yml is missing a top-level last_updated date.");
  process.exit(1);
}

const updatedAt = new Date(`${dateMatch[1]}T00:00:00Z`);
if (Number.isNaN(updatedAt.getTime())) {
  console.error(`sources.yml has an invalid last_updated date: ${dateMatch[1]}`);
  process.exit(1);
}

const ageDays = Math.floor((Date.now() - updatedAt.getTime()) / (1000 * 60 * 60 * 24));

const idMatches = Array.from(sourceYaml.matchAll(/^\s*-\s+id:\s*([^\n]+)$/gm)).map((match) =>
  match[1].trim()
);
const urlMatches = Array.from(sourceYaml.matchAll(/^\s*url:\s*(https?:\/\/[^\s]+)$/gm)).map((match) =>
  match[1].trim()
);
const nameMatches = Array.from(sourceYaml.matchAll(/^\s*name:\s*([^\n]+)$/gm)).map((match) =>
  match[1].trim()
);

const uniqueIds = new Set(idMatches);
if (idMatches.length === 0) {
  console.error("sources.yml contains no source entries.");
  process.exit(1);
}
if (uniqueIds.size !== idMatches.length) {
  console.error("sources.yml contains duplicate source IDs.");
  process.exit(1);
}
if (urlMatches.length < idMatches.length) {
  console.error("At least one source entry is missing a URL.");
  process.exit(1);
}
if (nameMatches.length < idMatches.length) {
  console.error("At least one source entry is missing a name.");
  process.exit(1);
}
if (ageDays > maxSourceAgeDays) {
  console.error(
    `Source metadata is stale: last_updated=${dateMatch[1]} (${ageDays} days old, max=${maxSourceAgeDays}).`
  );
  process.exit(1);
}

console.log(
  JSON.stringify(
    {
      status: "ok",
      sources_count: idMatches.length,
      last_updated: dateMatch[1],
      age_days: ageDays,
      max_age_days: maxSourceAgeDays
    },
    null,
    2
  )
);
