import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { initializeDatabase } from "../src/db/database.js";
import { TelecomDomainService } from "../src/domain/service.js";

interface GoldenHashesFile {
  dataset_version: string;
  dataset_fingerprint: string;
}

const fixturePath = resolve(process.cwd(), "fixtures", "golden-hashes.json");
const fixture = JSON.parse(readFileSync(fixturePath, "utf8")) as GoldenHashesFile;

const db = initializeDatabase(":memory:");
const service = new TelecomDomainService(db);
const metadata = service.metadataContext();
db.close();

const errors: string[] = [];

if (fixture.dataset_version !== metadata.datasetVersion) {
  errors.push(
    `Dataset version mismatch: expected ${fixture.dataset_version}, actual ${metadata.datasetVersion}.`
  );
}

if (fixture.dataset_fingerprint !== metadata.datasetFingerprint) {
  errors.push(
    `Dataset fingerprint mismatch: expected ${fixture.dataset_fingerprint}, actual ${metadata.datasetFingerprint}.`
  );
}

if (errors.length > 0) {
  for (const error of errors) {
    console.error(error);
  }
  process.exit(1);
}

console.log(
  JSON.stringify(
    {
      status: "ok",
      dataset_version: metadata.datasetVersion,
      dataset_fingerprint: metadata.datasetFingerprint
    },
    null,
    2
  )
);
