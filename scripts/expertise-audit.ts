import { initializeDatabase } from "../src/db/database.js";
import { TelecomDomainService } from "../src/domain/service.js";

function main() {
  const db = initializeDatabase(":memory:");
  const service = new TelecomDomainService(db);
  const report = service.auditExpertiseQuality();

  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  db.close();

  if (!report.pass) {
    process.exit(1);
  }
}

main();
