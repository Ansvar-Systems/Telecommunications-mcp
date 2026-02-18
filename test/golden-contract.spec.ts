import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { initializeDatabase } from "../src/db/database.js";
import { TelecomDomainService } from "../src/domain/service.js";

type GoldenClauseTest = {
  id: string;
  jurisdiction: string;
  regulation_id: string;
  article_or_section: string;
};

type GoldenFixture = {
  version: string;
  generated_at: string;
  tests: GoldenClauseTest[];
};

const fixturePath = resolve(process.cwd(), "fixtures", "golden-tests.json");
const fixture = JSON.parse(readFileSync(fixturePath, "utf8")) as GoldenFixture;

function createService() {
  const db = initializeDatabase(":memory:");
  const service = new TelecomDomainService(db);
  return { service, db };
}

describe("golden contract fixtures", () => {
  it("contains at least 10 golden cases", () => {
    expect(fixture.tests.length).toBeGreaterThanOrEqual(10);
  });

  for (const entry of fixture.tests) {
    it(`matches fixture ${entry.id}`, () => {
      const { service, db } = createService();
      const pack = service.getJurisdictionClausePack(entry.jurisdiction);
      const match = pack.assertions.find(
        (assertion) =>
          assertion.regulation_id === entry.regulation_id &&
          assertion.article_or_section === entry.article_or_section
      );

      expect(match).toBeDefined();
      expect(match?.citations.length ?? 0).toBeGreaterThan(0);
      expect(match?.citations.every((citation) => citation.source_url.startsWith("https://"))).toBe(true);

      db.close();
    });
  }
});
