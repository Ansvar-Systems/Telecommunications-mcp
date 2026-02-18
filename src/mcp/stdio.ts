import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { initializeDatabase } from "../db/database.js";
import { TelecomDomainService } from "../domain/service.js";
import { createTelecommunicationsMcpServer } from "./server.js";

async function main() {
  const db = initializeDatabase(process.env.TELECOM_MCP_DB_PATH);
  const service = new TelecomDomainService(db);
  const server = createTelecommunicationsMcpServer(service);
  const transport = new StdioServerTransport();

  await server.connect(transport);
}

main().catch((error) => {
  console.error("Failed to start telecommunications MCP stdio transport:", error);
  process.exit(1);
});
