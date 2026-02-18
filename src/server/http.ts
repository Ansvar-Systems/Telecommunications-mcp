import express from "express";
import { initializeDatabase } from "../db/database.js";
import { TelecomDomainService } from "../domain/service.js";
import { TelecomToolDispatcher } from "./dispatcher.js";

const port = Number(process.env.PORT ?? 8000);

function createApp() {
  const db = initializeDatabase(process.env.TELECOM_MCP_DB_PATH);
  const service = new TelecomDomainService(db);
  const dispatcher = new TelecomToolDispatcher(service);

  const app = express();
  app.use(express.json({ limit: "1mb" }));

  app.get("/health", (_req, res) => {
    const about = service.about();
    res.json({
      status: "ok",
      service: about.name,
      version: about.version,
      domain: about.domain,
      last_updated: about.last_updated,
      coverage_summary: about.coverage_summary
    });
  });

  app.get("/mcp", (_req, res) => {
    res.json({
      name: "telecommunications-mcp",
      transport: "http",
      endpoint: "/mcp",
      usage: {
        method: "POST",
        payload: {
          tool: "about",
          arguments: {}
        }
      }
    });
  });

  app.post("/mcp", async (req, res) => {
    const { tool, arguments: args } = req.body as { tool?: string; arguments?: Record<string, unknown> };

    if (!tool || typeof tool !== "string") {
      res.status(400).json({
        error: "Invalid request",
        detail: "Field 'tool' is required and must be a string."
      });
      return;
    }

    try {
      const result = await dispatcher.dispatch({ tool, arguments: args });
      res.json(result);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown error";
      res.status(500).json({
        error: "Tool execution failed",
        detail: message
      });
    }
  });

  const close = () => db.close();

  return { app, close };
}

const { app, close } = createApp();
const server = app.listen(port, () => {
  console.log(`telecommunications-mcp HTTP server listening on :${port}`);
});

const shutdown = () => {
  server.close(() => {
    close();
    process.exit(0);
  });
};

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
