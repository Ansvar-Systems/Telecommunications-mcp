import { randomUUID } from "node:crypto";
import express, { type Request, type Response } from "express";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { initializeDatabase } from "../db/database.js";
import { TelecomDomainService } from "../domain/service.js";
import { createTelecommunicationsMcpServer } from "../mcp/server.js";

const port = Number(process.env.PORT ?? 8000);
const staleWindowDays = 30;

function createApp() {
  const db = initializeDatabase(process.env.TELECOM_MCP_DB_PATH);
  const service = new TelecomDomainService(db);
  const mcpServer = createTelecommunicationsMcpServer(service);
  const transports = new Map<string, StreamableHTTPServerTransport>();

  const app = express();
  app.use(express.json({ limit: "1mb" }));

  app.get("/health", (_req, res) => {
    const about = service.about();
    const updatedAt = new Date(about.last_updated);
    const daysSinceUpdate = Number.isNaN(updatedAt.getTime())
      ? Number.POSITIVE_INFINITY
      : (Date.now() - updatedAt.getTime()) / (1000 * 60 * 60 * 24);
    const status =
      Number.isFinite(daysSinceUpdate) && daysSinceUpdate > staleWindowDays ? "stale" : "ok";

    res.json({
      status,
      service: about.name,
      version: about.version,
      domain: about.domain,
      last_updated: about.last_updated,
      stale_after_days: staleWindowDays,
      coverage_summary: about.coverage_summary
    });
  });

  const getSessionId = (req: Request): string | undefined => {
    const raw = req.headers["mcp-session-id"];
    if (Array.isArray(raw)) {
      return raw[0];
    }
    return typeof raw === "string" ? raw : undefined;
  };

  const closeTransport = async (transport: StreamableHTTPServerTransport) => {
    const sid = transport.sessionId;
    if (sid) {
      transports.delete(sid);
    }
    await transport.close();
  };

  app.get("/mcp", async (req: Request, res: Response) => {
    const sessionId = getSessionId(req);
    if (!sessionId) {
      res.status(400).json({
        jsonrpc: "2.0",
        error: {
          code: -32600,
          message: "Missing Mcp-Session-Id header."
        },
        id: null
      });
      return;
    }

    const transport = transports.get(sessionId);
    if (!transport) {
      res.status(404).json({
        jsonrpc: "2.0",
        error: {
          code: -32001,
          message: "Session not found."
        },
        id: null
      });
      return;
    }

    await transport.handleRequest(req, res);
  });

  app.post("/mcp", async (req: Request, res: Response) => {
    const sessionId = getSessionId(req);
    let transport = sessionId ? transports.get(sessionId) : undefined;

    try {
      if (!transport) {
        if (sessionId) {
          res.status(404).json({
            jsonrpc: "2.0",
            error: {
              code: -32001,
              message: "Session not found. Start with an initialize request without Mcp-Session-Id."
            },
            id: null
          });
          return;
        }

        if (!isInitializeRequest(req.body)) {
          res.status(400).json({
            jsonrpc: "2.0",
            error: {
              code: -32600,
              message: "Bad Request: initialize must be sent before other MCP methods."
            },
            id: null
          });
          return;
        }

        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (sid) => {
            transports.set(sid, transport!);
          }
        });
        transport.onclose = () => {
          const sid = transport?.sessionId;
          if (sid) {
            transports.delete(sid);
          }
        };
        transport.onerror = (error) => {
          console.error("MCP transport error:", error);
        };
        await mcpServer.connect(transport);
      }

      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown error";
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: "2.0",
          error: {
            code: -32603,
            message: "Internal server error",
            data: message
          },
          id: null
        });
      }
      if (transport && !res.writableEnded) {
        await closeTransport(transport);
      }
    }
  });

  app.delete("/mcp", async (req: Request, res: Response) => {
    const sessionId = getSessionId(req);
    if (!sessionId) {
      res.status(400).json({
        jsonrpc: "2.0",
        error: {
          code: -32600,
          message: "Missing Mcp-Session-Id header."
        },
        id: null
      });
      return;
    }

    const transport = transports.get(sessionId);
    if (!transport) {
      res.status(404).json({
        jsonrpc: "2.0",
        error: {
          code: -32001,
          message: "Session not found."
        },
        id: null
      });
      return;
    }

    await transport.handleRequest(req, res);
  });

  const close = async () => {
    for (const transport of transports.values()) {
      await closeTransport(transport);
    }
    await mcpServer.close();
    db.close();
  };

  return { app, close };
}

const { app, close } = createApp();
const server = app.listen(port, () => {
  console.log(`telecommunications-mcp HTTP server listening on :${port}`);
});

const shutdown = () => {
  server.close(async () => {
    await close();
    process.exit(0);
  });
};

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
