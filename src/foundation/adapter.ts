export type FoundationMcpName = "eu-regulations" | "us-regulations" | "security-controls" | "dutch-law";

export interface FoundationCallPlan {
  mcp: FoundationMcpName;
  tool: string;
  params: Record<string, unknown>;
}

export interface FoundationCallResult extends FoundationCallPlan {
  status: "success" | "error" | "skipped";
  endpoint?: string;
  http_status?: number;
  latency_ms: number;
  response?: unknown;
  error?: string;
}

export interface FoundationMcpAdapterOptions {
  endpoints?: Partial<Record<FoundationMcpName, string>>;
  timeoutMs?: number;
  fetchFn?: typeof fetch;
}

const MCP_PROTOCOL_VERSION = "2025-03-26";
const ADAPTER_CLIENT_INFO = {
  name: "telecommunications-foundation-adapter",
  version: "1.0.0"
};

function normalizeEndpoint(base: string): string {
  const trimmed = base.trim().replace(/\/+$/, "");
  if (trimmed.endsWith("/mcp")) {
    return trimmed;
  }
  return `${trimmed}/mcp`;
}

function defaultEndpointsFromEnv(): Partial<Record<FoundationMcpName, string>> {
  return {
    "eu-regulations": process.env.FOUNDATION_MCP_EU_REGULATIONS_URL,
    "us-regulations": process.env.FOUNDATION_MCP_US_REGULATIONS_URL,
    "security-controls": process.env.FOUNDATION_MCP_SECURITY_CONTROLS_URL,
    "dutch-law": process.env.FOUNDATION_MCP_DUTCH_LAW_URL
  };
}

export class FoundationMcpAdapter {
  private readonly endpoints: Partial<Record<FoundationMcpName, string>>;
  private readonly timeoutMs: number;
  private readonly fetchFn: typeof fetch;

  constructor(options?: FoundationMcpAdapterOptions) {
    this.endpoints = {
      ...defaultEndpointsFromEnv(),
      ...(options?.endpoints ?? {})
    };
    this.timeoutMs = options?.timeoutMs ?? Number(process.env.FOUNDATION_MCP_TIMEOUT_MS ?? "3500");
    this.fetchFn = options?.fetchFn ?? fetch;
  }

  private async parseResponseBody(response: Response): Promise<unknown> {
    const bodyText = await response.text();
    if (!bodyText || bodyText.trim().length === 0) {
      return {};
    }

    const contentType = response.headers.get("content-type") ?? "";
    if (contentType.includes("text/event-stream")) {
      const dataLine = bodyText
        .split(/\r?\n/)
        .find((line) => line.startsWith("data: "));
      if (dataLine) {
        try {
          return JSON.parse(dataLine.slice(6));
        } catch {
          return { parse_error: "SSE payload was not valid JSON", raw: bodyText };
        }
      }
      return { parse_error: "SSE payload did not include a data line", raw: bodyText };
    }

    try {
      return JSON.parse(bodyText);
    } catch {
      return { parse_error: "Response was not JSON", raw: bodyText };
    }
  }

  private async invokeMcpJsonRpc(endpoint: string, plan: FoundationCallPlan): Promise<FoundationCallResult> {
    const controller = new AbortController();
    const startedAt = Date.now();
    const timeoutHandle = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const initResponse = await this.fetchFn(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json, text/event-stream"
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {
            protocolVersion: MCP_PROTOCOL_VERSION,
            capabilities: {},
            clientInfo: ADAPTER_CLIENT_INFO
          }
        }),
        signal: controller.signal
      });
      const initPayload = await this.parseResponseBody(initResponse);
      const sessionId = initResponse.headers.get("mcp-session-id") ?? undefined;

      if (!initResponse.ok) {
        clearTimeout(timeoutHandle);
        return {
          ...plan,
          status: "error",
          endpoint,
          http_status: initResponse.status,
          latency_ms: Date.now() - startedAt,
          error: `MCP initialize failed (HTTP ${initResponse.status})`,
          response: initPayload
        };
      }

      const callHeaders: Record<string, string> = {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream"
      };
      if (sessionId) {
        callHeaders["Mcp-Session-Id"] = sessionId;
      }

      const callResponse = await this.fetchFn(endpoint, {
        method: "POST",
        headers: callHeaders,
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 2,
          method: "tools/call",
          params: {
            name: plan.tool,
            arguments: plan.params
          }
        }),
        signal: controller.signal
      });
      const callPayload = await this.parseResponseBody(callResponse);

      if (sessionId) {
        void this.fetchFn(endpoint, {
          method: "DELETE",
          headers: {
            Accept: "application/json, text/event-stream",
            "Mcp-Session-Id": sessionId
          }
        }).catch(() => undefined);
      }

      clearTimeout(timeoutHandle);
      const latency = Date.now() - startedAt;
      const parsedCall = callPayload as { result?: unknown; error?: unknown } | undefined;

      if (!callResponse.ok || parsedCall?.error) {
        return {
          ...plan,
          status: "error",
          endpoint,
          http_status: callResponse.status,
          latency_ms: latency,
          error:
            parsedCall?.error && typeof parsedCall.error === "object"
              ? "MCP tools/call returned error"
              : `MCP tools/call failed (HTTP ${callResponse.status})`,
          response: callPayload
        };
      }

      return {
        ...plan,
        status: "success",
        endpoint,
        http_status: callResponse.status,
        latency_ms: latency,
        response: parsedCall?.result ?? callPayload
      };
    } catch (error) {
      clearTimeout(timeoutHandle);
      return {
        ...plan,
        status: "error",
        endpoint,
        latency_ms: Date.now() - startedAt,
        error: error instanceof Error ? error.message : "Unknown MCP JSON-RPC request error"
      };
    }
  }

  private async invokeLegacyToolPayload(endpoint: string, plan: FoundationCallPlan): Promise<FoundationCallResult> {
    const controller = new AbortController();
    const startedAt = Date.now();
    const timeoutHandle = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await this.fetchFn(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          tool: plan.tool,
          arguments: plan.params
        }),
        signal: controller.signal
      });
      const parsedBody = await this.parseResponseBody(response);
      clearTimeout(timeoutHandle);

      if (!response.ok) {
        return {
          ...plan,
          status: "error",
          endpoint,
          http_status: response.status,
          latency_ms: Date.now() - startedAt,
          error: `Legacy tool payload failed (HTTP ${response.status})`,
          response: parsedBody
        };
      }

      return {
        ...plan,
        status: "success",
        endpoint,
        http_status: response.status,
        latency_ms: Date.now() - startedAt,
        response: parsedBody
      };
    } catch (error) {
      clearTimeout(timeoutHandle);
      return {
        ...plan,
        status: "error",
        endpoint,
        latency_ms: Date.now() - startedAt,
        error: error instanceof Error ? error.message : "Unknown legacy foundation MCP request error"
      };
    }
  }

  async invoke(plan: FoundationCallPlan): Promise<FoundationCallResult> {
    const endpointBase = this.endpoints[plan.mcp];
    if (!endpointBase) {
      return {
        ...plan,
        status: "skipped",
        latency_ms: 0,
        error: `No endpoint configured for foundation MCP '${plan.mcp}'.`
      };
    }

    const endpoint = normalizeEndpoint(endpointBase);
    const mcpAttempt = await this.invokeMcpJsonRpc(endpoint, plan);
    if (mcpAttempt.status === "success") {
      return mcpAttempt;
    }

    const legacyAttempt = await this.invokeLegacyToolPayload(endpoint, plan);
    if (legacyAttempt.status === "success") {
      return legacyAttempt;
    }

    return {
      ...legacyAttempt,
      error: [mcpAttempt.error, legacyAttempt.error].filter(Boolean).join(" | "),
      response: {
        mcp_jsonrpc: mcpAttempt.response,
        legacy_tool_payload: legacyAttempt.response
      }
    };
  }

  async invokeAll(plans: FoundationCallPlan[]): Promise<FoundationCallResult[]> {
    if (plans.length === 0) {
      return [];
    }

    return Promise.all(plans.map((plan) => this.invoke(plan)));
  }
}
