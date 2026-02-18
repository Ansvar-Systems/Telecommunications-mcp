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

      clearTimeout(timeoutHandle);
      const latency = Date.now() - startedAt;

      let parsedBody: unknown;
      try {
        parsedBody = await response.json();
      } catch {
        parsedBody = { parse_error: "Response was not JSON" };
      }

      if (!response.ok) {
        return {
          ...plan,
          status: "error",
          endpoint,
          http_status: response.status,
          latency_ms: latency,
          error: `HTTP ${response.status}`,
          response: parsedBody
        };
      }

      return {
        ...plan,
        status: "success",
        endpoint,
        http_status: response.status,
        latency_ms: latency,
        response: parsedBody
      };
    } catch (error) {
      clearTimeout(timeoutHandle);
      return {
        ...plan,
        status: "error",
        endpoint,
        latency_ms: Date.now() - startedAt,
        error: error instanceof Error ? error.message : "Unknown foundation MCP request error"
      };
    }
  }

  async invokeAll(plans: FoundationCallPlan[]): Promise<FoundationCallResult[]> {
    if (plans.length === 0) {
      return [];
    }

    return Promise.all(plans.map((plan) => this.invoke(plan)));
  }
}
