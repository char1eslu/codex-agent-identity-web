interface Env {
  ASSETS: Fetcher;
}

const AUTH_BASE = "https://auth.openai.com";
const CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
const MAX_BODY_BYTES = 128 * 1024;
const RUNTIME_PATTERN = /^[A-Za-z0-9_-]{8,256}$/;

const SECURITY_HEADERS: Record<string, string> = {
  "Cache-Control": "no-store, max-age=0",
  "Content-Security-Policy": "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
};

class PublicError extends Error {
  constructor(message: string, readonly status = 400) {
    super(message);
  }
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS },
  });
}

async function readJson(request: Request): Promise<Record<string, unknown>> {
  const contentLength = Number(request.headers.get("content-length") ?? "0");
  if (contentLength > MAX_BODY_BYTES) throw new PublicError("请求体过大", 413);
  const text = await request.text();
  if (text.length > MAX_BODY_BYTES) throw new PublicError("请求体过大", 413);
  try {
    const parsed = JSON.parse(text) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error();
    return parsed as Record<string, unknown>;
  } catch {
    throw new PublicError("请求体必须是 JSON 对象");
  }
}

function stringField(body: Record<string, unknown>, key: string, maxLength: number): string {
  const value = body[key];
  if (typeof value !== "string" || !value || value.length > maxLength) {
    throw new PublicError(`无效的 ${key}`);
  }
  return value;
}

async function upstreamJson(url: string, init: RequestInit): Promise<Record<string, unknown>> {
  const response = await fetch(url, {
    ...init,
    redirect: "manual",
    headers: {
      "User-Agent": "codex-agent-identity/1",
      ...(init.headers ?? {}),
    },
  });
  let payload: unknown = null;
  try { payload = await response.json(); } catch { /* upstream returned non-JSON */ }
  if (!response.ok) {
    const isClientError = response.status >= 400 && response.status < 500;
    throw new PublicError(
      isClientError ? "OpenAI 认证请求被拒绝" : "OpenAI 认证服务暂时不可用",
      isClientError ? response.status : 502,
    );
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new PublicError("上游返回了无效响应", 502);
  }
  return payload as Record<string, unknown>;
}

async function refreshOAuth(request: Request): Promise<Response> {
  const body = await readJson(request);
  const refreshToken = stringField(body, "refresh_token", 16_384);
  const payload = await upstreamJson(`${AUTH_BASE}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ client_id: CLIENT_ID, grant_type: "refresh_token", refresh_token: refreshToken }),
  });
  return json({
    access_token: typeof payload.access_token === "string" ? payload.access_token : null,
    id_token: typeof payload.id_token === "string" ? payload.id_token : null,
  });
}

async function registerRuntime(request: Request): Promise<Response> {
  const body = await readJson(request);
  const accessToken = stringField(body, "access_token", 16_384);
  const publicKey = stringField(body, "agent_public_key", 1024);
  if (!/^ssh-ed25519 [A-Za-z0-9+/=]+$/.test(publicKey)) {
    throw new PublicError("无效的 agent_public_key");
  }
  const headers: Record<string, string> = {
    Authorization: `Bearer ${accessToken}`,
    "Content-Type": "application/json",
  };
  if (body.is_fedramp === true) headers["X-OpenAI-Fedramp"] = "true";
  const payload = await upstreamJson(`${AUTH_BASE}/api/accounts/v1/agent/register`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      abom: {
        agent_version: "agentid-web-1",
        agent_harness_id: "codex-cli",
        running_location: "cloudflare-worker",
      },
      agent_public_key: publicKey,
      capabilities: ["responsesapi"],
      ttl: null,
    }),
  });
  const runtimeId = payload.agent_runtime_id;
  if (typeof runtimeId !== "string" || !RUNTIME_PATTERN.test(runtimeId)) {
    throw new PublicError("注册响应缺少 agent_runtime_id", 502);
  }
  return json({ agent_runtime_id: runtimeId });
}

async function registerTask(request: Request, runtimeId: string): Promise<Response> {
  if (!RUNTIME_PATTERN.test(runtimeId)) throw new PublicError("无效的 agent_runtime_id");
  const body = await readJson(request);
  const timestamp = stringField(body, "timestamp", 64);
  const signature = stringField(body, "signature", 512);
  const time = Date.parse(timestamp);
  if (!Number.isFinite(time) || Math.abs(Date.now() - time) > 5 * 60 * 1000) {
    throw new PublicError("签名时间戳无效");
  }
  if (!/^[A-Za-z0-9+/=]+$/.test(signature)) throw new PublicError("签名格式无效");
  const payload = await upstreamJson(`${AUTH_BASE}/api/accounts/v1/agent/${encodeURIComponent(runtimeId)}/task/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ timestamp, signature }),
  });
  const taskId = payload.task_id ?? payload.taskId;
  const encryptedTaskId = payload.encrypted_task_id ?? payload.encryptedTaskId;
  if (typeof taskId === "string" && taskId) return json({ task_id: taskId });
  if (typeof encryptedTaskId === "string" && encryptedTaskId) {
    return json({ encrypted_task_id: encryptedTaskId });
  }
  throw new PublicError("task 注册响应缺少 task_id", 502);
}

async function api(request: Request, url: URL): Promise<Response> {
  if (request.method !== "POST") return json({ error: "仅支持 POST" }, 405);
  if (url.pathname === "/api/oauth/refresh") return refreshOAuth(request);
  if (url.pathname === "/api/agent/register") return registerRuntime(request);
  const taskMatch = url.pathname.match(/^\/api\/agent\/([^/]+)\/task\/register$/);
  if (taskMatch) return registerTask(request, decodeURIComponent(taskMatch[1]));
  return json({ error: "接口不存在" }, 404);
}

function securedAsset(response: Response, url: URL): Response {
  const headers = new Headers(response.headers);
  for (const [key, value] of Object.entries(SECURITY_HEADERS)) headers.set(key, value);
  if (url.pathname.startsWith("/assets/")) {
    headers.set("Cache-Control", "public, max-age=31536000, immutable");
  }
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    try {
      if (url.pathname.startsWith("/api/")) return await api(request, url);
      return securedAsset(await env.ASSETS.fetch(request), url);
    } catch (error) {
      if (error instanceof PublicError) return json({ error: error.message }, error.status);
      return json({ error: "服务暂时不可用" }, 502);
    }
  },
} satisfies ExportedHandler<Env>;
