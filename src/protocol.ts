export type InputKind = "web-auth" | "codex-oauth" | "agent-identity";

export interface ParsedOAuthInput {
  kind: "web-auth" | "codex-oauth";
  accessToken: string;
  idToken: string;
  refreshToken?: string;
}

export interface AgentIdentityRecord {
  agent_runtime_id: string;
  agent_private_key: string;
  account_id: string;
  chatgpt_user_id: string;
  email: string | null;
  plan_type: string;
  chatgpt_account_is_fedramp: boolean;
  task_id: string;
}

export interface AgentIdentityAuthJson {
  auth_mode: "agentIdentity";
  OPENAI_API_KEY: null;
  agent_identity: AgentIdentityRecord;
}

export interface ParsedAgentInput {
  kind: "agent-identity";
  authJson: AgentIdentityAuthJson;
}

export type ParsedInput = ParsedOAuthInput | ParsedAgentInput;

export interface IdentityClaims {
  accountId: string;
  userId: string;
  email: string | null;
  planType: string;
  isFedramp: boolean;
}

type JsonObject = Record<string, unknown>;

function object(value: unknown): JsonObject | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonObject)
    : null;
}

function requiredString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`缺少 ${field}`);
  }
  return value;
}

export function decodeJwt(jwt: string): JsonObject {
  const parts = jwt.split(".");
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    throw new Error("认证 token 不是有效 JWT");
  }
  try {
    const normalized = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
    const bytes = Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
    return JSON.parse(new TextDecoder().decode(bytes)) as JsonObject;
  } catch {
    throw new Error("认证 token 的 JWT payload 无效");
  }
}

export function jwtExpiresSoon(jwt: string, nowSeconds = Date.now() / 1000): boolean {
  const claims = decodeJwt(jwt);
  return typeof claims.exp !== "number" || claims.exp <= nowSeconds + 60;
}

export function extractIdentityClaims(...tokens: string[]): IdentityClaims {
  for (const token of tokens) {
    if (!token) continue;
    const claims = decodeJwt(token);
    const auth = object(claims["https://api.openai.com/auth"]);
    if (!auth) continue;
    const profile = object(claims["https://api.openai.com/profile"]);
    const accountId = auth.chatgpt_account_id;
    const userId = auth.chatgpt_user_id ?? auth.user_id;
    if (typeof accountId !== "string" || typeof userId !== "string") continue;
    const email = typeof claims.email === "string"
      ? claims.email
      : typeof profile?.email === "string"
        ? profile.email
        : null;
    return {
      accountId,
      userId,
      email,
      planType: typeof auth.chatgpt_plan_type === "string" ? auth.chatgpt_plan_type : "unknown",
      isFedramp: auth.chatgpt_account_is_fedramp === true,
    };
  }
  throw new Error("认证 JSON 缺少 ChatGPT 账号身份声明");
}

function normalizeExistingIdentity(root: JsonObject): AgentIdentityAuthJson {
  const identity = object(root.agent_identity);
  if (!identity) throw new Error("Agent Identity JSON 缺少 agent_identity");
  const normalized: AgentIdentityRecord = {
    agent_runtime_id: requiredString(identity.agent_runtime_id, "agent_runtime_id"),
    agent_private_key: requiredString(identity.agent_private_key, "agent_private_key"),
    account_id: requiredString(identity.account_id, "account_id"),
    chatgpt_user_id: requiredString(identity.chatgpt_user_id, "chatgpt_user_id"),
    email: typeof identity.email === "string" ? identity.email : null,
    plan_type: requiredString(identity.plan_type, "plan_type"),
    chatgpt_account_is_fedramp: identity.chatgpt_account_is_fedramp === true,
    task_id: requiredString(identity.task_id, "task_id"),
  };
  return buildAuthJson(normalized);
}

export function parseInputJson(raw: string): ParsedInput {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("输入不是有效 JSON");
  }
  const root = object(parsed);
  if (!root) throw new Error("认证 JSON 必须是对象");

  if (root.auth_mode === "agentIdentity" || root.agent_identity !== undefined) {
    return { kind: "agent-identity", authJson: normalizeExistingIdentity(root) };
  }

  if (typeof root.accessToken === "string" && root.accessToken) {
    return {
      kind: "web-auth",
      accessToken: root.accessToken,
      idToken: root.accessToken,
    };
  }

  const tokens = object(root.tokens);
  if (tokens) {
    const accessToken = requiredString(tokens.access_token, "tokens.access_token");
    const idToken = requiredString(tokens.id_token, "tokens.id_token");
    return {
      kind: "codex-oauth",
      accessToken,
      idToken,
      refreshToken: typeof tokens.refresh_token === "string" && tokens.refresh_token
        ? tokens.refresh_token
        : undefined,
    };
  }

  throw new Error("无法识别认证 JSON；需要 Web accessToken 或 Codex tokens");
}

export function buildAuthJson(identity: AgentIdentityRecord): AgentIdentityAuthJson {
  return {
    auth_mode: "agentIdentity",
    OPENAI_API_KEY: null,
    agent_identity: identity,
  };
}

export function inputKindLabel(kind: InputKind): string {
  switch (kind) {
    case "web-auth": return "ChatGPT Web auth";
    case "codex-oauth": return "Codex OAuth auth.json";
    case "agent-identity": return "Agent Identity auth.json";
  }
}
