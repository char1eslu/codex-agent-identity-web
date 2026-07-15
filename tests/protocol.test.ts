import { describe, expect, it } from "vitest";
import { extractIdentityClaims, jwtExpiresSoon, parseInputJson } from "../src/protocol";

function jwt(payload: Record<string, unknown>): string {
  const encode = (value: unknown) => btoa(JSON.stringify(value))
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
  return `${encode({ alg: "none" })}.${encode(payload)}.signature`;
}

const authClaims = {
  exp: 4_000_000_000,
  email: "test@example.com",
  "https://api.openai.com/auth": {
    chatgpt_account_id: "account-test",
    chatgpt_user_id: "user-test",
    chatgpt_plan_type: "pro",
    chatgpt_account_is_fedramp: false,
  },
};

describe("parseInputJson", () => {
  it("recognizes ChatGPT Web auth and ignores sessionToken", () => {
    const accessToken = jwt(authClaims);
    const parsed = parseInputJson(JSON.stringify({ accessToken, sessionToken: "not-used" }));
    expect(parsed).toMatchObject({ kind: "web-auth", accessToken, idToken: accessToken });
    expect(JSON.stringify(parsed)).not.toContain("not-used");
  });

  it("recognizes Codex OAuth auth.json", () => {
    const token = jwt(authClaims);
    const parsed = parseInputJson(JSON.stringify({
      auth_mode: "chatgpt",
      tokens: { access_token: token, id_token: token, refresh_token: "refresh-test" },
    }));
    expect(parsed).toMatchObject({ kind: "codex-oauth", refreshToken: "refresh-test" });
  });

  it("normalizes existing Agent Identity without OAuth material", () => {
    const parsed = parseInputJson(JSON.stringify({
      auth_mode: "agentIdentity",
      tokens: { access_token: "must-not-survive" },
      agent_identity: {
        agent_runtime_id: "runtime-test",
        agent_private_key: "private-test",
        account_id: "account-test",
        chatgpt_user_id: "user-test",
        email: null,
        plan_type: "pro",
        chatgpt_account_is_fedramp: false,
        task_id: "task-test",
      },
    }));
    expect(parsed.kind).toBe("agent-identity");
    expect(JSON.stringify(parsed)).not.toContain("must-not-survive");
    if (parsed.kind === "agent-identity") {
      expect(Object.keys(parsed.authJson)).toEqual(["auth_mode", "OPENAI_API_KEY", "agent_identity"]);
    }
  });
});

describe("JWT handling", () => {
  it("extracts account identity claims", () => {
    expect(extractIdentityClaims(jwt(authClaims))).toEqual({
      accountId: "account-test",
      userId: "user-test",
      email: "test@example.com",
      planType: "pro",
      isFedramp: false,
    });
  });

  it("detects expired access tokens", () => {
    expect(jwtExpiresSoon(jwt({ ...authClaims, exp: 100 }), 200)).toBe(true);
    expect(jwtExpiresSoon(jwt(authClaims), 200)).toBe(false);
  });
});
