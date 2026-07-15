import sodium from "libsodium-wrappers";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildAssertion, ready } from "../src/crypto";
import type { AgentIdentityAuthJson } from "../src/protocol";

const authPath = process.env.AUTH_PATH ?? join(tmpdir(), "agentid-worker-validation", "auth.json");

await ready();
const auth = JSON.parse(await readFile(authPath, "utf8")) as AgentIdentityAuthJson;
const identity = auth.agent_identity;
const der = sodium.from_base64(identity.agent_private_key, sodium.base64_variants.ORIGINAL);
if (der.length !== 48) throw new Error("invalid PKCS#8 private key");
const keyPair = sodium.crypto_sign_seed_keypair(der.slice(16));
const authorization = buildAssertion(keyPair.privateKey, identity.agent_runtime_id, identity.task_id);
const response = await fetch("https://chatgpt.com/backend-api/wham/usage", {
  signal: AbortSignal.timeout(15_000),
  headers: {
    Authorization: authorization,
    "ChatGPT-Account-ID": identity.account_id,
    originator: "codex_cli_rs",
  },
});
const responseText = await response.text();
let payload: Record<string, unknown> = {};
try { payload = JSON.parse(responseText) as Record<string, unknown>; } catch { /* non-JSON challenge */ }
console.log(`usage_http_status=${response.status}`);
console.log(`cf_mitigated=${String(response.headers.get("cf-mitigated"))}`);
if (!response.ok) throw new Error(typeof payload.error === "string" ? payload.error : "usage verification failed");
console.log(`usage_plan=${String(payload.plan_type ?? "unknown")}`);
console.log(`usage_limited=${String(Boolean(payload.rate_limit_reached_type))}`);
