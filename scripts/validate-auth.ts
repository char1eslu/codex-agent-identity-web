import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
  decryptTaskId,
  generateKeyPair,
  pkcs8PrivateKey,
  ready,
  signRegistration,
  sshPublicKey,
} from "../src/crypto";
import { buildAuthJson, extractIdentityClaims, parseInputJson } from "../src/protocol";

const authPath = process.env.AUTH_PATH;
const baseUrl = (process.env.BASE_URL ?? "http://localhost:8787").replace(/\/$/, "");
const outputPath = process.env.OUTPUT_PATH ?? join(tmpdir(), "agentid-worker-validation", "auth.json");

if (!authPath) throw new Error("AUTH_PATH is required");

async function post<T>(path: string, body: Record<string, unknown>): Promise<T> {
  const response = await fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const payload = await response.json() as { error?: string } & T;
  if (!response.ok) throw new Error(`${payload.error || "请求失败"}（HTTP ${response.status}）`);
  return payload;
}

await ready();
const parsed = parseInputJson(await readFile(authPath, "utf8"));
if (parsed.kind === "agent-identity") throw new Error("validation requires OAuth input");
const claims = extractIdentityClaims(parsed.idToken, parsed.accessToken);
const keyPair = generateKeyPair();
const runtime = await post<{ agent_runtime_id: string }>("/api/agent/register", {
  access_token: parsed.accessToken,
  agent_public_key: sshPublicKey(keyPair.publicKey),
  is_fedramp: claims.isFedramp,
});
const timestamp = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
const task = await post<{ task_id?: string; encrypted_task_id?: string }>(
  `/api/agent/${encodeURIComponent(runtime.agent_runtime_id)}/task/register`,
  {
    timestamp,
    signature: signRegistration(keyPair.privateKey, runtime.agent_runtime_id, timestamp),
  },
);
const taskId = task.task_id ?? (task.encrypted_task_id
  ? decryptTaskId(task.encrypted_task_id, keyPair.publicKey, keyPair.privateKey)
  : "");
if (!taskId) throw new Error("task_id missing");
const authJson = buildAuthJson({
  agent_runtime_id: runtime.agent_runtime_id,
  agent_private_key: pkcs8PrivateKey(keyPair.privateKey),
  account_id: claims.accountId,
  chatgpt_user_id: claims.userId,
  email: claims.email,
  plan_type: claims.planType,
  chatgpt_account_is_fedramp: claims.isFedramp,
  task_id: taskId,
});
await mkdir(dirname(outputPath), { recursive: true, mode: 0o700 });
await writeFile(outputPath, JSON.stringify(authJson, null, 2) + "\n", { mode: 0o600 });
await chmod(outputPath, 0o600);
console.log("conversion=ok");
console.log("runtime_present=true");
console.log("task_present=true");
console.log("oauth_token_persisted=false");
console.log(`output_mode=0600`);
