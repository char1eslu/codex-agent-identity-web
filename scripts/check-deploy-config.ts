import { readFile } from "node:fs/promises";

const config = await readFile(new URL("../wrangler.jsonc", import.meta.url), "utf8");
const workerName = config.match(/"name"\s*:\s*"([^"]+)"/)?.[1];

if (!workerName || workerName === "codex-agent-identity-web") {
  throw new Error("Set a unique Worker name in wrangler.jsonc before deploying");
}

console.log(`deploy_config=ok name=${workerName}`);
