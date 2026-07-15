import "./styles.css";
import { siGithub } from "simple-icons";
import {
  decryptTaskId,
  generateKeyPair,
  pkcs8PrivateKey,
  ready,
  signRegistration,
  sshPublicKey,
} from "./crypto";
import {
  buildAuthJson,
  extractIdentityClaims,
  inputKindLabel,
  jwtExpiresSoon,
  parseInputJson,
  type AgentIdentityAuthJson,
  type ParsedOAuthInput,
} from "./protocol";

function element<T extends Element>(id: string): T {
  const value = document.getElementById(id);
  if (!value) throw new Error(`Missing element: ${id}`);
  return value as unknown as T;
}

const input = element<HTMLTextAreaElement>("auth-input");
const output = element<HTMLTextAreaElement>("auth-output");
const inputView = element<HTMLElement>("input-view");
const convertButton = element<HTMLButtonElement>("convert-button");
const detectedType = element<HTMLSpanElement>("detected-type");
const progressSection = element<HTMLElement>("progress-section");
const progressFill = element<HTMLSpanElement>("progress-fill");
const progressTitle = element<HTMLElement>("progress-title");
const progressDetail = element<HTMLElement>("progress-detail");
const resultSection = element<HTMLElement>("result-section");
const resultSource = element<HTMLElement>("result-source");
const resultPlan = element<HTMLElement>("result-plan");
const errorBanner = element<HTMLElement>("error-banner");
const errorMessage = element<HTMLElement>("error-message");
element<SVGPathElement>("github-icon-path").setAttribute("d", siGithub.path);

function setProgress(percent: number, title: string, detail: string): void {
  progressSection.hidden = false;
  progressFill.style.width = `${percent}%`;
  progressTitle.textContent = title;
  progressDetail.textContent = detail;
}

function showError(error: unknown): void {
  const message = error instanceof Error ? error.message : "未知错误";
  errorMessage.textContent = message;
  errorBanner.hidden = false;
}

function clearError(): void {
  errorBanner.hidden = true;
  errorMessage.textContent = "";
}

async function post<T>(path: string, body: Record<string, unknown>): Promise<T> {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    cache: "no-store",
  });
  const payload = await response.json() as { error?: string } & T;
  if (!response.ok) throw new Error(payload.error || `请求失败（HTTP ${response.status}）`);
  return payload;
}

async function usableOAuth(inputValue: ParsedOAuthInput): Promise<ParsedOAuthInput> {
  if (!jwtExpiresSoon(inputValue.accessToken)) return inputValue;
  if (!inputValue.refreshToken) throw new Error("OAuth access token 已过期，且没有 refresh_token");
  setProgress(12, "刷新 OAuth", "使用 Codex refresh_token 获取一次性 access token");
  const refreshed = await post<{ access_token: string | null; id_token: string | null }>(
    "/api/oauth/refresh",
    { refresh_token: inputValue.refreshToken },
  );
  if (!refreshed.access_token) throw new Error("OAuth 刷新响应缺少 access_token");
  return {
    ...inputValue,
    accessToken: refreshed.access_token,
    idToken: refreshed.id_token || inputValue.idToken,
  };
}

async function convertOAuth(source: ParsedOAuthInput): Promise<AgentIdentityAuthJson> {
  await ready();
  const oauth = await usableOAuth(source);
  const claims = extractIdentityClaims(oauth.idToken, oauth.accessToken);

  setProgress(28, "生成身份密钥", "Ed25519 私钥保留在当前浏览器内存");
  const keyPair = generateKeyPair();
  const runtime = await post<{ agent_runtime_id: string }>("/api/agent/register", {
    access_token: oauth.accessToken,
    agent_public_key: sshPublicKey(keyPair.publicKey),
    is_fedramp: claims.isFedramp,
  });

  setProgress(62, "注册 Codex task", "为新 runtime 签发 task 注册请求");
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
  if (!taskId) throw new Error("task 注册响应缺少 task_id");

  setProgress(88, "生成 auth.json", "OAuth token 将从输出中移除");
  return buildAuthJson({
      agent_runtime_id: runtime.agent_runtime_id,
      agent_private_key: pkcs8PrivateKey(keyPair.privateKey),
      account_id: claims.accountId,
      chatgpt_user_id: claims.userId,
      email: claims.email,
      plan_type: claims.planType,
      chatgpt_account_is_fedramp: claims.isFedramp,
      task_id: taskId,
  });
}

function showResult(authJson: AgentIdentityAuthJson, source: string): void {
  output.value = JSON.stringify(authJson, null, 2);
  resultSource.textContent = source;
  resultPlan.textContent = authJson.agent_identity.plan_type;
  input.value = "";
  detectedType.hidden = true;
  progressSection.hidden = true;
  inputView.hidden = true;
  resultSection.hidden = false;
}

async function convert(): Promise<void> {
  clearError();
  resultSection.hidden = true;
  convertButton.disabled = true;
  convertButton.textContent = "正在转换";
  try {
    const parsed = parseInputJson(input.value.trim());
    if (parsed.kind === "agent-identity") {
      setProgress(70, "校验现有身份", "规范化 Codex Agent Identity auth.json");
      await new Promise((resolve) => setTimeout(resolve, 180));
      showResult(parsed.authJson, inputKindLabel(parsed.kind));
      return;
    }
    setProgress(5, "读取认证信息", inputKindLabel(parsed.kind));
    const converted = await convertOAuth(parsed);
    setProgress(100, "转换完成", "Agent Identity 已生成");
    showResult(converted, inputKindLabel(parsed.kind));
  } catch (error) {
    progressSection.hidden = true;
    showError(error);
  } finally {
    convertButton.disabled = false;
    convertButton.textContent = "转换";
  }
}

function reset(): void {
  clearError();
  output.value = "";
  resultSection.hidden = true;
  progressSection.hidden = true;
  inputView.hidden = false;
  detectedType.hidden = true;
  input.focus();
}

function updateDetectedType(): void {
  try {
    if (!input.value.trim()) throw new Error();
    const parsed = parseInputJson(input.value.trim());
    detectedType.textContent = inputKindLabel(parsed.kind);
    detectedType.hidden = false;
  } catch {
    detectedType.hidden = true;
  }
}

async function copyOutput(): Promise<void> {
  if (!output.value) return;
  await navigator.clipboard.writeText(output.value);
  const button = element<HTMLButtonElement>("copy-button");
  button.textContent = "已复制";
  setTimeout(() => { button.textContent = "复制"; }, 1400);
}

function downloadOutput(): void {
  if (!output.value) return;
  const url = URL.createObjectURL(new Blob([output.value + "\n"], { type: "application/json" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = "auth.json";
  link.click();
  URL.revokeObjectURL(url);
}

input.addEventListener("input", updateDetectedType);
convertButton.addEventListener("click", () => void convert());
element("copy-button").addEventListener("click", () => void copyOutput());
element("download-button").addEventListener("click", downloadOutput);
element("reset-button").addEventListener("click", reset);
element("dismiss-error").addEventListener("click", clearError);
