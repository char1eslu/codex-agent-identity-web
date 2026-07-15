import sodium from "libsodium-wrappers";

const PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

export interface AgentKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, value) => sum + value.length, 0);
  const output = new Uint8Array(total);
  let offset = 0;
  for (const value of arrays) {
    output.set(value, offset);
    offset += value.length;
  }
  return output;
}

function uint32(value: number): Uint8Array {
  const output = new Uint8Array(4);
  new DataView(output.buffer).setUint32(0, value, false);
  return output;
}

export async function ready(): Promise<void> {
  await sodium.ready;
}

export function generateKeyPair(): AgentKeyPair {
  const pair = sodium.crypto_sign_keypair();
  return { publicKey: pair.publicKey, privateKey: pair.privateKey };
}

export function sshPublicKey(publicKey: Uint8Array): string {
  const algorithm = new TextEncoder().encode("ssh-ed25519");
  const blob = concat(uint32(algorithm.length), algorithm, uint32(publicKey.length), publicKey);
  return `ssh-ed25519 ${sodium.to_base64(blob, sodium.base64_variants.ORIGINAL)}`;
}

export function pkcs8PrivateKey(privateKey: Uint8Array): string {
  const seed = privateKey.slice(0, 32);
  return sodium.to_base64(concat(PKCS8_PREFIX, seed), sodium.base64_variants.ORIGINAL);
}

export function signRegistration(privateKey: Uint8Array, runtimeId: string, timestamp: string): string {
  const payload = new TextEncoder().encode(`${runtimeId}:${timestamp}`);
  const signature = sodium.crypto_sign_detached(payload, privateKey);
  return sodium.to_base64(signature, sodium.base64_variants.ORIGINAL);
}

export function decryptTaskId(
  encryptedTaskId: string,
  publicKey: Uint8Array,
  privateKey: Uint8Array,
): string {
  const curvePublic = sodium.crypto_sign_ed25519_pk_to_curve25519(publicKey);
  const curvePrivate = sodium.crypto_sign_ed25519_sk_to_curve25519(privateKey);
  const encrypted = sodium.from_base64(encryptedTaskId, sodium.base64_variants.ORIGINAL);
  const decrypted = sodium.crypto_box_seal_open(encrypted, curvePublic, curvePrivate);
  if (!decrypted) throw new Error("无法解密 task_id");
  const taskId = new TextDecoder().decode(decrypted);
  if (!taskId) throw new Error("解密后的 task_id 为空");
  return taskId;
}

function base64Url(bytes: Uint8Array): string {
  return sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING);
}

export function buildAssertion(
  privateKey: Uint8Array,
  runtimeId: string,
  taskId: string,
  timestamp = new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
): string {
  const payload = new TextEncoder().encode(`${runtimeId}:${taskId}:${timestamp}`);
  const signature = sodium.crypto_sign_detached(payload, privateKey);
  const envelope = JSON.stringify({
    agent_runtime_id: runtimeId,
    task_id: taskId,
    timestamp,
    signature: sodium.to_base64(signature, sodium.base64_variants.ORIGINAL),
  });
  return `AgentAssertion ${base64Url(new TextEncoder().encode(envelope))}`;
}
