import sodium from "libsodium-wrappers";
import { beforeAll, describe, expect, it } from "vitest";
import {
  buildAssertion,
  generateKeyPair,
  pkcs8PrivateKey,
  ready,
  signRegistration,
  sshPublicKey,
} from "../src/crypto";

beforeAll(async () => { await ready(); });

describe("Agent Identity crypto", () => {
  it("exports Codex-compatible SSH and PKCS#8 key formats", () => {
    const pair = generateKeyPair();
    expect(sshPublicKey(pair.publicKey)).toMatch(/^ssh-ed25519 /);
    const der = sodium.from_base64(pkcs8PrivateKey(pair.privateKey), sodium.base64_variants.ORIGINAL);
    expect(der.length).toBe(48);
    expect(Array.from(der.slice(0, 16))).toEqual([
      0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
      0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    ]);
  });

  it("signs runtime registration and fresh assertions", () => {
    const pair = generateKeyPair();
    const timestamp = "2026-07-15T08:00:00Z";
    const registration = signRegistration(pair.privateKey, "runtime-test", timestamp);
    expect(sodium.from_base64(registration, sodium.base64_variants.ORIGINAL)).toHaveLength(64);
    const assertion = buildAssertion(pair.privateKey, "runtime-test", "task-test", timestamp);
    expect(assertion).toMatch(/^AgentAssertion /);
    const encoded = assertion.slice("AgentAssertion ".length);
    const envelope = JSON.parse(sodium.to_string(
      sodium.from_base64(encoded, sodium.base64_variants.URLSAFE_NO_PADDING),
    ));
    expect(envelope).toMatchObject({
      agent_runtime_id: "runtime-test",
      task_id: "task-test",
      timestamp,
    });
  });
});
