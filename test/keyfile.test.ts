import { describe, expect, it } from "vitest";
import { generateKeyPair, loadPublicKey, open, seal } from "../src/core.js";
import { protectPrivateKey, unlockPrivateKey } from "../src/keyfile.js";

describe("秘密鍵ファイル", () => {
  it("パスフレーズで開け、その鍵で復号できる", async () => {
    const kp = await generateKeyPair();
    const file = await protectPrivateKey(kp.privateKey, kp.publicDoc.publicKey, "correct horse battery");
    expect(JSON.stringify(file)).not.toContain(Buffer.from(kp.privateKey).toString("base64url"));
    const unlocked = await unlockPrivateKey(JSON.parse(JSON.stringify(file)), "correct horse battery");
    const t = await seal(await loadPublicKey(kp.publicDoc), "ok", { form: "/f", field: "x" });
    expect((await open(unlocked, t)).plaintext).toBe("ok");
  });

  it("パスフレーズが違えば開けない", async () => {
    const kp = await generateKeyPair();
    const file = await protectPrivateKey(kp.privateKey, kp.publicDoc.publicKey, "correct horse battery");
    await expect(unlockPrivateKey(file, "wrong horse battery")).rejects.toThrow(/パスフレーズが違う/);
  });

  it("短いパスフレーズを拒否する", async () => {
    const kp = await generateKeyPair();
    await expect(protectPrivateKey(kp.privateKey, kp.publicDoc.publicKey, "short")).rejects.toThrow(/12 文字以上/);
  });

  it("鍵導出の設定値が極端なファイルを拒否する", async () => {
    const kp = await generateKeyPair();
    const file = await protectPrivateKey(kp.privateKey, kp.publicDoc.publicKey, "correct horse battery");
    await expect(unlockPrivateKey({ ...file, kdf: { ...file.kdf, m: 1 << 30 } }, "correct horse battery")).rejects.toThrow(/大きすぎ/);
  });
});
