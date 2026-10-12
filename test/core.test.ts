import { describe, expect, it } from "vitest";
import { findTokens, generateKeyPair, inspect, isSealed, loadPublicKey, open, seal, SealformError } from "../src/core.js";
import { b64url, fromB64url } from "../src/encoding.js";

const ctx = { form: "/contact", field: "body" };

async function setup() {
  const kp = await generateKeyPair();
  const key = await loadPublicKey(kp.publicDoc);
  return { kp, key };
}

async function code(p: Promise<unknown>) {
  try {
    await p;
  } catch (e) {
    return (e as SealformError).code;
  }
  return "no-error";
}

describe("seal / open", () => {
  it("往復できる（日本語・絵文字・空文字・長文）", async () => {
    const { kp, key } = await setup();
    for (const text of ["こんにちは、相談です。", "🔐👀", "", "あ".repeat(20000)]) {
      const t = await seal(key, text, ctx);
      expect(isSealed(t)).toBe(true);
      const r = await open(kp.privateKey, kp.publicDoc.kid, t, ctx);
      expect(r.plaintext).toBe(text);
      expect(r.form).toBe("/contact");
      expect(r.field).toBe("body");
    }
  });

  it("同じ平文でも毎回違う暗号文になる", async () => {
    const { key } = await setup();
    expect(await seal(key, "x", ctx)).not.toBe(await seal(key, "x", ctx));
  });

  it("長さを丸めるので、短い文の長さの差は暗号文に出ない", async () => {
    const { key } = await setup();
    const a = await seal(key, "a", ctx);
    const b = await seal(key, "a".repeat(50), ctx);
    expect(a.length).toBe(b.length);
  });

  it("本文を1文字でも書き換えると復号に失敗する", async () => {
    const { kp, key } = await setup();
    const t = await seal(key, "秘密", ctx);
    const parts = t.split(".");
    const ct = fromB64url(parts[4]!);
    ct[0]! ^= 1;
    parts[4] = b64url(ct);
    expect(await code(open(kp.privateKey, kp.publicDoc.kid, parts.join("."), ctx))).toBe("decrypt-failed");
  });

  it("宛先フォームを書き換えると復号に失敗する（見出しも認証対象）", async () => {
    const { kp, key } = await setup();
    const t = await seal(key, "秘密", ctx);
    const parts = t.split(".");
    parts[2] = b64url(new TextEncoder().encode(JSON.stringify({ v: 1, f: "/other", n: "body", t: 0 })));
    expect(await code(open(kp.privateKey, kp.publicDoc.kid, parts.join("."), ctx))).toBe("decrypt-failed");
  });

  it("別フォーム・別項目宛ての暗号文は、期待値を渡すと拒否できる", async () => {
    const { kp, key } = await setup();
    const t = await seal(key, "秘密", { form: "/other", field: "body" });
    expect(await code(open(kp.privateKey, kp.publicDoc.kid, t, { form: "/contact" }))).toBe("wrong-form");
    const t2 = await seal(key, "秘密", { form: "/contact", field: "name" });
    expect(await code(open(kp.privateKey, kp.publicDoc.kid, t2, ctx))).toBe("wrong-field");
  });

  it("別の鍵では復号できない", async () => {
    const a = await setup();
    const b = await setup();
    const t = await seal(a.key, "秘密", ctx);
    expect(await code(open(b.kp.privateKey, b.kp.publicDoc.kid, t))).toBe("wrong-key");
    // kid を偽っても中身は開かない
    expect(await code(open(b.kp.privateKey, a.kp.publicDoc.kid, t))).toBe("decrypt-failed");
  });

  it("inspect は復号せずに宛先と時刻を読める", async () => {
    const { key } = await setup();
    const now = new Date("2026-10-01T00:00:00Z");
    const info = inspect(await seal(key, "x", ctx, { now }));
    expect(info).toMatchObject({ form: "/contact", field: "body", sealedAt: now });
  });

  it("findTokens は CSV などから暗号文だけを拾う", async () => {
    const { key } = await setup();
    const t1 = await seal(key, "1", ctx);
    const t2 = await seal(key, "2", ctx);
    expect(findTokens(`id,body\n1,"${t1}"\n2,${t2}\n`)).toEqual([t1, t2]);
  });

  it("isSealed は平文を弾く", () => {
    expect(isSealed("ふつうの文章")).toBe(false);
    expect(isSealed("sf1.abc")).toBe(false);
    expect(isSealed(undefined)).toBe(false);
  });
});

describe("loadPublicKey", () => {
  it("期限切れの鍵を拒否する", async () => {
    const kp = await generateKeyPair({ validDays: 1, now: new Date("2020-01-01") });
    expect(await code(loadPublicKey(kp.publicDoc))).toBe("key-expired");
  });

  it("指紋の固定値と違う鍵を拒否する", async () => {
    const a = await generateKeyPair();
    const b = await generateKeyPair();
    expect(await code(loadPublicKey(b.publicDoc, { pin: a.publicDoc.fingerprint }))).toBe("fingerprint-mismatch");
    await expect(loadPublicKey(a.publicDoc, { pin: a.publicDoc.fingerprint })).resolves.toBeTruthy();
  });

  it("kid や指紋を書き換えた JSON を拒否する（鍵本体から計算し直す）", async () => {
    const a = await generateKeyPair();
    const b = await generateKeyPair();
    const forged = { ...b.publicDoc, kid: a.publicDoc.kid, fingerprint: a.publicDoc.fingerprint };
    expect(await code(loadPublicKey(forged, { pin: a.publicDoc.fingerprint }))).toBe("bad-key");
  });

  it("壊れた鍵・別方式の鍵を拒否する", async () => {
    const a = await generateKeyPair();
    expect(await code(loadPublicKey({ ...a.publicDoc, publicKey: "AAAA" }))).toBe("bad-key");
    expect(await code(loadPublicKey({ ...a.publicDoc, alg: "RSA" }))).toBe("bad-key");
    expect(await code(loadPublicKey(null))).toBe("bad-key");
  });
});
