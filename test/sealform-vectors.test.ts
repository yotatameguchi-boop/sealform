import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { open, openFile, SealformError, type PrivateKeyEntry } from "../src/core.js";
import { b64url, fromB64url } from "../src/encoding.js";

// sealform 自身の形式のテストベクタ。別の言語で実装するときも、この結果に合わせる
const V = JSON.parse(readFileSync("test-vectors/sealform-sf2.json", "utf8"));
const ring = (names: string[]): PrivateKeyEntry[] =>
  names.map((n) => ({ kid: V.keys[n].kid, privateKey: fromB64url(V.keys[n].privateKey) }));

describe("sealform テストベクタ（sf2）", () => {
  for (const c of V.text) {
    it(c.name, async () => {
      const p = open(ring(c.keys), c.token, c.expectContext ?? {});
      if (c.expect.error) {
        await expect(p).rejects.toSatisfy((e: unknown) => e instanceof SealformError && e.code === c.expect.error);
        return;
      }
      const r = await p;
      expect(r.plaintext).toBe(c.expect.plaintext);
      if (c.expect.form) expect(r.form).toBe(c.expect.form);
      if (c.expect.field) expect(r.field).toBe(c.expect.field);
      if (c.expect.sealedAt) expect(r.sealedAt.toISOString()).toBe(c.expect.sealedAt);
    });
  }
  for (const c of V.files) {
    it(c.name, async () => {
      const r = await openFile(ring(c.keys), fromB64url(c.sealed));
      expect(r.name).toBe(c.expect.name);
      expect(r.type).toBe(c.expect.type);
      expect(b64url(r.data)).toBe(c.expect.data);
      expect(r.field).toBe(c.expect.field);
    });
  }
});
