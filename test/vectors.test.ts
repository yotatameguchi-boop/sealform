import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { XWing } from "@hpke/hybridkem-x-wing";

// X-Wing の仕様書（IETF ドラフト）付録の公式テストベクタで、使っている実装が仕様どおりかを確かめる
const { vectors } = JSON.parse(readFileSync("test-vectors/xwing-draft-10.json", "utf8")) as {
  vectors: Record<"seed" | "sk" | "pk" | "eseed" | "ct" | "ss", string>[];
};
const hex = (s: string) => Uint8Array.from(Buffer.from(s, "hex"));
const toHex = (b: ArrayBuffer) => Buffer.from(b).toString("hex");

describe("X-Wing 公式テストベクタ（draft-connolly-cfrg-xwing-kem-10）", () => {
  vectors.forEach((v, i) => {
    it(`ベクタ ${i + 1}: 鍵生成・カプセル化・復元が仕様の値と一致する`, async () => {
      const kem = new XWing();
      const kp = await kem.generateKeyPairDerand(hex(v.sk));
      expect(toHex(await kem.serializePublicKey(kp.publicKey))).toBe(v.pk);
      const { enc, sharedSecret } = await kem.encap({ recipientPublicKey: kp.publicKey, ekm: hex(v.eseed) });
      expect(toHex(enc)).toBe(v.ct);
      expect(toHex(sharedSecret)).toBe(v.ss);
      expect(toHex(await kem.decap({ recipientKey: kp.privateKey, enc: hex(v.ct) }))).toBe(v.ss);
    });
  });
});
