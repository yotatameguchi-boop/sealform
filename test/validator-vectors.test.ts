import { expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { isSealed, isSealedFile } from "../src/core.js";

// PHP（server/php/test.php）・Python（server/python/test_sealform_check.py）と同じベクタ
const V = JSON.parse(readFileSync("test-vectors/validator.json", "utf8"));

it("検証関数の共通ベクタ（Node）", () => {
  for (const c of V.text) expect(isSealed(c.value), c.value.slice(0, 30)).toBe(c.sealed);
  for (const c of V.files) expect(isSealedFile(Uint8Array.from(Buffer.from(c.base64, "base64")))).toBe(c.sealed);
});
