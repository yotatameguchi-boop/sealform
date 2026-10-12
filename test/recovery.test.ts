import { describe, expect, it } from "vitest";
import { generateKeyPair, loadPublicKey, open, seal } from "../src/core.js";
import { describePrivateKey, fromRecoveryCode, recoverySheetHtml, toRecoveryCode } from "../src/recovery.js";

describe("復旧コード", () => {
  it("紙から戻した鍵で、元の鍵宛ての暗号文を開ける", async () => {
    const kp = await generateKeyPair();
    const code = await toRecoveryCode(kp.privateKey);
    expect(code).toMatch(/^SFR1(-[0-9A-HJKMNP-TV-Z]{1,4}){15}$/);
    const t = await seal(await loadPublicKey(kp.publicDoc), "紙から復旧", { form: "/f", field: "x" });
    const seed = await fromRecoveryCode(code);
    const info = await describePrivateKey(seed);
    expect(info.kid).toBe(kp.publicDoc.kid);
    expect(info.fingerprint).toBe(kp.publicDoc.fingerprint);
    expect((await open({ kid: info.kid, privateKey: seed }, t)).plaintext).toBe("紙から復旧");
  });

  it("小文字・区切り無し・I/L/O の読み違いを許す", async () => {
    const kp = await generateKeyPair();
    const code = await toRecoveryCode(kp.privateKey);
    const sloppy = code.toLowerCase().replace(/-/g, " ").replace(/1/g, "l").replace(/0/g, "o");
    expect(await fromRecoveryCode(sloppy)).toEqual(kp.privateKey);
  });

  it("1文字の書き間違い・入れ替え・書き漏れを検出する", async () => {
    const kp = await generateKeyPair();
    const code = await toRecoveryCode(kp.privateKey);
    const chars = [...code];
    const i = chars.findIndex((c, j) => j > 8 && c !== "-");
    const typo = [...chars];
    typo[i] = typo[i] === "A" ? "B" : "A";
    await expect(fromRecoveryCode(typo.join(""))).rejects.toThrow(/検査値/);
    const swapped = [...chars];
    const j = swapped.findIndex((c, k) => k > i && c !== "-" && c !== swapped[i]);
    [swapped[i], swapped[j]] = [swapped[j]!, swapped[i]!];
    await expect(fromRecoveryCode(swapped.join(""))).rejects.toThrow(/検査値/);
    await expect(fromRecoveryCode(code.slice(0, -5))).rejects.toThrow(/短すぎ/);
    await expect(fromRecoveryCode("ABCD-" + code)).rejects.toThrow(/SFR1/);
    await expect(fromRecoveryCode(code + "U")).rejects.toThrow(/使えない文字/);
  });

  it("印刷用ページは外部に通信せず、ラベルを無害化する", async () => {
    const html = recoverySheetHtml({ code: "SFR1-AAAA", kid: "k", fingerprint: "f", label: "<script>x</script>", created: "2026-10-12" });
    expect(html).toContain("default-src 'none'");
    expect(html).not.toContain("<script>x");
  });
});
