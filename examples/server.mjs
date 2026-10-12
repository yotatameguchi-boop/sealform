// 動作確認用のサーバー（依存なし）。npm run build のあと: npm run example
// 受け取った暗号文を examples/.data/submissions.csv に貯めるだけで、サーバーは平文に一切触れない。
import { createServer } from "node:http";
import { readFile, appendFile, mkdir, access } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { isSealed } from "../dist/index.js";

const root = dirname(fileURLToPath(import.meta.url));
const dist = join(root, "..", "dist");
const data = join(root, ".data");
const port = Number(process.env.PORT ?? 8787);

await mkdir(data, { recursive: true });
const keyPath = join(data, "sealform-key.json");
if (!(await access(keyPath).then(() => true, () => false))) {
  // デモ用の鍵を作る（本番では担当者の手元で keygen し、公開鍵だけをサーバーに置く）
  execFileSync(process.execPath, [join(dist, "cli.js"), "keygen", "--out", data], {
    env: { ...process.env, SEALFORM_PASSPHRASE: process.env.SEALFORM_PASSPHRASE ?? "demo-passphrase-123" },
    stdio: "inherit",
  });
}
const integrity = Object.values(JSON.parse(await readFile(join(dist, "hashes.json"), "utf8"))).at(-1);
const fingerprint = JSON.parse(await readFile(keyPath, "utf8")).fingerprint;

const CSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";
const send = (res, status, type, body) => {
  res.writeHead(status, { "content-type": type, "content-security-policy": CSP, "x-content-type-options": "nosniff" });
  res.end(body);
};
const esc = (s) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
const csv = (s) => `"${s.replace(/"/g, '""')}"`;

createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  try {
    if (req.method === "GET" && url.pathname === "/") {
      const html = (await readFile(join(root, "public", "index.html"), "utf8"))
        .replace("__INTEGRITY__", integrity)
        .replace("__FINGERPRINT__", fingerprint);
      return send(res, 200, "text/html; charset=utf-8", html);
    }
    if (req.method === "GET" && url.pathname === "/sealform.js") {
      return send(res, 200, "text/javascript; charset=utf-8", await readFile(join(dist, "sealform.js")));
    }
    if (req.method === "GET" && url.pathname === "/opener") {
      // 復号ツールは本来ダウンロードしてオフラインで使う。デモの確認用に配信する（CSP はファイル内の meta で効く）
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      return res.end(await readFile(join(dist, "sealform-opener.html")));
    }
    if (req.method === "GET" && url.pathname === "/.well-known/sealform-key.json") {
      return send(res, 200, "application/json", await readFile(keyPath));
    }
    if (req.method === "POST" && url.pathname === "/contact") {
      let body = "";
      for await (const c of req) body += c;
      const form = new URLSearchParams(body);
      const name = form.get("name") ?? "";
      const message = form.get("message") ?? "";
      // 平文が混ざって届いたら保存しない（設定ミスや JS の差し替えへの保険）
      if (!isSealed(name) || !isSealed(message)) {
        return send(res, 400, "text/plain; charset=utf-8", "暗号化されていない値が届いたため、受け付けませんでした");
      }
      await appendFile(join(data, "submissions.csv"), `${new Date().toISOString()},${csv(name)},${csv(message)}\n`);
      console.log(`受信: ${req.headers["content-length"]} バイト（暗号文のみ）`);
      return send(res, 200, "text/html; charset=utf-8", `<!doctype html><meta charset="utf-8"><title>送信しました</title>
<body style="font-family:system-ui;max-width:720px;margin:40px auto;padding:0 16px;line-height:1.7">
<h1>送信しました</h1><p>サーバーに届いて保存されたのは、次の暗号文だけです。</p>
<pre style="white-space:pre-wrap;word-break:break-all;font-size:11px;background:#f3f3f0;padding:12px">${esc(message)}</pre>
<p><a href="/">戻る</a></p></body>`);
    }
    send(res, 404, "text/plain; charset=utf-8", "not found");
  } catch (e) {
    console.error(e);
    send(res, 500, "text/plain; charset=utf-8", "error");
  }
}).listen(port, () => {
  console.log(`http://localhost:${port}/`);
  console.log(`受信データ: ${join(data, "submissions.csv")}`);
  console.log(`復号ツール: http://localhost:${port}/opener`);
  console.log(`復号: node dist/cli.js open --key ${join(data, "sealform-private-key.json")} ${join(data, "submissions.csv")}`);
});
