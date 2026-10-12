// Express での受け取り例。npm run build のあと:
//   cd examples/express && npm install && npm start   → http://localhost:8788
import express from "express";
import multer from "multer";
import { appendFile, writeFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { isSealed, isSealedFile } from "sealform";
import { prepareDemo, formHtml, dist, data, keySetPath } from "../shared/demo.mjs";

const demo = await prepareDemo();
const app = express();
// 添付ファイルはメモリで受けて中身を確かめる（暗号化後の上限 + 余裕）
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 11 * 1024 * 1024, files: 5 } });

app.use((req, res, next) => {
  res.set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; base-uri 'none'");
  next();
});
app.get("/", async (req, res) => res.type("html").send(await formHtml(demo, "sealform デモ・Express")));
app.get("/sealform.js", (req, res) => res.sendFile(join(dist, "sealform.js")));
app.get("/.well-known/sealform-key.json", (req, res) => res.sendFile(keySetPath, { dotfiles: "allow" }));

app.post("/contact", upload.array("attachment"), async (req, res) => {
  const { name, message } = req.body;
  // 平文が混ざっていたら保存しない（設定ミスや JS の差し替えへの保険）
  if (!isSealed(name) || !isSealed(message)) return res.status(400).send("暗号化されていない値が届きました");
  const files = (req.files ?? []).filter((f) => f.size > 0);
  if (files.some((f) => !isSealedFile(new Uint8Array(f.buffer)))) return res.status(400).send("暗号化されていないファイルが届きました");
  const saved = [];
  for (const f of files) {
    const id = `${randomBytes(8).toString("hex")}.sf`;
    await writeFile(join(data, "files", id), f.buffer);
    saved.push(id);
  }
  const csv = (s) => `"${String(s).replace(/"/g, '""')}"`;
  await appendFile(join(data, "submissions.csv"), [new Date().toISOString(), csv(name), csv(message), csv(saved.join(" ")), "express"].join(",") + "\n");
  res.type("html").send(`<!doctype html><meta charset="utf-8"><title>送信しました</title><p>送信しました（Express・添付 ${saved.length} 件）。保存されたのは暗号文だけです。</p><p><a href="/">戻る</a></p>`);
});

const port = Number(process.env.PORT ?? 8788);
app.listen(port, () => console.log(`Express の例: http://localhost:${port}/`));
