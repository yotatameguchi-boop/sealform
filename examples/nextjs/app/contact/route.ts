import { appendFile, writeFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { isSealed, isSealedFile } from "sealform";

const DATA = join(process.cwd(), "..", ".data");

// フォームの送信先。届くのは暗号文だけで、サーバーは平文に触れない
export async function POST(req: Request) {
  const form = await req.formData();
  const name = form.get("name");
  const message = form.get("message");
  // 平文が混ざっていたら保存しない（設定ミスや JS の差し替えへの保険）
  if (!isSealed(name) || !isSealed(message)) return new Response("暗号化されていない値が届きました", { status: 400 });
  const saved: string[] = [];
  for (const f of form.getAll("attachment")) {
    if (typeof f === "string" || f.size === 0) continue;
    const bytes = new Uint8Array(await f.arrayBuffer());
    if (!isSealedFile(bytes)) return new Response("暗号化されていないファイルが届きました", { status: 400 });
    const id = `${randomBytes(8).toString("hex")}.sf`;
    await writeFile(join(DATA, "files", id), bytes);
    saved.push(id);
  }
  const csv = (s: string) => `"${s.replace(/"/g, '""')}"`;
  await appendFile(join(DATA, "submissions.csv"), [new Date().toISOString(), csv(name), csv(message), csv(saved.join(" ")), "nextjs"].join(",") + "\n");
  return new Response(
    `<!doctype html><meta charset="utf-8"><title>送信しました</title><p>送信しました（Next.js・添付 ${saved.length} 件）。保存されたのは暗号文だけです。</p><p><a href="/">戻る</a></p>`,
    { headers: { "content-type": "text/html; charset=utf-8" } },
  );
}
