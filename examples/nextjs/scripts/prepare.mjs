// sealform.js と鍵の束を public/ に置く（next dev / build の前に自動で実行）
import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { prepareDemo, dist, keySetPath } from "../../shared/demo.mjs";

const demo = await prepareDemo();
await mkdir("public/.well-known", { recursive: true });
await copyFile(join(dist, "sealform.js"), "public/sealform.js");
await copyFile(keySetPath, "public/.well-known/sealform-key.json");
// ページに埋め込む SRI の値と指紋（本番では設定ファイルや環境変数で管理する）
await writeFile("sealform.config.json", JSON.stringify(demo, null, 2) + "\n");
console.log("sealform: public/ に配布ファイルを用意しました");
