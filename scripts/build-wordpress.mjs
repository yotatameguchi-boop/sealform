// WordPress プラグインを組み立てる: dist/wordpress/sealform/ と dist/wordpress/sealform.zip
// 検証関数（server/php/sealform.php）と配布用の sealform.js を同梱する
import { cp, mkdir, rm, copyFile, readdir } from "node:fs/promises";
import { execFileSync } from "node:child_process";

const out = "dist/wordpress/sealform";
// フォルダ自体は消さずに中身だけ入れ替える（Docker でマウントしていても見え続けるように）
await mkdir(out, { recursive: true });
for (const f of await readdir(out)) await rm(`${out}/${f}`, { recursive: true, force: true });
await rm("dist/wordpress/sealform.zip", { force: true });
await mkdir(`${out}/includes`, { recursive: true });
await mkdir(`${out}/assets`, { recursive: true });
await cp("wordpress/sealform", out, { recursive: true });
await copyFile("server/php/sealform.php", `${out}/includes/validator.php`);
await copyFile("dist/sealform.js", `${out}/assets/sealform.js`);
await copyFile("LICENSE", `${out}/LICENSE`);
execFileSync("zip", ["-qr", "sealform.zip", "sealform"], { cwd: "dist/wordpress" });
console.log("dist/wordpress/sealform.zip を作りました");
