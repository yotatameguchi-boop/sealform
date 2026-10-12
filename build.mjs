// dist/ を作る: ブラウザ用 sealform.js、npm 用 index.js、CLI、オフライン復号ツール
import { build } from "esbuild";
import { createHash } from "node:crypto";
import { readFile, writeFile, mkdir, chmod } from "node:fs/promises";

const pkg = JSON.parse(await readFile("package.json", "utf8"));
const define = { __SEALFORM_VERSION__: JSON.stringify(pkg.version) };
const sha384 = (s) => "sha384-" + createHash("sha384").update(s).digest("base64");
await mkdir("dist", { recursive: true });

// ブラウザ用（1ファイル・依存込み）
await build({
  entryPoints: ["src/browser-entry.ts"], outfile: "dist/sealform.js",
  bundle: true, minify: true, format: "iife", target: "es2020", define, legalComments: "eof",
});
const browserJs = await readFile("dist/sealform.js");
const hash = sha384(browserJs);
// 版ごとのハッシュを残す（sealform check が「公式の配布物か」を照合する）
// 記録するのは --release のときだけ。記録済みの版の中身が変わっていたら止める（版の上げ忘れ）
const release = process.argv.includes("--release");
let hashes = {};
try { hashes = JSON.parse(await readFile("hashes.json", "utf8")); } catch {}
if (release) {
  if (hashes[pkg.version] && hashes[pkg.version] !== hash) {
    console.error(`hashes.json の ${pkg.version} と配布物が一致しません。package.json の version を上げてください`);
    process.exit(1);
  }
  hashes[pkg.version] = hash;
  await writeFile("hashes.json", JSON.stringify(hashes, null, 2) + "\n");
}
// 手元のビルドは「+dev」として同梱する（デモや check の動作確認用）
const bundled = hashes[pkg.version] === hash ? hashes : { ...hashes, [`${pkg.version}+dev`]: hash };
await writeFile("dist/hashes.json", JSON.stringify(bundled, null, 2) + "\n");

// npm 用ライブラリと CLI（依存は node_modules から読む）
await build({
  entryPoints: ["src/index.ts"], outfile: "dist/index.js",
  bundle: true, format: "esm", platform: "neutral", target: "es2022", define, packages: "external",
});
await build({
  entryPoints: ["src/cli.ts"], outfile: "dist/cli.js",
  bundle: true, format: "esm", platform: "node", target: "node20", define, packages: "external",
  banner: { js: "#!/usr/bin/env node" },
});
await chmod("dist/cli.js", 0o755);

// オフライン復号ツール（HTML 1ファイル。CSP でスクリプトのハッシュを固定する）
const opener = await build({
  entryPoints: ["src/opener.ts"], write: false,
  bundle: true, minify: true, format: "iife", target: "es2020", define, legalComments: "none",
});
const script = opener.outputFiles[0].text.replace(/<\/script/gi, "<\\/script").trimEnd();
const html = (await readFile("src/opener.html", "utf8"))
  .replace("__SCRIPT_HASH__", sha384(script))
  .replace("__VERSION__", pkg.version)
  .replace("__SCRIPT__", () => script);
await writeFile("dist/sealform-opener.html", html);

console.log(`dist/sealform.js  ${(browserJs.length / 1024).toFixed(1)} KB  integrity=${hash}`);
