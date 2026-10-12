// 各サーバーの例で共通に使う、デモ用の鍵と配布ファイルの準備。
// 初回だけ担当者2人分の鍵を作り、鍵の束（examples/.data/sealform-key.json）にする。
// 本番では各担当者が手元で keygen し、公開鍵だけを集めて keys add する。
import { readFile, readdir, access, mkdir } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const root = join(dirname(fileURLToPath(import.meta.url)), "..");
export const dist = join(root, "..", "dist");
export const data = join(root, ".data");
export const keySetPath = join(data, "sealform-key.json");
export const DEMO_PASSPHRASE = "demo-passphrase-123";

const exists = (p) => access(p).then(() => true, () => false);

export async function prepareDemo() {
  if (!(await exists(join(dist, "sealform.js")))) throw new Error("先に npm run build を実行してください");
  await mkdir(join(data, "files"), { recursive: true });
  if (!(await exists(keySetPath))) {
    const cli = (...args) =>
      execFileSync(process.execPath, [join(dist, "cli.js"), ...args], {
        env: { ...process.env, SEALFORM_PASSPHRASE: process.env.SEALFORM_PASSPHRASE ?? DEMO_PASSPHRASE },
        stdio: ["ignore", "ignore", "inherit"],
      });
    const keysDir = join(data, "keys");
    cli("keygen", "--out", keysDir, "--label", "相談員A");
    cli("keygen", "--out", keysDir, "--label", "相談員B");
    const pubs = (await readdir(keysDir)).filter((f) => f.startsWith("sealform-key-")).map((f) => join(keysDir, f));
    cli("keys", "add", keySetPath, ...pubs);
  }
  const integrity = Object.values(JSON.parse(await readFile(join(dist, "hashes.json"), "utf8"))).at(-1);
  const set = JSON.parse(await readFile(keySetPath, "utf8"));
  const fingerprints = (set.keys ?? [set]).map((k) => k.fingerprint).join(" ");
  return { integrity, fingerprints };
}

/** 共通のフォーム HTML に、SRI の値と指紋を埋め込む。 */
export async function formHtml({ integrity, fingerprints }, title = "sealform デモ") {
  return (await readFile(join(root, "shared", "form.html"), "utf8"))
    .replace("__INTEGRITY__", integrity)
    .replace("__FINGERPRINT__", fingerprints)
    .replace("sealform デモ", title);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  // node examples/shared/demo.mjs で、他言語の例のために鍵だけ用意する
  const r = await prepareDemo();
  console.log(`鍵の束: ${keySetPath}\n指紋: ${r.fingerprints}\nintegrity: ${r.integrity}`);
}
