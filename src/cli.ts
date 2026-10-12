import { readFile, writeFile, access } from "node:fs/promises";
import { createHash } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { findTokens, generateKeyPair, loadPublicKey, open, SealformError } from "./core.js";
import { MIN_PASSPHRASE_LENGTH, protectPrivateKey, unlockPrivateKey } from "./keyfile.js";
import { checkSite, worstLevel } from "./check.js";

const HERE = dirname(fileURLToPath(import.meta.url));

const HELP = `sealform ${__SEALFORM_VERSION__} — Web フォームをブラウザ内で暗号化する

使い方:
  sealform keygen [--out <dir>] [--days <n>]
      鍵ペアを作る。sealform-key.json（公開鍵・サイトに置く）と
      sealform-private-key.json（秘密鍵・パスフレーズで保護）を出力する

  sealform open --key <秘密鍵> [--form <id>] [--field <name>] [--json] [<file>...]
      暗号文を復号する。ファイル（CSV・ログ等）や標準入力から sf1. で始まる暗号文を拾う

  sealform check <url> [--fingerprint <SHA256:...>] [--script-hash <sha384-...>] [--json]
      公開中のページを外から点検する（JS・公開鍵の差し替え、送信ボタンの保護など）
      問題があれば終了コード 1。定期実行して改ざんを検知する用途を想定

  sealform sri
      同梱の sealform.js の integrity 値を表示する

パスフレーズは環境変数 SEALFORM_PASSPHRASE でも渡せる（自動化用）。`;

async function promptHidden(question: string): Promise<string> {
  const { stdin, stderr } = process;
  if (!stdin.isTTY) throw new Error("パスフレーズを入力できません。SEALFORM_PASSPHRASE を設定してください");
  stderr.write(question);
  stdin.setRawMode(true);
  stdin.resume();
  stdin.setEncoding("utf8");
  return new Promise((done, fail) => {
    let buf = "";
    const onData = (ch: string) => {
      for (const c of ch) {
        if (c === "\r" || c === "\n") {
          cleanup();
          stderr.write("\n");
          return done(buf);
        }
        if (c === "\u0003") {
          cleanup();
          stderr.write("\n");
          return fail(new Error("中断しました"));
        }
        if (c === "\u007f" || c === "\b") buf = [...buf].slice(0, -1).join("");
        else buf += c;
      }
    };
    const cleanup = () => {
      stdin.off("data", onData);
      stdin.setRawMode(false);
      stdin.pause();
    };
    stdin.on("data", onData);
  });
}

async function passphrase(confirm: boolean): Promise<string> {
  const env = process.env.SEALFORM_PASSPHRASE;
  if (env) return env;
  const p = await promptHidden("パスフレーズ: ");
  if (confirm && (await promptHidden("もう一度: ")) !== p) throw new Error("パスフレーズが一致しません");
  return p;
}

async function exists(p: string) {
  return access(p).then(() => true, () => false);
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

async function cmdKeygen(args: string[]) {
  const { values } = parseArgs({ args, options: { out: { type: "string", default: "." }, days: { type: "string", default: "365" } } });
  const dir = resolve(values.out!);
  const pubPath = join(dir, "sealform-key.json");
  const privPath = join(dir, "sealform-private-key.json");
  for (const p of [pubPath, privPath]) {
    if (await exists(p)) throw new Error(`${p} は既にあります。上書きはしません`);
  }
  const days = Number(values.days);
  if (!Number.isInteger(days) || days < 1 || days > 3650) throw new Error("--days は 1〜3650 の整数で指定してください");
  process.stderr.write(`秘密鍵を守るパスフレーズを決めてください（${MIN_PASSPHRASE_LENGTH} 文字以上）\n`);
  const pass = await passphrase(true);
  const kp = await generateKeyPair({ validDays: days });
  const file = await protectPrivateKey(kp.privateKey, kp.publicDoc.publicKey, pass);
  kp.privateKey.fill(0);
  await writeFile(privPath, JSON.stringify(file, null, 2) + "\n", { mode: 0o600, flag: "wx" });
  await writeFile(pubPath, JSON.stringify(kp.publicDoc, null, 2) + "\n", { flag: "wx" });
  console.log(`公開鍵: ${pubPath}
  → サイトの /.well-known/sealform-key.json に置いてください
秘密鍵: ${privPath}
  → サーバーには置かないでください。復号する担当者の手元だけで保管します
指紋:   ${kp.publicDoc.fingerprint}
  → フォームの data-sealform-fingerprint と、sealform check --fingerprint に使います
有効期限: ${kp.publicDoc.expires}`);
}

async function cmdOpen(args: string[]) {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: { key: { type: "string" }, form: { type: "string" }, field: { type: "string" }, json: { type: "boolean" } },
  });
  if (!values.key) throw new Error("--key に秘密鍵ファイルを指定してください");
  const text = positionals.length ? (await Promise.all(positionals.map((p) => readFile(p, "utf8")))).join("\n") : await readStdin();
  const tokens = findTokens(text);
  if (tokens.length === 0) throw new Error("暗号文（sf1.〜）が見つかりません");
  const { kid, privateKey } = await unlockPrivateKey(JSON.parse(await readFile(values.key, "utf8")), await passphrase(false));
  let failed = 0;
  for (const t of tokens) {
    try {
      const r = await open(privateKey, kid, t, { form: values.form, field: values.field });
      if (values.json) {
        console.log(JSON.stringify({ ok: true, form: r.form, field: r.field, sealedAt: r.sealedAt.toISOString(), value: r.plaintext }));
      } else {
        console.log(`[${r.sealedAt.toISOString()}] ${r.form} / ${r.field}\n${r.plaintext}\n`);
      }
    } catch (e) {
      failed++;
      const msg = e instanceof Error ? e.message : String(e);
      if (values.json) console.log(JSON.stringify({ ok: false, error: msg, token: t.slice(0, 40) + "…" }));
      else console.error(`✗ ${msg}（${t.slice(0, 40)}…）\n`);
    }
  }
  privateKey.fill(0);
  process.stderr.write(`${tokens.length - failed}/${tokens.length} 件を復号しました\n`);
  if (failed) process.exitCode = 1;
}

async function bundledScriptHashes(): Promise<string[]> {
  try {
    const h = JSON.parse(await readFile(join(HERE, "hashes.json"), "utf8")) as Record<string, string>;
    return Object.values(h);
  } catch {
    return [];
  }
}

async function cmdCheck(args: string[]) {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: {
      fingerprint: { type: "string" },
      "script-hash": { type: "string", multiple: true },
      json: { type: "boolean" },
    },
  });
  const url = positionals[0];
  if (!url) throw new Error("点検するページの URL を指定してください");
  const findings = await checkSite(url, {
    fingerprint: values.fingerprint,
    knownScriptHashes: [...(await bundledScriptHashes()), ...(values["script-hash"] ?? [])],
  });
  const worst = worstLevel(findings);
  if (values.json) console.log(JSON.stringify({ url, result: worst, findings }, null, 2));
  else {
    const mark = { pass: "✓", warn: "!", fail: "✗" } as const;
    for (const f of findings) console.log(`${mark[f.level]} ${f.message}`);
    console.log(`\n結果: ${{ pass: "問題なし", warn: "警告あり", fail: "要対応" }[worst]}`);
  }
  if (worst === "fail") process.exitCode = 1;
}

async function cmdSri() {
  const js = await readFile(join(HERE, "sealform.js"));
  console.log("sha384-" + createHash("sha384").update(js).digest("base64"));
}

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  switch (cmd) {
    case "keygen": return cmdKeygen(rest);
    case "open": return cmdOpen(rest);
    case "check": return cmdCheck(rest);
    case "sri": return cmdSri();
    case "fingerprint": {
      const k = await loadPublicKey(JSON.parse(await readFile(rest[0]!, "utf8")));
      return console.log(k.doc.fingerprint);
    }
    case "--version": case "-v": return console.log(__SEALFORM_VERSION__);
    default:
      console.log(HELP);
      if (cmd && cmd !== "help" && cmd !== "--help" && cmd !== "-h") process.exitCode = 2;
  }
}

main().catch((e) => {
  console.error(`エラー: ${e instanceof SealformError || e instanceof Error ? e.message : String(e)}`);
  process.exitCode = 1;
});

