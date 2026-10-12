import { readFile, writeFile, access, mkdir } from "node:fs/promises";
import { createHash } from "node:crypto";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import {
  findTokens,
  generateKeyPair,
  inspectFile,
  isSealedFile,
  loadKeys,
  loadPublicKey,
  open,
  openFile,
  safeFileName,
  SealformError,
  type KeySetDoc,
  type PrivateKeyEntry,
  type PublicKeyDoc,
} from "./core.js";
import { MIN_PASSPHRASE_LENGTH, protectPrivateKey, unlockPrivateKey } from "./keyfile.js";
import { checkSite, worstLevel } from "./check.js";

const HERE = dirname(fileURLToPath(import.meta.url));

const HELP = `sealform ${__SEALFORM_VERSION__} — Web フォームをブラウザ内で暗号化する

使い方:
  sealform keygen [--out <dir>] [--days <n>] [--label <名前>]
      鍵ペアを作る。sealform-key-<kid>.json（公開鍵）と
      sealform-private-key-<kid>.json（秘密鍵・パスフレーズで保護）を出力する

  sealform keys add <鍵の束.json> <公開鍵.json>...
  sealform keys remove <鍵の束.json> <kid>
  sealform keys list <鍵の束.json>
      サイトに置く鍵の束（/.well-known/sealform-key.json）を編集する。
      複数の担当者の鍵を並べると、誰の鍵でも復号できる。
      鍵の更新は「新しい鍵を add → 古い鍵を remove」。古い秘密鍵は手元に残せば古い暗号文も開ける

  sealform open --key <秘密鍵> [--key <秘密鍵>...] [--form <id>] [--field <name>] [--out <dir>] [--json] [<file>...]
      復号する。テキスト（CSV・ログ等）や標準入力からは sf1./sf2. で始まる暗号文を拾う。
      暗号化された添付ファイル（.sf）を渡すと、--out のフォルダに元の名前で書き出す

  sealform check <url> [--fingerprint <SHA256:...>...] [--script-hash <sha384-...>] [--json]
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

async function passphrase(question: string, confirm: boolean): Promise<string> {
  const env = process.env.SEALFORM_PASSPHRASE;
  if (env) return env;
  const p = await promptHidden(question);
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
  const { values } = parseArgs({
    args,
    options: { out: { type: "string", default: "." }, days: { type: "string", default: "365" }, label: { type: "string" } },
  });
  const dir = resolve(values.out!);
  const days = Number(values.days);
  if (!Number.isInteger(days) || days < 1 || days > 3650) throw new Error("--days は 1〜3650 の整数で指定してください");
  process.stderr.write(`秘密鍵を守るパスフレーズを決めてください（${MIN_PASSPHRASE_LENGTH} 文字以上）\n`);
  const pass = await passphrase("パスフレーズ: ", true);
  const kp = await generateKeyPair({ validDays: days, label: values.label });
  const pubPath = join(dir, `sealform-key-${kp.publicDoc.kid}.json`);
  const privPath = join(dir, `sealform-private-key-${kp.publicDoc.kid}.json`);
  const file = await protectPrivateKey(kp.privateKey, kp.publicDoc.publicKey, pass);
  kp.privateKey.fill(0);
  await mkdir(dir, { recursive: true });
  await writeFile(privPath, JSON.stringify(file, null, 2) + "\n", { mode: 0o600, flag: "wx" });
  await writeFile(pubPath, JSON.stringify(kp.publicDoc, null, 2) + "\n", { flag: "wx" });
  console.log(`公開鍵: ${pubPath}
  → sealform keys add <鍵の束.json> ${basename(pubPath)} で、サイトに置く鍵の束に加えてください
秘密鍵: ${privPath}
  → サーバーには置かないでください。復号する担当者の手元だけで保管します
指紋:   ${kp.publicDoc.fingerprint}
有効期限: ${kp.publicDoc.expires}`);
}

async function readKeySet(path: string): Promise<KeySetDoc> {
  if (!(await exists(path))) return { sealform: 1, type: "key-set", keys: [] };
  const doc = JSON.parse(await readFile(path, "utf8"));
  if (doc?.type === "key-set") return doc as KeySetDoc;
  // 1つの公開鍵だけのファイル（v0.1 の形式）は束に変換する
  await loadPublicKey(doc).catch((e) => {
    if (!(e instanceof SealformError && e.code === "key-expired")) throw e;
  });
  return { sealform: 1, type: "key-set", keys: [doc as PublicKeyDoc] };
}

function describeSet(set: KeySetDoc) {
  const now = Date.now();
  for (const k of set.keys) {
    const expired = Date.parse(k.expires) <= now;
    console.log(`${expired ? "✗ 期限切れ" : "✓ 有効   "}  ${k.kid}  ${k.fingerprint}  〜${k.expires.slice(0, 10)}${k.label ? `  ${k.label}` : ""}`);
  }
  const active = set.keys.filter((k) => Date.parse(k.expires) > now);
  if (active.length > 0) {
    console.log(`\nHTML の data-sealform-fingerprint と sealform check に使う指紋:\n  ${active.map((k) => k.fingerprint).join(" ")}`);
  }
}

async function cmdKeys(args: string[]) {
  const [sub, setPath, ...rest] = args;
  if (!sub || !setPath) throw new Error("使い方: sealform keys add|remove|list <鍵の束.json> ...");
  const set = await readKeySet(setPath);
  if (sub === "list") {
    if (set.keys.length === 0) throw new Error(`${setPath} に鍵がありません`);
    return describeSet(set);
  }
  const notes: string[] = [];
  if (sub === "add") {
    if (rest.length === 0) throw new Error("加える公開鍵ファイルを指定してください");
    for (const p of rest) {
      const k = await loadPublicKey(JSON.parse(await readFile(p, "utf8")));
      if (set.keys.some((x) => x.kid === k.doc.kid)) {
        console.error(`! ${k.doc.kid} は既に入っています`);
        continue;
      }
      set.keys.push(k.doc);
      notes.push(`+ ${k.doc.kid}${k.doc.label ? `（${k.doc.label}）` : ""} を加えました`);
    }
  } else if (sub === "remove") {
    const kid = rest[0];
    const before = set.keys.length;
    set.keys = set.keys.filter((k) => k.kid !== kid);
    if (set.keys.length === before) throw new Error(`${kid} は鍵の束にありません`);
    if (set.keys.length === 0) throw new Error("最後の鍵は外せません。先に新しい鍵を add してください");
    notes.push(`- ${kid} を外しました。古い暗号文を開くために、この鍵の秘密鍵は手元に残してください`);
  } else {
    throw new Error(`不明なサブコマンドです: ${sub}`);
  }
  await loadKeys(set); // 有効な鍵が残っているか、上限を超えていないかを確かめてから保存する
  await writeFile(setPath, JSON.stringify(set, null, 2) + "\n");
  notes.forEach((n) => console.error(n));
  describeSet(set);
}

async function unlockAll(paths: string[]): Promise<PrivateKeyEntry[]> {
  const ring: PrivateKeyEntry[] = [];
  for (const p of paths) {
    const file = JSON.parse(await readFile(p, "utf8"));
    ring.push(await unlockPrivateKey(file, await passphrase(`パスフレーズ（${basename(p)}）: `, false)));
  }
  return ring;
}

async function cmdOpen(args: string[]) {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: {
      key: { type: "string", multiple: true },
      form: { type: "string" },
      field: { type: "string" },
      out: { type: "string" },
      json: { type: "boolean" },
    },
  });
  if (!values.key?.length) throw new Error("--key に秘密鍵ファイルを指定してください（複数指定できます）");
  const expect = { form: values.form, field: values.field };

  // 入力を、暗号化された添付ファイルとテキストに振り分ける
  const sealedFiles: [string, Uint8Array][] = [];
  let text = "";
  if (positionals.length === 0) text = await readStdin();
  for (const p of positionals) {
    const buf = new Uint8Array(await readFile(p));
    if (isSealedFile(buf)) sealedFiles.push([p, buf]);
    else text += new TextDecoder().decode(buf) + "\n";
  }
  const tokens = findTokens(text);
  if (tokens.length === 0 && sealedFiles.length === 0) throw new Error("暗号文（sf1./sf2.〜）も、暗号化されたファイルも見つかりません");
  if (sealedFiles.length > 0 && !values.out) throw new Error("暗号化されたファイルを復号するには --out <フォルダ> を指定してください");

  const ring = await unlockAll(values.key);
  let failed = 0;
  const report = (ok: boolean, obj: Record<string, unknown>, human: string) => {
    if (!ok) failed++;
    if (values.json) console.log(JSON.stringify({ ok, ...obj }));
    else if (ok) console.log(human);
    else console.error(human);
  };

  for (const t of tokens) {
    try {
      const r = await open(ring, t, expect);
      report(true, { form: r.form, field: r.field, sealedAt: r.sealedAt.toISOString(), value: r.plaintext },
        `[${r.sealedAt.toISOString()}] ${r.form} / ${r.field}\n${r.plaintext}\n`);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      report(false, { error: msg, token: t.slice(0, 40) + "…" }, `✗ ${msg}（${t.slice(0, 40)}…）\n`);
    }
  }
  if (sealedFiles.length > 0) await mkdir(resolve(values.out!), { recursive: true });
  for (const [path, buf] of sealedFiles) {
    try {
      const r = await openFile(ring, buf, expect);
      // 同じ名前があれば上書きせず、番号を付ける
      const name = safeFileName(r.name);
      let dest = join(resolve(values.out!), name);
      for (let i = 1; await exists(dest); i++) dest = join(resolve(values.out!), name.replace(/(\.[^.]*)?$/, `-${i}$1`));
      await writeFile(dest, r.data, { flag: "wx", mode: 0o600 });
      report(true, { form: r.form, field: r.field, sealedAt: r.sealedAt.toISOString(), file: dest, type: r.type, bytes: r.data.length },
        `[${r.sealedAt.toISOString()}] ${r.form} / ${r.field}\n${basename(path)} → ${dest}（${r.type || "種類不明"}, ${r.data.length} バイト）\n`);
      r.data.fill(0);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      const info = (() => { try { return inspectFile(buf); } catch { return undefined; } })();
      report(false, { error: msg, file: path, recipients: info?.recipients }, `✗ ${basename(path)}: ${msg}\n`);
    }
  }
  ring.forEach((k) => k.privateKey.fill(0));
  const total = tokens.length + sealedFiles.length;
  process.stderr.write(`${total - failed}/${total} 件を復号しました\n`);
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
      fingerprint: { type: "string", multiple: true },
      "script-hash": { type: "string", multiple: true },
      json: { type: "boolean" },
    },
  });
  const url = positionals[0];
  if (!url) throw new Error("点検するページの URL を指定してください");
  const findings = await checkSite(url, {
    fingerprints: (values.fingerprint ?? []).flatMap((f) => f.split(/[\s,]+/)).filter(Boolean),
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
    case "keys": return cmdKeys(rest);
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
  console.error(`エラー: ${e instanceof Error ? e.message : String(e)}`);
  process.exitCode = 1;
});
