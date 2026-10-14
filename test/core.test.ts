import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import {
  findTokens, generateKeyPair, inspect, inspectFile, isSealed, isSealedFile, loadKeys, loadPublicKey,
  MAX_RECIPIENTS, open, openFile, safeFileName, seal, sealFile, SealformError, type KeyPair,
} from "../src/core.js";
import { b64url, fromB64url } from "../src/encoding.js";

const ctx = { form: "/contact", field: "body" };
const entry = (kp: KeyPair) => ({ kid: kp.publicDoc.kid, privateKey: kp.privateKey });

async function setup() {
  const kp = await generateKeyPair();
  const key = await loadPublicKey(kp.publicDoc);
  return { kp, key };
}

async function code(p: Promise<unknown>) {
  try {
    await p;
  } catch (e) {
    return (e as SealformError).code;
  }
  return "no-error";
}

describe("seal / open", () => {
  it("往復できる（日本語・絵文字・空文字・長文）", async () => {
    const { kp, key } = await setup();
    for (const text of ["こんにちは、相談です。", "🔐👀", "", "あ".repeat(20000)]) {
      const t = await seal(key, text, ctx);
      expect(t.startsWith("sf2.")).toBe(true);
      expect(isSealed(t)).toBe(true);
      const r = await open(entry(kp), t, ctx);
      expect(r.plaintext).toBe(text);
      expect(r).toMatchObject({ form: "/contact", field: "body", kind: "text", recipients: [kp.publicDoc.kid] });
    }
  });

  it("同じ平文でも毎回違う暗号文になる", async () => {
    const { key } = await setup();
    expect(await seal(key, "x", ctx)).not.toBe(await seal(key, "x", ctx));
  });

  it("長さを丸めるので、短い文の長さの差は暗号文に出ない", async () => {
    const { key } = await setup();
    expect((await seal(key, "a", ctx)).length).toBe((await seal(key, "a".repeat(50), ctx)).length);
  });

  it("本文を1ビットでも書き換えると復号に失敗する", async () => {
    const { kp, key } = await setup();
    const parts = (await seal(key, "秘密", ctx)).split(".");
    const body = fromB64url(parts[3]!);
    body[20]! ^= 1;
    parts[3] = b64url(body);
    expect(await code(open(entry(kp), parts.join("."), ctx))).toBe("decrypt-failed");
  });

  it("宛先フォームを書き換えると復号に失敗する（見出しも認証対象）", async () => {
    const { kp, key } = await setup();
    const parts = (await seal(key, "秘密", ctx)).split(".");
    parts[1] = b64url(new TextEncoder().encode(JSON.stringify({ v: 2, f: "/other", n: "body", t: 0, k: "text" })));
    expect(await code(open(entry(kp), parts.join("."), ctx))).toBe("decrypt-failed");
  });

  it("別フォーム・別項目宛ての暗号文は、期待値を渡すと拒否できる", async () => {
    const { kp, key } = await setup();
    const t = await seal(key, "秘密", { form: "/other", field: "body" });
    expect(await code(open(entry(kp), t, { form: "/contact" }))).toBe("wrong-form");
    const t2 = await seal(key, "秘密", { form: "/contact", field: "name" });
    expect(await code(open(entry(kp), t2, ctx))).toBe("wrong-field");
  });

  it("別の鍵では復号できない", async () => {
    const a = await setup();
    const b = await setup();
    const t = await seal(a.key, "秘密", ctx);
    expect(await code(open(entry(b.kp), t))).toBe("wrong-key");
    // kid を偽っても中身は開かない
    expect(await code(open({ kid: a.kp.publicDoc.kid, privateKey: b.kp.privateKey }, t))).toBe("decrypt-failed");
  });

  it("inspect は復号せずに宛先と時刻を読める", async () => {
    const { kp, key } = await setup();
    const now = new Date("2026-10-01T00:00:00Z");
    expect(inspect(await seal(key, "x", ctx, { now }))).toMatchObject({
      version: "sf2", kind: "text", form: "/contact", field: "body", sealedAt: now, recipients: [kp.publicDoc.kid],
    });
  });

  it("findTokens は CSV などから暗号文だけを拾う（sf1 と sf2 の両方）", async () => {
    const { key } = await setup();
    const fx = JSON.parse(readFileSync("test/fixtures/sf1.json", "utf8"));
    const t1 = await seal(key, "1", ctx);
    const t2 = await seal(key, "2", ctx);
    expect(findTokens(`id,body\n1,"${t1}"\n2,${t2}\n3,${fx.token}`)).toEqual([t1, t2, fx.token]);
  });

  it("isSealed は平文を弾く", () => {
    expect(isSealed("ふつうの文章")).toBe(false);
    expect(isSealed("sf2.abc")).toBe(false);
    expect(isSealed(undefined)).toBe(false);
  });
});

describe("v0.1 の暗号文（sf1）との互換", () => {
  it("v0.1.0 が出力した暗号文を今も復号できる", async () => {
    const fx = JSON.parse(readFileSync("test/fixtures/sf1.json", "utf8"));
    const r = await open({ kid: fx.publicDoc.kid, privateKey: fromB64url(fx.privateKey) }, fx.token, { form: "/contact" });
    expect(r.plaintext).toBe(fx.plaintext);
    expect(r.version).toBe("sf1");
  });
});

describe("複数の担当者", () => {
  it("束の全員がそれぞれ自分の鍵だけで復号できる", async () => {
    const people = await Promise.all([1, 2, 3].map(() => generateKeyPair()));
    const keys = await Promise.all(people.map((p) => loadPublicKey(p.publicDoc)));
    const t = await seal(keys, "3人に宛てた相談", ctx);
    expect(inspect(t).recipients).toEqual(people.map((p) => p.publicDoc.kid));
    for (const p of people) expect((await open(entry(p), t)).plaintext).toBe("3人に宛てた相談");
    // 宛先に入っていない人は開けない
    expect(await code(open(entry(await generateKeyPair()), t))).toBe("wrong-key");
  });

  it("宛先一覧から自分以外を消しても、本文の認証で検出される", async () => {
    const [a, b] = await Promise.all([generateKeyPair(), generateKeyPair()]);
    const t = await seal([await loadPublicKey(a.publicDoc), await loadPublicKey(b.publicDoc)], "x", ctx);
    const parts = t.split(".");
    parts[2] = b64url(fromB64url(parts[2]!).slice(0, 1176)); // a の分だけ残す
    expect(await code(open(entry(a), parts.join(".")))).toBe("decrypt-failed");
  });

  it(`宛先は ${MAX_RECIPIENTS} 個まで`, async () => {
    const { key } = await setup();
    expect(await code(seal(Array(MAX_RECIPIENTS + 1).fill(key), "x", ctx))).toBe("bad-key");
  });
});

describe("鍵の束と鍵の更新", () => {
  const set = (...kps: KeyPair[]) => ({ sealform: 1, type: "key-set", keys: kps.map((k) => k.publicDoc) });

  it("期限切れの鍵は暗号化に使わず、有効な鍵だけを使う", async () => {
    const old = await generateKeyPair({ validDays: 1, now: new Date("2020-01-01") });
    const cur = await generateKeyPair();
    const keys = await loadKeys(set(old, cur));
    expect(keys.map((k) => k.doc.kid)).toEqual([cur.publicDoc.kid]);
  });

  it("更新後も、古い秘密鍵を一緒に渡せば古い暗号文を開ける", async () => {
    const old = await generateKeyPair();
    const tOld = await seal(await loadKeys(set(old)), "更新前", ctx);
    const cur = await generateKeyPair();
    const tNew = await seal(await loadKeys(set(cur)), "更新後", ctx);
    const ring = [entry(cur), entry(old)];
    expect((await open(ring, tOld)).plaintext).toBe("更新前");
    expect((await open(ring, tNew)).plaintext).toBe("更新後");
    // 新しい鍵だけでは古い暗号文は開けない
    expect(await code(open(entry(cur), tOld))).toBe("wrong-key");
  });

  it("移行期間中は新旧の両方に宛てる", async () => {
    const [old, cur] = await Promise.all([generateKeyPair(), generateKeyPair()]);
    const t = await seal(await loadKeys(set(old, cur)), "移行中", ctx);
    expect((await open(entry(old), t)).plaintext).toBe("移行中");
    expect((await open(entry(cur), t)).plaintext).toBe("移行中");
  });

  it("読み込んだあとに期限が切れた鍵には暗号化しない（復号はできる）", async () => {
    const kp = await generateKeyPair({ validDays: 1 });
    const key = await loadPublicKey(kp.publicDoc);
    const later = new Date(Date.now() + 2 * 86400_000);
    expect(await code(seal(key, "x", ctx, { now: later }))).toBe("key-expired");
    expect(await code(sealFile(key, new Uint8Array(1), { name: "a", type: "" }, ctx, { now: later }))).toBe("key-expired");
    const t = await seal(key, "期限内に暗号化", ctx);
    expect((await open(entry(kp), t)).plaintext).toBe("期限内に暗号化");
  });

  it("有効な鍵が1つも無ければエラー", async () => {
    const old = await generateKeyPair({ validDays: 1, now: new Date("2020-01-01") });
    expect(await code(loadKeys(set(old)))).toBe("key-expired");
  });

  it("登録した指紋に無い鍵が束に足されていたら拒否する（写しを横取りする攻撃）", async () => {
    const [a, b, evil] = await Promise.all([generateKeyPair(), generateKeyPair(), generateKeyPair()]);
    const pins = [a.publicDoc.fingerprint, b.publicDoc.fingerprint];
    await expect(loadKeys(set(a, b), { pins })).resolves.toHaveLength(2);
    expect(await code(loadKeys(set(a, b, evil), { pins }))).toBe("fingerprint-mismatch");
  });

  it("同じ鍵の重複・壊れた鍵を含む束を拒否する", async () => {
    const a = await generateKeyPair();
    expect(await code(loadKeys(set(a, a)))).toBe("bad-key");
    expect(await code(loadKeys({ ...set(a), keys: [{ ...a.publicDoc, publicKey: "AAAA" }] }))).toBe("bad-key");
    expect(await code(loadKeys({ sealform: 1, type: "key-set", keys: [] }))).toBe("bad-key");
  });

  it("1つの公開鍵だけの JSON（v0.1 の形式）も読める", async () => {
    const a = await generateKeyPair();
    await expect(loadKeys(a.publicDoc)).resolves.toHaveLength(1);
  });
});

describe("添付ファイル", () => {
  const bytes = (n: number) => Uint8Array.from({ length: n }, (_, i) => (i * 31) & 0xff);

  it("往復でき、元のファイル名と種類は暗号文の中に隠れる", async () => {
    const { kp, key } = await setup();
    const data = bytes(100_000);
    const sealed = await sealFile(key, data, { name: "診断書_山田.pdf", type: "application/pdf" }, { form: "/contact", field: "doc" });
    expect(isSealedFile(sealed)).toBe(true);
    expect(Buffer.from(sealed).includes(Buffer.from("診断書"))).toBe(false);
    expect(Buffer.from(sealed).includes(Buffer.from("application/pdf"))).toBe(false);
    expect(inspectFile(sealed)).toMatchObject({ kind: "file", form: "/contact", field: "doc" });
    const r = await openFile(entry(kp), sealed, { form: "/contact", field: "doc" });
    expect(r.name).toBe("診断書_山田.pdf");
    expect(r.type).toBe("application/pdf");
    expect(Buffer.from(r.data).equals(Buffer.from(data))).toBe(true);
  });

  it("大きさは 4KB 単位に丸められる", async () => {
    const { key } = await setup();
    const a = await sealFile(key, bytes(10), { name: "a", type: "" }, ctx);
    const b = await sealFile(key, bytes(3000), { name: "b", type: "" }, ctx);
    expect(a.length).toBe(b.length);
  });

  it("書き換えると復号に失敗する", async () => {
    const { kp, key } = await setup();
    const sealed = await sealFile(key, bytes(5000), { name: "a.bin", type: "" }, ctx);
    sealed[sealed.length - 100]! ^= 1;
    expect(await code(openFile(entry(kp), sealed))).toBe("decrypt-failed");
  });

  it("上限を超えるファイルは暗号化しない", async () => {
    const { key } = await setup();
    expect(await code(sealFile(key, bytes(2000), { name: "a", type: "" }, ctx, { maxBytes: 1000 }))).toBe("too-large");
  });

  it("複数の担当者に宛てられる", async () => {
    const [a, b] = await Promise.all([generateKeyPair(), generateKeyPair()]);
    const sealed = await sealFile([await loadPublicKey(a.publicDoc), await loadPublicKey(b.publicDoc)], bytes(10), { name: "x", type: "" }, ctx);
    expect((await openFile(entry(b), sealed)).data.length).toBe(10);
  });

  it("文字列の暗号文とファイルは取り違えられない", async () => {
    const { kp, key } = await setup();
    const sealed = await sealFile(key, bytes(10), { name: "x", type: "" }, ctx);
    expect(isSealed(new TextDecoder().decode(sealed))).toBe(false);
    expect(isSealedFile(new TextEncoder().encode(await seal(key, "x", ctx)))).toBe(false);
    expect(await code(openFile(entry(kp), new Uint8Array(10)))).toBe("bad-token");
  });

  it("safeFileName はパスや制御文字を取り除く", () => {
    expect(safeFileName("../../etc/passwd")).toBe("passwd");
    expect(safeFileName("C:\\Users\\a\\報告.docx")).toBe("報告.docx");
    expect(safeFileName("..hidden")).toBe("hidden");
    expect(safeFileName("a\u0000b?.txt")).toBe("a_b_.txt");
    expect(safeFileName("")).toBe("file");
  });
});

describe("loadPublicKey", () => {
  it("期限切れの鍵を拒否する", async () => {
    const kp = await generateKeyPair({ validDays: 1, now: new Date("2020-01-01") });
    expect(await code(loadPublicKey(kp.publicDoc))).toBe("key-expired");
  });

  it("指紋の固定値と違う鍵を拒否する", async () => {
    const a = await generateKeyPair();
    const b = await generateKeyPair();
    expect(await code(loadPublicKey(b.publicDoc, { pin: a.publicDoc.fingerprint }))).toBe("fingerprint-mismatch");
    await expect(loadPublicKey(a.publicDoc, { pin: a.publicDoc.fingerprint })).resolves.toBeTruthy();
  });

  it("kid や指紋を書き換えた JSON を拒否する（鍵本体から計算し直す）", async () => {
    const a = await generateKeyPair();
    const b = await generateKeyPair();
    const forged = { ...b.publicDoc, kid: a.publicDoc.kid, fingerprint: a.publicDoc.fingerprint };
    expect(await code(loadPublicKey(forged, { pin: a.publicDoc.fingerprint }))).toBe("bad-key");
  });

  it("壊れた鍵・別方式の鍵を拒否する", async () => {
    const a = await generateKeyPair();
    expect(await code(loadPublicKey({ ...a.publicDoc, publicKey: "AAAA" }))).toBe("bad-key");
    expect(await code(loadPublicKey({ ...a.publicDoc, alg: "RSA" }))).toBe("bad-key");
    expect(await code(loadPublicKey(null))).toBe("bad-key");
  });
});
