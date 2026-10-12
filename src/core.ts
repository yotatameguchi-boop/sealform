import { Aes256Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { XWing } from "@hpke/hybridkem-x-wing";
import { b64url, fromB64url, fromUtf8, sha256, toHex, utf8 } from "./encoding.js";

/** 暗号文の形式の版。形式を変えたら上げる（docs/FORMAT.md 参照）。 */
export const FORMAT_VERSION = "sf1";
export const ALGORITHM = "HPKE-Base/X-Wing/HKDF-SHA256/AES-256-GCM";

const INFO = utf8("sealform/v1");
const DEFAULT_PAD = 64;
const TOKEN_RE = /^sf1\.([0-9a-f]{16})\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/;

export class SealformError extends Error {
  constructor(
    readonly code:
      | "bad-key"
      | "key-expired"
      | "fingerprint-mismatch"
      | "bad-token"
      | "wrong-key"
      | "decrypt-failed"
      | "wrong-form"
      | "wrong-field",
    message: string,
  ) {
    super(message);
    this.name = "SealformError";
  }
}

let suiteCache: CipherSuite | undefined;
function suite(): CipherSuite {
  suiteCache ??= new CipherSuite({ kem: new XWing(), kdf: new HkdfSha256(), aead: new Aes256Gcm() });
  return suiteCache;
}

/** サイトに置いて配布する公開鍵（/.well-known/sealform-key.json）。 */
export interface PublicKeyDoc {
  sealform: 1;
  kid: string;
  alg: string;
  publicKey: string;
  fingerprint: string;
  created: string;
  expires: string;
}

export interface KeyPair {
  publicDoc: PublicKeyDoc;
  /** X-Wing の秘密鍵（32バイトの種）。そのまま保存せず keyfile.ts で保護する。 */
  privateKey: Uint8Array;
}

/** 公開鍵の指紋。SSH と同じ "SHA256:<base64>" の表記。 */
export async function fingerprintOf(publicKey: Uint8Array): Promise<string> {
  return "SHA256:" + btoa(String.fromCharCode(...(await sha256(publicKey)))).replace(/=+$/, "");
}

export async function kidOf(publicKey: Uint8Array): Promise<string> {
  return toHex(await sha256(publicKey)).slice(0, 16);
}

export async function generateKeyPair(opts: { validDays?: number; now?: Date } = {}): Promise<KeyPair> {
  const kp = await suite().kem.generateKeyPair();
  const pub = new Uint8Array(await suite().kem.serializePublicKey(kp.publicKey));
  const priv = new Uint8Array(await suite().kem.serializePrivateKey(kp.privateKey));
  const now = opts.now ?? new Date();
  const expires = new Date(now.getTime() + (opts.validDays ?? 365) * 86400_000);
  return {
    publicDoc: {
      sealform: 1,
      kid: await kidOf(pub),
      alg: ALGORITHM,
      publicKey: b64url(pub),
      fingerprint: await fingerprintOf(pub),
      created: now.toISOString(),
      expires: expires.toISOString(),
    },
    privateKey: priv,
  };
}

export interface LoadedPublicKey {
  doc: PublicKeyDoc;
  raw: Uint8Array;
}

/**
 * 公開鍵 JSON を検証して読み込む。kid と指紋は鍵本体から計算し直して照合するので、
 * JSON 内の値が書き換えられていても気づける。pin を渡すと指紋が一致しない鍵を拒否する。
 */
export async function loadPublicKey(
  input: unknown,
  opts: { pin?: string; now?: Date } = {},
): Promise<LoadedPublicKey> {
  const doc = input as PublicKeyDoc;
  if (!doc || typeof doc !== "object" || doc.sealform !== 1 || typeof doc.publicKey !== "string") {
    throw new SealformError("bad-key", "sealform の公開鍵ではありません");
  }
  if (doc.alg !== ALGORITHM) {
    throw new SealformError("bad-key", `対応していない方式です: ${doc.alg}`);
  }
  let raw: Uint8Array;
  try {
    raw = fromB64url(doc.publicKey);
    await suite().kem.deserializePublicKey(raw.slice().buffer);
  } catch {
    throw new SealformError("bad-key", "公開鍵の中身が壊れています");
  }
  const fp = await fingerprintOf(raw);
  if (doc.kid !== (await kidOf(raw)) || doc.fingerprint !== fp) {
    throw new SealformError("bad-key", "公開鍵の kid または指紋が鍵本体と一致しません");
  }
  if (opts.pin && opts.pin !== fp) {
    throw new SealformError("fingerprint-mismatch", `公開鍵の指紋が固定値と一致しません（受信: ${fp}）`);
  }
  const expires = Date.parse(doc.expires);
  if (!Number.isFinite(expires) || expires <= (opts.now ?? new Date()).getTime()) {
    throw new SealformError("key-expired", `公開鍵の有効期限が切れています（${doc.expires}）`);
  }
  return { doc, raw };
}

/** 暗号文に結びつける文脈。復号時に取り出せ、改ざんすると復号に失敗する。 */
export interface SealContext {
  /** 送信先フォームの識別子（既定はフォームの action のパス）。 */
  form: string;
  /** 項目名。 */
  field: string;
}

interface Meta {
  v: 1;
  f: string;
  n: string;
  t: number;
}

function pad(data: Uint8Array, bucket: number): Uint8Array {
  const len = new Uint8Array(4);
  new DataView(len.buffer).setUint32(0, data.length);
  const total = Math.ceil((data.length + 4) / bucket) * bucket;
  const out = new Uint8Array(total);
  out.set(len, 0);
  out.set(data, 4);
  return out;
}

function unpad(data: Uint8Array): Uint8Array {
  if (data.length < 4) throw new Error("short");
  const n = new DataView(data.buffer, data.byteOffset).getUint32(0);
  if (n > data.length - 4) throw new Error("bad length");
  return data.subarray(4, 4 + n);
}

/**
 * 文字列を暗号化して1つのトークン文字列にする。
 * 形式: sf1.<kid>.<meta>.<enc>.<ct>
 *   meta = base64url(JSON {v,f,n,t})、AAD = "sf1.<kid>.<meta>"
 */
export async function seal(
  key: LoadedPublicKey,
  plaintext: string,
  ctx: SealContext,
  opts: { pad?: number; now?: Date } = {},
): Promise<string> {
  const meta: Meta = { v: 1, f: ctx.form, n: ctx.field, t: Math.floor((opts.now ?? new Date()).getTime() / 1000) };
  const head = `${FORMAT_VERSION}.${key.doc.kid}.${b64url(utf8(JSON.stringify(meta)))}`;
  const s = suite();
  const pk = await s.kem.deserializePublicKey(key.raw.slice().buffer);
  const { ct, enc } = await s.seal(
    { recipientPublicKey: pk, info: INFO },
    pad(utf8(plaintext), opts.pad ?? DEFAULT_PAD),
    utf8(head),
  );
  return `${head}.${b64url(new Uint8Array(enc))}.${b64url(new Uint8Array(ct))}`;
}

export interface ParsedToken {
  kid: string;
  form: string;
  field: string;
  sealedAt: Date;
}

/** サーバー側で「暗号文の形をしているか」を確かめる。復号はしない。 */
export function isSealed(value: unknown): value is string {
  return typeof value === "string" && TOKEN_RE.test(value);
}

/** トークンの外側（kid・宛先・時刻）を読む。改ざんの有無は open() でしか分からない。 */
export function inspect(token: string): ParsedToken {
  const m = TOKEN_RE.exec(token.trim());
  if (!m) throw new SealformError("bad-token", "sealform の暗号文ではありません");
  let meta: Meta;
  try {
    meta = JSON.parse(fromUtf8(fromB64url(m[2]!)));
  } catch {
    throw new SealformError("bad-token", "暗号文の見出し部分が壊れています");
  }
  if (meta.v !== 1 || typeof meta.f !== "string" || typeof meta.n !== "string" || typeof meta.t !== "number") {
    throw new SealformError("bad-token", "暗号文の見出し部分が壊れています");
  }
  return { kid: m[1]!, form: meta.f, field: meta.n, sealedAt: new Date(meta.t * 1000) };
}

export interface Opened extends ParsedToken {
  plaintext: string;
}

/**
 * 復号する。expect を渡すと、宛先フォームや項目名が違う暗号文（差し替え・使い回し）を拒否する。
 */
export async function open(
  privateKey: Uint8Array,
  publicKid: string,
  token: string,
  expect: Partial<SealContext> = {},
): Promise<Opened> {
  const info = inspect(token);
  if (info.kid !== publicKid) {
    throw new SealformError("wrong-key", `別の鍵（kid: ${info.kid}）で暗号化されています`);
  }
  const [v, kid, meta, enc, ct] = token.trim().split(".");
  const s = suite();
  let pt: Uint8Array;
  try {
    const sk = await s.kem.deserializePrivateKey(privateKey.slice().buffer);
    const out = await s.open(
      { recipientKey: sk, enc: fromB64url(enc!).slice().buffer, info: INFO },
      fromB64url(ct!),
      utf8(`${v}.${kid}.${meta}`),
    );
    pt = unpad(new Uint8Array(out));
  } catch {
    throw new SealformError("decrypt-failed", "復号できません。暗号文が改ざんされているか、壊れています");
  }
  if (expect.form !== undefined && expect.form !== info.form) {
    throw new SealformError("wrong-form", `別のフォーム宛ての暗号文です（宛先: ${info.form}）`);
  }
  if (expect.field !== undefined && expect.field !== info.field) {
    throw new SealformError("wrong-field", `別の項目の暗号文です（項目: ${info.field}）`);
  }
  return { ...info, plaintext: fromUtf8(pt) };
}

/** 文章中から sealform の暗号文をすべて拾う（CSV やログの貼り付け用）。 */
export function findTokens(text: string): string[] {
  return text.match(/sf1\.[0-9a-f]{16}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g) ?? [];
}

