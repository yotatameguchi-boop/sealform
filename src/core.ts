import { Aes256Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { XWing } from "@hpke/hybridkem-x-wing";
import { b64url, concat, fromB64url, fromUtf8, sha256, toHex, utf8 } from "./encoding.js";

/** 暗号文の形式の版。形式を変えたら上げる（docs/FORMAT.md 参照）。sf1 は復号のみ対応。 */
export const FORMAT_VERSION = "sf2";
export const ALGORITHM = "HPKE-Base/X-Wing/HKDF-SHA256/AES-256-GCM";
/** 1つの暗号文に含められる宛先（担当者の鍵）の上限。 */
export const MAX_RECIPIENTS = 10;
/** 添付ファイルの上限（暗号化前）。 */
export const MAX_FILE_BYTES = 50 * 1024 * 1024;

const INFO_V1 = utf8("sealform/v1");
const INFO_V2 = utf8("sealform/v2");
const TEXT_PAD = 64;
const FILE_PAD = 4096;
const FILE_MAGIC = utf8("sf2f");
const KID_BYTES = 8;
const ENC_BYTES = 1120;
const WRAPPED_BYTES = 32 + 16;
const RECIPIENT_BYTES = KID_BYTES + ENC_BYTES + WRAPPED_BYTES;
const SF1_RE = /^sf1\.([0-9a-f]{16})\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/;
const SF2_RE = /^sf2\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/;
const SF2_HEAD_RE = /^sf2\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/;

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
      | "wrong-field"
      | "wrong-kind"
      | "too-large",
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

// ---------------------------------------------------------------- 鍵

/** 1人の担当者の公開鍵。 */
export interface PublicKeyDoc {
  sealform: 1;
  kid: string;
  alg: string;
  publicKey: string;
  fingerprint: string;
  created: string;
  expires: string;
  /** 誰の鍵か（任意。表示用）。 */
  label?: string;
}

/**
 * サイトに置く公開鍵の束（/.well-known/sealform-key.json）。
 * 複数の担当者の鍵や、更新中の新旧の鍵を並べる。ブラウザは有効な全部の鍵に宛てて暗号化する。
 */
export interface KeySetDoc {
  sealform: 1;
  type: "key-set";
  keys: PublicKeyDoc[];
}

export interface KeyPair {
  publicDoc: PublicKeyDoc;
  /** X-Wing の秘密鍵（32バイトの種）。そのまま保存せず keyfile.ts で保護する。 */
  privateKey: Uint8Array;
}

/** 復号に使う秘密鍵（kid で引く）。更新前の古い鍵も並べておけば、古い暗号文も開ける。 */
export interface PrivateKeyEntry {
  kid: string;
  privateKey: Uint8Array;
}

/** 公開鍵の指紋。SSH と同じ "SHA256:<base64>" の表記。 */
export async function fingerprintOf(publicKey: Uint8Array): Promise<string> {
  return "SHA256:" + btoa(String.fromCharCode(...(await sha256(publicKey)))).replace(/=+$/, "");
}

export async function kidOf(publicKey: Uint8Array): Promise<string> {
  return toHex(await sha256(publicKey)).slice(0, KID_BYTES * 2);
}

export async function generateKeyPair(opts: { validDays?: number; now?: Date; label?: string } = {}): Promise<KeyPair> {
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
      ...(opts.label ? { label: opts.label } : {}),
    },
    privateKey: priv,
  };
}

export interface LoadedPublicKey {
  doc: PublicKeyDoc;
  raw: Uint8Array;
}

/** 鍵本体から kid と指紋を計算し直して照合する。JSON 内の値が書き換えられていても気づける。 */
async function verifyDoc(input: unknown): Promise<LoadedPublicKey> {
  const doc = input as PublicKeyDoc;
  if (!doc || typeof doc !== "object" || doc.sealform !== 1 || typeof doc.publicKey !== "string") {
    throw new SealformError("bad-key", "sealform の公開鍵ではありません");
  }
  if (doc.alg !== ALGORITHM) throw new SealformError("bad-key", `対応していない方式です: ${doc.alg}`);
  let raw: Uint8Array;
  try {
    raw = fromB64url(doc.publicKey);
    await suite().kem.deserializePublicKey(raw.slice().buffer);
  } catch {
    throw new SealformError("bad-key", "公開鍵の中身が壊れています");
  }
  if (doc.kid !== (await kidOf(raw)) || doc.fingerprint !== (await fingerprintOf(raw))) {
    throw new SealformError("bad-key", "公開鍵の kid または指紋が鍵本体と一致しません");
  }
  return { doc, raw };
}

function isExpired(doc: PublicKeyDoc, now: Date) {
  const t = Date.parse(doc.expires);
  return !Number.isFinite(t) || t <= now.getTime();
}

/** 1つの公開鍵を読み込む。pin を渡すと指紋が一致しない鍵を拒否する。 */
export async function loadPublicKey(
  input: unknown,
  opts: { pin?: string; now?: Date } = {},
): Promise<LoadedPublicKey> {
  const k = await verifyDoc(input);
  if (opts.pin && opts.pin !== k.doc.fingerprint) {
    throw new SealformError("fingerprint-mismatch", `公開鍵の指紋が固定値と一致しません（受信: ${k.doc.fingerprint}）`);
  }
  if (isExpired(k.doc, opts.now ?? new Date())) {
    throw new SealformError("key-expired", `公開鍵の有効期限が切れています（${k.doc.expires}）`);
  }
  return k;
}

/**
 * 公開鍵を読み込み、暗号化に使う鍵の一覧を返す。1つの公開鍵でも、鍵の束（key-set）でもよい。
 * - 期限切れの鍵は使わない（更新で役目を終えた鍵）。有効な鍵が1つも無ければエラー
 * - pins を渡すと、使う鍵の**すべて**が pins に含まれている必要がある。
 *   攻撃者が自分の鍵を束に足して写しを受け取る、という差し替えを防ぐため
 */
export async function loadKeys(
  input: unknown,
  opts: { pins?: string[]; now?: Date } = {},
): Promise<LoadedPublicKey[]> {
  const set = input as KeySetDoc;
  const docs: unknown[] =
    set && typeof set === "object" && set.type === "key-set"
      ? Array.isArray(set.keys)
        ? set.keys
        : []
      : [input];
  if (docs.length === 0) throw new SealformError("bad-key", "鍵の束に鍵がありません");
  if (docs.length > MAX_RECIPIENTS * 2) throw new SealformError("bad-key", "鍵の束に含まれる鍵が多すぎます");
  const all = await Promise.all(docs.map(verifyDoc));
  if (new Set(all.map((k) => k.doc.kid)).size !== all.length) {
    throw new SealformError("bad-key", "鍵の束に同じ鍵が重複しています");
  }
  const now = opts.now ?? new Date();
  const active = all.filter((k) => !isExpired(k.doc, now));
  if (active.length === 0) {
    throw new SealformError("key-expired", "有効期限内の公開鍵がありません。鍵を更新してください");
  }
  if (active.length > MAX_RECIPIENTS) {
    throw new SealformError("bad-key", `宛先にできる鍵は ${MAX_RECIPIENTS} 個までです`);
  }
  const pins = opts.pins?.filter(Boolean) ?? [];
  if (pins.length > 0) {
    const unknown = active.filter((k) => !pins.includes(k.doc.fingerprint));
    if (unknown.length > 0) {
      throw new SealformError(
        "fingerprint-mismatch",
        `登録されていない公開鍵が含まれています（${unknown.map((k) => k.doc.fingerprint).join(", ")}）`,
      );
    }
  }
  return active;
}

// ---------------------------------------------------------------- 暗号文

/** 暗号文に結びつける文脈。復号時に取り出せ、改ざんすると復号に失敗する。 */
export interface SealContext {
  /** 送信先フォームの識別子（既定はフォームの action のパス）。 */
  form: string;
  /** 項目名。 */
  field: string;
}

type Kind = "text" | "file";

interface Meta {
  v: 1 | 2;
  f: string;
  n: string;
  t: number;
  /** 種類（sf2 のみ）。文字列の暗号文とファイルを取り違えないように結びつける。 */
  k?: Kind;
}

function pad(data: Uint8Array, bucket: number): Uint8Array {
  const total = Math.ceil((data.length + 4) / bucket) * bucket;
  const out = new Uint8Array(total);
  new DataView(out.buffer).setUint32(0, data.length);
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
 * 宛先の鍵を確かめる。期限切れの鍵には暗号化しない（読み込んだあと長く開いていたページでも、
 * 暗号化するその時点の期限で判断する）。過去の暗号文の復号は、期限に関係なく行える。
 */
function asArray(keys: LoadedPublicKey | LoadedPublicKey[], now: Date = new Date()): LoadedPublicKey[] {
  const list = Array.isArray(keys) ? keys : [keys];
  if (list.length === 0) throw new SealformError("bad-key", "宛先の鍵がありません");
  if (list.length > MAX_RECIPIENTS) throw new SealformError("bad-key", `宛先にできる鍵は ${MAX_RECIPIENTS} 個までです`);
  const expired = list.filter((k) => isExpired(k.doc, now));
  if (expired.length > 0) {
    throw new SealformError("key-expired", `公開鍵の有効期限が切れています（${expired.map((k) => k.doc.kid).join(", ")}）`);
  }
  return list;
}

/**
 * sf2 の中核。本文を使い捨ての鍵（DEK）で AES-256-GCM 暗号化し、DEK を宛先ごとに HPKE で包む。
 * 戻り値の head は "sf2.<meta>.<宛先一覧>"、body は iv||暗号文。
 */
async function sealCore(
  keys: LoadedPublicKey[],
  plaintext: Uint8Array,
  meta: Meta,
): Promise<{ head: string; body: Uint8Array }> {
  const metaPart = b64url(utf8(JSON.stringify(meta)));
  const wrapAad = utf8(`sf2.${metaPart}`);
  const dek = crypto.getRandomValues(new Uint8Array(32));
  const s = suite();
  const recipients: Uint8Array[] = [];
  for (const k of keys) {
    const pk = await s.kem.deserializePublicKey(k.raw.slice().buffer);
    const { ct, enc } = await s.seal({ recipientPublicKey: pk, info: INFO_V2 }, dek, wrapAad);
    recipients.push(concat(fromHex(k.doc.kid), new Uint8Array(enc), new Uint8Array(ct)));
  }
  const head = `sf2.${metaPart}.${b64url(concat(...recipients))}`;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", dek, "AES-GCM", false, ["encrypt"]);
  dek.fill(0);
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: utf8(head) as BufferSource },
    key,
    plaintext as BufferSource,
  );
  return { head, body: concat(iv, new Uint8Array(ct)) };
}

function fromHex(hex: string): Uint8Array {
  return Uint8Array.from(hex.match(/../g)!, (h) => parseInt(h, 16));
}

/**
 * 文字列を暗号化して1つのトークン文字列にする。keys に複数の鍵を渡すと、どの鍵でも復号できる。
 * 形式: sf2.<meta>.<宛先一覧>.<本文>（docs/FORMAT.md）
 */
export async function seal(
  keys: LoadedPublicKey | LoadedPublicKey[],
  plaintext: string,
  ctx: SealContext,
  opts: { now?: Date } = {},
): Promise<string> {
  const meta: Meta = { v: 2, f: ctx.form, n: ctx.field, t: unixNow(opts.now), k: "text" };
  const { head, body } = await sealCore(asArray(keys, opts.now), pad(utf8(plaintext), TEXT_PAD), meta);
  return `${head}.${b64url(body)}`;
}

export interface FileInfo {
  name: string;
  type: string;
}

/**
 * ファイルを暗号化する。元のファイル名と種類も中に入れて隠す。
 * 形式: "sf2f" | u32 head の長さ | head | iv||暗号文
 */
export async function sealFile(
  keys: LoadedPublicKey | LoadedPublicKey[],
  data: Uint8Array,
  info: FileInfo,
  ctx: SealContext,
  opts: { now?: Date; maxBytes?: number } = {},
): Promise<Uint8Array> {
  const max = opts.maxBytes ?? MAX_FILE_BYTES;
  if (data.length > max) {
    throw new SealformError("too-large", `ファイルが大きすぎます（上限 ${Math.floor(max / 1024 / 1024)}MB）`);
  }
  const infoBytes = utf8(JSON.stringify({ name: info.name, type: info.type }));
  const inner = new Uint8Array(4 + infoBytes.length + data.length);
  new DataView(inner.buffer).setUint32(0, infoBytes.length);
  inner.set(infoBytes, 4);
  inner.set(data, 4 + infoBytes.length);
  const meta: Meta = { v: 2, f: ctx.form, n: ctx.field, t: unixNow(opts.now), k: "file" };
  const { head, body } = await sealCore(asArray(keys, opts.now), pad(inner, FILE_PAD), meta);
  const headBytes = utf8(head);
  const len = new Uint8Array(4);
  new DataView(len.buffer).setUint32(0, headBytes.length);
  return concat(FILE_MAGIC, len, headBytes, body);
}

const unixNow = (d?: Date) => Math.floor((d ?? new Date()).getTime() / 1000);

// ---------------------------------------------------------------- 読み取り

export interface ParsedToken {
  version: "sf1" | "sf2";
  kind: Kind;
  /** 復号できる鍵の kid の一覧。 */
  recipients: string[];
  form: string;
  field: string;
  sealedAt: Date;
}

interface Parsed extends ParsedToken {
  metaPart: string;
  /** sf2: 宛先ごとの [kid, enc, wrapped]。sf1: [kid, enc, (空)] */
  entries: { kid: string; enc: Uint8Array; wrapped: Uint8Array }[];
  body: Uint8Array;
  aad: Uint8Array;
}

/** 本文（iv 12 バイト ‖ 暗号文 ‖ 認証タグ 16 バイト）の長さが、丸めの単位に合っているか。 */
function bodyLengthOk(bodyLength: number, bucket: number, ivBytes = 12): boolean {
  const ct = bodyLength - ivBytes - 16;
  return ct >= bucket && ct % bucket === 0;
}

/**
 * サーバー側で「暗号文の形をしているか」を確かめる。復号はしない（サーバーは秘密鍵を持たない）。
 * 見出しの JSON・種類・宛先一覧の長さ・本文の長さまで確かめるが、**形が正しいことしか分からない**。
 * 暗号文が本物か（改ざんされていないか）は、秘密鍵で復号するときに初めて分かる。
 */
export function isSealed(value: unknown): value is string {
  if (typeof value !== "string") return false;
  try {
    const p = parseToken(value, false);
    if (p.kind !== "text") return false;
    if (p.version === "sf1") return p.entries[0]!.enc.length === ENC_BYTES && bodyLengthOk(p.body.length, TEXT_PAD, 0);
    return bodyLengthOk(p.body.length, TEXT_PAD);
  } catch {
    return false;
  }
}

/** 受け取ったファイルが sealform で暗号化されたものの形をしているかを確かめる。復号はしない。 */
export function isSealedFile(data: Uint8Array): boolean {
  try {
    const p = parseFile(data);
    return p.kind === "file" && bodyLengthOk(p.body.length, FILE_PAD);
  } catch {
    return false;
  }
}

function parseMeta(part: string): Meta {
  let meta: Meta;
  try {
    meta = JSON.parse(fromUtf8(fromB64url(part)));
  } catch {
    throw new SealformError("bad-token", "暗号文の見出し部分が壊れています");
  }
  if (typeof meta?.f !== "string" || typeof meta.n !== "string" || typeof meta.t !== "number") {
    throw new SealformError("bad-token", "暗号文の見出し部分が壊れています");
  }
  return meta;
}

function parseHead(metaPart: string, rcptPart: string) {
  const meta = parseMeta(metaPart);
  if (meta.v !== 2 || (meta.k !== "text" && meta.k !== "file")) {
    throw new SealformError("bad-token", "暗号文の見出し部分が壊れています");
  }
  const rcpt = fromB64url(rcptPart);
  if (rcpt.length === 0 || rcpt.length % RECIPIENT_BYTES !== 0 || rcpt.length / RECIPIENT_BYTES > MAX_RECIPIENTS) {
    throw new SealformError("bad-token", "暗号文の宛先部分が壊れています");
  }
  const entries = [];
  for (let o = 0; o < rcpt.length; o += RECIPIENT_BYTES) {
    entries.push({
      kid: toHex(rcpt.subarray(o, o + KID_BYTES)),
      enc: rcpt.slice(o + KID_BYTES, o + KID_BYTES + ENC_BYTES),
      wrapped: rcpt.slice(o + KID_BYTES + ENC_BYTES, o + RECIPIENT_BYTES),
    });
  }
  return { meta, entries };
}

function parseToken(token: string, trim = true): Parsed {
  const t = trim ? token.trim() : token;
  const m2 = SF2_RE.exec(t);
  if (m2) {
    const { meta, entries } = parseHead(m2[1]!, m2[2]!);
    return {
      version: "sf2",
      kind: meta.k!,
      recipients: entries.map((e) => e.kid),
      form: meta.f,
      field: meta.n,
      sealedAt: new Date(meta.t * 1000),
      metaPart: m2[1]!,
      entries,
      body: fromB64url(m2[3]!),
      aad: utf8(`sf2.${m2[1]}.${m2[2]}`),
    };
  }
  const m1 = SF1_RE.exec(t);
  if (m1) {
    const meta = parseMeta(m1[2]!);
    if (meta.v !== 1) throw new SealformError("bad-token", "暗号文の見出し部分が壊れています");
    return {
      version: "sf1",
      kind: "text",
      recipients: [m1[1]!],
      form: meta.f,
      field: meta.n,
      sealedAt: new Date(meta.t * 1000),
      metaPart: m1[2]!,
      entries: [{ kid: m1[1]!, enc: fromB64url(m1[3]!), wrapped: new Uint8Array() }],
      body: fromB64url(m1[4]!),
      aad: utf8(`sf1.${m1[1]}.${m1[2]}`),
    };
  }
  throw new SealformError("bad-token", "sealform の暗号文ではありません");
}

function parseFile(data: Uint8Array): Parsed {
  const bad = () => new SealformError("bad-token", "sealform で暗号化したファイルではありません");
  if (data.length < 8 || FILE_MAGIC.some((b, i) => data[i] !== b)) throw bad();
  const headLen = new DataView(data.buffer, data.byteOffset).getUint32(4);
  if (headLen > 64 * 1024 || 8 + headLen > data.length) throw bad();
  let head: string;
  try {
    head = fromUtf8(data.subarray(8, 8 + headLen));
  } catch {
    throw bad();
  }
  const m = SF2_HEAD_RE.exec(head);
  if (!m) throw bad();
  const { meta, entries } = parseHead(m[1]!, m[2]!);
  return {
    version: "sf2",
    kind: meta.k!,
    recipients: entries.map((e) => e.kid),
    form: meta.f,
    field: meta.n,
    sealedAt: new Date(meta.t * 1000),
    metaPart: m[1]!,
    entries,
    body: data.subarray(8 + headLen),
    aad: utf8(head),
  };
}

/** 暗号文の外側（宛先の鍵・フォーム・時刻）を読む。改ざんの有無は open() でしか分からない。 */
export function inspect(token: string): ParsedToken {
  const { version, kind, recipients, form, field, sealedAt } = parseToken(token);
  return { version, kind, recipients, form, field, sealedAt };
}

export function inspectFile(data: Uint8Array): ParsedToken {
  const { version, kind, recipients, form, field, sealedAt } = parseFile(data);
  return { version, kind, recipients, form, field, sealedAt };
}

// ---------------------------------------------------------------- 復号

type Keyring = PrivateKeyEntry | PrivateKeyEntry[];

async function openCore(keyring: Keyring, p: Parsed): Promise<Uint8Array> {
  const ring = Array.isArray(keyring) ? keyring : [keyring];
  const entry = p.entries.find((e) => ring.some((k) => k.kid === e.kid));
  if (!entry) {
    throw new SealformError("wrong-key", `この暗号文を開ける鍵を持っていません（宛先の鍵: ${p.recipients.join(", ")}）`);
  }
  const sk = ring.find((k) => k.kid === entry.kid)!;
  const s = suite();
  try {
    const recipientKey = await s.kem.deserializePrivateKey(sk.privateKey.slice().buffer);
    if (p.version === "sf1") {
      const out = await s.open({ recipientKey, enc: entry.enc.buffer as ArrayBuffer, info: INFO_V1 }, p.body, p.aad);
      return unpad(new Uint8Array(out));
    }
    const dek = new Uint8Array(
      await s.open(
        { recipientKey, enc: entry.enc.buffer as ArrayBuffer, info: INFO_V2 },
        entry.wrapped,
        utf8(`sf2.${p.metaPart}`),
      ),
    );
    const key = await crypto.subtle.importKey("raw", dek, "AES-GCM", false, ["decrypt"]);
    dek.fill(0);
    const out = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: p.body.subarray(0, 12) as BufferSource, additionalData: p.aad as BufferSource },
      key,
      p.body.subarray(12) as BufferSource,
    );
    return unpad(new Uint8Array(out));
  } catch {
    throw new SealformError("decrypt-failed", "復号できません。暗号文が改ざんされているか、壊れています");
  }
}

function checkExpect(p: ParsedToken, expect: Partial<SealContext>) {
  if (expect.form !== undefined && expect.form !== p.form) {
    throw new SealformError("wrong-form", `別のフォーム宛ての暗号文です（宛先: ${p.form}）`);
  }
  if (expect.field !== undefined && expect.field !== p.field) {
    throw new SealformError("wrong-field", `別の項目の暗号文です（項目: ${p.field}）`);
  }
}

export interface Opened extends ParsedToken {
  plaintext: string;
}

/**
 * 文字列の暗号文を復号する。keyring に新旧・複数の秘密鍵を渡すと、宛先に合うものを使う。
 * expect を渡すと、宛先フォームや項目名が違う暗号文（差し替え・使い回し）を拒否する。
 */
export async function open(keyring: Keyring, token: string, expect: Partial<SealContext> = {}): Promise<Opened> {
  const p = parseToken(token);
  if (p.kind !== "text") throw new SealformError("wrong-kind", "ファイルの暗号文です");
  const pt = await openCore(keyring, p);
  checkExpect(p, expect);
  return { ...inspect(token), plaintext: fromUtf8(pt) };
}

export interface OpenedFile extends ParsedToken, FileInfo {
  data: Uint8Array;
}

export async function openFile(
  keyring: Keyring,
  sealed: Uint8Array,
  expect: Partial<SealContext> = {},
): Promise<OpenedFile> {
  const p = parseFile(sealed);
  if (p.kind !== "file") throw new SealformError("wrong-kind", "ファイルの暗号文ではありません");
  const inner = await openCore(keyring, p);
  checkExpect(p, expect);
  const n = new DataView(inner.buffer, inner.byteOffset).getUint32(0);
  const info = JSON.parse(fromUtf8(inner.subarray(4, 4 + n))) as FileInfo;
  return {
    ...inspectFile(sealed),
    name: String(info.name ?? ""),
    type: String(info.type ?? ""),
    data: inner.slice(4 + n),
  };
}

/** 文章中から sealform の暗号文をすべて拾う（CSV やログの貼り付け用）。 */
export function findTokens(text: string): string[] {
  return (
    text.match(
      /sf2\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|sf1\.[0-9a-f]{16}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,
    ) ?? []
  );
}

/** ファイル名として安全な名前にする（復号したファイルを保存するとき用）。 */
export function safeFileName(name: string): string {
  const base = name.split(/[\\/]/).pop() ?? "";
  const cleaned = base.replace(/[\u0000-\u001f<>:"|?*]/g, "_").replace(/^\.+/, "").slice(0, 200);
  return cleaned || "file";
}
