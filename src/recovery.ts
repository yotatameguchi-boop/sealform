import { XWing } from "@hpke/hybridkem-x-wing";
import { concat, sha256, utf8, b64url } from "./encoding.js";
import { fingerprintOf, kidOf } from "./core.js";

/**
 * 紙に印刷して保管する復旧コード。
 *
 * 秘密鍵（X-Wing の 32 バイトの種）そのものを、読み間違えにくい Crockford Base32 で書いたもの。
 * 末尾に 4 バイトの検査値を付けるので、書き写しの誤りはほぼ確実に検出できる。
 * **パスフレーズ無しで秘密鍵を復元できる**ので、金庫など物理的に安全な場所に保管する前提。
 *
 * 形式: "SFR1-" + Base32(種 32 バイト ‖ SHA-256("sealform-recovery-v1" ‖ 種) の先頭 4 バイト) を 4 文字ずつ区切ったもの
 */

const PREFIX = "SFR1";
const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const SEED_BYTES = 32;
const CHECK_BYTES = 4;

function base32(bytes: Uint8Array): string {
  let out = "";
  let bits = 0;
  let value = 0;
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

function fromBase32(s: string, byteLength: number): Uint8Array {
  const out = new Uint8Array(byteLength);
  let bits = 0;
  let value = 0;
  let i = 0;
  for (const ch of s) {
    const v = ALPHABET.indexOf(ch);
    if (v < 0) throw new Error(`復旧コードに使えない文字があります: ${ch}`);
    value = ((value << 5) | v) & 0xfff;
    bits += 5;
    if (bits >= 8) {
      if (i >= byteLength) throw new Error("復旧コードが長すぎます");
      out[i++] = (value >>> (bits - 8)) & 0xff;
      bits -= 8;
    }
  }
  if (i !== byteLength) throw new Error("復旧コードが短すぎます。書き写し漏れがないか確かめてください");
  return out;
}

async function checksum(seed: Uint8Array) {
  return (await sha256(concat(utf8("sealform-recovery-v1"), seed))).subarray(0, CHECK_BYTES);
}

export async function toRecoveryCode(privateKey: Uint8Array): Promise<string> {
  if (privateKey.length !== SEED_BYTES) throw new Error("秘密鍵の長さが不正です");
  const body = base32(concat(privateKey, await checksum(privateKey)));
  return [PREFIX, ...(body.match(/.{1,4}/g) ?? [])].join("-");
}

/** 書き写した復旧コードから秘密鍵を取り出す。区切り・空白・大文字小文字の違い、I/L→1、O→0 の読み違いは許す。 */
export async function fromRecoveryCode(code: string): Promise<Uint8Array> {
  const normalized = code
    .normalize("NFKC")
    .toUpperCase()
    .replace(/[\s\-_]/g, "")
    .replace(/[IL]/g, "1")
    .replace(/O/g, "0");
  if (!normalized.startsWith(PREFIX)) throw new Error(`復旧コードは ${PREFIX}- で始まります`);
  const bytes = fromBase32(normalized.slice(PREFIX.length), SEED_BYTES + CHECK_BYTES);
  const seed = bytes.slice(0, SEED_BYTES);
  const expected = await checksum(seed);
  if (!expected.every((b, i) => b === bytes[SEED_BYTES + i])) {
    throw new Error("復旧コードの検査値が一致しません。書き写しに誤りがあります");
  }
  return seed;
}

/** 秘密鍵から公開鍵・kid・指紋を計算し直す（復旧したときに、元の鍵と同じかを確かめるため）。 */
export async function describePrivateKey(privateKey: Uint8Array) {
  const kem = new XWing();
  const kp = await kem.generateKeyPairDerand(privateKey);
  const pub = new Uint8Array(await kem.serializePublicKey(kp.publicKey));
  return { publicKey: b64url(pub), kid: await kidOf(pub), fingerprint: await fingerprintOf(pub) };
}

/** 印刷用の HTML。ネットワークに一切つながらない（CSP で遮断）1 枚の紙。 */
export function recoverySheetHtml(p: { code: string; kid: string; fingerprint: string; label?: string; created: string }): string {
  const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
  const groups = p.code.split("-");
  const lines = [groups.slice(0, 6), groups.slice(6, 11), groups.slice(11)].map((g) => g.join("-"));
  return `<!doctype html>
<html lang="ja"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>sealform 復旧コード ${esc(p.kid)}</title>
<style>
  body { font: 14px/1.7 system-ui, "Hiragino Sans", sans-serif; max-width: 680px; margin: 32px auto; padding: 0 16px; color: #111; }
  h1 { font-size: 20px; margin: 0 0 4px; }
  .warn { border: 2px solid #111; padding: 10px 14px; margin: 16px 0; }
  .code { font: 600 22px/1.8 ui-monospace, "SF Mono", Menlo, monospace; letter-spacing: .06em; border: 1px dashed #555; padding: 12px 16px; margin: 16px 0; }
  table { border-collapse: collapse; margin: 8px 0 16px; }
  td { padding: 2px 12px 2px 0; vertical-align: top; }
  td:first-child { color: #555; white-space: nowrap; }
  .mono { font-family: ui-monospace, Menlo, monospace; word-break: break-all; }
  @media print { body { margin: 0 auto; } }
</style></head><body>
<h1>sealform 秘密鍵の復旧コード</h1>
<div class="warn"><strong>この紙はそれだけで秘密鍵になります。</strong>パスフレーズ無しで、この鍵宛ての相談をすべて読めます。
金庫など鍵のかかる場所に保管し、写真を撮ったりクラウドに保存したりしないでください。</div>
<table>
  ${p.label ? `<tr><td>担当者</td><td>${esc(p.label)}</td></tr>` : ""}
  <tr><td>鍵 ID（kid）</td><td class="mono">${esc(p.kid)}</td></tr>
  <tr><td>指紋</td><td class="mono">${esc(p.fingerprint)}</td></tr>
  <tr><td>印刷日</td><td>${esc(p.created)}</td></tr>
</table>
<div class="code">${lines.map(esc).join("<br>")}</div>
<p><strong>復旧のしかた</strong>: <code>sealform recovery import</code> を実行してこのコードを入力し、新しいパスフレーズを決めます。
表示される kid と指紋が、この紙と同じであることを確かめてください。
区切りの「-」や空白、大文字・小文字は気にせず入力して構いません。書き写しを間違えると検出されます。</p>
</body></html>
`;
}
