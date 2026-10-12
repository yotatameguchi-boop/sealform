import { argon2idAsync } from "@noble/hashes/argon2.js";
import { b64url, fromB64url, utf8 } from "./encoding.js";
import { kidOf } from "./core.js";

/**
 * パスフレーズで保護した秘密鍵ファイル。
 * Argon2id（OWASP 推奨の m=19MiB, t=2, p=1）で鍵を導出し、AES-256-GCM で秘密鍵を包む。
 */
export interface PrivateKeyFile {
  sealform: 1;
  type: "private-key";
  kid: string;
  publicKey: string;
  kdf: { alg: "argon2id"; m: number; t: number; p: number; salt: string };
  iv: string;
  ciphertext: string;
}

export const MIN_PASSPHRASE_LENGTH = 12;
const KDF = { m: 19456, t: 2, p: 1 } as const;

async function deriveKey(passphrase: string, salt: Uint8Array, k: { m: number; t: number; p: number }) {
  const raw = await argon2idAsync(utf8(passphrase.normalize("NFC")), salt, { ...k, dkLen: 32 });
  return crypto.subtle.importKey("raw", raw as BufferSource, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function protectPrivateKey(
  privateKey: Uint8Array,
  publicKeyB64: string,
  passphrase: string,
): Promise<PrivateKeyFile> {
  if ([...passphrase].length < MIN_PASSPHRASE_LENGTH) {
    throw new Error(`パスフレーズは ${MIN_PASSPHRASE_LENGTH} 文字以上にしてください`);
  }
  const kid = await kidOf(fromB64url(publicKeyB64));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt, KDF);
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: utf8(`sealform-private-key.${kid}`) as BufferSource },
    key,
    privateKey as BufferSource,
  );
  return {
    sealform: 1,
    type: "private-key",
    kid,
    publicKey: publicKeyB64,
    kdf: { alg: "argon2id", ...KDF, salt: b64url(salt) },
    iv: b64url(iv),
    ciphertext: b64url(new Uint8Array(ct)),
  };
}

export async function unlockPrivateKey(file: unknown, passphrase: string): Promise<{ kid: string; privateKey: Uint8Array }> {
  const f = file as PrivateKeyFile;
  if (!f || f.sealform !== 1 || f.type !== "private-key" || f.kdf?.alg !== "argon2id") {
    throw new Error("sealform の秘密鍵ファイルではありません");
  }
  // 保存された kid を信用せず、公開鍵から計算し直す
  const kid = await kidOf(fromB64url(f.publicKey));
  if (kid !== f.kid) throw new Error("秘密鍵ファイルが壊れています（kid 不一致）");
  // 極端な値で端末を固まらせるファイルを拒否する
  if (f.kdf.m > 1_048_576 || f.kdf.t > 20 || f.kdf.p > 8) throw new Error("鍵導出の設定値が大きすぎます");
  const key = await deriveKey(passphrase, fromB64url(f.kdf.salt), f.kdf);
  try {
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromB64url(f.iv) as BufferSource, additionalData: utf8(`sealform-private-key.${kid}`) as BufferSource },
      key,
      fromB64url(f.ciphertext) as BufferSource,
    );
    return { kid, privateKey: new Uint8Array(pt) };
  } catch {
    throw new Error("パスフレーズが違うか、秘密鍵ファイルが壊れています");
  }
}

