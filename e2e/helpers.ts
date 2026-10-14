import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { findTokens, unlockPrivateKey, type PrivateKeyEntry } from "../dist/index.js";

export const DATA = join(dirname(fileURLToPath(import.meta.url)), "..", "examples", ".data");

/** デモ用の相談員の秘密鍵（パスフレーズは examples/shared/demo.mjs の既定値）。 */
export async function demoKeyring(): Promise<PrivateKeyEntry[]> {
  const dir = join(DATA, "keys");
  const files = readdirSync(dir).filter((f) => f.startsWith("sealform-private-key-"));
  return Promise.all(files.map((f) => unlockPrivateKey(JSON.parse(readFileSync(join(dir, f), "utf8")), "demo-passphrase-123")));
}

/** 送られたバイト列に、平文（UTF-8）がそのまま含まれていないか。 */
export function containsText(body: Buffer, text: string): boolean {
  return body.includes(Buffer.from(text, "utf8"));
}

/** multipart の本文から、指定した名前の項目の値（文字列）を取り出す。 */
export function multipartField(body: Buffer, contentType: string, name: string): string[] {
  const boundary = /boundary=(?:"([^"]+)"|([^;]+))/.exec(contentType)!;
  const sep = "--" + (boundary[1] ?? boundary[2]);
  return body
    .toString("latin1")
    .split(sep)
    .filter((part) => part.includes(`name="${name}"`) && !part.includes("filename="))
    .map((part) => Buffer.from(part.slice(part.indexOf("\r\n\r\n") + 4).replace(/\r\n$/, ""), "latin1").toString("utf8"));
}

/** multipart の本文から、指定した名前のファイル（ファイル名と中身）を取り出す。 */
export function multipartFiles(body: Buffer, contentType: string, name: string): { filename: string; data: Buffer }[] {
  const boundary = /boundary=(?:"([^"]+)"|([^;]+))/.exec(contentType)!;
  const sep = Buffer.from("--" + (boundary[1] ?? boundary[2]));
  const out: { filename: string; data: Buffer }[] = [];
  let start = body.indexOf(sep);
  while (start !== -1) {
    const next = body.indexOf(sep, start + sep.length);
    if (next === -1) break;
    const part = body.subarray(start + sep.length + 2, next - 2);
    const headEnd = part.indexOf("\r\n\r\n");
    const head = part.subarray(0, headEnd).toString("utf8");
    const fn = /filename="([^"]*)"/.exec(head);
    if (head.includes(`name="${name}"`) && fn && fn[1]) out.push({ filename: fn[1], data: Buffer.from(part.subarray(headEnd + 4)) });
    start = next;
  }
  return out;
}

export const findTokensIn = (text: string): string[] => findTokens(text);
