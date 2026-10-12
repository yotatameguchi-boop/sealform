// @vitest-environment happy-dom
import { beforeAll, describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { generateKeyPair, loadPublicKey, seal, sealFile, type KeyPair } from "../src/core.js";
import { protectPrivateKey } from "../src/keyfile.js";

const PASS = "correct horse battery";
let a: KeyPair, b: KeyPair, old: KeyPair;
let keyFileA: File, keyFileOld: File;

async function keyFile(kp: KeyPair, name: string) {
  const f = await protectPrivateKey(kp.privateKey, kp.publicDoc.publicKey, PASS);
  return new File([JSON.stringify(f)], name, { type: "application/json" });
}

function setFiles(input: HTMLInputElement, files: File[]) {
  const dt = new DataTransfer();
  files.forEach((f) => dt.items.add(f));
  input.files = dt.files;
  input.dispatchEvent(new Event("change"));
}

async function until(cond: () => boolean) {
  for (let i = 0; i < 500 && !cond(); i++) await new Promise((r) => setTimeout(r, 10));
  if (!cond()) throw new Error("timeout");
}

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const status = () => $("status").textContent ?? "";
const rows = () => Array.from(document.querySelectorAll("#results tr"), (tr) => tr.textContent ?? "");

beforeAll(async () => {
  [a, b, old] = await Promise.all([generateKeyPair(), generateKeyPair(), generateKeyPair()]);
  keyFileA = await keyFile(a, "a.json");
  keyFileOld = await keyFile(old, "old.json");
  const html = readFileSync("src/opener.html", "utf8");
  document.body.innerHTML = /<body>([\s\S]*)<script>/.exec(html)![1]!;
  await import("../src/opener.js");
});

describe("オフライン復号ツール", () => {
  it("鍵の更新前後の暗号文・2人宛ての暗号文・添付ファイルをまとめて開ける", async () => {
    const [ka, kb, kold] = await Promise.all([a, b, old].map((k) => loadPublicKey(k.publicDoc)));
    const tOld = await seal(kold!, "更新前の相談", { form: "/contact", field: "message" });
    const tBoth = await seal([ka!, kb!], "2人宛ての相談", { form: "/contact", field: "message" });
    const sf = await sealFile([ka!, kb!], new TextEncoder().encode("添付の中身"), { name: "../写真.txt", type: "text/plain" }, { form: "/contact", field: "attachment" });

    setFiles($("key"), [keyFileA, keyFileOld]);
    $<HTMLInputElement>("pass").value = PASS;
    $<HTMLTextAreaElement>("tokens").value = `時刻,本文\nx,"${tOld}"\ny,"${tBoth}"`;
    setFiles($("tokens-file"), [new File([sf as BlobPart], "668cc579.sf")]);
    await until(() => $("sealed-files").children.length === 1);

    $("run").click();
    await until(() => status().includes("件を復号しました"));
    expect(status()).toContain("3 件中 3 件");
    const r = rows();
    expect(r[0]).toContain("更新前の相談");
    expect(r[1]).toContain("2人宛ての相談");
    const link = document.querySelector<HTMLAnchorElement>("#results a")!;
    expect(link.download).toBe("写真.txt"); // パスは取り除く
    expect($<HTMLInputElement>("pass").value).toBe(""); // パスフレーズは使い終わったら消す
  });

  it("鍵を持っていない暗号文や、パスフレーズ違いの鍵はその旨を表示する", async () => {
    const kb = await loadPublicKey(b.publicDoc);
    setFiles($("key"), [keyFileA]);
    $<HTMLInputElement>("pass").value = PASS;
    $<HTMLTextAreaElement>("tokens").value = await seal(kb, "Bだけ宛て", { form: "/contact", field: "message" });
    $("clear").click();
    $<HTMLTextAreaElement>("tokens").value = await seal(kb, "Bだけ宛て", { form: "/contact", field: "message" });
    $<HTMLInputElement>("pass").value = PASS;
    $("run").click();
    await until(() => status().includes("件を復号しました"));
    expect(rows()[0]).toContain("開ける鍵を持っていません");

    $<HTMLInputElement>("pass").value = "wrong passphrase!!";
    $("run").click();
    await until(() => status().includes("パスフレーズが違う"));
  });
});
