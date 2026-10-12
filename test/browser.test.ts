// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { attach } from "../src/browser.js";
import { generateKeyPair, isSealed, open, type KeyPair } from "../src/core.js";

let kp: KeyPair;
let submitted: FormData[];
let n = 0;

async function until(cond: () => boolean) {
  for (let i = 0; i < 200 && !cond(); i++) await new Promise((r) => setTimeout(r, 10));
  if (!cond()) throw new Error("timeout");
}

function mount(html: string): HTMLFormElement {
  document.body.innerHTML = html;
  const form = document.querySelector("form")!;
  attach(form);
  return form;
}

beforeEach(async () => {
  kp ??= await generateKeyPair();
  submitted = [];
  vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(kp.publicDoc))));
  vi.spyOn(HTMLFormElement.prototype, "submit").mockImplementation(function (this: HTMLFormElement) {
    submitted.push(new FormData(this));
  });
});
afterEach(() => vi.restoreAllMocks());

const FORM = (attrs = 'method="post"', fields = "") => `
<form action="/contact" ${attrs} data-sealform-key="/.well-known/sealform-key.json?${++n}">
  <input type="hidden" name="csrf" value="tok123">
  <input name="name" value="山田">
  <textarea name="body" data-seal>いじめの相談です</textarea>
  ${fields}
  <p data-sealform-status></p>
  <button type="submit" name="action" value="send" disabled data-sealform-submit>送信</button>
</form>`;

describe("フォームへの組み込み", () => {
  it("鍵が読めたら送信ボタンが押せるようになる", async () => {
    const form = mount(FORM());
    const btn = form.querySelector("button")!;
    expect(btn.disabled).toBe(true);
    await until(() => form.dataset.sealformState === "ready");
    expect(btn.disabled).toBe(false);
    expect(form.querySelector("[data-sealform-status]")!.textContent).toContain("暗号化してから送信");
  });

  it("data-seal の項目だけ暗号化され、他（CSRF トークン等）はそのまま送られる", async () => {
    const form = mount(FORM());
    await until(() => form.dataset.sealformState === "ready");
    form.requestSubmit(form.querySelector("button")!);
    await until(() => submitted.length === 1);
    const fd = submitted[0]!;
    expect(fd.get("csrf")).toBe("tok123");
    expect(fd.get("name")).toBe("山田");
    expect(fd.get("action")).toBe("send");
    const body = fd.getAll("body");
    expect(body).toHaveLength(1);
    expect(isSealed(body[0])).toBe(true);
    const r = await open(kp.privateKey, kp.publicDoc.kid, body[0] as string, { form: "/contact", field: "body" });
    expect(r.plaintext).toBe("いじめの相談です");
    // 画面上の入力欄は書き換えない
    expect(form.querySelector("textarea")!.value).toBe("いじめの相談です");
  });

  it("data-seal が無ければ hidden 以外の全項目を暗号化する", async () => {
    const form = mount(FORM().replace(" data-seal>", ">"));
    await until(() => form.dataset.sealformState === "ready");
    form.requestSubmit();
    await until(() => submitted.length === 1);
    const fd = submitted[0]!;
    expect(fd.get("csrf")).toBe("tok123");
    expect(isSealed(fd.get("name"))).toBe(true);
    expect(isSealed(fd.get("body"))).toBe(true);
  });

  it("鍵が取れないときは送信ボタンが押せないまま", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("not found", { status: 404 })));
    const form = mount(FORM());
    await until(() => form.dataset.sealformState === "error");
    expect(form.querySelector("button")!.disabled).toBe(true);
    expect(form.querySelector("[data-sealform-status]")!.getAttribute("role")).toBe("alert");
  });

  it("指紋の固定値と違う鍵が来たら送信できない", async () => {
    const other = await generateKeyPair();
    const form = mount(FORM(`method="post" data-sealform-fingerprint="${other.publicDoc.fingerprint}"`));
    await until(() => form.dataset.sealformState === "error");
    expect(form.querySelector("button")!.disabled).toBe(true);
  });

  it("GET のフォームは扱わない", async () => {
    const form = mount(FORM('method="get"'));
    expect(form.dataset.sealformState).toBe("error");
    expect(form.querySelector("button")!.disabled).toBe(true);
  });

  it("全項目モードで添付ファイルがあると、平文で漏れないよう送信を止める", async () => {
    const form = mount(FORM().replace(" data-seal>", ">").replace("<p data", '<input type="file" name="doc"><p data'));
    await until(() => form.dataset.sealformState === "ready");
    form.requestSubmit();
    await until(() => form.dataset.sealformState === "error");
    expect(submitted).toHaveLength(0);
    expect(form.querySelector("[data-sealform-status]")!.textContent).toContain("添付ファイル");
  });
});
