// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { attach } from "../src/browser.js";
import { generateKeyPair, isSealed, isSealedFile, open, openFile, type KeyPair } from "../src/core.js";

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
    const r = await open({ kid: kp.publicDoc.kid, privateKey: kp.privateKey }, body[0] as string, { form: "/contact", field: "body" });
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

  it("添付ファイルは暗号化したファイルに入れ替えて送る（元の名前は送らない）", async () => {
    const form = mount(FORM('method="post" enctype="multipart/form-data"', '<input type="file" name="doc" data-seal>'));
    const input = form.querySelector<HTMLInputElement>("input[type=file]")!;
    const original = new File(["診断書の中身"], "診断書.pdf", { type: "application/pdf" });
    const dt = new DataTransfer();
    dt.items.add(original);
    input.files = dt.files;
    await until(() => form.dataset.sealformState === "ready");
    form.requestSubmit();
    await until(() => submitted.length === 1);
    const sent = submitted[0]!.get("doc") as File;
    expect(sent.name).toMatch(/^sealed-[0-9a-f]{16}\.sf$/);
    const bytes = new Uint8Array(await sent.arrayBuffer());
    expect(isSealedFile(bytes)).toBe(true);
    const r = await openFile({ kid: kp.publicDoc.kid, privateKey: kp.privateKey }, bytes, { form: "/contact", field: "doc" });
    expect(r.name).toBe("診断書.pdf");
    expect(new TextDecoder().decode(r.data)).toBe("診断書の中身");
  });

  it("添付ファイルを暗号化するのに multipart でなければ、最初から送信できない", async () => {
    const form = mount(FORM('method="post"', '<input type="file" name="doc" data-seal>'));
    expect(form.dataset.sealformState).toBe("error");
    expect(form.querySelector("[data-sealform-status]")!.textContent).toContain("multipart/form-data");
    expect(form.querySelector("button")!.disabled).toBe(true);
  });

  it("上限を超える添付ファイルは送らずに止める", async () => {
    const form = mount(FORM('method="post" enctype="multipart/form-data" data-sealform-max-mb="0.001"', '<input type="file" name="doc" data-seal>'));
    const input = form.querySelector<HTMLInputElement>("input[type=file]")!;
    const dt = new DataTransfer();
    dt.items.add(new File([new Uint8Array(5000)], "big.bin"));
    input.files = dt.files;
    await until(() => form.dataset.sealformState === "ready");
    form.requestSubmit();
    await until(() => form.dataset.sealformState === "error");
    expect(submitted).toHaveLength(0);
    expect(form.querySelector("[data-sealform-status]")!.textContent).toContain("大きすぎ");
  });

  it("鍵の束なら全員に宛てて暗号化し、全員の指紋が登録されていれば送れる", async () => {
    const other = await generateKeyPair();
    const set = { sealform: 1, type: "key-set", keys: [kp.publicDoc, other.publicDoc] };
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(set))));
    const fps = `${kp.publicDoc.fingerprint} ${other.publicDoc.fingerprint}`;
    const form = mount(FORM(`method="post" data-sealform-fingerprint="${fps}"`));
    await until(() => form.dataset.sealformState === "ready");
    expect(form.querySelector("[data-sealform-status]")!.textContent).toContain("2 個");
    form.requestSubmit();
    await until(() => submitted.length === 1);
    const t = submitted[0]!.get("body") as string;
    expect((await open({ kid: other.publicDoc.kid, privateKey: other.privateKey }, t)).plaintext).toBe("いじめの相談です");
  });

  it("鍵の束に登録外の鍵が混ざっていたら送れない", async () => {
    const evil = await generateKeyPair();
    const set = { sealform: 1, type: "key-set", keys: [kp.publicDoc, evil.publicDoc] };
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(set))));
    const form = mount(FORM(`method="post" data-sealform-fingerprint="${kp.publicDoc.fingerprint}"`));
    await until(() => form.dataset.sealformState === "error");
    expect(form.querySelector("button")!.disabled).toBe(true);
  });

  it("フォーム部品が自前で付けた submit 処理には、平文の submit イベントを渡さない", async () => {
    const form = mount(FORM());
    const seen: string[] = [];
    // Contact Form 7 のように、submit を受けて FormData を AJAX 送信するスクリプトを想定
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      seen.push(String(new FormData(form).get("body")));
    });
    await until(() => form.dataset.sealformState === "ready");
    form.requestSubmit();
    await until(() => submitted.length === 1);
    expect(seen).toEqual([]);
  });

  it("lang=en のページでは英語で表示する", async () => {
    document.documentElement.lang = "en";
    try {
      const form = mount(FORM());
      await until(() => form.dataset.sealformState === "ready");
      expect(form.querySelector("[data-sealform-status]")!.textContent).toContain("encrypted on this device");
      vi.stubGlobal("fetch", vi.fn(async () => new Response("", { status: 404 })));
      const f2 = mount(FORM());
      await until(() => f2.dataset.sealformState === "error");
      expect(f2.querySelector("[data-sealform-status]")!.textContent).toContain("could not be loaded");
    } finally {
      document.documentElement.lang = "";
    }
  });

  it("data-sealform-manual のフォームは自動初期化しない", async () => {
    const { init } = await import("../src/browser.js");
    document.body.innerHTML = FORM('method="post" data-sealform-manual');
    init();
    expect(document.forms[0]!.dataset.sealformAttached).toBeUndefined();
  });

  it("サーバーが差し戻した暗号文が入力欄に入っていたら、空にして知らせる（二重の暗号化を防ぐ）", async () => {
    const { seal: sealText, loadPublicKey } = await import("../src/core.js");
    const token = await sealText(await loadPublicKey(kp.publicDoc), "前回の入力", { form: "/contact", field: "name" });
    const form = mount(FORM().replace('value="山田"', `value="${token}"`));
    await until(() => form.dataset.sealformState === "ready");
    expect(form.querySelector<HTMLInputElement>("input[name=name]")!.value).toBe("");
    expect(form.querySelector<HTMLInputElement>("input[name=csrf]")!.value).toBe("tok123");
    expect(form.querySelector("[data-sealform-status]")!.textContent).toContain("入力し直して");
  });

  it("暗号化中に入力欄が足されたら送らない（レビューで再現された平文送信）", async () => {
    const form = mount(FORM());
    await until(() => form.dataset.sealformState === "ready");
    form.addEventListener("sealform:status", (e) => {
      if ((e as CustomEvent).detail.state !== "sending") return;
      const extra = document.createElement("input");
      extra.name = "injected";
      extra.value = "こっそり足された平文";
      extra.setAttribute("data-seal", "");
      form.appendChild(extra);
    });
    form.requestSubmit();
    await until(() => form.dataset.sealformState === "error");
    expect(submitted).toHaveLength(0);
    expect(form.dataset.sealformMessage).toContain("フォームの内容が変わった");
    expect(form.querySelector("button")!.disabled).toBe(false);
  });

  it("暗号化中に値が書き換えられたら送らない", async () => {
    const form = mount(FORM());
    await until(() => form.dataset.sealformState === "ready");
    form.addEventListener("sealform:status", (e) => {
      if ((e as CustomEvent).detail.state === "sending") form.querySelector<HTMLInputElement>("input[name=name]")!.value = "別の値";
    });
    form.requestSubmit();
    await until(() => form.dataset.sealformState === "error");
    expect(submitted).toHaveLength(0);
  });

  it("開いている間に鍵の期限が切れたら、取り直して、それも切れていれば送らない", async () => {
    const short = await generateKeyPair({ validDays: 1 });
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(short.publicDoc))));
    const form = mount(FORM());
    await until(() => form.dataset.sealformState === "ready");
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      vi.setSystemTime(Date.now() + 2 * 86400_000);
      form.requestSubmit();
      await until(() => form.dataset.sealformState === "error");
      expect(submitted).toHaveLength(0);
      expect(form.dataset.sealformMessage).toContain("有効期限");
      expect(form.querySelector("button")!.disabled).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("開いている間に鍵の期限が切れても、新しい鍵が取れればそれで送る", async () => {
    const short = await generateKeyPair({ validDays: 1 });
    const fetchMock = vi.fn(async () => new Response(JSON.stringify(short.publicDoc)));
    vi.stubGlobal("fetch", fetchMock);
    const form = mount(FORM());
    await until(() => form.dataset.sealformState === "ready");
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      vi.setSystemTime(Date.now() + 2 * 86400_000);
      const fresh = await generateKeyPair();
      fetchMock.mockImplementation(async () => new Response(JSON.stringify(fresh.publicDoc)));
      form.requestSubmit();
      await until(() => submitted.length === 1);
      const t = submitted[0]!.get("body") as string;
      expect((await open({ kid: fresh.publicDoc.kid, privateKey: fresh.privateKey }, t)).plaintext).toBe("いじめの相談です");
    } finally {
      vi.useRealTimers();
    }
  });

  it("必須の欄が空なら、暗号化する前に止めて知らせる（novalidate のフォームでも）", async () => {
    // Contact Form 7 などは novalidate を付けてブラウザの必須チェックを止めているので、sealform が確かめる
    const form = mount(FORM('method="post" novalidate').replace("<textarea name=\"body\" data-seal>いじめの相談です</textarea>", "<label for=\"b\">相談内容</label><textarea id=\"b\" name=\"body\" data-seal required></textarea>"));
    await until(() => form.dataset.sealformState === "ready");
    form.requestSubmit();
    await until(() => form.dataset.sealformState === "error");
    expect(submitted).toHaveLength(0);
    expect(form.dataset.sealformMessage).toContain("「相談内容」は必須");
  });

  it("任意の欄が空なら、暗号化せず空のまま送る（サーバー側の必須チェックが効くように）", async () => {
    const form = mount(FORM().replace('value="山田"', 'value="" data-seal'));
    await until(() => form.dataset.sealformState === "ready");
    form.requestSubmit();
    await until(() => submitted.length === 1);
    expect(submitted[0]!.get("name")).toBe("");
    expect(isSealed(submitted[0]!.get("body"))).toBe(true);
  });

  it("準備ができていない間は、他のスクリプトが送信ボタンを戻しても押せないままにする", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("not found", { status: 404 })));
    const form = mount(FORM());
    await until(() => form.dataset.sealformState === "error");
    const btn = form.querySelector("button")!;
    btn.disabled = false; // Contact Form 7 が同意チェックで戻すのと同じ
    await until(() => btn.disabled);
    expect(btn.disabled).toBe(true);
  });
});
