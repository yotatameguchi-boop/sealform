import { loadKeys, seal, sealFile, SealformError, type LoadedPublicKey } from "./core.js";

/**
 * フォームへの組み込み。
 *
 * <form method="post" action="/contact" data-sealform-key="/.well-known/sealform-key.json">
 *   <textarea name="body" data-seal></textarea>
 *   <p data-sealform-status></p>
 *   <button type="submit" disabled data-sealform-submit>送信</button>
 * </form>
 *
 * 安全側に倒す決まりごと（フェイルクローズ）:
 * - 送信ボタンは HTML の時点で disabled にしておく。JS が動かない・鍵が読めないときは押せないまま。
 * - 暗号化に失敗したら送信しない。平文で送り直すことはしない。
 * - method が POST でないフォームは扱わない（暗号文が URL やアクセスログに載るため）。
 * - 添付ファイルを暗号化するときは enctype="multipart/form-data" が必要。
 *
 * 公開鍵が鍵の束（複数の担当者・更新中の新旧の鍵）なら、有効な全部の鍵に宛てて暗号化する。
 * data-sealform-fingerprint には、空白区切りで複数の指紋を書ける。束の鍵はすべてこの中に無いといけない。
 */

const SKIP_TYPES = new Set(["hidden", "submit", "button", "reset", "image"]);

export interface FormStatus {
  state: "loading" | "ready" | "sending" | "error";
  message: string;
}

type Field = HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement;

const keyCache = new Map<string, Promise<LoadedPublicKey[]>>();

async function fetchKeys(url: string, pins: string[]): Promise<LoadedPublicKey[]> {
  const cacheKey = `${url}\n${pins.join(" ")}`;
  let p = keyCache.get(cacheKey);
  if (!p) {
    p = (async () => {
      const res = await fetch(url, { credentials: "omit", cache: "no-cache" });
      if (!res.ok) throw new SealformError("bad-key", `公開鍵を取得できません（HTTP ${res.status}）`);
      return loadKeys(await res.json(), { pins });
    })();
    keyCache.set(cacheKey, p);
    p.catch(() => keyCache.delete(cacheKey));
  }
  return p;
}

function setStatus(form: HTMLFormElement, status: FormStatus) {
  form.dataset.sealformState = status.state;
  const el = form.querySelector<HTMLElement>("[data-sealform-status]");
  if (el) {
    el.textContent = status.message;
    el.setAttribute("role", status.state === "error" ? "alert" : "status");
  }
  form.dispatchEvent(new CustomEvent("sealform:status", { detail: status }));
}

function setSubmittable(form: HTMLFormElement, on: boolean) {
  form.querySelectorAll<HTMLButtonElement | HTMLInputElement>("[data-sealform-submit]").forEach((b) => {
    b.disabled = !on;
  });
}

/** 暗号化する項目を選ぶ。data-seal が1つも無ければ、hidden 以外の全項目（添付ファイルを含む）を対象にする。 */
export function fieldsToSeal(form: HTMLFormElement): Field[] {
  const all = Array.from(form.elements).filter(
    (el): el is Field =>
      (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement || el instanceof HTMLSelectElement) &&
      !!el.name &&
      !el.disabled,
  );
  const marked = all.filter((el) => el.hasAttribute("data-seal"));
  return marked.length > 0 ? marked : all.filter((el) => !(el instanceof HTMLInputElement && SKIP_TYPES.has(el.type)));
}

const isFileInput = (el: Field): el is HTMLInputElement => el instanceof HTMLInputElement && el.type === "file";

/** フォームの設定が sealform の前提を満たしているか。満たさなければ理由を返す。 */
function configProblem(form: HTMLFormElement): string | undefined {
  if ((form.getAttribute("method") || "get").toLowerCase() !== "post") {
    return 'このフォームは method="post" ではないため、送信できません（設定の誤り）';
  }
  if (fieldsToSeal(form).some(isFileInput) && form.enctype !== "multipart/form-data") {
    return '添付ファイルを暗号化するには enctype="multipart/form-data" が必要です（設定の誤り）';
  }
  if (!globalThis.crypto?.subtle) return "このブラウザは暗号化に対応していないため、送信できません";
  return undefined;
}

function valuesOf(el: Field): string[] {
  if (el instanceof HTMLSelectElement) return Array.from(el.selectedOptions, (o) => o.value);
  if (el instanceof HTMLInputElement && (el.type === "checkbox" || el.type === "radio")) {
    return el.checked ? [el.value] : [];
  }
  return [el.value];
}

export function formIdOf(form: HTMLFormElement): string {
  return form.dataset.sealformId || new URL(form.getAttribute("action") || "", location.href).pathname;
}

function randomName() {
  return "sealed-" + Array.from(crypto.getRandomValues(new Uint8Array(8)), (b) => b.toString(16).padStart(2, "0")).join("") + ".sf";
}

/**
 * 送信用に差し替える。文字列は暗号化した値を hidden で差し込み、元の項目を送信対象から外す。
 * 添付ファイルは暗号化したファイルに入れ替える（元のファイル名は暗号文の中に隠す）。
 * すべての暗号化に成功してから DOM を触るので、途中で失敗しても平文が混ざった状態にはならない。
 * 元に戻すための関数を返す。
 */
async function swapInSealed(form: HTMLFormElement, keys: LoadedPublicKey[], submitter: HTMLElement | null) {
  const formId = formIdOf(form);
  const maxMb = Number(form.dataset.sealformMaxMb);
  const maxBytes = Number.isFinite(maxMb) && maxMb > 0 ? maxMb * 1024 * 1024 : undefined;
  const targets = fieldsToSeal(form);
  const texts = targets.filter((el) => !isFileInput(el));
  const files = targets.filter(isFileInput);

  const sealedTexts: [string, string][] = [];
  for (const el of texts) {
    for (const v of valuesOf(el)) sealedTexts.push([el.name, await seal(keys, v, { form: formId, field: el.name })]);
  }
  const sealedFiles: [HTMLInputElement, File[]][] = [];
  for (const el of files) {
    const out: File[] = [];
    for (const f of Array.from(el.files ?? [])) {
      const bytes = await sealFile(keys, new Uint8Array(await f.arrayBuffer()), { name: f.name, type: f.type }, { form: formId, field: el.name }, { maxBytes });
      out.push(new File([bytes as BlobPart], randomName(), { type: "application/octet-stream" }));
    }
    sealedFiles.push([el, out]);
  }
  if (sealedFiles.length > 0 && typeof DataTransfer === "undefined") {
    throw new SealformError("bad-token", "このブラウザでは添付ファイルを暗号化して送れません");
  }

  // ここまでで例外が出ていなければ、全項目の暗号化に成功している
  const added: HTMLInputElement[] = [];
  const add = (name: string, value: string) => {
    const h = document.createElement("input");
    h.type = "hidden";
    h.name = name;
    h.value = value;
    h.dataset.sealformGenerated = "";
    form.appendChild(h);
    added.push(h);
  };
  for (const el of texts) {
    el.dataset.sealformName = el.name;
    el.removeAttribute("name");
  }
  for (const [n, v] of sealedTexts) add(n, v);
  const originals: [HTMLInputElement, FileList | null][] = [];
  for (const [el, out] of sealedFiles) {
    originals.push([el, el.files]);
    const dt = new DataTransfer();
    out.forEach((f) => dt.items.add(f));
    el.files = dt.files;
  }
  // form.submit() は押されたボタンの name/value を送らないので補う
  if (submitter instanceof HTMLButtonElement || submitter instanceof HTMLInputElement) {
    if (submitter.name) add(submitter.name, submitter.value);
  }
  return () => {
    added.forEach((h) => h.remove());
    for (const el of texts) {
      el.name = el.dataset.sealformName!;
      delete el.dataset.sealformName;
    }
    for (const [el, list] of originals) if (list) el.files = list;
  };
}

export function attach(form: HTMLFormElement): void {
  if (form.dataset.sealformAttached) return;
  form.dataset.sealformAttached = "";
  const keyUrl = form.dataset.sealformKey!;
  const pins = (form.dataset.sealformFingerprint ?? "").split(/[\s,]+/).filter(Boolean);
  let keys: LoadedPublicKey[] | undefined;
  let restore: (() => void) | undefined;

  setSubmittable(form, false);
  setStatus(form, { state: "loading", message: "暗号化の準備をしています…" });

  const problem = configProblem(form);
  if (problem) {
    setStatus(form, { state: "error", message: problem });
    return;
  }

  const readyMessage = (ks: LoadedPublicKey[]) =>
    ks.length === 1
      ? `入力内容はこの端末で暗号化してから送信されます（鍵の指紋 ${ks[0]!.doc.fingerprint.slice(0, 19)}…）`
      : `入力内容はこの端末で暗号化してから送信されます（読める担当者の鍵 ${ks.length} 個）`;

  fetchKeys(keyUrl, pins).then(
    (ks) => {
      keys = ks;
      setSubmittable(form, true);
      setStatus(form, { state: "ready", message: readyMessage(ks) });
    },
    (e: unknown) => {
      setStatus(form, {
        state: "error",
        message: `暗号化の準備に失敗したため、送信できません: ${e instanceof Error ? e.message : String(e)}`,
      });
    },
  );

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    if (!keys || form.dataset.sealformState === "sending") return;
    setSubmittable(form, false);
    setStatus(form, { state: "sending", message: "暗号化しています…" });
    try {
      restore = await swapInSealed(form, keys, (ev as SubmitEvent).submitter);
    } catch (e) {
      setSubmittable(form, true);
      setStatus(form, {
        state: "error",
        message: `暗号化に失敗したため、送信を止めました: ${e instanceof Error ? e.message : String(e)}`,
      });
      return;
    }
    // requestSubmit() だと submit イベントが再び発火するので、素の submit() を使う
    HTMLFormElement.prototype.submit.call(form);
  });

  // 「戻る」で bfcache から復元されたときに、入力欄を元に戻す
  addEventListener("pageshow", (ev) => {
    if (!(ev as PageTransitionEvent).persisted || !restore) return;
    restore();
    restore = undefined;
    if (keys) {
      setSubmittable(form, true);
      setStatus(form, { state: "ready", message: readyMessage(keys) });
    }
  });
}

export function init(root: ParentNode = document): void {
  root.querySelectorAll<HTMLFormElement>("form[data-sealform-key]").forEach(attach);
}
