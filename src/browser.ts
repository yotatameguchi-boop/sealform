import { isSealed, loadKeys, seal, sealFile, SealformError, type LoadedPublicKey } from "./core.js";

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
 *
 * submit イベントは document の捕捉段階で先に受け取り、他のスクリプトには渡さない。
 * フォーム部品（Contact Form 7 など）が自前で平文を AJAX 送信してしまうのを防ぐため。
 *
 * 表示の言語は data-sealform-lang、無ければ祖先の lang 属性で決める（ja / en）。
 */

type Lang = "ja" | "en";

const MESSAGES = {
  ja: {
    loading: "暗号化の準備をしています…",
    readyOne: (fp: string) => `入力内容はこの端末で暗号化してから送信されます（鍵の指紋 ${fp}…）`,
    readyMany: (n: number) => `入力内容はこの端末で暗号化してから送信されます（読める担当者の鍵 ${n} 個）`,
    sending: "暗号化しています…",
    prepFailed: (r: string) => `暗号化の準備に失敗したため、送信できません: ${r}`,
    sealFailed: (r: string) => `暗号化に失敗したため、送信を止めました: ${r}`,
    notPost: 'このフォームは method="post" ではないため、送信できません（設定の誤り）',
    needMultipart: '添付ファイルを暗号化するには enctype="multipart/form-data" が必要です（設定の誤り）',
    noCrypto: "このブラウザは暗号化に対応していないため、送信できません",
    noDataTransfer: "このブラウザでは添付ファイルを暗号化して送れません",
    cleared: "前回の入力内容は暗号化して送信済みのため、ここには表示できません。お手数ですが入力し直してください。",
  },
  en: {
    loading: "Preparing encryption…",
    readyOne: (fp: string) => `Your input will be encrypted on this device before it is sent (key fingerprint ${fp}…)`,
    readyMany: (n: number) => `Your input will be encrypted on this device before it is sent (readable by ${n} recipients)`,
    sending: "Encrypting…",
    prepFailed: (r: string) => `This form cannot be sent because encryption could not be prepared: ${r}`,
    sealFailed: (r: string) => `Sending was stopped because encryption failed: ${r}`,
    notPost: 'This form cannot be sent because its method is not "post" (configuration error)',
    needMultipart: 'Encrypting attachments requires enctype="multipart/form-data" (configuration error)',
    noCrypto: "This browser does not support the encryption this form requires",
    noDataTransfer: "This browser cannot send encrypted attachments",
    cleared: "Your previous input was encrypted and cannot be shown here. Please enter it again.",
  },
} as const;

const EN_REASONS: Record<string, string> = {
  "bad-key": "the public key could not be loaded or is invalid",
  "key-expired": "the public key has expired",
  "fingerprint-mismatch": "the public key does not match the registered fingerprints",
  "too-large": "the file is too large",
};

function langOf(form: HTMLFormElement): Lang {
  const l = form.dataset.sealformLang || form.closest("[lang]")?.getAttribute("lang") || "ja";
  return l.toLowerCase().startsWith("en") ? "en" : "ja";
}

function reason(e: unknown, lang: Lang): string {
  if (lang === "ja") return e instanceof Error ? e.message : String(e);
  return (e instanceof SealformError && EN_REASONS[e.code]) || "an unexpected error occurred";
}

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
  // React などで後から購読する側のために、最新の表示を残しておく（sealform:status イベントでも通知する）
  form.dataset.sealformMessage = status.message;
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
function configProblem(form: HTMLFormElement): "notPost" | "needMultipart" | "noCrypto" | undefined {
  if ((form.getAttribute("method") || "get").toLowerCase() !== "post") return "notPost";
  if (fieldsToSeal(form).some(isFileInput) && form.enctype !== "multipart/form-data") return "needMultipart";
  if (!globalThis.crypto?.subtle) return "noCrypto";
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
    throw new SealformError("bad-token", MESSAGES[langOf(form)].noDataTransfer);
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
  const lang = langOf(form);
  const m = MESSAGES[lang];
  let keys: LoadedPublicKey[] | undefined;
  let restore: (() => void) | undefined;

  setSubmittable(form, false);
  setStatus(form, { state: "loading", message: m.loading });

  // 設定に問題があっても submit の横取りはしておく（他のスクリプトに平文を渡さないため）
  const problem = configProblem(form);

  // サーバーが検査で差し戻したとき、受け取った暗号文を入力欄に戻してくることがある（Contact Form 7 など）。
  // そのまま送ると暗号文をさらに暗号化してしまうので、暗号文の入った欄は空にする
  let cleared = false;
  for (const el of Array.from(form.elements)) {
    if ((el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) && el.type !== "hidden" && isSealed(el.value)) {
      el.value = "";
      cleared = true;
    }
  }

  const readyMessage = (ks: LoadedPublicKey[]) =>
    (cleared ? m.cleared + " " : "") +
    (ks.length === 1 ? m.readyOne(ks[0]!.doc.fingerprint.slice(0, 19)) : m.readyMany(ks.length));

  if (problem) {
    setStatus(form, { state: "error", message: m[problem] });
  } else {
    fetchKeys(keyUrl, pins).then(
      (ks) => {
        keys = ks;
        setSubmittable(form, true);
        setStatus(form, { state: "ready", message: readyMessage(ks) });
      },
      (e: unknown) => setStatus(form, { state: "error", message: m.prepFailed(reason(e, lang)) }),
    );
  }

  const onSubmit = async (ev: Event) => {
    if (ev.target !== form) return;
    ev.preventDefault();
    ev.stopImmediatePropagation();
    if (!keys || form.dataset.sealformState === "sending") return;
    setSubmittable(form, false);
    setStatus(form, { state: "sending", message: m.sending });
    try {
      restore = await swapInSealed(form, keys, (ev as SubmitEvent).submitter);
    } catch (e) {
      setSubmittable(form, true);
      setStatus(form, { state: "error", message: m.sealFailed(reason(e, lang)) });
      return;
    }
    // requestSubmit() だと submit イベントが再び発火するので、素の submit() を使う
    HTMLFormElement.prototype.submit.call(form);
  };
  form.ownerDocument.addEventListener("submit", onSubmit, true);

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

/**
 * ページ内のフォームを自動でつなぐ。data-sealform-manual の付いたフォームは対象外
 * （React などで、描画が落ち着いてから自分で attach() するとき用）。
 */
export function init(root: ParentNode = document): void {
  root.querySelectorAll<HTMLFormElement>("form[data-sealform-key]:not([data-sealform-manual])").forEach(attach);
}
