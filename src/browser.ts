import { loadPublicKey, seal, SealformError, type LoadedPublicKey } from "./core.js";

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
 */

const SKIP_TYPES = new Set(["hidden", "submit", "button", "reset", "image"]);

export interface FormStatus {
  state: "loading" | "ready" | "sending" | "error";
  message: string;
}

type Field = HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement;

const keyCache = new Map<string, Promise<LoadedPublicKey>>();

async function fetchKey(url: string, pin: string | undefined): Promise<LoadedPublicKey> {
  const cacheKey = `${url}\n${pin ?? ""}`;
  let p = keyCache.get(cacheKey);
  if (!p) {
    p = (async () => {
      const res = await fetch(url, { credentials: "omit", cache: "no-cache" });
      if (!res.ok) throw new SealformError("bad-key", `公開鍵を取得できません（HTTP ${res.status}）`);
      return loadPublicKey(await res.json(), { pin });
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

/** 暗号化する項目を選ぶ。data-seal が1つも無ければ、hidden 以外の全項目を対象にする。 */
export function fieldsToSeal(form: HTMLFormElement): Field[] {
  const all = Array.from(form.elements).filter(
    (el): el is Field =>
      (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement || el instanceof HTMLSelectElement) &&
      !!el.name &&
      !el.disabled,
  );
  const marked = all.filter((el) => el.hasAttribute("data-seal"));
  const targets = marked.length > 0 ? marked : all.filter((el) => !(el instanceof HTMLInputElement && SKIP_TYPES.has(el.type)));
  for (const el of targets) {
    if (el instanceof HTMLInputElement && el.type === "file") {
      throw new SealformError(
        "bad-token",
        marked.length > 0
          ? `添付ファイル「${el.name}」の暗号化にはまだ対応していません`
          : `添付ファイル「${el.name}」が平文で送られてしまうため送信を止めました。暗号化する項目に data-seal を付けてください`,
      );
    }
  }
  return targets;
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

/** 送信用に、暗号化した値を hidden で差し込み、元の項目を送信対象から外す。戻すための関数を返す。 */
async function swapInSealed(form: HTMLFormElement, key: LoadedPublicKey, submitter: HTMLElement | null) {
  const formId = formIdOf(form);
  const targets = fieldsToSeal(form);
  const sealed: [string, string][] = [];
  for (const el of targets) {
    for (const v of valuesOf(el)) sealed.push([el.name, await seal(key, v, { form: formId, field: el.name })]);
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
  for (const el of targets) {
    el.dataset.sealformName = el.name;
    el.removeAttribute("name");
  }
  for (const [n, v] of sealed) add(n, v);
  // form.submit() は押されたボタンの name/value を送らないので補う
  if (submitter instanceof HTMLButtonElement || submitter instanceof HTMLInputElement) {
    if (submitter.name) add(submitter.name, submitter.value);
  }
  return () => {
    added.forEach((h) => h.remove());
    for (const el of targets) {
      el.name = el.dataset.sealformName!;
      delete el.dataset.sealformName;
    }
  };
}

export function attach(form: HTMLFormElement): void {
  if (form.dataset.sealformAttached) return;
  form.dataset.sealformAttached = "";
  const keyUrl = form.dataset.sealformKey!;
  const pin = form.dataset.sealformFingerprint || undefined;
  let key: LoadedPublicKey | undefined;
  let restore: (() => void) | undefined;

  setSubmittable(form, false);
  setStatus(form, { state: "loading", message: "暗号化の準備をしています…" });

  if ((form.getAttribute("method") || "get").toLowerCase() !== "post") {
    setStatus(form, { state: "error", message: "このフォームは method=\"post\" ではないため、送信できません（設定の誤り）" });
    return;
  }
  if (!globalThis.crypto?.subtle) {
    setStatus(form, { state: "error", message: "このブラウザは暗号化に対応していないため、送信できません" });
    return;
  }

  fetchKey(keyUrl, pin).then(
    (k) => {
      key = k;
      setSubmittable(form, true);
      setStatus(form, {
        state: "ready",
        message: `入力内容はこの端末で暗号化してから送信されます（鍵の指紋 ${k.doc.fingerprint.slice(0, 19)}…）`,
      });
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
    if (!key || form.dataset.sealformState === "sending") return;
    setSubmittable(form, false);
    setStatus(form, { state: "sending", message: "暗号化しています…" });
    try {
      restore = await swapInSealed(form, key, (ev as SubmitEvent).submitter);
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
    if (key) {
      setSubmittable(form, true);
      setStatus(form, { state: "ready", message: "入力内容はこの端末で暗号化してから送信されます" });
    }
  });
}

export function init(root: ParentNode = document): void {
  root.querySelectorAll<HTMLFormElement>("form[data-sealform-key]").forEach(attach);
}
