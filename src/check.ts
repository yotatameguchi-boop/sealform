import { parse } from "parse5";
import type { DefaultTreeAdapterMap } from "parse5";
import { loadKeys, SealformError } from "./core.js";

/**
 * 公開中のページを外から点検する。
 *
 * ブラウザで暗号化する方式の弱点は「サーバーを乗っ取られると、配る JS や公開鍵を差し替えられる」こと。
 * サーバーの中からは気づけないので、別の場所（手元の PC や GitHub Actions の定期実行）から
 * 「配っている JS が公式の配布物と同じか」「公開鍵の指紋が登録したものと同じか」を確かめる。
 *
 * HTML はブラウザと同じ規則で解釈する（parse5）。コメント・<template>・<noscript> の中身は、
 * ブラウザでもフォームやスクリプトにならないので、点検の対象にしない。
 *
 * **点検に通っても、実際にそのページで暗号化されることまでは保証しない。** 見ているのは配信中の
 * HTML・公開鍵・sealform.js で、ページ内の他のスクリプトがする事や、ブラウザでの実際の動きは確かめていない。
 */

export type Level = "pass" | "warn" | "fail";

export interface Finding {
  id: string;
  level: Level;
  message: string;
}

export interface CheckOptions {
  /** 登録しておいた公開鍵の指紋（SHA256:...）。複数の担当者・更新中の新旧の鍵なら全部並べる。 */
  fingerprints?: string[];
  /** 公式に配布している sealform.js の SHA-384（"sha384-..."）。 */
  knownScriptHashes?: string[];
  /** 監視するフォームの送信先（例: "/contact"）。そのフォームが sealform で守られていることを求める。 */
  formActions?: string[];
  /** 暗号化されていなければならない項目名。監視するフォームのどれかで暗号化されていることを求める。 */
  sealedFields?: string[];
  fetch?: typeof fetch;
  now?: Date;
}

export const CHECK_SCOPE_NOTE =
  "点検に通っても、実際にこのページで暗号化されることまでは保証しません。確かめたのは配信中の HTML・公開鍵・sealform.js で、" +
  "ページ内の他のスクリプトの動きや、ブラウザでの実際の送信内容は確かめていません。";

type Node = DefaultTreeAdapterMap["node"];
type Element = DefaultTreeAdapterMap["element"];

/** 文書の要素をたどる。<template> の中身は別の断片なので childNodes に含まれず、自然に対象外になる。 */
function* elements(node: Node): Generator<Element> {
  if ("tagName" in node) yield node;
  if ("childNodes" in node) for (const c of node.childNodes) yield* elements(c);
}

const attr = (el: Element, name: string): string | undefined => el.attrs.find((a) => a.name === name)?.value;
const has = (el: Element, name: string) => el.attrs.some((a) => a.name === name);

function isDescendant(el: Element, ancestor: Element): boolean {
  let p: Node | null = el.parentNode;
  while (p) {
    if (p === ancestor) return true;
    p = "parentNode" in p ? (p.parentNode as Node | null) : null;
  }
  return false;
}

const CONTROL_TAGS = new Set(["input", "textarea", "select", "button"]);
const SKIP_TYPES = new Set(["hidden", "submit", "button", "reset", "image"]);

/** フォームに属する部品（中にあるもの・form 属性でつながるもの）。 */
function controlsOf(form: Element, all: Element[]): Element[] {
  const id = attr(form, "id");
  return all.filter((el) => {
    if (!CONTROL_TAGS.has(el.tagName)) return false;
    const owner = attr(el, "form");
    if (owner !== undefined) return id !== undefined && owner === id;
    return isDescendant(el, form);
  });
}

function isSubmitButton(el: Element): boolean {
  const type = (attr(el, "type") ?? "").toLowerCase();
  if (el.tagName === "button") return type === "" || type === "submit";
  return el.tagName === "input" && (type === "submit" || type === "image");
}

async function sha384(data: ArrayBuffer): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-384", data));
  return "sha384-" + btoa(String.fromCharCode(...d));
}

function isLocal(u: URL) {
  return u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "[::1]";
}

/** CSP の script-src（無ければ default-src）を読み、広すぎる指定を挙げる。 */
function cspProblems(policies: string[]): { ok: boolean; problems: string[] } {
  if (policies.length === 0) return { ok: false, problems: ["Content-Security-Policy がありません"] };
  // 複数の CSP は「すべてを満たすもの」だけが許されるので、どれか1つでも制限できていればよい
  const results = policies.map((policy) => {
    const directive = (name: string) =>
      policy.split(";").map((d) => d.trim().split(/\s+/)).find((d) => d[0]?.toLowerCase() === name)?.slice(1);
    const sources = directive("script-src") ?? directive("default-src");
    if (!sources) return ["script-src（または default-src）がありません"];
    const lower = sources.map((s) => s.toLowerCase());
    const problems: string[] = [];
    const hashOrNonce = lower.some((s) => /^'(nonce-|sha(256|384|512)-)/.test(s));
    if (lower.includes("'unsafe-inline'") && !hashOrNonce && !lower.includes("'strict-dynamic'")) problems.push("'unsafe-inline' を許しています");
    if (lower.includes("'unsafe-eval'")) problems.push("'unsafe-eval' を許しています");
    if (!lower.includes("'strict-dynamic'")) {
      const broad = sources.filter((s) => s === "*" || /^(https?|data|blob|filesystem):$/i.test(s) || /^(https?:\/\/)?\*\./i.test(s));
      if (broad.length > 0) problems.push(`どこからでもスクリプトを読み込める指定があります（${broad.join(" ")}）`);
    }
    return problems;
  });
  const best = results.reduce((a, b) => (b.length < a.length ? b : a));
  return { ok: best.length === 0, problems: best };
}

export async function checkSite(pageUrl: string, opts: CheckOptions = {}): Promise<Finding[]> {
  const f = opts.fetch ?? fetch;
  const out: Finding[] = [];
  const add = (id: string, level: Level, message: string) => out.push({ id, level, message });
  const page = new URL(pageUrl);

  if (page.protocol === "https:") add("https", "pass", "HTTPS で配信されています");
  else if (isLocal(page)) add("https", "warn", "HTTPS ではありません（localhost なので警告に留めます）");
  else add("https", "fail", "HTTPS ではありません。暗号化の前に、ページと JS が改ざんされ得ます");

  const res = await f(page, { redirect: "follow" });
  if (!res.ok) {
    add("page", "fail", `ページを取得できません（HTTP ${res.status}）`);
    return out;
  }
  const doc = parse(await res.text());
  const all = Array.from(elements(doc));
  const baseEl = all.find((e) => e.tagName === "base" && has(e, "href"));
  const base = baseEl ? new URL(attr(baseEl, "href")!, page) : page;

  // --- CSP（ヘッダーと <meta http-equiv>） ---
  const policies = [
    ...(res.headers.get("content-security-policy") ? [res.headers.get("content-security-policy")!] : []),
    ...all
      .filter((e) => e.tagName === "meta" && (attr(e, "http-equiv") ?? "").toLowerCase() === "content-security-policy")
      .map((e) => attr(e, "content") ?? ""),
  ];
  const csp = cspProblems(policies);
  if (csp.ok) add("csp", "pass", "CSP で読み込めるスクリプトが制限されています");
  else add("csp", "warn", `CSP が不十分です: ${csp.problems.join("、")}。ページ内のスクリプトは入力内容を読めるので、読み込めるスクリプトを絞ってください`);

  // --- フォーム ---
  const allForms = all.filter((e) => e.tagName === "form");
  const forms = allForms.filter((e) => has(e, "data-sealform-key"));
  const actionOf = (form: Element) => new URL(attr(form, "action") ?? "", base).pathname;

  for (const action of opts.formActions ?? []) {
    const target = allForms.filter((form) => actionOf(form) === action);
    if (target.length === 0) add("watched-form", "fail", `送信先が ${action} のフォームが見つかりません`);
    else if (target.some((form) => !has(form, "data-sealform-key"))) {
      add("watched-form", "fail", `送信先が ${action} のフォームに sealform が付いていません（平文で送られます）`);
    } else add("watched-form", "pass", `送信先が ${action} のフォームは sealform で守られています`);
  }

  const unprotected = allForms.filter((form) => {
    if (has(form, "data-sealform-key")) return false;
    if ((attr(form, "method") ?? "get").toLowerCase() !== "post") return false;
    return controlsOf(form, all).some((c) => c.tagName === "textarea" || (c.tagName === "input" && !SKIP_TYPES.has((attr(c, "type") ?? "text").toLowerCase())));
  });
  if (unprotected.length > 0) {
    add("other-forms", "warn", `sealform の付いていない POST フォームが ${unprotected.length} 個あります（送信先: ${unprotected.map(actionOf).join(", ")}）。入力は暗号化されません`);
  }

  if (forms.length === 0) {
    add("form", "fail", "data-sealform-key の付いたフォームが見つかりません（sealform が外された可能性）");
    return out;
  }

  const keyUrls = new Set<string>();
  const sealedNames = new Set<string>();
  for (const [i, form] of forms.entries()) {
    const label = forms.length > 1 ? `フォーム${i + 1}（${actionOf(form)}）: ` : "";
    const method = (attr(form, "method") ?? "get").toLowerCase();
    if (method !== "post") add("form-method", "fail", `${label}method が POST ではありません`);
    else add("form-method", "pass", `${label}method は POST です`);

    const controls = controlsOf(form, all);
    const submits = controls.filter(isSubmitButton);
    const guards = submits.filter((b) => has(b, "data-sealform-submit"));
    const loose = submits.filter((b) => !has(b, "data-sealform-submit"));
    if (guards.length === 0) {
      add("submit-guard", "fail", `${label}送信ボタンに data-sealform-submit がありません。JS が動かないとき平文で送られます`);
    } else if (guards.some((g) => !has(g, "disabled"))) {
      add("submit-guard", "fail", `${label}送信ボタンが最初から押せる状態です。HTML で disabled にしてください`);
    } else if (loose.length > 0) {
      add("submit-guard", "fail", `${label}data-sealform-submit の付いていない送信ボタンが ${loose.length} 個あります。JS が動かないとき、そこから平文で送られます`);
    } else add("submit-guard", "pass", `${label}JS が動くまで送信ボタンは押せません`);

    const named = controls.filter((c) => c.tagName !== "button" && attr(c, "name"));
    const marked = named.filter((c) => has(c, "data-seal"));
    const covered = marked.length > 0 ? marked : named.filter((c) => !SKIP_TYPES.has((attr(c, "type") ?? "").toLowerCase()));
    covered.forEach((c) => sealedNames.add(attr(c, "name")!));
    if (marked.length === 0) add("fields", "pass", `${label}hidden 以外の全項目が暗号化されます`);
    else add("fields", "pass", `${label}暗号化される項目: ${marked.map((c) => attr(c, "name")).join(", ")}`);

    keyUrls.add(new URL(attr(form, "data-sealform-key")!, base).href);
    const pinned = (attr(form, "data-sealform-fingerprint") ?? "").split(/[\s,]+/).filter(Boolean);
    const registered = opts.fingerprints ?? [];
    const strange = pinned.filter((p) => registered.length > 0 && !registered.includes(p));
    if (strange.length > 0) {
      add("pin", "fail", `${label}ページに、登録していない指紋が書かれています（${strange.join(", ")}）`);
    }
  }

  for (const name of opts.sealedFields ?? []) {
    if (sealedNames.has(name)) add("watched-field", "pass", `項目「${name}」は暗号化されます`);
    else add("watched-field", "fail", `項目「${name}」が暗号化の対象になっていません（無いか、data-seal が外されています）`);
  }

  // --- 公開鍵 ---
  for (const url of keyUrls) {
    const u = new URL(url);
    if (u.protocol !== "https:" && !isLocal(u)) add("key", "fail", `公開鍵が HTTPS で配信されていません: ${url}`);
    let keyDoc: unknown;
    try {
      const r = await f(u);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      keyDoc = await r.json();
    } catch (e) {
      add("key", "fail", `公開鍵を取得できません: ${url}（${e instanceof Error ? e.message : e}）`);
      continue;
    }
    const registered = opts.fingerprints ?? [];
    try {
      const keys = await loadKeys(keyDoc, { pins: registered, now: opts.now });
      const fps = keys.map((k) => k.doc.fingerprint);
      if (registered.length > 0) {
        add("key", "pass", `暗号化に使われる鍵 ${keys.length} 個は、すべて登録したものです`);
        const missing = registered.filter((r) => !fps.includes(r));
        if (missing.length > 0) {
          add("key-missing", "warn", `登録した鍵のうち ${missing.length} 個が使われていません（更新で外した鍵なら登録からも外してください）: ${missing.join(", ")}`);
        }
      } else {
        add("key", "warn", `公開鍵は有効ですが、指紋を登録していないため差し替えを検出できません。${fps.map((f) => `--fingerprint ${f}`).join(" ")} を付けて実行してください`);
      }
      for (const k of keys) {
        const days = (Date.parse(k.doc.expires) - (opts.now ?? new Date()).getTime()) / 86400_000;
        const who = k.doc.label ? `「${k.doc.label}」の` : "";
        if (days < 30) add("key-expiry", "warn", `${who}公開鍵（${k.doc.kid}）の有効期限まで ${Math.floor(days)} 日です。鍵を更新してください`);
      }
    } catch (e) {
      const msg = e instanceof SealformError && e.code === "fingerprint-mismatch"
        ? `公開鍵が差し替えられたか、鍵が追加されています。${e.message}`
        : `公開鍵が不正です: ${e instanceof Error ? e.message : e}`;
      add("key", "fail", msg);
    }
  }

  // --- 配布している JS ---
  const scriptEls = all.filter((e) => e.tagName === "script");
  const scripts = scriptEls.filter((e) => /sealform/i.test(attr(e, "src") ?? ""));
  if (scripts.length === 0) {
    add("script", "fail", "sealform のスクリプトが読み込まれていません。インラインで書き換えられている可能性があります");
  }
  for (const s of scripts) {
    const src = new URL(attr(s, "src")!, base);
    let body: ArrayBuffer;
    try {
      const r = await f(src);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      body = await r.arrayBuffer();
    } catch (e) {
      add("script", "fail", `スクリプトを取得できません: ${src.href}（${e instanceof Error ? e.message : e}）`);
      continue;
    }
    const actual = await sha384(body);
    const integrity = attr(s, "integrity");
    if (!integrity) add("sri", "warn", "script に integrity（SRI）がありません");
    else if (!integrity.split(/\s+/).includes(actual)) add("sri", "fail", "integrity の値と、実際に配信されている JS が一致しません");
    else add("sri", "pass", "integrity（SRI）と配信中の JS が一致します");

    const known = opts.knownScriptHashes ?? [];
    if (known.length === 0) add("script", "warn", "公式配布物のハッシュが分からないため、JS の改ざんは確認していません");
    else if (known.includes(actual)) add("script", "pass", "配信中の JS は公式の配布物と同一です");
    else add("script", "fail", `配信中の JS が公式の配布物と一致しません（改ざんの可能性）: ${actual}`);
  }

  const others = scriptEls.length - scripts.length;
  if (others > 0) {
    const msg = `sealform 以外のスクリプトが ${others} 個あります。これらは入力内容を読めますが、内容は確かめていません`;
    add("other-scripts", csp.ok ? "pass" : "warn", csp.ok ? `${msg}（CSP で読み込み元は制限されています）` : msg);
  }

  return out;
}

export function worstLevel(findings: Finding[]): Level {
  if (findings.some((f) => f.level === "fail")) return "fail";
  if (findings.some((f) => f.level === "warn")) return "warn";
  return "pass";
}
