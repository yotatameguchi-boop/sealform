import { loadPublicKey, SealformError } from "./core.js";

/**
 * 公開中のページを外から点検する。
 *
 * ブラウザで暗号化する方式の弱点は「サーバーを乗っ取られると、配る JS や公開鍵を差し替えられる」こと。
 * サーバーの中からは気づけないので、別の場所（手元の PC や GitHub Actions の定期実行）から
 * 「配っている JS が公式の配布物と同じか」「公開鍵の指紋が登録したものと同じか」を確かめる。
 */

export type Level = "pass" | "warn" | "fail";

export interface Finding {
  id: string;
  level: Level;
  message: string;
}

export interface CheckOptions {
  /** 登録しておいた公開鍵の指紋（SHA256:...）。変わっていたら差し替えを疑う。 */
  fingerprint?: string;
  /** 公式に配布している sealform.js の SHA-384（"sha384-..."）。 */
  knownScriptHashes?: string[];
  fetch?: typeof fetch;
  now?: Date;
}

interface Tag {
  name: string;
  attrs: Map<string, string>;
  start: number;
  end: number;
}

function parseAttrs(s: string): Map<string, string> {
  const attrs = new Map<string, string>();
  const re = /([^\s"'<>\/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  for (const m of s.matchAll(re)) {
    attrs.set(m[1]!.toLowerCase(), decodeEntities(m[2] ?? m[3] ?? m[4] ?? ""));
  }
  return attrs;
}

function decodeEntities(s: string): string {
  return s.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
}

function findTags(html: string, name: string): Tag[] {
  const re = new RegExp(`<${name}\\b([^>]*)>`, "gi");
  return Array.from(html.matchAll(re), (m) => ({
    name,
    attrs: parseAttrs(m[1]!),
    start: m.index!,
    end: m.index! + m[0].length,
  }));
}

async function sha384(data: ArrayBuffer): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-384", data));
  return "sha384-" + btoa(String.fromCharCode(...d));
}

function isLocal(u: URL) {
  return u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "[::1]";
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
  const html = await res.text();

  // --- CSP ---
  const csp = res.headers.get("content-security-policy");
  if (!csp) {
    add("csp", "warn", "Content-Security-Policy がありません。外部スクリプトの混入を防ぐため設定を推奨します");
  } else {
    const scriptSrc = /(?:^|;)\s*script-src\s+([^;]*)/i.exec(csp)?.[1] ?? /(?:^|;)\s*default-src\s+([^;]*)/i.exec(csp)?.[1];
    if (!scriptSrc) add("csp", "warn", "CSP に script-src がありません");
    else if (/'unsafe-inline'/.test(scriptSrc) && !/'nonce-|'sha(256|384|512)-|'strict-dynamic'/.test(scriptSrc)) {
      add("csp", "warn", "CSP の script-src が 'unsafe-inline' を許しています");
    } else add("csp", "pass", "CSP で読み込めるスクリプトが制限されています");
  }

  // --- フォーム ---
  const forms = findTags(html, "form").filter((t) => t.attrs.has("data-sealform-key"));
  if (forms.length === 0) {
    add("form", "fail", "data-sealform-key の付いたフォームが見つかりません（sealform が外された可能性）");
    return out;
  }
  const keyUrls = new Set<string>();
  for (const [i, form] of forms.entries()) {
    const label = forms.length > 1 ? `フォーム${i + 1}: ` : "";
    const method = (form.attrs.get("method") || "get").toLowerCase();
    if (method !== "post") add("form-method", "fail", `${label}method が POST ではありません`);
    else add("form-method", "pass", `${label}method は POST です`);

    const close = html.toLowerCase().indexOf("</form>", form.end);
    const body = html.slice(form.end, close === -1 ? undefined : close);
    const guards = [...findTags(body, "button"), ...findTags(body, "input")].filter((t) => t.attrs.has("data-sealform-submit"));
    if (guards.length === 0) {
      add("submit-guard", "fail", `${label}送信ボタンに data-sealform-submit がありません。JS が動かないとき平文で送られます`);
    } else if (guards.some((g) => !g.attrs.has("disabled"))) {
      add("submit-guard", "fail", `${label}送信ボタンが最初から押せる状態です。HTML で disabled にしてください`);
    } else add("submit-guard", "pass", `${label}JS が動くまで送信ボタンは押せません`);

    const sealed = findTags(body, "(?:input|textarea|select)").filter((t) => t.attrs.has("data-seal"));
    if (sealed.length === 0) add("fields", "pass", `${label}hidden 以外の全項目が暗号化されます`);
    else add("fields", "pass", `${label}暗号化される項目: ${sealed.map((t) => t.attrs.get("name") ?? "?").join(", ")}`);

    keyUrls.add(new URL(form.attrs.get("data-sealform-key")!, page).href);
    const pinned = form.attrs.get("data-sealform-fingerprint");
    if (pinned && opts.fingerprint && pinned !== opts.fingerprint) {
      add("pin", "fail", `${label}ページに書かれた指紋が、登録した指紋と違います（${pinned}）`);
    }
  }

  // --- 公開鍵 ---
  for (const url of keyUrls) {
    const u = new URL(url);
    if (u.protocol !== "https:" && !isLocal(u)) add("key", "fail", `公開鍵が HTTPS で配信されていません: ${url}`);
    let doc: unknown;
    try {
      const r = await f(u);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      doc = await r.json();
    } catch (e) {
      add("key", "fail", `公開鍵を取得できません: ${url}（${e instanceof Error ? e.message : e}）`);
      continue;
    }
    try {
      const k = await loadPublicKey(doc, { pin: opts.fingerprint, now: opts.now });
      if (opts.fingerprint) add("key", "pass", `公開鍵の指紋が登録したものと一致します（${k.doc.fingerprint}）`);
      else add("key", "warn", `公開鍵は有効ですが、指紋を登録していないため差し替えを検出できません。--fingerprint ${k.doc.fingerprint} を付けて実行してください`);
      const days = (Date.parse(k.doc.expires) - (opts.now ?? new Date()).getTime()) / 86400_000;
      if (days < 30) add("key-expiry", "warn", `公開鍵の有効期限まで ${Math.floor(days)} 日です。鍵を更新してください`);
    } catch (e) {
      const msg = e instanceof SealformError && e.code === "fingerprint-mismatch"
        ? `公開鍵が差し替えられています。${e.message}`
        : `公開鍵が不正です: ${e instanceof Error ? e.message : e}`;
      add("key", "fail", msg);
    }
  }

  // --- 配布している JS ---
  const scripts = findTags(html, "script").filter((t) => /sealform/i.test(t.attrs.get("src") ?? ""));
  if (scripts.length === 0) {
    add("script", "fail", "sealform のスクリプトが読み込まれていません。インラインで書き換えられている可能性があります");
  }
  for (const s of scripts) {
    const src = new URL(s.attrs.get("src")!, page);
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
    const integrity = s.attrs.get("integrity");
    if (!integrity) add("sri", "warn", "script に integrity（SRI）がありません");
    else if (!integrity.split(/\s+/).includes(actual)) add("sri", "fail", "integrity の値と、実際に配信されている JS が一致しません");
    else add("sri", "pass", "integrity（SRI）と配信中の JS が一致します");

    const known = opts.knownScriptHashes ?? [];
    if (known.length === 0) add("script", "warn", "公式配布物のハッシュが分からないため、JS の改ざんは確認していません");
    else if (known.includes(actual)) add("script", "pass", "配信中の JS は公式の配布物と同一です");
    else add("script", "fail", `配信中の JS が公式の配布物と一致しません（改ざんの可能性）: ${actual}`);
  }

  return out;
}

export function worstLevel(findings: Finding[]): Level {
  if (findings.some((f) => f.level === "fail")) return "fail";
  if (findings.some((f) => f.level === "warn")) return "warn";
  return "pass";
}
