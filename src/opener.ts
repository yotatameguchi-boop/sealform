// オフライン復号ツール（dist/sealform-opener.html に1ファイルとして埋め込まれる）
import { findTokens, isSealedFile, open, openFile, safeFileName, type PrivateKeyEntry } from "./core.js";
import { unlockPrivateKey } from "./keyfile.js";

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;

const keyInput = $<HTMLInputElement>("key");
const passInput = $<HTMLInputElement>("pass");
const tokensInput = $<HTMLTextAreaElement>("tokens");
const fileInput = $<HTMLInputElement>("tokens-file");
const fileList = $<HTMLUListElement>("sealed-files");
const formInput = $<HTMLInputElement>("expect-form");
const runBtn = $<HTMLButtonElement>("run");
const clearBtn = $<HTMLButtonElement>("clear");
const statusEl = $<HTMLElement>("status");
const results = $<HTMLTableSectionElement>("results");
const table = $<HTMLTableElement>("result-table");

/** 読み込んだ暗号化ファイル（.sf）。テキストのファイルは暗号文の欄に足す。 */
let sealedFiles: { name: string; data: Uint8Array }[] = [];
/** 復号したファイルのダウンロード用 URL。消去するときに解放する。 */
let objectUrls: string[] = [];

function renderFileList() {
  fileList.replaceChildren(
    ...sealedFiles.map((f) => {
      const li = document.createElement("li");
      li.textContent = `${f.name}（${f.data.length.toLocaleString()} バイト）`;
      return li;
    }),
  );
}

fileInput.addEventListener("change", async () => {
  for (const f of Array.from(fileInput.files ?? [])) {
    const data = new Uint8Array(await f.arrayBuffer());
    if (isSealedFile(data)) sealedFiles.push({ name: f.name, data });
    else tokensInput.value += (tokensInput.value ? "\n" : "") + new TextDecoder().decode(data);
  }
  fileInput.value = "";
  renderFileList();
});

function say(msg: string, kind: "info" | "error" = "info") {
  statusEl.textContent = msg;
  statusEl.dataset.kind = kind;
}

function row(cells: (string | Node)[], cls?: string) {
  const tr = document.createElement("tr");
  if (cls) tr.className = cls;
  for (const c of cells) {
    const td = document.createElement("td");
    td.append(c);
    tr.append(td);
  }
  results.append(tr);
}

function releaseUrls() {
  objectUrls.forEach((u) => URL.revokeObjectURL(u));
  objectUrls = [];
}

runBtn.addEventListener("click", async () => {
  results.replaceChildren();
  releaseUrls();
  table.hidden = true;
  const keyFiles = Array.from(keyInput.files ?? []);
  if (keyFiles.length === 0) return say("秘密鍵ファイルを選んでください", "error");
  const tokens = findTokens(tokensInput.value);
  if (tokens.length === 0 && sealedFiles.length === 0) {
    return say("暗号文（sf1./sf2. で始まる文字列）も、暗号化されたファイルもありません", "error");
  }
  runBtn.disabled = true;
  say("鍵を開いています…（鍵1つにつき数秒かかります）");
  const ring: PrivateKeyEntry[] = [];
  const keyErrors: string[] = [];
  for (const f of keyFiles) {
    try {
      ring.push(await unlockPrivateKey(JSON.parse(await f.text()), passInput.value));
    } catch (e) {
      keyErrors.push(`${f.name}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  passInput.value = "";
  if (ring.length === 0) {
    runBtn.disabled = false;
    return say(keyErrors.join(" / "), "error");
  }
  const expect = { form: formInput.value.trim() || undefined };
  let ok = 0;
  for (const t of tokens) {
    try {
      const r = await open(ring, t, expect);
      const pre = document.createElement("pre");
      pre.textContent = r.plaintext;
      row([r.sealedAt.toLocaleString("ja-JP"), r.form, r.field, pre]);
      ok++;
    } catch (e) {
      row(["—", "—", "—", `✗ ${e instanceof Error ? e.message : String(e)}`], "error");
    }
  }
  for (const f of sealedFiles) {
    try {
      const r = await openFile(ring, f.data, expect);
      const url = URL.createObjectURL(new Blob([r.data as BlobPart], { type: "application/octet-stream" }));
      objectUrls.push(url);
      const a = document.createElement("a");
      a.href = url;
      a.download = safeFileName(r.name);
      a.textContent = `${safeFileName(r.name)} を保存`;
      const span = document.createElement("span");
      span.append(a, `（${r.type || "種類不明"}・${r.data.length.toLocaleString()} バイト）`);
      row([r.sealedAt.toLocaleString("ja-JP"), r.form, r.field, span]);
      ok++;
    } catch (e) {
      row(["—", "—", "—", `✗ ${f.name}: ${e instanceof Error ? e.message : String(e)}`], "error");
    }
  }
  ring.forEach((k) => k.privateKey.fill(0));
  table.hidden = false;
  runBtn.disabled = false;
  const total = tokens.length + sealedFiles.length;
  const keyNote = keyErrors.length ? `（開けなかった鍵: ${keyErrors.join(" / ")}）` : "";
  say(
    `${total} 件中 ${ok} 件を復号しました。結果はこの画面にだけ表示され、保存されません。${keyNote}`,
    ok === total && !keyErrors.length ? "info" : "error",
  );
});

clearBtn.addEventListener("click", () => {
  results.replaceChildren();
  releaseUrls();
  table.hidden = true;
  tokensInput.value = "";
  passInput.value = "";
  sealedFiles = [];
  renderFileList();
  say("消去しました");
});
