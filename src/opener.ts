// オフライン復号ツール（dist/sealform-opener.html に1ファイルとして埋め込まれる）
import { findTokens, open } from "./core.js";
import { unlockPrivateKey } from "./keyfile.js";

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;

const keyInput = $<HTMLInputElement>("key");
const passInput = $<HTMLInputElement>("pass");
const tokensInput = $<HTMLTextAreaElement>("tokens");
const fileInput = $<HTMLInputElement>("tokens-file");
const formInput = $<HTMLInputElement>("expect-form");
const runBtn = $<HTMLButtonElement>("run");
const clearBtn = $<HTMLButtonElement>("clear");
const statusEl = $<HTMLElement>("status");
const results = $<HTMLTableSectionElement>("results");
const table = $<HTMLTableElement>("result-table");

fileInput.addEventListener("change", async () => {
  const f = fileInput.files?.[0];
  if (f) tokensInput.value = await f.text();
  fileInput.value = "";
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

runBtn.addEventListener("click", async () => {
  results.replaceChildren();
  table.hidden = true;
  const keyFile = keyInput.files?.[0];
  if (!keyFile) return say("秘密鍵ファイルを選んでください", "error");
  const tokens = findTokens(tokensInput.value);
  if (tokens.length === 0) return say("暗号文（sf1. で始まる文字列）が見つかりません", "error");
  runBtn.disabled = true;
  say("鍵を開いています…（数秒かかります）");
  let unlocked: { kid: string; privateKey: Uint8Array };
  try {
    unlocked = await unlockPrivateKey(JSON.parse(await keyFile.text()), passInput.value);
  } catch (e) {
    runBtn.disabled = false;
    return say(e instanceof Error ? e.message : String(e), "error");
  }
  passInput.value = "";
  let ok = 0;
  for (const t of tokens) {
    try {
      const r = await open(unlocked.privateKey, unlocked.kid, t, { form: formInput.value.trim() || undefined });
      const pre = document.createElement("pre");
      pre.textContent = r.plaintext;
      row([r.sealedAt.toLocaleString("ja-JP"), r.form, r.field, pre]);
      ok++;
    } catch (e) {
      row(["—", "—", "—", `✗ ${e instanceof Error ? e.message : String(e)}`], "error");
    }
  }
  unlocked.privateKey.fill(0);
  table.hidden = false;
  runBtn.disabled = false;
  say(`${tokens.length} 件中 ${ok} 件を復号しました。結果はこの画面にだけ表示され、保存されません。`, ok === tokens.length ? "info" : "error");
});

clearBtn.addEventListener("click", () => {
  results.replaceChildren();
  table.hidden = true;
  tokensInput.value = "";
  passInput.value = "";
  say("消去しました");
});
