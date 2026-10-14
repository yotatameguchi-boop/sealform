import { expect, test, type Page, type Request } from "@playwright/test";
import { generateKeyPair, isSealed, isSealedFile, open, openFile } from "../dist/index.js";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { containsText, DATA, demoKeyring, findTokensIn } from "./helpers";

// 実ブラウザ（Chromium・Firefox・WebKit）で、デモのフォーム（examples/shared/form.html）から送り、
// ネットワークに出ていく中身そのものを確かめる。

const NAME = "テスト花子";
const MESSAGE = "実ブラウザから送る相談です。平文で出ていかないこと。";
const FILE_TEXT = "添付ファイルの中身（平文で出ていかないこと）";
const FILE_NAME = "診断書_テスト.txt";

async function ready(page: Page) {
  await page.goto("/");
  await expect(page.locator("form")).toHaveAttribute("data-sealform-state", "ready");
}

/** /contact への POST を記録する（送られなかったことも確かめられるように）。 */
function recordPosts(page: Page): Request[] {
  const posts: Request[] = [];
  page.on("request", (r) => {
    if (r.method() === "POST" && new URL(r.url()).pathname === "/contact") posts.push(r);
  });
  return posts;
}

/**
 * サーバー（examples/server.mjs）が受け取って保存したもの。ブラウザが実際に送った中身そのもの。
 * （Playwright が記録する送信内容は、ブラウザによって添付ファイルの中身が欠けるので、こちらで確かめる）
 */
function storedSince(csvSize: number, filesBefore: Set<string>) {
  const csv = readFileSync(join(DATA, "submissions.csv"));
  const filesDir = join(DATA, "files");
  const files = readdirSync(filesDir).filter((f) => !filesBefore.has(f)).map((f) => readFileSync(join(filesDir, f)));
  return { csv: csv.subarray(csvSize), files };
}

function storageMark() {
  let size = 0;
  try {
    size = statSync(join(DATA, "submissions.csv")).size;
  } catch {}
  return { size, files: new Set(readdirSync(join(DATA, "files"))) };
}

test("送られる中身は暗号文だけで、相談員の鍵で元に戻せる（添付ファイルを含む）", async ({ page }) => {
  await ready(page);
  await page.fill("#name", NAME);
  await page.fill("#message", MESSAGE);
  await page.setInputFiles("#attachment", { name: FILE_NAME, mimeType: "text/plain", buffer: Buffer.from(FILE_TEXT) });
  const mark = storageMark();
  const [req] = await Promise.all([page.waitForRequest((r) => r.method() === "POST" && r.url().endsWith("/contact")), page.click("button[type=submit]")]);
  await expect(page).toHaveTitle("送信しました");

  // ブラウザが記録できた範囲の送信内容にも、平文が無いこと
  const sent = req.postDataBuffer();
  if (sent) for (const plain of [NAME, MESSAGE, FILE_TEXT, FILE_NAME]) expect(containsText(sent, plain), plain).toBe(false);

  // サーバーに届いて保存されたもの
  const stored = storedSince(mark.size, mark.files);
  for (const plain of [NAME, MESSAGE, FILE_TEXT, FILE_NAME]) {
    expect(containsText(stored.csv, plain), plain).toBe(false);
    for (const f of stored.files) expect(containsText(f, plain), plain).toBe(false);
  }
  const ring = await demoKeyring();
  const tokens = findTokensIn(stored.csv.toString("utf8"));
  expect(tokens).toHaveLength(2);
  expect((await open(ring, tokens[0]!, { form: "/contact", field: "name" })).plaintext).toBe(NAME);
  expect((await open(ring, tokens[1]!, { form: "/contact", field: "message" })).plaintext).toBe(MESSAGE);

  expect(stored.files).toHaveLength(1);
  const sealedFile = new Uint8Array(stored.files[0]!);
  expect(isSealedFile(sealedFile)).toBe(true);
  const f = await openFile(ring, sealedFile, { form: "/contact", field: "attachment" });
  expect(f.name).toBe(FILE_NAME);
  expect(Buffer.from(f.data).toString("utf8")).toBe(FILE_TEXT);
});

test("任意の欄が空なら、空のまま送られる", async ({ page }) => {
  await ready(page);
  await page.fill("#message", MESSAGE);
  const mark = storageMark();
  await page.click("button[type=submit]");
  await expect(page).toHaveTitle("送信しました");
  const row = storedSince(mark.size, mark.files).csv.toString("utf8");
  // 列: 日時, name, message, 添付
  expect(row.split(",")[1]).toBe('""');
  expect(isSealed(findTokensIn(row)[0])).toBe(true);
});

test("必須の欄が空なら送らない", async ({ page }) => {
  const posts = recordPosts(page);
  await ready(page);
  // ブラウザ自身の必須チェックも止めて（Contact Form 7 と同じ状態）、sealform が止めることを確かめる
  await page.evaluate(() => document.querySelector("form")!.setAttribute("novalidate", ""));
  await page.click("button[type=submit]");
  await expect(page.locator("[data-sealform-status]")).toContainText("必須");
  await page.waitForTimeout(500);
  expect(posts).toHaveLength(0);
});

test("暗号化している間に入力欄を足されたら、何も送らない", async ({ page }) => {
  const posts = recordPosts(page);
  await ready(page);
  await page.fill("#message", MESSAGE);
  await page.evaluate(() => {
    const form = document.querySelector("form")!;
    form.addEventListener("sealform:status", (e) => {
      if ((e as CustomEvent).detail.state !== "sending") return;
      const extra = document.createElement("input");
      extra.name = "injected";
      extra.value = "こっそり足された平文";
      extra.setAttribute("data-seal", "");
      form.appendChild(extra);
    });
  });
  await page.click("button[type=submit]");
  await expect(page.locator("form")).toHaveAttribute("data-sealform-state", "error");
  await expect(page.locator("[data-sealform-status]")).toContainText("フォームの内容が変わった");
  await page.waitForTimeout(500);
  expect(posts).toHaveLength(0);
});

test("公開鍵の期限が切れていたら、送信ボタンは押せないまま", async ({ page }) => {
  const expired = await generateKeyPair({ validDays: 1, now: new Date("2020-01-01") });
  await page.route("**/.well-known/sealform-key.json", (route) => route.fulfill({ json: expired.publicDoc }));
  await page.goto("/");
  await expect(page.locator("form")).toHaveAttribute("data-sealform-state", "error");
  await expect(page.locator("button[type=submit]")).toBeDisabled();
});

test.describe("JavaScript が無効なとき", () => {
  test.use({ javaScriptEnabled: false });

  test("送信ボタンは押せず、Enter でも送られない", async ({ page }) => {
    const posts = recordPosts(page);
    await page.goto("/");
    await expect(page.locator("button[type=submit]")).toBeDisabled();
    await page.fill("#name", NAME);
    await page.press("#name", "Enter");
    await page.waitForTimeout(500);
    expect(posts).toHaveLength(0);
  });
});
