import { expect, test } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { generateKeyPair, isSealed, isSealedFile, open, openFile } from "../dist/index.js";
import { containsText, DATA, demoKeyring } from "./helpers";

// WordPress + Contact Form 7 の実環境（examples/wordpress）で確かめる。
//   docker compose -f examples/wordpress/compose.yml up -d && sh examples/wordpress/setup.sh
//   WP_URL=http://localhost:8795 npx playwright test --project=wordpress

test.skip(!process.env.WP_URL, "WP_URL が無いので WordPress のテストは飛ばす");

const COMPOSE = join(DATA, "..", "wordpress", "compose.yml");
const compose = (...args: string[]) =>
  execFileSync("docker", ["compose", "-f", COMPOSE, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
const wpEval = (php: string) => compose("run", "--rm", "-T", "cli", "eval", php);

/** CF7 が受け取った値（検証用の mu-plugin が書き出す） */
function received(): { posted: Record<string, string | string[]>; files: { field: string; base64: string }[] }[] {
  let text = "";
  try {
    text = compose("exec", "-T", "wordpress", "cat", "wp-content/sealform-received.jsonl");
  } catch {}
  return text.trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
}

/** 相談ページの CF7 フォームの ID と unit tag（setup.sh を実行するたびに変わる） */
async function cf7Ids(request: import("@playwright/test").APIRequestContext) {
  const html = await (await request.get("/soudan/")).text();
  return {
    id: /name="_wpcf7" value="(\d+)"/.exec(html)![1]!,
    unit: /name="_wpcf7_unit_tag" value="([^"]+)"/.exec(html)![1]!,
  };
}

async function postPlain(request: import("@playwright/test").APIRequestContext) {
  const { id, unit } = await cf7Ids(request);
  const res = await request.post(`/wp-json/contact-form-7/v1/contact-forms/${id}/feedback`, {
    multipart: { _wpcf7: id, _wpcf7_unit_tag: unit, "your-name": "平文", "your-email": "a@example.test", "your-message": "平文の相談", agree: "1" },
  });
  return (await res.json()).status as string;
}

function useKeySet(path: string) {
  wpEval(`update_option("sealform_settings", ["key_set" => file_get_contents("${path}"), "max_mb" => "10", "cf7" => "1"]);`);
}

test.afterEach(() => useKeySet("/sealform-data/sealform-key.json"));

test("CF7 から添付ファイル付きで送ると、WordPress には暗号文だけが届く", async ({ page }) => {
  const before = received().length;
  await page.goto("/soudan/");
  await expect(page.locator("form.wpcf7-form")).toHaveAttribute("data-sealform-state", "ready");
  await page.fill("[name=your-name]", "WP 相談者");
  await page.fill("[name=your-email]", "someone@example.test");
  await page.fill("[name=your-message]", "WordPress から送った相談です");
  await page.setInputFiles("[name=your-file]", { name: "wp-添付.txt", mimeType: "text/plain", buffer: Buffer.from("WP の添付") });
  await page.check("[name=agree]");
  await page.click("[type=submit]");
  await expect(page.locator(".wpcf7-response-output")).toContainText(/sent|送信/);

  const got = received().slice(before);
  expect(got).toHaveLength(1);
  const raw = JSON.stringify(got[0]);
  for (const plain of ["WP 相談者", "someone@example.test", "WordPress から送った相談です", "wp-添付"]) expect(raw.includes(plain), plain).toBe(false);
  const ring = await demoKeyring();
  expect((await open(ring, got[0]!.posted["your-message"] as string)).plaintext).toBe("WordPress から送った相談です");
  const file = new Uint8Array(Buffer.from(got[0]!.files[0]!.base64, "base64"));
  expect(isSealedFile(file)).toBe(true);
  expect((await openFile(ring, file)).name).toBe("wp-添付.txt");
});

test("必須の欄が空なら、ブラウザが暗号化する前に止める", async ({ page }) => {
  const before = received().length;
  await page.goto("/soudan/");
  await expect(page.locator("form.wpcf7-form")).toHaveAttribute("data-sealform-state", "ready");
  await page.fill("[name=your-name]", "WP 相談者");
  // CF7 は同意のチェックが入るまで送信ボタンを押せなくするので、先にチェックする
  await page.check("[name=agree]");
  await page.click("[type=submit]");
  await expect(page.locator("[data-sealform-status]")).toContainText("必須");
  expect(received().length).toBe(before);
});

test("任意の欄が空でも送れて、空のまま届く", async ({ page }) => {
  const before = received().length;
  await page.goto("/soudan/");
  await expect(page.locator("form.wpcf7-form")).toHaveAttribute("data-sealform-state", "ready");
  await page.fill("[name=your-name]", "WP 相談者");
  await page.fill("[name=your-email]", "someone@example.test");
  await page.fill("[name=your-message]", "添付なし");
  await page.check("[name=agree]");
  await page.click("[type=submit]");
  await expect(page.locator(".wpcf7-response-output")).toContainText(/sent|送信/);
  const got = received().slice(before);
  expect(isSealed(got[0]!.posted["your-message"])).toBe(true);
});

test("JS を通さず平文を直接送ると、WordPress が拒否する", async ({ request }) => {
  const before = received().length;
  expect(await postPlain(request)).toBe("validation_failed");
  expect(received().length).toBe(before);
});

test("公開鍵がすべて期限切れでも平文フォームには戻らず、送れない。サーバーも平文を拒否し続ける（レビューの指摘）", async ({ page, request }) => {
  const expired = await generateKeyPair({ validDays: 1, now: new Date("2020-01-01") });
  writeFileSync(join(DATA, "expired-key.json"), JSON.stringify({ sealform: 1, type: "key-set", keys: [expired.publicDoc] }));
  useKeySet("/sealform-data/expired-key.json");

  await page.goto("/soudan/");
  const form = page.locator("form.wpcf7-form");
  await expect(form).toHaveAttribute("data-sealform-key", /sealform\/v1\/key/);
  await expect(form).toHaveAttribute("data-sealform-state", "error");
  await expect(page.locator("[data-sealform-status]")).toContainText("有効期限");
  await expect(page.locator("[type=submit]")).toBeDisabled();

  // CF7 は同意にチェックが入ると送信ボタンを押せる状態に戻してしまう。それでも sealform が送信を止めること
  const posts: string[] = [];
  page.on("request", (r) => { if (r.method() === "POST") posts.push(r.url()); });
  await page.fill("[name=your-message]", "期限切れのときに入力した相談");
  await page.check("[name=agree]");
  if (await page.locator("[type=submit]").isEnabled()) await page.click("[type=submit]");
  await page.waitForTimeout(1000);
  expect(posts).toEqual([]);
  await expect(page.locator("form.wpcf7-form")).toHaveAttribute("data-sealform-state", "error");

  const before = received().length;
  expect(await postPlain(request)).toBe("validation_failed");
  expect(received().length).toBe(before);
});

test("鍵の束が空・壊れていても、送れないまま", async ({ page }) => {
  writeFileSync(join(DATA, "expired-key.json"), "");
  useKeySet("/sealform-data/expired-key.json");
  await page.goto("/soudan/");
  await expect(page.locator("form.wpcf7-form")).toHaveAttribute("data-sealform-state", "error");
  await expect(page.locator("[type=submit]")).toBeDisabled();
});
