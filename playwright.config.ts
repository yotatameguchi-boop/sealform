import { defineConfig, devices } from "@playwright/test";

// 実ブラウザで送信して、送られた中身を確かめるテスト。
//   npm run build && npx playwright test                      … Node のデモサーバーに対して 3 ブラウザ
//   WP_URL=http://localhost:8795 npx playwright test wordpress … WordPress + Contact Form 7（examples/wordpress）
const PORT = 8797;

export default defineConfig({
  testDir: "e2e",
  timeout: 60_000,
  retries: process.env.CI ? 1 : 0,
  // 送信結果をサーバーの保存先で確かめるので、テストどうしが混ざらないよう 1 つずつ動かす
  workers: 1,
  use: { baseURL: `http://localhost:${PORT}` },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] }, testIgnore: /wordpress/ },
    { name: "firefox", use: { ...devices["Desktop Firefox"] }, testIgnore: /wordpress/ },
    { name: "webkit", use: { ...devices["Desktop Safari"] }, testIgnore: /wordpress/ },
    { name: "wordpress", use: { ...devices["Desktop Chrome"], baseURL: process.env.WP_URL }, testMatch: /wordpress/ },
  ],
  webServer: {
    command: "node examples/server.mjs",
    url: `http://localhost:${PORT}/`,
    env: { PORT: String(PORT) },
    reuseExistingServer: !process.env.CI,
  },
});
