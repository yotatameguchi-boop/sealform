import { defineConfig } from "vitest/config";

// 単体テストだけ。実ブラウザのテスト（e2e/）は Playwright で動かす
export default defineConfig({ test: { include: ["test/**/*.test.ts"] } });
