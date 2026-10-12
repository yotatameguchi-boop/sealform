// <script src="sealform.js"> で読み込まれる配布用の入口。
import { findTokens, inspect, isSealed, loadKeys, loadPublicKey, seal, sealFile } from "./core.js";
import { attach, init } from "./browser.js";

const api = { attach, init, seal, sealFile, loadKeys, loadPublicKey, isSealed, inspect, findTokens, version: __SEALFORM_VERSION__ };
(globalThis as { sealform?: typeof api }).sealform = api;

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => init());
} else {
  init();
}

