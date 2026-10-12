"use client";
import { useEffect, useRef, useState } from "react";

declare global {
  interface Window {
    sealform?: { attach(form: HTMLFormElement): void };
  }
}

/**
 * sealform を React で使う例。
 * - data-sealform-manual で自動初期化を止め、描画が落ち着いた useEffect の中で sealform.attach() でつなぐ
 *   （自動初期化に任せると、React が引き継ぐ前に属性が変わってハイドレーションの警告が出る）
 * - 表示は sealform:status イベントで受けて React の state にする
 * - 送信ボタンの disabled は最初の HTML で true にしておき、以後は sealform に任せる
 */
export function SealedForm({ fingerprints }: { fingerprints: string }) {
  const ref = useRef<HTMLFormElement>(null);
  const [status, setStatus] = useState("暗号化の準備をしています…");

  useEffect(() => {
    const form = ref.current!;
    const onStatus = (e: Event) => setStatus((e as CustomEvent<{ message: string }>).detail.message);
    form.addEventListener("sealform:status", onStatus);
    const attach = () => {
      window.sealform!.attach(form);
      if (form.dataset.sealformMessage) setStatus(form.dataset.sealformMessage);
    };
    if (window.sealform) attach();
    else document.querySelector('script[src="/sealform.js"]')?.addEventListener("load", attach, { once: true });
    return () => form.removeEventListener("sealform:status", onStatus);
  }, []);

  const field = { display: "block", width: "100%", boxSizing: "border-box", font: "inherit", padding: "8px 10px" } as const;
  return (
    <form
      ref={ref}
      method="post"
      action="/contact"
      encType="multipart/form-data"
      data-sealform-key="/.well-known/sealform-key.json"
      data-sealform-fingerprint={fingerprints}
      data-sealform-max-mb="10"
      data-sealform-manual
    >
      <label htmlFor="name">お名前（匿名可）</label>
      <input id="name" name="name" data-seal autoComplete="off" style={field} />
      <label htmlFor="message">相談内容</label>
      <textarea id="message" name="message" data-seal required style={{ ...field, minHeight: 160 }} />
      <label htmlFor="attachment">添付ファイル（任意・10MB まで）</label>
      <input id="attachment" type="file" name="attachment" data-seal multiple />
      <p aria-live="polite" style={{ fontSize: ".9rem" }}>{status}</p>
      <noscript>このフォームは JavaScript を有効にしないと送信できません（暗号化のため）。</noscript>
      <button type="submit" disabled data-sealform-submit>
        暗号化して送信
      </button>
    </form>
  );
}
