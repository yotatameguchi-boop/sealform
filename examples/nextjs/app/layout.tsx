import config from "../sealform.config.json";

export const metadata = { title: "相談フォーム（sealform デモ・Next.js）" };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="ja">
      <body style={{ font: "16px/1.7 system-ui, sans-serif", maxWidth: 640, margin: "40px auto", padding: "0 16px" }}>
        {children}
        {/* SRI で、配信中の sealform.js が想定どおりかをブラウザに確かめさせる */}
        <script src="/sealform.js" integrity={config.integrity} crossOrigin="anonymous" defer />
      </body>
    </html>
  );
}
