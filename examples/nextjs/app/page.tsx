import config from "../sealform.config.json";
import { SealedForm } from "./sealed-form";

export default function Page() {
  return (
    <main>
      <h1>相談フォーム</h1>
      <p>お名前・相談内容・添付ファイルは、このブラウザの中で暗号化してから送信されます。</p>
      <SealedForm fingerprints={config.fingerprints} />
    </main>
  );
}
