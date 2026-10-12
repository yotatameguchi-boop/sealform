# sealform

**Web フォームの入力を、ブラウザの中で耐量子ハイブリッド暗号で暗号化してから送るライブラリ。**
サーバー・DB・ログ・CDN には暗号文しか残らず、読めるのは秘密鍵を持つ担当者の手元だけです。

```html
<script src="/sealform.js" integrity="sha384-..." crossorigin="anonymous" defer></script>

<form method="post" action="/contact" data-sealform-key="/.well-known/sealform-key.json">
  <textarea name="message" data-seal></textarea>          <!-- この欄を暗号化 -->
  <p data-sealform-status></p>
  <button type="submit" disabled data-sealform-submit>送信</button>  <!-- JS が動くまで押せない -->
</form>
```

> 状態: v0.1（試作）。暗号の専門家による第三者レビューはまだ受けていません。本番の重要なデータに使う前に、下の「守れないもの」を読んでください。

## なぜ必要か

HTTPS が守るのは通信の途中だけです。サーバーに届いた瞬間に平文に戻り、DB・アクセスログ・エラー監視・バックアップ・CDN や WAF にまで広がります。
相談窓口・内部通報・採用応募・問診のようなフォームでは、その一つが漏れるだけで深刻な事故になります。

sealform を使うと、サーバーは**平文に一度も触れません**。サーバーが乗っ取られても、保存されているのは暗号文だけです。

## 特徴

| | |
|---|---|
| **耐量子ハイブリッド** | HPKE（RFC 9180）＋ X-Wing（X25519 + ML-KEM-768）。どちらか一方が安全なら安全。「今盗んで後で解読」にも備える |
| **既存フォームに後付け** | script 1行と属性だけ。暗号文は元の name のまま送るので、サーバー側の処理はほぼそのまま |
| **フェイルクローズ** | JS 無効・鍵が取れない・暗号化失敗のときは**送信自体ができない**。平文で送り直すことはしない |
| **差し替え・使い回しの検出** | 宛先フォームと項目名を暗号文に結びつける。別フォーム宛ての暗号文を混ぜても復号時に分かる |
| **外からの改ざん監視** | `sealform check` が、配っている JS が公式の配布物と同じか、公開鍵の指紋が変わっていないかを別の場所から確かめる |
| **オフライン復号** | 担当者向けの復号ツールは HTML 1ファイル。CSP でネットワークを完全に遮断して動く |

## 使い方

### 1. 鍵を作る（担当者の手元で）

```bash
npx sealform keygen
```

- `sealform-key.json`（公開鍵）→ サイトの `/.well-known/sealform-key.json` に置く
- `sealform-private-key.json`（秘密鍵、パスフレーズで保護）→ **サーバーには置かない**
- 表示された指紋（`SHA256:...`）を控えておく

### 2. フォームに組み込む

上の HTML のとおりです。必ず守ること:

- `method="post"`（GET だと暗号文が URL とアクセスログに載るため、sealform は動きません）
- 送信ボタンは `disabled data-sealform-submit` にしておく（JS が動かないときに平文で送られないように）
- `data-seal` を付けた項目だけが暗号化されます。1つも付けなければ hidden 以外の全項目が対象です
- 公開鍵を別の場所から配るときは `data-sealform-fingerprint="SHA256:..."` で指紋を固定できます

`npx sealform sri` で `integrity` に書く値が出ます。

### 3. サーバー側

受け取った値をそのまま保存するだけです。平文が混ざって届いていないかは `isSealed()` で確かめられます。

```js
import { isSealed } from "sealform";
if (!isSealed(req.body.message)) return res.status(400).send("暗号化されていません");
```

### 4. 復号する（担当者の手元で）

```bash
npx sealform open --key sealform-private-key.json --form /contact submissions.csv
```

CSV やメール本文をそのまま渡しても、`sf1.` で始まる暗号文だけを拾います。
エンジニアでない担当者には、`dist/sealform-opener.html`（オフラインで動く復号ツール）を渡してください。

### 5. 外から点検する

```bash
npx sealform check https://example.org/contact --fingerprint "SHA256:..."
```

```
✓ CSP で読み込めるスクリプトが制限されています
✓ method は POST です
✓ JS が動くまで送信ボタンは押せません
✓ 公開鍵の指紋が登録したものと一致します
✓ integrity（SRI）と配信中の JS が一致します
✓ 配信中の JS は公式の配布物と同一です
```

問題があれば終了コード 1 を返します。[GitHub Actions で1時間ごとに実行する例](examples/github-actions/sealform-check.yml)があります。

## 脅威モデル

### 守れるもの

- サーバー・DB の侵害、バックアップの流出
- アクセスログ・エラー監視・解析ツールへの平文の混入
- CDN・WAF・ホスティング事業者からの閲覧
- 将来の量子計算機による解読（ハイブリッド KEM）
- 暗号文の改ざん、別フォーム・別項目への差し替え

### 守れないもの

- **サーバーを乗っ取られ、配る JS やページそのものを書き換えられること。** Web 上のエンドツーエンド暗号化に共通する限界です。sealform では次の方法で**検知**を助けます（防げるわけではありません）。
  - SRI（`integrity`）と CSP で、想定外のスクリプトを読み込ませにくくする
  - 公開鍵の指紋の固定
  - `sealform check` を別の場所から定期実行し、JS と公開鍵の差し替えに気づく
- 利用者の端末のマルウェア、ブラウザ拡張による盗み見
- 担当者の端末や秘密鍵の漏えい
- 「送信したこと」「時刻」「おおよその大きさ」などのメタデータ

## 開発

```bash
npm install
npm run build     # dist/ を作る
npm test          # 30 件のテスト
npm run example   # http://localhost:8787 でデモ
```

- 暗号文と鍵の形式: [docs/FORMAT.md](docs/FORMAT.md)
- 要件定義: [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md)
- 脆弱性の報告: [SECURITY.md](SECURITY.md)

## ライセンス

Apache-2.0
