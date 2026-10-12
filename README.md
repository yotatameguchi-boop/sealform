# sealform

[English](README.en.md)

**Web フォームの入力を、ブラウザの中で耐量子ハイブリッド暗号で暗号化してから送るライブラリ。**
サーバー・DB・ログ・CDN には暗号文しか残らず、読めるのは秘密鍵を持つ担当者の手元だけです。

```html
<script src="/sealform.js" integrity="sha384-..." crossorigin="anonymous" defer></script>

<form method="post" action="/contact" enctype="multipart/form-data"
      data-sealform-key="/.well-known/sealform-key.json">
  <textarea name="message" data-seal></textarea>          <!-- この欄を暗号化 -->
  <input type="file" name="attachment" data-seal>         <!-- 添付ファイルも暗号化 -->
  <p data-sealform-status></p>
  <button type="submit" disabled data-sealform-submit>送信</button>  <!-- JS が動くまで押せない -->
</form>
```

> 状態: v0.3（試作）。暗号の専門家による第三者レビューはまだ受けていません。本番の重要なデータに使う前に、下の「守れないもの」を読んでください。

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
| **複数の担当者** | 相談員が何人いても、それぞれ自分の秘密鍵だけで読める。1人が鍵を失くしても他の人が読める |
| **添付ファイル** | 中身だけでなく、元のファイル名と種類も暗号化する。大きさも 4KB 単位に丸める |
| **鍵の更新** | 新しい鍵を足して古い鍵を外すだけ。古い秘密鍵を手元に残せば、過去の相談も読める |
| **差し替え・使い回しの検出** | 宛先フォームと項目名を暗号文に結びつける。別フォーム宛ての暗号文を混ぜても復号時に分かる |
| **外からの改ざん監視** | `sealform check` が、配っている JS が公式の配布物と同じか、公開鍵の指紋が変わっていないかを別の場所から確かめる |
| **オフライン復号** | 担当者向けの復号ツールは HTML 1ファイル。CSP でネットワークを完全に遮断して動く |
| **紙の復旧コード** | 秘密鍵を印刷できるコードにして金庫で保管できる。書き写しの誤りは検査値で検出する |
| **主要なサーバーに対応** | Node・Express・Next.js・Flask・PHP の受け取り例と、WordPress（Contact Form 7）用プラグイン |

## 使い方

### 1. 鍵を作る（担当者の手元で）

担当者がそれぞれ自分の PC で鍵を作り、公開鍵だけを集めて「鍵の束」にします。

```bash
npx sealform keygen --label 相談員A          # 各担当者が手元で実行
npx sealform keys add sealform-key.json sealform-key-<kid>.json ...   # 公開鍵を束ねる
```

- `sealform-key.json`（鍵の束）→ サイトの `/.well-known/sealform-key.json` に置く
- `sealform-private-key-<kid>.json`（秘密鍵、パスフレーズで保護）→ **サーバーには置かない**
- `keys add` / `keys list` が表示する指紋（`SHA256:...`）を控えておく

1人だけで運用する場合は、束に鍵を1つだけ入れます。

### 2. フォームに組み込む

上の HTML のとおりです。必ず守ること:

- `method="post"`（GET だと暗号文が URL とアクセスログに載るため、sealform は動きません）
- 送信ボタンは `disabled data-sealform-submit` にしておく（JS が動かないときに平文で送られないように）
- `data-seal` を付けた項目だけが暗号化されます。1つも付けなければ hidden 以外の全項目（添付ファイルを含む）が対象です
- 添付ファイルを暗号化するときは `enctype="multipart/form-data"` が必要です。上限は 50MB で、`data-sealform-max-mb="10"` のように下げられます
- `data-sealform-fingerprint="SHA256:... SHA256:..."` で使う鍵の指紋を固定できます（空白区切りで全員分）。束に知らない鍵が足されていたら送信できなくなります

`npx sealform sri` で `integrity` に書く値が出ます。

React などで描画を自分で管理するときは、フォームに `data-sealform-manual` を付けて自動初期化を止め、描画のあとで `sealform.attach(form)` を呼びます（[Next.js の例](examples/nextjs/app/sealed-form.tsx)）。
`<html lang="en">` のページでは表示が英語になります（`data-sealform-lang="en"` でも指定できます）。

### 3. サーバー側

受け取った値をそのまま保存するだけです。平文が混ざって届いていないかは `isSealed()` / `isSealedFile()` で確かめられます。

PHP（`server/php/sealform.php`）と Python（`server/python/sealform_check.py`）にも同じ判定の関数があります。Node・Express・Next.js・Flask・PHP・WordPress の動く例は [examples/](examples/README.md) にあります。

```js
import { isSealed, isSealedFile } from "sealform";
if (!isSealed(form.get("message"))) return res.status(400).send("暗号化されていません");
const file = form.get("attachment");   // 名前は sealed-xxxx.sf、中身は暗号文
if (file.size > 0 && !isSealedFile(new Uint8Array(await file.arrayBuffer()))) return res.status(400).end();
```

### 4. 復号する（担当者の手元で）

```bash
npx sealform open --key sealform-private-key-<kid>.json --form /contact --out ./decrypted submissions.csv files/*.sf
```

CSV やメール本文をそのまま渡しても、`sf2.`（または v0.1 の `sf1.`）で始まる暗号文だけを拾います。
添付ファイル（`.sf`）は `--out` のフォルダに元の名前で書き出します。
エンジニアでない担当者には、`dist/sealform-opener.html`（オフラインで動く復号ツール）を渡してください。

### 秘密鍵の紛失に備える（紙の復旧コード）

```bash
npx sealform recovery export sealform-private-key-<kid>.json   # 印刷用の HTML ができる
npx sealform recovery import                                    # 紙のコードを入力して秘密鍵ファイルを作り直す
```

復旧コードは**パスフレーズ無しで秘密鍵になります**。印刷したら HTML ファイルは消し、紙を金庫など鍵のかかる場所に保管してください。
書き写しの誤り（1文字違い・入れ替え・抜け）は検査値で検出します。

### 鍵の更新

```bash
npx sealform keygen --label "相談員A（2027）"
npx sealform keys add sealform-key.json sealform-key-<新しい kid>.json   # しばらく新旧の両方に宛てる
npx sealform keys remove sealform-key.json <古い kid>
npx sealform open --key 新しい秘密鍵.json --key 古い秘密鍵.json submissions.csv   # 過去の相談も開ける
```

HTML の `data-sealform-fingerprint` と `check --fingerprint` の指紋も入れ替えてください。期限の 30 日前になると `check` が知らせます。
最後の1つの鍵は外せません。

### 5. 外から点検する

```bash
npx sealform check https://example.org/contact --fingerprint "SHA256:..."
```

```
✓ CSP で読み込めるスクリプトが制限されています
✓ method は POST です
✓ JS が動くまで送信ボタンは押せません
✓ 暗号化に使われる鍵 2 個は、すべて登録したものです
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
- 暗号文の改ざん、別フォーム・別項目への差し替え、宛先の一部の削除
- 鍵の束に攻撃者の鍵を足して写しを受け取ること（指紋を固定している場合）

### 守れないもの

- **サーバーを乗っ取られ、配る JS やページそのものを書き換えられること。** Web 上のエンドツーエンド暗号化に共通する限界です。sealform では次の方法で**検知**を助けます（防げるわけではありません）。
  - SRI（`integrity`）と CSP で、想定外のスクリプトを読み込ませにくくする
  - 公開鍵の指紋の固定
  - `sealform check` を別の場所から定期実行し、JS と公開鍵の差し替えに気づく
- 利用者の端末のマルウェア、ブラウザ拡張による盗み見
- 担当者の端末や秘密鍵の漏えい
- 「送信したこと」「時刻」「おおよその大きさ」「宛先の鍵の kid」などのメタデータ

## 開発

```bash
npm install
npm run build     # dist/ を作る
npm test          # 76 件のテスト
npm run example   # http://localhost:8787 でデモ
npm run build:wordpress   # WordPress プラグインの zip
python3 server/python/test_sealform_check.py   # Python の検証関数
php server/php/test.php                          # PHP の検証関数
```

テストベクタ:
- `test-vectors/xwing-draft-10.json` — X-Wing の仕様書（draft-connolly-cfrg-xwing-kem-10）付録の公式ベクタ。使っている実装が仕様どおりかを確かめる
- `test-vectors/sealform-sf2.json` — sealform の形式の復号ベクタ（正常系と、改ざん・宛先違いなどの異常系）。別の言語で実装するときの答え合わせ用
- `test-vectors/validator.json` — サーバー側の検証関数のベクタ。Node・PHP・Python で同じ結果になることを確かめる

- 暗号文と鍵の形式: [docs/FORMAT.md](docs/FORMAT.md)
- 要件定義: [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md)
- 脆弱性の報告: [SECURITY.md](SECURITY.md)

## ライセンス

Apache-2.0
