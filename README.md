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

> 状態: v0.4（試作）。暗号の専門家による第三者レビューはまだ受けていません。npm には公開していません。GitHub から直接入れられます（インストール時に自動でビルドされます）。
>
> ```bash
> npm install github:yotatameguchi-boop/sealform#v0.4.0
> ```
>
> 以下の `npx sealform` は、入れたあとならそのまま、入れずに使うなら `npx github:yotatameguchi-boop/sealform#v0.4.0` に読み替えてください。ビルド済みの `sealform.js`・復号ツールの HTML・WordPress プラグインの zip は [Releases](https://github.com/yotatameguchi-boop/sealform/releases) からダウンロードできます。本番の重要なデータに使う前に、下の「守れないもの」を読んでください。

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
| **別フォーム・別項目への転用の検出** | 宛先フォームと項目名を暗号文に結びつける。別フォーム宛ての暗号文を混ぜても復号時に分かる（同じフォーム・同じ項目への再送は防がない。下の脅威モデル参照） |
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
- 送信ボタンは1つにし、すべてに `data-sealform-submit` を付けます（付いていないボタンがあると、JS が動かないときにそこから送れてしまいます）

送信するときの動き:

- `required`（または `aria-required="true"`）の欄が空なら、暗号化する前に止めて知らせます
- **空欄は暗号化せず、空のまま送ります。** サーバー側の必須チェックが働くようにするためです。そのため「どの欄が空だったか」はサーバーに分かります
- 暗号化している間にフォームの項目・値・添付ファイルが変わったら、送信を止めます（後から足された欄が平文で送られるのを防ぐため）
- 送信するときに鍵の期限を確かめ直し、切れていれば取り直します。取れなければ送りません

`npx sealform sri` で `integrity` に書く値が出ます。

React などで描画を自分で管理するときは、フォームに `data-sealform-manual` を付けて自動初期化を止め、描画のあとで `sealform.attach(form)` を呼びます（[Next.js の例](examples/nextjs/app/sealed-form.tsx)）。
`<html lang="en">` のページでは表示が英語になります（`data-sealform-lang="en"` でも指定できます）。

### 3. サーバー側

受け取った値をそのまま保存するだけです。平文が混ざって届いていないかは `isSealed()` / `isSealedFile()` で確かめられます。

これらが確かめるのは**形だけ**です（見出しの中身、種類、宛先一覧と本文の長さ）。暗号文が本物か（改ざんされていないか）は、秘密鍵で復号するときに初めて分かります。また、空欄は空のまま届くので、任意の欄は空も受け付けてください。

PHP（`server/php/sealform.php`）と Python（`server/python/sealform_check.py`）にも同じ判定の関数があります。Node・Express・Next.js・Flask・PHP・WordPress の動く例は [examples/](examples/README.md) にあります。

```js
import { isSealed, isSealedFile } from "sealform";
if (!isSealed(form.get("message"))) return res.status(400).send("暗号化されていません");   // 必須の欄
const name = form.get("name");                                                              // 任意の欄
if (name !== "" && !isSealed(name)) return res.status(400).send("暗号化されていません");
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
npx sealform check https://example.org/contact --fingerprint "SHA256:..." \
  --form-action /contact --sealed-field message --sealed-field attachment
```

`--form-action` と `--sealed-field` を付けると、そのフォームと項目が sealform で守られていることも確かめます（フォームごと平文のものに差し替えられた・`data-seal` が外された、に気づけます）。
HTML はブラウザと同じ規則で解釈するので、コメントや `<template>` の中に残した「正しい HTML」には騙されません。

```
✓ CSP で読み込めるスクリプトが制限されています
✓ method は POST です
✓ JS が動くまで送信ボタンは押せません
✓ 暗号化に使われる鍵 2 個は、すべて登録したものです
✓ integrity（SRI）と配信中の JS が一致します
✓ 配信中の JS は公式の配布物と同一です
```

問題があれば終了コード 1 を返します。[GitHub Actions で1時間ごとに実行する例](examples/github-actions/sealform-check.yml)があります。

**点検に通っても、そのページで実際に暗号化されることまでは保証しません。** 確かめているのは配信中の HTML・公開鍵・sealform.js で、ページ内の他のスクリプトの動きや、ブラウザでの実際の送信内容は確かめていません。

## 脅威モデル

### 守れるもの

- サーバー・DB の侵害、バックアップの流出
- アクセスログ・エラー監視・解析ツールへの平文の混入
- CDN・WAF・ホスティング事業者からの閲覧
- 将来の量子計算機による解読（ハイブリッド KEM）
- 暗号文の改ざん、別フォーム・別項目への転用、宛先の一部の削除
- 鍵の束に攻撃者の鍵を足して写しを受け取ること（指紋を固定している場合）

### 守れないもの

- **サーバーを乗っ取られ、配る JS やページそのものを書き換えられること。** Web 上のエンドツーエンド暗号化に共通する限界です。sealform では次の方法で**検知**を助けます（防げるわけではありません）。
  - SRI（`integrity`）と CSP で、想定外のスクリプトを読み込ませにくくする
  - 公開鍵の指紋の固定
  - `sealform check` を別の場所から定期実行し、JS と公開鍵の差し替えに気づく
- 利用者の端末のマルウェア、ブラウザ拡張による盗み見
- 担当者の端末や秘密鍵の漏えい
- **同じ暗号文の再送（リプレイ）。** 同じフォーム・同じ項目に、過去に送られた暗号文をもう一度送ることはできます。重複を避けたいときは、サーバー側で暗号文のハッシュを記録して重複を拒否してください
- **同じページの他のスクリプト。** ページに読み込まれたスクリプトは、暗号化される前の入力内容を読めます。CSP で読み込めるスクリプトを絞ってください
- 「送信したこと」「時刻」「おおよその大きさ」「宛先の鍵の kid」「どの欄が空だったか」などのメタデータ
- 中身の形式の確認（メールアドレスとして正しいか等）。サーバーは中身を見られません

## 開発

```bash
npm install
npm run build     # dist/ を作る
npm test          # 単体テスト（90 件）
npm run example   # http://localhost:8787 でデモ
npx playwright install chromium firefox webkit
npx playwright test --project=chromium --project=firefox --project=webkit   # 実ブラウザで送信して中身を確かめる
npm run build:wordpress   # WordPress プラグインの zip
python3 server/python/test_sealform_check.py   # Python の検証関数
php server/php/test.php                          # PHP の検証関数
```

テストベクタ:
- `test-vectors/xwing-draft-10.json` — X-Wing の仕様書（draft-connolly-cfrg-xwing-kem-10）付録の公式ベクタ。使っている実装が仕様どおりかを確かめる
- `test-vectors/sealform-sf2.json` — sealform の形式の復号ベクタ（正常系と、改ざん・宛先違いなどの異常系）。別の言語で実装するときの答え合わせ用
- `test-vectors/validator.json` — サーバー側の検証関数のベクタ。Node・PHP・Python で同じ結果になることを確かめる

WordPress + Contact Form 7 の実環境テストは [examples/README.md](examples/README.md) の手順で環境を立ててから、`WP_URL=http://localhost:8795 npx playwright test --project=wordpress` で動かします。CI ではすべて自動で実行しています。

- 対応環境と保守方針: [docs/SUPPORT.md](docs/SUPPORT.md)
- 貢献のしかた: [CONTRIBUTING.md](CONTRIBUTING.md)
- 暗号文と鍵の形式: [docs/FORMAT.md](docs/FORMAT.md)
- 要件定義: [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md)
- 脆弱性の報告: [SECURITY.md](SECURITY.md)

## ライセンス

Apache-2.0
