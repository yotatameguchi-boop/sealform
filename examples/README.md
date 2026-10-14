# サーバー側の受け取り例

どの例も同じフォーム（[shared/form.html](shared/form.html)）を配り、届いた暗号文を `examples/.data/` に保存します。
サーバーは平文に一切触れず、暗号文の形をしていない値が届いたら保存を拒否します。

最初に一度だけ、ビルドとデモ用の鍵（相談員 2 人分）を用意します。

```bash
npm install && npm run build
node examples/shared/demo.mjs
```

| 例 | 起動 | URL | 検証関数 |
|---|---|---|---|
| Node（依存なし） | `npm run example` | http://localhost:8787 | `isSealed` / `isSealedFile`（npm の sealform） |
| Express | `cd examples/express && npm install && npm start` | http://localhost:8788 | 同上 |
| Flask | `cd examples/flask && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt && .venv/bin/python app.py` | http://localhost:8789 | [server/python/sealform_check.py](../server/python/sealform_check.py) |
| PHP | `php -S localhost:8790 examples/php/index.php` | http://localhost:8790 | [server/php/sealform.php](../server/php/sealform.php) |
| Next.js | `cd examples/nextjs && npm install && npm run dev` | http://localhost:8791 | `isSealed` / `isSealedFile` |
| WordPress + Contact Form 7 | 下記 | http://localhost:8795/soudan/ | プラグインに同梱 |

PHP が手元に無い場合は Docker で動かせます。

```bash
docker run --rm -p 8790:8790 -v "$PWD":/app -w /app php:8.3-cli \
  php -d upload_max_filesize=20M -d post_max_size=60M -S 0.0.0.0:8790 examples/php/index.php
```

## 受け取ったものを復号する

```bash
npx sealform open --key examples/.data/keys/sealform-private-key-<kid>.json \
  --out ./decrypted examples/.data/submissions.csv examples/.data/files/*.sf
```

パスフレーズはデモ用の `demo-passphrase-123` です。

## 例ごとの注意

- **任意の欄**: 空欄は暗号化されずに空のまま届きます。サーバー側では、任意の欄は空も受け付けてください（例はすべてそうしています）。
- **PHP**: 複数の添付ファイルを受け取るには `name="attachment[]"` にします（例では配信時に書き換えています）。
- **Next.js（React）**: フォームに `data-sealform-manual` を付けて自動初期化を止め、`useEffect` の中で `sealform.attach()` を呼びます。自動初期化に任せると、React が HTML を引き継ぐ前に属性が変わり、ハイドレーションの警告が出ます。表示は `sealform:status` イベントで受け取ります。[nextjs/app/sealed-form.tsx](nextjs/app/sealed-form.tsx) を参照してください。
- **CSP**: Node・Express・Flask・PHP の例は `script-src 'self'` の CSP を付けています。Next.js はインラインのスクリプトを使うため、この例では付けていません（本番では Next.js の nonce を使う CSP を設定してください）。

## WordPress + Contact Form 7

```bash
npm run build:wordpress                                  # dist/wordpress/sealform.zip
docker compose -f examples/wordpress/compose.yml up -d
sh examples/wordpress/setup.sh                           # WordPress・CF7・sealform を設定し、相談ページを作る
```

本番のサイトには `dist/wordpress/sealform.zip` を「プラグイン → 新規追加 → アップロード」で入れ、「設定 → sealform」に鍵の束（`sealform-key.json` の中身）を貼り付けて、「すべての Contact Form 7 のフォームを暗号化する」にチェックを入れます（既定では無効です）。

一度有効にすると、公開鍵が期限切れ・未設定になってもフォームは平文には戻らず、「送信できない」状態になります。管理画面に警告が出るので、期限が切れる前に新しい鍵を加えてください。

- すべての Contact Form 7 のフォームで、hidden 以外の全項目と添付ファイルが暗号化されます
- 添付ファイルの欄には `filetypes:sf` を付けます（例: `[file your-file filetypes:sf limit:20mb]`）
- 暗号文は「メールアドレスの形式」「文字数」などの検査を通らないので、プラグインが CF7 自身の検査を「必須かどうか」と「暗号文か」の検査に差し替えます（他のプラグインの検査は残します）。**中身の形式の検査はできなくなります**
- 空欄は暗号化せずに空のまま送るので、必須チェックは働きます（どの欄が空だったかはサーバーに分かります）
- 通知メールには暗号文と `.sf` ファイルが届きます。メール本文をそのまま復号ツールに貼り付ければ開けます
- CF7 の AJAX 送信は使わず、通常のフォーム送信になります（CF7 の AJAX は平文を送ってしまうため、sealform が止めます）

[wordpress/mu-plugins/sealform-test-log.php](wordpress/mu-plugins/sealform-test-log.php) は検証用です（受け取った値をファイルに書き出し、メール送信を止めます）。本番には入れないでください。
