# 貢献のしかた

sealform への関心をありがとうございます。試作段階なので、特に次のような協力を歓迎しています。

- 暗号の組み立て方へのツッコミ（[docs/FORMAT.md](docs/FORMAT.md) に形式を書いています）
- 「このフォーム部品・この環境だと平文が漏れた」という報告
- 実際に相談窓口・内部通報窓口を運営している方からの、運用上の要望
- 他の言語での検証関数や復号の実装（`test-vectors/` の結果に合わせてください）

## 脆弱性は公開の Issue に書かない

平文が漏れる・暗号が破れるなどの問題は、Issue ではなく [SECURITY.md](SECURITY.md) の手順で非公開で報告してください。

## 開発の準備

```bash
npm install
npm run build
npm test                         # 単体テスト
node examples/shared/demo.mjs    # デモ用の鍵を作る
npx playwright install chromium firefox webkit
npx playwright test --project=chromium --project=firefox --project=webkit
```

PHP と Python の検証関数を変えたときは、それぞれのテストも動かしてください。

```bash
python3 server/python/test_sealform_check.py
php server/php/test.php
```

WordPress プラグインを変えたときは、[examples/README.md](examples/README.md) の手順で Docker の WordPress を立てて、`WP_URL=http://localhost:8795 npx playwright test --project=wordpress` を動かしてください。

## 変更するときの決まり

- **暗号の部品は自作しません。** HPKE・X-Wing・AES-GCM は既存の実装（`@hpke/*`、Web Crypto）を使います。
- **平文で送る道を作らない。** 失敗したら送らない（フェイルクローズ）が原則です。送信に関わる変更には、平文が出ていかないことを確かめるテスト（単体テストと実ブラウザのテスト）を付けてください。
- **暗号文の形式を変えるとき**は、版の記号（`sf2` など）を上げ、古い形式の復号を残し、[docs/FORMAT.md](docs/FORMAT.md) と `test-vectors/` を更新してください。
- **サーバー側の検証関数**（Node・PHP・Python）は同じ結果を返す必要があります。`test-vectors/validator.json` にケースを足して、3つとも通してください。
- **ブラウザ用の sealform.js を変えたら、版を上げます。** 版ごとの公式ハッシュを `hashes.json` に記録するためです（`npm run release:build` は、記録済みの版の中身が変わっていると止まります）。
- 変更点は [CHANGELOG.md](CHANGELOG.md) に書いてください。
- コードのコメント・ドキュメント・画面の文言は、今は日本語が中心です（ブラウザの表示と README は英語もあります）。

## リリース（保守者向け）

1. `package.json` と WordPress プラグインの `Version:` を上げる
2. `npm run release:build` で `hashes.json` に記録し、CHANGELOG を書いてコミット
3. `v<版>` のタグを push すると、Release ワークフローが GitHub Release（配布物・`SHA256SUMS`）を作ります
