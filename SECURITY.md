# セキュリティ上の問題の報告

sealform の脆弱性を見つけた場合は、公開の Issue には書かず、GitHub の
「Security」タブ → 「Report a vulnerability」（Private Vulnerability Reporting）から報告してください。

- 受け取りの連絡: 3 営業日以内
- 修正と公開: 原則 90 日以内。利用者への影響が大きい場合は調整のうえ早めます

対象: 暗号文の形式、鍵の扱い、ブラウザ組み込みのフェイルクローズ、`sealform check` の見落とし、復号ツールからの情報漏えいなど。
「サーバーを乗っ取られると JS を差し替えられる」こと自体は既知の限界です（README の脅威モデル参照）。
