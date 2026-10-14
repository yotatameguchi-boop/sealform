# 変更履歴

## 0.4.0（2026-10-14）

外部レビュー（v0.3.0 対象）の指摘への対応。平文が送られうる経路を閉じた。

### 平文が送られうる経路を閉じた
- **WordPress: 公開鍵がすべて期限切れになると、普通の平文フォームに戻っていた。** 「暗号化を有効にする」設定と鍵の有効性を切り離した。有効にした後は、鍵が期限切れ・不正・未設定でもフォームは「送信できない」状態のままにし、サーバー側の平文の拒否も続ける。管理画面に警告を出し、期限 30 日前にも知らせる。**この設定は既定で無効になった**（有効にしないと何も変わらない）
- **暗号化している間にフォームへ足された欄が、平文で送られていた。** 送信開始時のフォームの状態を記録し、暗号化の直後に照合して、変わっていれば送らない。照合から送信までは同期処理で、割り込めない
- **読み込んだ後に期限切れになった鍵で暗号化し続けていた。** 送信時に期限を確かめ直し、切れていれば取り直す（取れなければ送らない）。`seal` / `sealFile` も期限切れの鍵を拒否する
- 鍵が無いなど送れない状態の間は、他のスクリプト（Contact Form 7 の同意チェックなど）が送信ボタンを押せる状態に戻しても、押せないままにする

### 必須チェック
- `required` / `aria-required="true"` の欄が空なら、暗号化する前にブラウザで止める
- 空欄は暗号化せずに空のまま送る。サーバー側（Contact Form 7 を含む）の必須チェックが働く。どの欄が空だったかはサーバーに分かる
- WordPress: 外す Contact Form 7 の検査を、CF7 自身の処理（関数名が `wpcf7_` で始まるもの）だけに絞った。他のプラグインの検査は残す

### sealform check
- HTML をブラウザと同じ規則で解釈する（parse5）。コメント・`<template>`・`<noscript>` の中の「正しい HTML」に騙されない
- `script-src *`・`https:`・`'unsafe-eval'` など広すぎる CSP を「制限なし」とみなす。`<meta>` の CSP も読む
- `--form-action` と `--sealed-field` で、守られているべきフォームと項目を登録できる
- 保護の付いていない送信ボタン、sealform の付いていない POST フォーム、sealform 以外のスクリプトを知らせる
- 「点検に通っても実際の暗号化までは保証しない」ことを出力と README に明記

### 検証関数
- `isSealed` / `isSealedFile`（Node・PHP・Python）が、見出しの中身・種類・宛先一覧と本文の長さまで確かめるようにした（`sf2.YQ.YQ.YQ` や見出しだけのファイルを通していた）。共通ベクタを 33 件に増やした

### テストと配布
- 実ブラウザ（Chromium・Firefox・WebKit）で送信し、サーバーに届いた中身に平文が無いことを確かめるテスト（Playwright）
- WordPress 7.1 + Contact Form 7 6.2.2 の実環境テスト（期限切れの鍵、必須の空欄、添付、平文の直接送信）。どちらも CI で実行
- GitHub Actions をコミット SHA で固定。リリースに全配布物の `SHA256SUMS` と既知の制限を載せる
- 検証用の WordPress・MariaDB・wp-cli・Contact Form 7 の版を固定

### その他
- 「使い回しの検出」の説明を「別フォーム・別項目への転用の検出」に改め、同じ暗号文の再送（リプレイ）は防がないことを明記
- 復旧コードの HTML（`sealform-recovery-*.html`）を Git の除外対象にした
- 対応する Node を 20.19.0 以上にした（依存の @noble/hashes に合わせた）。package-lock.json の版・ライセンス表記を揃えた
- CONTRIBUTING.md と docs/SUPPORT.md（対応環境と保守方針）を加えた


## 0.3.0（2026-10-12）

- 紙の復旧コード: `sealform recovery export / import`。秘密鍵を検査値付きの Crockford Base32 にし、印刷用 HTML を出力する
- サーバー側の受け取り例: Express・Next.js・Flask・PHP（examples/）。PHP と Python の検証関数（server/）
- WordPress プラグイン（wordpress/sealform、`npm run build:wordpress`）: Contact Form 7 のフォームを丸ごと暗号化し、CF7 の値の検査を暗号文向けに差し替える
- submit イベントを document の捕捉段階で受け取り、他のスクリプトに渡さないようにした（CF7 などが平文を AJAX 送信するのを防ぐ）
- サーバーが差し戻した暗号文が入力欄に入っていたら空にする（二重の暗号化を防ぐ）
- `data-sealform-manual`: 自動初期化しない指定（React などで自分で attach するとき）。最新の表示を `data-sealform-message` にも残す
- 英語表示: `<html lang="en">` または `data-sealform-lang="en"`。README.en.md
- テストベクタ: X-Wing 公式ベクタ（draft-10）、sealform の復号ベクタ、Node・PHP・Python 共通の検証関数ベクタ
- 配布物のハッシュは `npm run release:build` のときだけ hashes.json に記録し、記録済みの版の中身が変わっていたら止める
- CI（Node 20/22/24、PHP 7.4、Python 3.9）と、タグで GitHub Release を作るワークフロー（npm には公開しない方針。NPM_TOKEN を登録したときだけ provenance 付きで公開する）
- GitHub から直接インストールできるようにした（`npm install github:yotatameguchi-boop/sealform#v0.3.0`。インストール時に自動でビルド）

## 0.2.0（2026-10-12）

暗号文の形式が sf2 に変わった。v0.1.0 の暗号文（sf1）は引き続き復号できる。

- 複数の担当者: サイトに置く公開鍵を「鍵の束」にでき、束の全員に宛てて暗号化する。各自が自分の秘密鍵だけで読める
- 鍵の更新: `sealform keys add/remove/list`。期限切れの鍵は使わない。`open --key` を複数並べれば古い暗号文も開ける
- 添付ファイル: `<input type="file" data-seal>` の中身・ファイル名・種類を暗号化して送る（上限 50MB、`data-sealform-max-mb` で変更可）
- 指紋の固定を複数の鍵に対応。束に登録外の鍵が足されていたら送信しない。`check` も検出する
- `keygen` の出力ファイル名に kid を含めるようにした（鍵の更新で上書きしないため）
- 復号ツール（単一 HTML）で複数の秘密鍵と添付ファイルを扱えるようにした
- API の変更: `open(秘密鍵, kid, 暗号文)` → `open({ kid, privateKey } または その配列, 暗号文)`

## 0.1.0（2026-10-12）

最初の版。
