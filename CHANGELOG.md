# 変更履歴

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
- CI（Node 20/22/24、PHP 7.4、Python 3.9）と、provenance 付きで npm に公開する Release ワークフロー

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
