# 暗号文と鍵の形式（sf1）

この形式は実装から独立して読めるように書いている。形式を変えるときは版（`sf1`）とパッケージのメジャー版を上げる。

## 暗号方式

| 部品 | 方式 |
|---|---|
| 全体 | HPKE（RFC 9180）Base モード |
| KEM | X-Wing（X25519 + ML-KEM-768 のハイブリッド、draft-connolly-cfrg-xwing-kem） |
| KDF | HKDF-SHA256 |
| AEAD | AES-256-GCM |
| info | UTF-8 の `sealform/v1` |

実装には `@hpke/core` と `@hpke/hybridkem-x-wing` を使い、暗号部品は自作しない。

## 暗号文（トークン）

```
sf1.<kid>.<meta>.<enc>.<ct>
```

| 部分 | 中身 |
|---|---|
| `sf1` | 形式の版 |
| `kid` | 公開鍵（X-Wing の公開鍵 1216 バイト）の SHA-256 の先頭 8 バイトを16進で表したもの（16 文字） |
| `meta` | base64url（パディング無し）で包んだ UTF-8 の JSON: `{"v":1,"f":"<フォーム識別子>","n":"<項目名>","t":<UNIX 秒>}` |
| `enc` | HPKE のカプセル化鍵（1120 バイト）を base64url にしたもの |
| `ct` | AEAD 暗号文を base64url にしたもの |

- **AAD** は `sf1.<kid>.<meta>` の UTF-8 バイト列。宛先フォーム・項目名・時刻を書き換えると復号に失敗する。
- **平文** は「4 バイト（ビッグエンディアン）の長さ + UTF-8 本文 + 0 埋め」で、全体を 64 バイトの倍数に丸めてから暗号化する。短い文の長さの差が暗号文に出ないようにするため。
- サーバー側は正規表現 `^sf1\.[0-9a-f]{16}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$` で形を確かめられる（`isSealed()`）。

## 公開鍵（`/.well-known/sealform-key.json`）

```json
{
  "sealform": 1,
  "kid": "23662db0cbd499e5",
  "alg": "HPKE-Base/X-Wing/HKDF-SHA256/AES-256-GCM",
  "publicKey": "<base64url>",
  "fingerprint": "SHA256:<公開鍵の SHA-256 を base64（パディング無し）>",
  "created": "2026-10-12T00:00:00.000Z",
  "expires": "2027-10-12T00:00:00.000Z"
}
```

読み込むときは `kid` と `fingerprint` を鍵本体から計算し直して照合する。期限切れの鍵では暗号化しない。

## 秘密鍵ファイル

```json
{
  "sealform": 1,
  "type": "private-key",
  "kid": "...",
  "publicKey": "<base64url>",
  "kdf": { "alg": "argon2id", "m": 19456, "t": 2, "p": 1, "salt": "<16 バイト>" },
  "iv": "<12 バイト>",
  "ciphertext": "<X-Wing 秘密鍵（32 バイトの種）を AES-256-GCM で暗号化したもの>"
}
```

- 鍵: Argon2id(NFC 正規化したパスフレーズ, salt, m, t, p) → 32 バイト
- AAD: `sealform-private-key.<kid>`
- 開くときは `kid` を公開鍵から計算し直し、`m > 1 GiB` などの極端な値は拒否する。
