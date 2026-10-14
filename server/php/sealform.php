<?php
/**
 * sealform のサーバー側検証（PHP 7.4 以降）。
 *
 * ブラウザから届いた値が sealform の暗号文の形をしているかを確かめる。復号はしない
 * （サーバーは秘密鍵を持たない）。平文が混ざって届いたときに保存を拒否するために使う。
 * 判定は Node 版の isSealed / isSealedFile と同じ（test-vectors/validator.json で確認）。
 *
 * 注意: 確かめられるのは「形」だけで、暗号文が本物か（改ざんされていないか）は
 * 秘密鍵で復号するときに初めて分かる。
 */

if (!function_exists('sealform_is_sealed')) {
    function sealform_b64url_decode(string $s)
    {
        if (strlen($s) % 4 === 1) {
            return false;
        }
        $b = strtr($s, '-_', '+/');
        $b .= str_repeat('=', (4 - strlen($b) % 4) % 4);
        return base64_decode($b, true);
    }

    /** 見出しの JSON を確かめて返す。不正なら null。 */
    function sealform_meta(string $part, int $version): ?array
    {
        $json = sealform_b64url_decode($part);
        if ($json === false) {
            return null;
        }
        $meta = json_decode($json, true);
        if (!is_array($meta) || ($meta['v'] ?? null) !== $version) {
            return null;
        }
        if (!is_string($meta['f'] ?? null) || !is_string($meta['n'] ?? null)) {
            return null;
        }
        if (!is_int($meta['t'] ?? null) && !is_float($meta['t'] ?? null)) {
            return null;
        }
        return $meta;
    }

    function sealform_recipients_ok(string $part): bool
    {
        $r = sealform_b64url_decode($part);
        if ($r === false) {
            return false;
        }
        $n = strlen($r);
        $per = 8 + 1120 + 48;
        return $n > 0 && $n % $per === 0 && intdiv($n, $per) <= 10;
    }

    function sealform_body_ok(int $length, int $bucket, int $iv = 12): bool
    {
        $ct = $length - $iv - 16;
        return $ct >= $bucket && $ct % $bucket === 0;
    }

    /** 文字列の値が暗号文（sf1 / sf2）の形をしているか。 */
    function sealform_is_sealed($value): bool
    {
        if (!is_string($value)) {
            return false;
        }
        if (preg_match('/\Asf2\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\z/', $value, $m) === 1) {
            $meta = sealform_meta($m[1], 2);
            $body = sealform_b64url_decode($m[3]);
            return $meta !== null && ($meta['k'] ?? null) === 'text' && sealform_recipients_ok($m[2])
                && $body !== false && sealform_body_ok(strlen($body), 64);
        }
        if (preg_match('/\Asf1\.[0-9a-f]{16}\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\z/', $value, $m) === 1) {
            $enc = sealform_b64url_decode($m[2]);
            $ct = sealform_b64url_decode($m[3]);
            return sealform_meta($m[1], 1) !== null && $enc !== false && strlen($enc) === 1120
                && $ct !== false && sealform_body_ok(strlen($ct), 64, 0);
        }
        return false;
    }

    /** ファイルの中身（バイト列）が、sealform で暗号化したファイル（sf2f）の形をしているか。 */
    function sealform_is_sealed_file(string $data): bool
    {
        if (strlen($data) < 8 || substr($data, 0, 4) !== 'sf2f') {
            return false;
        }
        $headLen = unpack('N', substr($data, 4, 4))[1];
        if ($headLen > 65536 || 8 + $headLen > strlen($data)) {
            return false;
        }
        if (preg_match('/\Asf2\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\z/', substr($data, 8, $headLen), $m) !== 1) {
            return false;
        }
        $meta = sealform_meta($m[1], 2);
        return $meta !== null && ($meta['k'] ?? null) === 'file' && sealform_recipients_ok($m[2])
            && sealform_body_ok(strlen($data) - 8 - $headLen, 4096);
    }

    /** アップロードされたファイル（$_FILES の1件）が暗号化済みか。未選択（サイズ 0）は true を返す。 */
    function sealform_is_sealed_upload(array $file): bool
    {
        if (($file['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_NO_FILE) {
            return true;
        }
        if (($file['error'] ?? 1) !== UPLOAD_ERR_OK || !is_uploaded_file($file['tmp_name'])) {
            return false;
        }
        return sealform_is_sealed_file((string) file_get_contents($file['tmp_name']));
    }
}
