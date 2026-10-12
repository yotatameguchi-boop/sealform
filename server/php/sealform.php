<?php
/**
 * sealform のサーバー側検証（PHP 7.4 以降）。
 *
 * ブラウザから届いた値が sealform の暗号文の形をしているかを確かめる。復号はしない
 * （サーバーは秘密鍵を持たない）。平文が混ざって届いたときに保存を拒否するために使う。
 * 判定は Node 版の isSealed / isSealedFile と同じ（test-vectors/validator.json で確認）。
 */

if (!function_exists('sealform_is_sealed')) {
    /** 文字列の値が暗号文（sf1 / sf2）の形をしているか。 */
    function sealform_is_sealed($value): bool
    {
        return is_string($value) && (
            preg_match('/\Asf2\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\z/', $value) === 1 ||
            preg_match('/\Asf1\.[0-9a-f]{16}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\z/', $value) === 1
        );
    }

    function sealform_b64url_decode(string $s)
    {
        $b = strtr($s, '-_', '+/');
        $b .= str_repeat('=', (4 - strlen($b) % 4) % 4);
        return base64_decode($b, true);
    }

    /** ファイルの中身（バイト列）が、sealform で暗号化したファイル（sf2f）か。 */
    function sealform_is_sealed_file(string $data): bool
    {
        if (strlen($data) < 8 || substr($data, 0, 4) !== 'sf2f') {
            return false;
        }
        $headLen = unpack('N', substr($data, 4, 4))[1];
        if ($headLen > 65536 || 8 + $headLen > strlen($data)) {
            return false;
        }
        $head = substr($data, 8, $headLen);
        if (preg_match('/\Asf2\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\z/', $head, $m) !== 1) {
            return false;
        }
        $metaJson = sealform_b64url_decode($m[1]);
        $rcpt = sealform_b64url_decode($m[2]);
        if ($metaJson === false || $rcpt === false) {
            return false;
        }
        $meta = json_decode($metaJson, true);
        if (!is_array($meta) || ($meta['v'] ?? null) !== 2 || !in_array($meta['k'] ?? null, ['text', 'file'], true)) {
            return false;
        }
        if (!is_string($meta['f'] ?? null) || !is_string($meta['n'] ?? null)) {
            return false;
        }
        if (!is_int($meta['t'] ?? null) && !is_float($meta['t'] ?? null)) {
            return false;
        }
        $n = strlen($rcpt);
        $per = 8 + 1120 + 48;
        return $n > 0 && $n % $per === 0 && intdiv($n, $per) <= 10;
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
