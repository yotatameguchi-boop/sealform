<?php
/**
 * 素の PHP での受け取り例（PHP 7.4 以降・拡張不要）。
 *
 *   node examples/shared/demo.mjs     # デモ用の鍵を用意（初回のみ。先に npm run build）
 *   php -S localhost:8790 examples/php/index.php
 *   （PHP が無ければ）docker run --rm -p 8790:8790 -v "$PWD":/app -w /app php:8.3-cli \
 *       php -d upload_max_filesize=20M -d post_max_size=60M -S 0.0.0.0:8790 examples/php/index.php
 */
require __DIR__ . '/../../server/php/sealform.php';

$root = realpath(__DIR__ . '/../..');
$data = "$root/examples/.data";
$keySet = "$data/sealform-key.json";
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; base-uri 'none'");

if ($_SERVER['REQUEST_METHOD'] === 'GET' && $path === '/') {
    $hashes = json_decode(file_get_contents("$root/dist/hashes.json"), true);
    $ks = json_decode(file_get_contents($keySet), true);
    $fps = implode(' ', array_map(fn($k) => $k['fingerprint'], $ks['keys'] ?? [$ks]));
    $html = file_get_contents("$root/examples/shared/form.html");
    // PHP で複数ファイルを受け取るには name="attachment[]" にする
    echo str_replace(
        ['__INTEGRITY__', '__FINGERPRINT__', 'sealform デモ', 'name="attachment"'],
        [end($hashes), $fps, 'sealform デモ・PHP', 'name="attachment[]"'],
        $html
    );
    return;
}
if ($_SERVER['REQUEST_METHOD'] === 'GET' && $path === '/sealform.js') {
    header('Content-Type: text/javascript; charset=utf-8');
    readfile("$root/dist/sealform.js");
    return;
}
if ($_SERVER['REQUEST_METHOD'] === 'GET' && $path === '/.well-known/sealform-key.json') {
    header('Content-Type: application/json');
    readfile($keySet);
    return;
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $path === '/contact') {
    $name = $_POST['name'] ?? null;
    $message = $_POST['message'] ?? null;
    // 平文が混ざっていたら保存しない（設定ミスや JS の差し替えへの保険）
    if (!sealform_is_sealed($name) || !sealform_is_sealed($message)) {
        http_response_code(400);
        exit('暗号化されていない値が届きました');
    }
    // name="attachment[]" の複数ファイルは、項目ごとの配列で届くので 1 件ずつに並べ直す
    $uploads = [];
    if (isset($_FILES['attachment'])) {
        $f = $_FILES['attachment'];
        if (is_array($f['name'])) {
            foreach (array_keys($f['name']) as $i) {
                $uploads[] = ['name' => $f['name'][$i], 'tmp_name' => $f['tmp_name'][$i], 'error' => $f['error'][$i], 'size' => $f['size'][$i]];
            }
        } else {
            $uploads[] = $f;
        }
    }
    $saved = [];
    foreach ($uploads as $u) {
        if (!sealform_is_sealed_upload($u)) {
            http_response_code(400);
            exit('暗号化されていないファイルが届きました');
        }
        if (($u['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_NO_FILE) {
            continue;
        }
        $id = bin2hex(random_bytes(8)) . '.sf';
        move_uploaded_file($u['tmp_name'], "$data/files/$id");
        $saved[] = $id;
    }
    $fh = fopen("$data/submissions.csv", 'a');
    fputcsv($fh, [gmdate('c'), $name, $message, implode(' ', $saved), 'php'], ',', '"', '');
    fclose($fh);
    echo '<!doctype html><meta charset="utf-8"><title>送信しました</title><p>送信しました（PHP・添付 ' . count($saved) . ' 件）。保存されたのは暗号文だけです。</p><p><a href="/">戻る</a></p>';
    return;
}
http_response_code(404);
echo 'not found';
