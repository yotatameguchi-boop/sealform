<?php
// 検証用: CF7 が受け取った値と添付ファイルを wp-content/sealform-received.jsonl に書き出し、メール送信は省く。
// 本番には入れないこと。
add_filter('wpcf7_skip_mail', '__return_true');
add_action('wpcf7_before_send_mail', function ($form) {
    $sub = WPCF7_Submission::get_instance();
    if (!$sub) {
        return;
    }
    $files = [];
    foreach ($sub->uploaded_files() as $name => $paths) {
        foreach ((array) $paths as $p) {
            $files[] = ['field' => $name, 'name' => basename($p), 'base64' => base64_encode((string) file_get_contents($p))];
        }
    }
    file_put_contents(WP_CONTENT_DIR . '/sealform-received.jsonl', wp_json_encode([
        'posted' => $sub->get_posted_data(),
        'files' => $files,
    ], JSON_UNESCAPED_UNICODE) . "\n", FILE_APPEND);
});
