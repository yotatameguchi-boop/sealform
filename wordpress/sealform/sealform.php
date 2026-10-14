<?php
/**
 * Plugin Name:       sealform
 * Description:       フォームの入力をブラウザの中で耐量子ハイブリッド暗号（HPKE + X-Wing）で暗号化してから送ります。Contact Form 7 に対応。
 * Version:           0.4.0
 * Requires at least: 6.4
 * Requires PHP:      7.4
 * License:           Apache-2.0
 * Text Domain:       sealform
 */

if (!defined('ABSPATH')) {
    exit;
}

require_once __DIR__ . '/includes/validator.php';

const SEALFORM_OPTION = 'sealform_settings';

function sealform_settings(): array
{
    $s = get_option(SEALFORM_OPTION, []);
    return [
        'key_set' => is_string($s['key_set'] ?? null) ? $s['key_set'] : '',
        'max_mb' => max(1, min(50, (int) ($s['max_mb'] ?? 10))),
        // 暗号化を有効にするかどうか。鍵が有効かどうかとは切り離して持つ（下の sealform_cf7_enabled を参照）
        'cf7' => ($s['cf7'] ?? '0') === '1',
    ];
}

/**
 * 鍵の束 JSON の鍵を、形を確かめて返す（期限切れの鍵も含む）。形が不正なら null。
 * 暗号として正しい鍵かどうかはブラウザ側（loadKeys）で確かめる。
 */
function sealform_keys(string $json): ?array
{
    $doc = json_decode($json, true);
    if (!is_array($doc)) {
        return null;
    }
    $keys = (($doc['type'] ?? null) === 'key-set') ? ($doc['keys'] ?? null) : [$doc];
    if (!is_array($keys) || !$keys) {
        return null;
    }
    foreach ($keys as $k) {
        if (!is_array($k) || ($k['sealform'] ?? null) !== 1 || !is_string($k['fingerprint'] ?? null)
            || !preg_match('/\ASHA256:[A-Za-z0-9+\/]{43}\z/', $k['fingerprint'])) {
            return null;
        }
    }
    return $keys;
}

/** 鍵の束の指紋。$active_only なら有効期限内の鍵だけ。形が不正なら空。 */
function sealform_fingerprints(string $json, bool $active_only = true): array
{
    $fps = [];
    foreach (sealform_keys($json) ?? [] as $k) {
        if (!$active_only || strtotime((string) ($k['expires'] ?? '')) > time()) {
            $fps[] = $k['fingerprint'];
        }
    }
    return $fps;
}

/** 有効期限内の鍵があるか（設定画面の案内と警告に使う）。 */
function sealform_has_active_key(): bool
{
    return (bool) sealform_fingerprints(sealform_settings()['key_set']);
}

/**
 * 暗号化を有効にしているか。**鍵の有効性には左右されない。**
 * 鍵が期限切れ・不正・未設定になっても、フォームは「送信できない」状態のまま（平文のフォームには戻らない）、
 * サーバー側の平文の拒否も続ける。
 */
function sealform_cf7_enabled(): bool
{
    return sealform_settings()['cf7'];
}

// ---------------------------------------------------------------- 公開鍵の配信

add_action('rest_api_init', function () {
    register_rest_route('sealform/v1', '/key', [
        'methods' => 'GET',
        'permission_callback' => '__return_true',
        'callback' => function () {
            $json = sealform_settings()['key_set'];
            // 期限切れの鍵でもそのまま返す（ブラウザが「期限切れ」と表示して送信を止める）
            if (sealform_keys($json) === null) {
                return new WP_Error('sealform_no_key', 'sealform の公開鍵が設定されていません', ['status' => 404]);
            }
            $res = new WP_REST_Response(json_decode($json, true));
            $res->header('Cache-Control', 'no-cache');
            return $res;
        },
    ]);
});

function sealform_key_url(): string
{
    return rest_url('sealform/v1/key');
}

// ---------------------------------------------------------------- スクリプト

add_action('wp_enqueue_scripts', function () {
    if (!sealform_cf7_enabled()) {
        return;
    }
    wp_enqueue_script('sealform', plugins_url('assets/sealform.js', __FILE__), [], null, ['strategy' => 'defer', 'in_footer' => true]);
});

// SRI（integrity）を付ける。sealform check が、配信中の JS と公式配布物のハッシュを照合する
add_filter('script_loader_tag', function ($tag, $handle) {
    if ($handle !== 'sealform') {
        return $tag;
    }
    $integrity = 'sha384-' . base64_encode(hash_file('sha384', __DIR__ . '/assets/sealform.js', true));
    return str_replace(' src=', sprintf(' integrity="%s" crossorigin="anonymous" src=', esc_attr($integrity)), $tag);
}, 10, 2);

// ---------------------------------------------------------------- Contact Form 7

/** フォームに付ける属性。テーマで自作のフォームに使うときは sealform_form_attributes() を出力する。 */
function sealform_form_attributes(): array
{
    $s = sealform_settings();
    $atts = [
        'data-sealform-key' => sealform_key_url(),
        'data-sealform-max-mb' => (string) $s['max_mb'],
    ];
    // 束のすべての鍵の指紋で固定する（束に知らない鍵が足されたら、ブラウザが送信を止める）
    $fps = sealform_fingerprints($s['key_set'], false);
    if ($fps) {
        $atts['data-sealform-fingerprint'] = implode(' ', $fps);
    }
    return $atts;
}

add_filter('wpcf7_form_additional_atts', function ($atts) {
    return sealform_cf7_enabled() ? array_merge((array) $atts, sealform_form_attributes()) : $atts;
});

// 送信ボタンは JS が動くまで押せないようにする（平文の送信を防ぐ）。状態表示の場所も足す
add_filter('wpcf7_form_elements', function ($html) {
    if (!sealform_cf7_enabled()) {
        return $html;
    }
    $html = preg_replace_callback('/<input\b[^>]*\btype="submit"[^>]*>/', function ($m) {
        return str_replace('type="submit"', 'type="submit" disabled data-sealform-submit', $m[0]);
    }, $html);
    $html = preg_replace_callback('/<button\b[^>]*\btype="submit"[^>]*>/', function ($m) {
        return str_replace('type="submit"', 'type="submit" disabled data-sealform-submit', $m[0]);
    }, $html);
    return $html . '<p class="sealform-status" data-sealform-status aria-live="polite"></p>'
        . '<noscript><p>' . esc_html__('このフォームは JavaScript を有効にしないと送信できません（暗号化のため）。', 'sealform') . '</p></noscript>';
});

/**
 * 暗号文は「メールアドレスの形式」「文字数」「選択肢」などの検査を必ず通らないので、
 * 暗号化を有効にしたフォームでは、CF7 の値の検査を「必須かどうか」と「暗号文か」の検査に差し替える。
 * - 外すのは CF7 自身の検査（関数名が wpcf7_ で始まるもの）だけ。他のプラグインが足した検査は残す
 * - 空欄はブラウザが暗号化せずに空のまま送るので、必須かどうかはここで確かめられる
 * - 中身の形式（メールアドレスとして正しいか等）は確かめられない（サーバーは平文を見ないため）
 */
const SEALFORM_CF7_TYPES = ['text', 'email', 'url', 'tel', 'textarea', 'number', 'range', 'date', 'select', 'checkbox', 'radio'];

add_action('wpcf7_init', function () {
    if (!sealform_cf7_enabled()) {
        return;
    }
    foreach (SEALFORM_CF7_TYPES as $type) {
        foreach ([$type, "$type*"] as $hook) {
            sealform_remove_cf7_callbacks("wpcf7_validate_$hook");
            add_filter("wpcf7_validate_$hook", 'sealform_cf7_validate', 10, 2);
        }
    }
    foreach (['file', 'file*'] as $hook) {
        add_filter("wpcf7_validate_$hook", 'sealform_cf7_validate_file', 20, 3);
    }
    // CF7 6 系は文字数・形式・選択肢の検査を「スキーマ」で行うので、そちらも外す。
    // 添付ファイルの規則（拡張子 .sf と大きさの上限）は暗号化後のファイルにも有効なので残す
    sealform_remove_cf7_callbacks('wpcf7_swv_create_schema', ['wpcf7_swv_add_file_rules']);
}, 99);

/** フックから CF7 自身の処理（関数名が wpcf7_ で始まるもの）だけを外す。 */
function sealform_remove_cf7_callbacks(string $hook, array $keep = []): void
{
    global $wp_filter;
    if (!isset($wp_filter[$hook])) {
        return;
    }
    foreach ($wp_filter[$hook]->callbacks as $priority => $callbacks) {
        foreach ($callbacks as $cb) {
            $fn = $cb['function'];
            if (is_string($fn) && strpos($fn, 'wpcf7_') === 0 && !in_array($fn, $keep, true)) {
                remove_filter($hook, $fn, $priority);
            }
        }
    }
}

function sealform_cf7_validate($result, $tag)
{
    $raw = $_POST[$tag->name] ?? '';
    $values = array_values(array_filter((array) wp_unslash($raw), fn($v) => $v !== ''));
    if (!$values) {
        if ($tag->is_required()) {
            $result->invalidate($tag, wpcf7_get_message('invalid_required'));
        }
        return $result;
    }
    foreach ($values as $v) {
        if (!sealform_is_sealed($v)) {
            $result->invalidate($tag, __('暗号化されていない値が届いたため、受け付けませんでした。', 'sealform'));
            break;
        }
    }
    return $result;
}

function sealform_cf7_validate_file($result, $tag, $args = [])
{
    $files = (array) ($args['uploaded_files'] ?? []);
    foreach ($files as $path) {
        if (is_string($path) && is_file($path) && !sealform_is_sealed_file((string) file_get_contents($path))) {
            $result->invalidate($tag, __('暗号化されていないファイルが届いたため、受け付けませんでした。', 'sealform'));
            break;
        }
    }
    return $result;
}

// ---------------------------------------------------------------- 設定画面

// 暗号化を有効にしているのに使える鍵が無い（期限切れなど）ときは、管理画面のどこにいても知らせる
add_action('admin_notices', function () {
    if (!sealform_cf7_enabled() || !current_user_can('manage_options')) {
        return;
    }
    $s = sealform_settings();
    if (!sealform_has_active_key()) {
        printf(
            '<div class="notice notice-error"><p><strong>sealform:</strong> %s <a href="%s">%s</a></p></div>',
            esc_html__('暗号化は有効ですが、有効期限内の公開鍵がありません。Contact Form 7 のフォームは今、送信できない状態です（平文で送られることはありません）。', 'sealform'),
            esc_url(admin_url('options-general.php?page=sealform')),
            esc_html__('鍵を更新する', 'sealform')
        );
        return;
    }
    $soon = array_filter(sealform_keys($s['key_set']) ?? [], function ($k) {
        $t = strtotime((string) ($k['expires'] ?? ''));
        return $t > time() && $t < time() + 30 * DAY_IN_SECONDS;
    });
    if ($soon) {
        printf(
            '<div class="notice notice-warning"><p><strong>sealform:</strong> %s</p></div>',
            esc_html__('有効期限が 30 日以内の公開鍵があります。期限が切れる前に新しい鍵を加えてください。', 'sealform')
        );
    }
});

add_action('admin_menu', function () {
    add_options_page('sealform', 'sealform', 'manage_options', 'sealform', 'sealform_settings_page');
});

add_action('admin_init', function () {
    register_setting('sealform', SEALFORM_OPTION, [
        'type' => 'array',
        'sanitize_callback' => function ($in) {
            $json = trim((string) wp_unslash($in['key_set'] ?? ''));
            if ($json !== '' && sealform_keys($json) === null) {
                add_settings_error(SEALFORM_OPTION, 'bad_key', __('鍵の束の JSON が正しくありません。', 'sealform'));
                return get_option(SEALFORM_OPTION, []);
            }
            return [
                'key_set' => $json,
                'max_mb' => (string) max(1, min(50, (int) ($in['max_mb'] ?? 10))),
                'cf7' => !empty($in['cf7']) ? '1' : '0',
            ];
        },
    ]);
});

function sealform_settings_page()
{
    if (!current_user_can('manage_options')) {
        return;
    }
    $s = sealform_settings();
    $fps = sealform_fingerprints($s['key_set'], false);
    ?>
    <div class="wrap">
        <h1>sealform</h1>
        <p><?php esc_html_e('フォームの入力をブラウザの中で暗号化します。読めるのは秘密鍵を持つ担当者だけで、このサイトのサーバーやデータベース、通知メールには暗号文しか残りません。', 'sealform'); ?></p>
        <form method="post" action="options.php">
            <?php settings_fields('sealform'); ?>
            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row"><label for="sealform-key-set"><?php esc_html_e('鍵の束（sealform-key.json）', 'sealform'); ?></label></th>
                    <td>
                        <textarea id="sealform-key-set" name="<?php echo esc_attr(SEALFORM_OPTION); ?>[key_set]" rows="8" class="large-text code"><?php echo esc_textarea($s['key_set']); ?></textarea>
                        <p class="description"><?php esc_html_e('担当者の手元で npx sealform keygen と keys add を実行して作った sealform-key.json の中身を貼り付けます。秘密鍵は貼らないでください。', 'sealform'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="sealform-max-mb"><?php esc_html_e('添付ファイルの上限（MB）', 'sealform'); ?></label></th>
                    <td><input id="sealform-max-mb" type="number" min="1" max="50" name="<?php echo esc_attr(SEALFORM_OPTION); ?>[max_mb]" value="<?php echo esc_attr((string) $s['max_mb']); ?>"></td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html_e('Contact Form 7', 'sealform'); ?></th>
                    <td><label><input type="checkbox" name="<?php echo esc_attr(SEALFORM_OPTION); ?>[cf7]" value="1" <?php checked($s['cf7']); ?>> <?php esc_html_e('すべての Contact Form 7 のフォームを暗号化する', 'sealform'); ?></label>
                    <p class="description"><?php esc_html_e('hidden 以外の全項目と添付ファイルが暗号化されます。添付ファイルの欄には filetypes:sf を付けてください（例: [file your-file filetypes:sf limit:20mb]）。通知メールには暗号文と .sf ファイルが届くので、sealform の復号ツールで開きます。', 'sealform'); ?></p>
                    <p class="description"><?php esc_html_e('有効にすると、公開鍵が期限切れ・未設定になってもフォームは平文には戻らず、「送信できない」状態になります。空欄は暗号化せずに送るので必須チェックは働きますが、メールアドレスの形式のような中身の確認はできません。', 'sealform'); ?></p></td>
                </tr>
            </table>
            <?php submit_button(); ?>
        </form>
        <?php if ($fps) : ?>
            <h2><?php esc_html_e('外からの点検', 'sealform'); ?></h2>
            <p><?php esc_html_e('別の PC や GitHub Actions から定期的に実行すると、JS や公開鍵の差し替えに気づけます。', 'sealform'); ?></p>
            <pre style="white-space:pre-wrap">npx github:yotatameguchi-boop/sealform#v0.4.0 check <?php echo esc_html(home_url('/')); ?>&lt;フォームのあるページ&gt; --fingerprint "<?php echo esc_html(implode(' ', $fps)); ?>"</pre>
        <?php endif; ?>
    </div>
    <?php
}
