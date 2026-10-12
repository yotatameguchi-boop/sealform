<?php
/**
 * Plugin Name:       sealform
 * Description:       フォームの入力をブラウザの中で耐量子ハイブリッド暗号（HPKE + X-Wing）で暗号化してから送ります。Contact Form 7 に対応。
 * Version:           0.3.0
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
        'cf7' => !isset($s['cf7']) || $s['cf7'] === '1',
    ];
}

/** 鍵の束 JSON から、有効期限内の鍵の指紋を取り出す。不正なら null。 */
function sealform_fingerprints(string $json): ?array
{
    $doc = json_decode($json, true);
    if (!is_array($doc)) {
        return null;
    }
    $keys = (($doc['type'] ?? null) === 'key-set') ? ($doc['keys'] ?? []) : [$doc];
    $fps = [];
    foreach ($keys as $k) {
        if (!is_array($k) || ($k['sealform'] ?? null) !== 1 || !is_string($k['fingerprint'] ?? null)) {
            return null;
        }
        if (!preg_match('/\ASHA256:[A-Za-z0-9+\/]{43}\z/', $k['fingerprint'])) {
            return null;
        }
        if (strtotime((string) ($k['expires'] ?? '')) > time()) {
            $fps[] = $k['fingerprint'];
        }
    }
    return $fps ?: null;
}

function sealform_is_configured(): bool
{
    return sealform_fingerprints(sealform_settings()['key_set']) !== null;
}

// ---------------------------------------------------------------- 公開鍵の配信

add_action('rest_api_init', function () {
    register_rest_route('sealform/v1', '/key', [
        'methods' => 'GET',
        'permission_callback' => '__return_true',
        'callback' => function () {
            $json = sealform_settings()['key_set'];
            if (sealform_fingerprints($json) === null) {
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
    if (!sealform_is_configured()) {
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
    return [
        'data-sealform-key' => sealform_key_url(),
        'data-sealform-fingerprint' => implode(' ', sealform_fingerprints($s['key_set']) ?? []),
        'data-sealform-max-mb' => (string) $s['max_mb'],
    ];
}

function sealform_cf7_enabled(): bool
{
    return sealform_settings()['cf7'] && sealform_is_configured();
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
 * 中身の検査はできなくなる（サーバーは平文を見ないため）。
 */
const SEALFORM_CF7_TYPES = ['text', 'email', 'url', 'tel', 'textarea', 'number', 'range', 'date', 'select', 'checkbox', 'radio'];

add_action('wpcf7_init', function () {
    if (!sealform_cf7_enabled()) {
        return;
    }
    foreach (SEALFORM_CF7_TYPES as $type) {
        foreach ([$type, "$type*"] as $hook) {
            remove_all_filters("wpcf7_validate_$hook");
            add_filter("wpcf7_validate_$hook", 'sealform_cf7_validate', 10, 2);
        }
    }
    foreach (['file', 'file*'] as $hook) {
        add_filter("wpcf7_validate_$hook", 'sealform_cf7_validate_file', 20, 3);
    }
    // CF7 6 系は文字数・形式・選択肢の検査を「スキーマ」で行うので、そちらも外す。
    // 添付ファイルの規則（拡張子 .sf と大きさの上限）は暗号化後のファイルにも有効なので残す
    global $wp_filter;
    if (isset($wp_filter['wpcf7_swv_create_schema'])) {
        foreach ($wp_filter['wpcf7_swv_create_schema']->callbacks as $priority => $callbacks) {
            foreach ($callbacks as $cb) {
                $fn = $cb['function'];
                if (is_string($fn) && strpos($fn, 'wpcf7_swv_add_') === 0 && $fn !== 'wpcf7_swv_add_file_rules') {
                    remove_action('wpcf7_swv_create_schema', $fn, $priority);
                }
            }
        }
    }
}, 99);

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

add_action('admin_menu', function () {
    add_options_page('sealform', 'sealform', 'manage_options', 'sealform', 'sealform_settings_page');
});

add_action('admin_init', function () {
    register_setting('sealform', SEALFORM_OPTION, [
        'type' => 'array',
        'sanitize_callback' => function ($in) {
            $json = trim((string) wp_unslash($in['key_set'] ?? ''));
            if ($json !== '' && sealform_fingerprints($json) === null) {
                add_settings_error(SEALFORM_OPTION, 'bad_key', __('鍵の束の JSON が正しくないか、有効期限内の鍵がありません。', 'sealform'));
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
    $fps = sealform_fingerprints($s['key_set']);
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
                    <p class="description"><?php esc_html_e('hidden 以外の全項目と添付ファイルが暗号化されます。添付ファイルの欄には filetypes:sf を付けてください（例: [file your-file filetypes:sf limit:20mb]）。通知メールには暗号文と .sf ファイルが届くので、sealform の復号ツールで開きます。', 'sealform'); ?></p></td>
                </tr>
            </table>
            <?php submit_button(); ?>
        </form>
        <?php if ($fps) : ?>
            <h2><?php esc_html_e('外からの点検', 'sealform'); ?></h2>
            <p><?php esc_html_e('別の PC や GitHub Actions から定期的に実行すると、JS や公開鍵の差し替えに気づけます。', 'sealform'); ?></p>
            <pre style="white-space:pre-wrap">npx sealform check <?php echo esc_html(home_url('/')); ?>&lt;フォームのあるページ&gt; --fingerprint "<?php echo esc_html(implode(' ', $fps)); ?>"</pre>
        <?php endif; ?>
    </div>
    <?php
}
