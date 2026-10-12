#!/bin/sh
# WordPress を初期設定し、Contact Form 7 と sealform を有効にして、相談フォームのページを作る
set -e
cd "$(dirname "$0")"
wp() { docker compose -f compose.yml run --rm -T cli "$@"; }
until wp db check >/dev/null 2>&1; do sleep 2; done
if ! wp core is-installed 2>/dev/null; then
  wp core install --url=http://localhost:8795 --title="sealform 検証" --admin_user=admin \
    --admin_password="$(head -c 18 /dev/urandom | base64)" --admin_email=admin@example.test --skip-email
fi
wp language core install ja --activate >/dev/null 2>&1 || true
wp plugin install contact-form-7 --activate
wp plugin activate sealform
wp option update permalink_structure '/%postname%/'
wp eval '
$set = file_get_contents("/sealform-data/sealform-key.json");
update_option("sealform_settings", ["key_set" => $set, "max_mb" => "10", "cf7" => "1"]);
$form = WPCF7_ContactForm::get_template(["title" => "相談フォーム"]);
$form->set_properties(["form" => "<label>お名前 [text* your-name]</label>\n<label>メール [email* your-email]</label>\n<label>相談内容 [textarea* your-message]</label>\n<label>添付 [file your-file filetypes:sf limit:20mb]</label>\n[acceptance agree]内容を確認しました[/acceptance]\n[submit \"送信\"]"]);
$id = $form->save();
$page = get_page_by_path("soudan");
if ($page) wp_delete_post($page->ID, true);
wp_insert_post(["post_type" => "page", "post_status" => "publish", "post_name" => "soudan", "post_title" => "相談", "post_content" => "[contact-form-7 id=\"$id\"]"]);
echo "form $id\n";
'
echo "http://localhost:8795/soudan/"
