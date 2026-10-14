<?php
// php server/php/test.php で実行。test-vectors/validator.json と同じ結果になるかを確かめる
require __DIR__ . '/sealform.php';
$v = json_decode(file_get_contents(__DIR__ . '/../../test-vectors/validator.json'), true);
$fail = 0;
foreach ($v['text'] as $c) {
    if (sealform_is_sealed($c['value']) !== $c['sealed']) { $fail++; echo "NG text: {$c['note']}\n"; }
}
foreach ($v['files'] as $i => $c) {
    if (sealform_is_sealed_file(base64_decode($c['base64'])) !== $c['sealed']) { $fail++; echo "NG file: {$c['note']}\n"; }
}
if (sealform_is_sealed(null) !== false) { $fail++; echo "NG null\n"; }
$total = count($v['text']) + count($v['files']) + 1;
echo ($total - $fail) . "/$total OK\n";
exit($fail ? 1 : 0);
