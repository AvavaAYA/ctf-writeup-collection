#!/bin/sh

exec 2>/dev/null
rm /home/ctf/flag*
cp /flag "/home/ctf/flag`head /dev/urandom |cksum |md5sum |cut -c 1-20`"
chmod 744 /home/ctf/flag*