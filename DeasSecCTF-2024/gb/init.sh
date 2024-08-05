#!/usr/bin/env bash

(while sleep 300;do rm /tmp/* ;done) &

socat TCP-LISTEN:1337,reuseaddr,fork EXEC:/start_server.sh,stderr
