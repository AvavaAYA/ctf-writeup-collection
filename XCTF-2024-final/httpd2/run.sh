#!/usr/bin/env bash

docker run -it --privileged -p 80:80 -p 8888:8888 -p 1234:1234 httpd2
