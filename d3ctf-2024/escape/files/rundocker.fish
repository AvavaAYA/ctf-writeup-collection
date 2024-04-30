#!/usr/bin/env fish

docker build -t ubuntu-gcc .
docker run -it -v $(pwd):/app ubuntu-gcc
