#!/usr/bin/env bash

docker build -t ubuntu-gcc .
docker run -it --rm -v $(pwd):/app ubuntu-gcc
