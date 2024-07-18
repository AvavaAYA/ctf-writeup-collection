FROM ubuntu:22.04

RUN apt-get update && apt-get install -y wget xz-utils socat
RUN wget -O - https://github.com/bytecodealliance/wasmtime/releases/download/v21.0.1/wasmtime-v21.0.1-x86_64-linux.tar.xz \
		| tar -xJ wasmtime-v21.0.1-x86_64-linux/wasmtime
RUN mv wasmtime-v21.0.1-x86_64-linux/wasmtime /usr/bin/wasmtime

COPY cache.toml run.sh flag.txt banner.txt chall /
RUN chmod +x /run.sh
CMD socat TCP-LISTEN:5000,reuseaddr,fork EXEC:/run.sh
