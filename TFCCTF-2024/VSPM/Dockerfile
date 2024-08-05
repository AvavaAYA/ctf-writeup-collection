FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    socat \
    libstdc++6 \
    libgcc-s1 \
    libssl-dev \
    patchelf \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /home/ctf

COPY chall /home/ctf/chall
COPY ld-2.30.so /home/ctf/ld-2.30.so
COPY libc-2.30.so /home/ctf/libc-2.30.so
COPY libc.so.6 /home/ctf/libc.so.6
COPY ld.so.2 /home/ctf/ld.so.2
COPY flag.txt /home/ctf/flag.txt

RUN chmod +x /home/ctf/chall
WORKDIR /home/ctf

EXPOSE 1337

CMD socat TCP-LISTEN:1337,reuseaddr,fork EXEC:/home/ctf/chall
