FROM ubuntu:17.04

RUN sed -i -re 's/([a-z]{2}\.)?archive.ubuntu.com|security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list
RUN apt update
RUN apt install -y socat netcat net-tools gdb

RUN useradd ctf 

WORKDIR /home/ctf
COPY ./chall /home/ctf/
COPY ./flag.txt /home/ctf/

RUN chmod +x /home/ctf/chall

EXPOSE 1337

USER ctf
CMD socat TCP-LISTEN:1337,reuseaddr,fork EXEC:./chall,stderr
