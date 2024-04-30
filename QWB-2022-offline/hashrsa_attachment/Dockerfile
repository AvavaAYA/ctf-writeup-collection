FROM python:latest

RUN sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list
RUN apt update && apt upgrade -y && apt install -y socat
RUN pip install unicorn filelock

WORKDIR             /root
COPY chal.py        /root/
COPY scores.json    /root/
COPY rank.json      /root/
COPY teams.json     /root/

EXPOSE 10111

ENTRYPOINT socat TCP-LISTEN:10111,fork,reuseaddr,bind=0.0.0.0 EXEC:"python3 chal.py",stderr