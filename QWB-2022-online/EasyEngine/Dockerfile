FROM ubuntu:20.04

COPY sources.list /etc/apt/sources.list
RUN export DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get upgrade -y
RUN apt-get install lib32z1 xinetd python3 python3-pip -y

RUN useradd -m ctf

RUN mkdir /challenge
COPY ./challenge/ /challenge
RUN chown -R root:ctf /challenge && chmod -R 750 /challenge 

COPY flag /flag
RUN chmod 444 /flag

COPY ./ctf.xinetd /etc/xinetd.d/ctf
COPY ./start.sh /start.sh
RUN echo "Blocked by ctf_xinetd" > /etc/banner_fail

RUN chmod +x /start.sh

CMD ["/start.sh"]

EXPOSE 9999
