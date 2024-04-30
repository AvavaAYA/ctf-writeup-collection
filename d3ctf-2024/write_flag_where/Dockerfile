FROM ubuntu:mantic-20240416

RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list && \
    apt-get update && apt-get -y dist-upgrade && \
    apt-get install -y lib32z1 xinetd

COPY ./ctf.xinetd /etc/xinetd.d/ctf
COPY ./start.sh /start.sh
COPY ./flag /flag
RUN echo "Blocked by ctf_xinetd" > /etc/banner_fail

RUN chmod +x /start.sh

COPY ./vuln /

CMD ["/start.sh"]

EXPOSE 9999
