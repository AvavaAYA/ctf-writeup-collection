FROM ubuntu:22.04

RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list && \
    apt-get update && apt-get -y dist-upgrade && \
    apt-get install -y lib32z1 xinetd apache2 netcat

RUN useradd -m ctf

WORKDIR /home/ctf

RUN cp -R /usr/lib* /home/ctf

RUN mkdir /home/ctf/dev && \
    mknod /home/ctf/dev/null c 1 3 && \
    mknod /home/ctf/dev/zero c 1 5 && \
    mknod /home/ctf/dev/random c 1 8 && \
    mknod /home/ctf/dev/urandom c 1 9 && \
    chmod 666 /home/ctf/dev/*

RUN mkdir /home/ctf/bin && \
    cp /bin/sh /home/ctf/bin && \
    cp /bin/ls /home/ctf/bin && \
    cp /bin/cat /home/ctf/bin && \
    cp /bin/nc /home/ctf/nc


RUN echo "Blocked by ctf_xinetd" > /etc/banner_fail


COPY ./bin/ /home/ctf/

#RUN cp /home/ctf/bin/cgi-bin/libc.so.6 /lib/x86_64-linux-gnu/libc.so.6
RUN chown -R root:ctf /home/ctf && \
    chmod -R 755 /home/ctf && \
    cp /home/ctf/cgi-bin/ld-linux-x86-64.so.2 /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 && \
    chmod 744 /home/ctf/flag && \
    chmod -R 555 /home/ctf/cgi-bin/ && \
    a2enmod cgi && \
    a2enmod cgid && \
    cp /home/ctf/serve-cgi-bin.conf /etc/apache2/conf-available/serve-cgi-bin.conf && \
    chown -R root:ctf /var/www/ && \
    chmod 555 /var/www/

RUN apt-get install -y gdbserver

#CMD service apache2 start
CMD ["apachectl", "-D", "FOREGROUND"]

# 8888 for reverse shell
EXPOSE 80 8888
