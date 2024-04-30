FROM ubuntu:18.04

RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list && \
    apt-get update && apt-get -y dist-upgrade && \
    apt-get update && apt-get install -y lib32z1 xinetd build-essential && \
    apt-get install -y openssl && \
    apt-get install -y sqlite3 && \
    apt-get install -y apache2 &&\
    apt-get install -y gdbserver &&\
    useradd -m ctf

RUN chmod 777 /var/www/* &&\
    chmod 777 /var/www/html/* &&\
    chown root:ctf /var/www &&\
    chown root:ctf /var/www/html
COPY ./ctf.xinetd /etc/xinetd.d/ctf
COPY ./index.html /var/www/html
COPY ./apache2.conf /etc/apache2
COPY ./check-ok.cgi /var/www/html
COPY ./getcookie.cgi /var/www/html
COPY ./libcgicc.so.3 /usr/lib/libcgicc.so.3
COPY ./libgcc_s.so.1 /lib/x86_64-linux-gnu/libgcc_s.so.1
COPY ./start.sh /home/ctf
COPY ./real.sh /var/www/html/debug.sh

RUN echo "Blocked by ctf_xinetd" > /etc/banner_fail && \
    echo 'ctf - nproc 1500' >>/etc/security/limits.conf

CMD exec /bin/bash -c "echo dXNlcj1gbHMgL2hvbWVgCmlmIFsgISAkREFTRkxBRyBdO3RoZW4KIGVjaG8gZmxhZ3tURVNUX0RBU0ZMQUd9fHRlZSAvaG9tZS8kdXNlci9mbGFnIC9mbGFnCmVsc2UKIGVjaG8gJERBU0ZMQUd8dGVlIC9ob21lLyR1c2VyL2ZsYWcgL2ZsYWcKZmkKY3AgL2hvbWUvJHVzZXIvZmxhZyAvdmFyL3d3dy9mbGFnCmNob3duIHJvb3Q6JHVzZXIgL2hvbWUvJHVzZXIvZmxhZyAvZmxhZyAvdmFyL3d3dy9mbGFnCmNobW9kIDc1NSAvaG9tZS8kdXNlci9mbGFnIC9mbGFnIC92YXIvd3d3L2ZsYWcKL2V0Yy9pbml0LmQvYXBhY2hlMiByZXN0YXJ0|base64 -d|sh;/etc/init.d/xinetd start; trap : TERM INT; sleep infinity & wait"

EXPOSE 80 
