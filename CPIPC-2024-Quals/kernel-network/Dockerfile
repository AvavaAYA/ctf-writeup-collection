FROM ubuntu:20.04

RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list && \
    apt-get update && apt-get -y dist-upgrade && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get install -y lib32z1 xinetd git libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev qemu qemu-system-x86 cpio
RUN useradd -m ctf
WORKDIR /

COPY ./ctf.xinetd /etc/xinetd.d/ctf
COPY ./bzImage /
#COPY ./rootfs.img /
COPY ./boot.sh /
COPY ./_install /_install
COPY ./start.sh /
RUN chmod +x /boot.sh && chmod +x /start.sh

ENV flag flag{bad_guys!}

RUN echo "Blocked by ctf_xinetd" > /etc/banner_fail
RUN echo 'ctf - nproc 1500' >>/etc/security/limits.conf
CMD exec /bin/bash -c "/etc/init.d/xinetd start; trap : TERM INT; sleep infinity & wait"

EXPOSE 8888 
