FROM ubuntu:18.04

RUN sed -i 's@//.*archive.ubuntu.com@//mirrors.ustc.edu.cn@g' /etc/apt/sources.list && \
    apt-get update && \
    apt-get -y install gdbserver libncurses5 xinetd python3

COPY 6502_proccessor /root/6502_proccessor
COPY libc.so.6 /lib/x86_64-linux-gnu/libc.so.6
COPY ctf.xinetd /etc/xinetd.d/ctf

# CMD ["/bin/bash"]
CMD ["/usr/sbin/xinetd","-dontfork"]
