FROM ubuntu:20.04
RUN apt update && apt install -y python3
RUN useradd -m pwn
COPY checker.py /
COPY overflow /home/pwn
COPY hello /
RUN chmod +x /home/pwn/overflow && \
    find /home/pwn -type f -user pwn -delete && \
    cp -r /usr/lib* /home/pwn && \
    mkdir /home/pwn/bin && \
    cp /bin/sh /bin/cat /bin/ls /home/pwn/bin && \
    mkdir -p /home/pwn/dev/fd && cd /home/pwn/dev/fd && touch 0 1 2 3 4 5
CMD ["/usr/bin/python3", "-u", "checker.py"]
