FROM ubuntu:22.04

RUN apt update --fix-missing && \
 apt install -y socat && \
 rm -rf /var/lib/apt/lists/*
RUN groupadd -r ctf && useradd -r -g ctf ctf
ADD user_management /home/ctf/
ADD flag.txt /home/ctf/
RUN chmod 644 /home/ctf/flag.txt
RUN chmod +x /home/ctf/user_management
USER ctf
WORKDIR /home/ctf
EXPOSE 1337
ENTRYPOINT ["socat", "tcp-l:1337,reuseaddr,fork", "EXEC:/home/ctf/user_management"]