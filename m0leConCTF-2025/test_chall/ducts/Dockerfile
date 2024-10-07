FROM cybersecnatlab/socaz:ubuntu-jammy

RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y socat
RUN apt-get install -y libssl-dev

RUN useradd -ms /bin/sh pwn

WORKDIR /home/pwn

COPY ./flag.txt ./
COPY ./chal ./

RUN chown -R root:pwn /home/pwn && chmod 750 /home/pwn && chown root:pwn /home/pwn/flag.txt && chmod 440 /home/pwn/flag.txt && chmod 550 /home/pwn/chal

EXPOSE 4444

CMD ["socat", "-T60", "TCP-LISTEN:4444,reuseaddr,fork,su=pwn", "EXEC:/home/pwn/chal,pty,raw,stderr,echo=0"]