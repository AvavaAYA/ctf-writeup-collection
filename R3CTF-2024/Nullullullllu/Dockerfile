FROM ubuntu:24.04@sha256:3f85b7caad41a95462cf5b787d8a04604c8262cdcdf9a472b8c52ef83375fe15

RUN apt-get -y update --fix-missing
RUN apt-get -y upgrade
RUN apt-get -y install socat gdb
RUN groupadd -r ctf && useradd -r -g ctf ctf
RUN chmod 1733 /tmp /var/tmp /dev/shm

ADD . /home/ctf

WORKDIR /home/ctf
RUN echo "R3CTF{test_flag}" > flag.txt
RUN chmod 440 flag.txt
RUN chmod 550 chall

RUN chown -R root:ctf /home/ctf

USER ctf
CMD socat TCP-L:9999,reuseaddr,fork EXEC:"./chall"