# ubuntu 20.04
FROM ubuntu@sha256:48c35f3de33487442af224ed4aabac19fd9bfbd91ee90e9471d412706b20ba73 as inner

RUN apt-get update && apt-get install -y python3

COPY flag.txt /app/flag.txt

COPY src/mixtape /app/mixtape
COPY src/mixtape_runner.py /app/mixtape_runner.py

COPY src/wrapper.sh /app/run
RUN chmod 755 /app/run


FROM pwn.red/jail

COPY --from=inner / /srv

# temp folder is needed for writing bytecode
# jail pids is by default 5, not enough cause there is a wrapper, python, mixtape, and shell, and I guess something else
ENV JAIL_MEM=10M JAIL_TIME=120 JAIL_TMP_SIZE=4096 JAIL_PIDS=10
