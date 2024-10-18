FROM pwn.red/jail

COPY --from=sha256:77906da86b60585ce12215807090eb327e7386c8fafb5402369e421f44eff17e / /srv
COPY chal /srv/app/run
COPY flag.txt /srv/app/run
RUN chmod 755 /srv/app/run

ENV JAIL_MEM=10M JAIL_TIME=500
