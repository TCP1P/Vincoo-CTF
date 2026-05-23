FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y socat && \
    useradd -m ctf


WORKDIR /home/ctf/chal
COPY chall /home/ctf/chal/chall


COPY flag.txt /flag.txt


RUN chmod 755 /home/ctf/chal/chall && \
    chmod 600 /flag.txt && \
    chown ctf:ctf /home/ctf/chal/chall /flag.txt


USER ctf

EXPOSE 1337

CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/home/ctf/chal/chall,pty,stderr,setsid,sigint,sane"]
