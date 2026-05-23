FROM python:3.11-alpine

RUN apk update && apk add socat

RUN adduser -D -u 1001 -s /bin/sh ctf

RUN mkdir -p /home/ctf/chall/src

COPY ./chall.py /home/ctf/chall/src
COPY ./run.sh /home/ctf/chall/src
COPY ./flag.txt /home/ctf/chall/src

RUN chown -R root:root /home/ctf/chall
RUN chmod -R 555 /home/ctf/chall
RUN chmod +x /home/ctf/chall/src/run.sh

USER ctf
WORKDIR /home/ctf/chall/src

CMD ["./run.sh"]
