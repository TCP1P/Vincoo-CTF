FROM python:3.11-alpine

RUN apk add --no-cache socat

RUN adduser -D -u 1001 -s /bin/sh ctf

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /home/ctf/chall

COPY ./requirements.txt /home/ctf/chall/requirements.txt
RUN pip3 install --no-cache-dir -r /home/ctf/chall/requirements.txt

COPY ./server.py /home/ctf/chall/server.py
COPY ./tbvm.py /home/ctf/chall/tbvm.py
COPY ./run.sh /home/ctf/chall/run.sh
COPY ./flag.txt /home/ctf/chall/flag.txt

RUN chown -R root:root /home/ctf/chall \
 && chmod 555 /home/ctf/chall \
 && chmod 555 /home/ctf/chall/*.py /home/ctf/chall/run.sh \
 && chmod 444 /home/ctf/chall/flag.txt

USER ctf
WORKDIR /home/ctf/chall

CMD ["./run.sh"]
