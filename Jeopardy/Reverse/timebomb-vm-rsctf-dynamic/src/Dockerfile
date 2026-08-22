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

# RSCTF dynamic-flag compatibility layer. The build-time scan records
# exact marker-bearing files; runtime replacement is therefore bounded
# to those files instead of walking the image on every team start.
USER root
COPY rsctf-entrypoint.sh /usr/local/bin/rsctf-entrypoint
RUN set -eu; \
    chmod 0555 /usr/local/bin/rsctf-entrypoint; \
    : > /etc/rsctf-flag-targets; \
    for root in /home/ctf/chall/flag.txt /home/ctf/chall/run.sh /home/ctf/chall/tbvm.py /home/ctf/chall/server.py /home/ctf/chall/requirements.txt /home/ctf/chall /app /src /srv /home /opt /var/www /challenge /chall /ctf /root /usr/src /usr/local/bin /workspace /flag /flag.txt; do \
      if [ -e "$root" ]; then \
        find "$root" -xdev -type f ! -path /usr/local/bin/rsctf-entrypoint -exec grep -lF -e RSCTF_DYNAMIC_FLAG_8dcbe28221ab55ab63c4f49c511 -e RSCTF_DYNAMIC_FLAG_a5e067a676b2e955 {} + >> /etc/rsctf-flag-targets 2>/dev/null || true; \
      fi; \
    done; \
    sort -u /etc/rsctf-flag-targets > /etc/rsctf-flag-targets.sorted; \
    mv /etc/rsctf-flag-targets.sorted /etc/rsctf-flag-targets; \
    while IFS= read -r target; do [ -f "$target" ] && chmod a+w "$target"; done < /etc/rsctf-flag-targets
USER ctf
ENTRYPOINT ["/usr/local/bin/rsctf-entrypoint"]
