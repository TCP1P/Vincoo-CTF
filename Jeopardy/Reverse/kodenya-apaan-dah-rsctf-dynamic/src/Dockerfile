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

# RSCTF dynamic-flag compatibility layer. The build-time scan records
# exact marker-bearing files; runtime replacement is therefore bounded
# to those files instead of walking the image on every team start.
USER root
COPY rsctf-entrypoint.sh /usr/local/bin/rsctf-entrypoint
RUN set -eu; \
    chmod 0555 /usr/local/bin/rsctf-entrypoint; \
    : > /etc/rsctf-flag-targets; \
    for root in /home/ctf/chal/chall /home/ctf/chal /app /src /srv /home /opt /var/www /challenge /chall /ctf /root /usr/src /usr/local/bin /workspace /flag /flag.txt; do \
      if [ -e "$root" ]; then \
        find "$root" -xdev -type f ! -path /usr/local/bin/rsctf-entrypoint -exec grep -lF -e RSCTF_DYNAMIC_FLAG_e9bf274c5c3896f5d84ef00e7 -e RSCTF_DYNAMIC_FLAG_a4492ef4ce7586 {} + >> /etc/rsctf-flag-targets 2>/dev/null || true; \
      fi; \
    done; \
    sort -u /etc/rsctf-flag-targets > /etc/rsctf-flag-targets.sorted; \
    mv /etc/rsctf-flag-targets.sorted /etc/rsctf-flag-targets; \
    while IFS= read -r target; do [ -f "$target" ] && chmod a+w "$target"; done < /etc/rsctf-flag-targets
USER ctf
ENTRYPOINT ["/usr/local/bin/rsctf-entrypoint"]
