FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    gcc \
    socat \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash echo

WORKDIR /home/echo

COPY main.c .

# Compile with some protections but format string still works
RUN gcc -o vuln main.c -fno-stack-protector -no-pie

RUN chmod 755 vuln

COPY run.sh .
RUN chmod +x run.sh

USER echo

EXPOSE 1337

CMD ["./run.sh"]

# RSCTF dynamic-flag compatibility layer. The build-time scan records
# exact marker-bearing files; runtime replacement is therefore bounded
# to those files instead of walking the image on every team start.
USER root
COPY rsctf-entrypoint.sh /usr/local/bin/rsctf-entrypoint
RUN set -eu; \
    chmod 0555 /usr/local/bin/rsctf-entrypoint; \
    : > /etc/rsctf-flag-targets; \
    for root in /home/echo /app /src /srv /home /opt /var/www /challenge /chall /ctf /root /usr/src /usr/local/bin /workspace /flag /flag.txt; do \
      if [ -e "$root" ]; then \
        find "$root" -xdev -type f ! -path /usr/local/bin/rsctf-entrypoint -exec grep -lF -e RSCTF_DYNAMIC_FLAG_04fb926ef4d00a3a0cfba49651c886 -e RSCTF_DYNAMIC_FLAG_81b2f3059cb7ead414e {} + >> /etc/rsctf-flag-targets 2>/dev/null || true; \
      fi; \
    done; \
    sort -u /etc/rsctf-flag-targets > /etc/rsctf-flag-targets.sorted; \
    mv /etc/rsctf-flag-targets.sorted /etc/rsctf-flag-targets; \
    while IFS= read -r target; do [ -f "$target" ] && chmod a+w "$target"; done < /etc/rsctf-flag-targets
USER echo
ENTRYPOINT ["/usr/local/bin/rsctf-entrypoint"]
