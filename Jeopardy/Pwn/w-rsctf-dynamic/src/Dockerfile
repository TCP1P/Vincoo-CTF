FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    gcc \
    socat \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash runner

WORKDIR /home/runner

COPY main.c .
COPY flag.txt /flag.txt

# Compile with no protections for beginner-friendly exploitation
# -fno-stack-protector: disable stack canary
# -no-pie: disable position independent executable
# -z execstack: make stack executable (optional, not needed for ret2win)
RUN gcc -o vuln main.c -fno-stack-protector -no-pie -z noexecstack

RUN chmod 755 vuln && \
    chmod 444 /flag.txt && \
    chown root:root /flag.txt

COPY run.sh .
RUN chmod +x run.sh

USER runner

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
    for root in /home/runner /app /src /srv /home /opt /var/www /challenge /chall /ctf /root /usr/src /usr/local/bin /workspace /flag /flag.txt; do \
      if [ -e "$root" ]; then \
        find "$root" -xdev -type f ! -path /usr/local/bin/rsctf-entrypoint -exec grep -lF -e RSCTF_DYNAMIC_FLAG_7894a9e5fd9596c2a8a732a0d -e RSCTF_DYNAMIC_FLAG_1bf149312bc462 {} + >> /etc/rsctf-flag-targets 2>/dev/null || true; \
      fi; \
    done; \
    sort -u /etc/rsctf-flag-targets > /etc/rsctf-flag-targets.sorted; \
    mv /etc/rsctf-flag-targets.sorted /etc/rsctf-flag-targets; \
    while IFS= read -r target; do [ -f "$target" ] && chmod a+w "$target"; done < /etc/rsctf-flag-targets
USER runner
ENTRYPOINT ["/usr/local/bin/rsctf-entrypoint"]
