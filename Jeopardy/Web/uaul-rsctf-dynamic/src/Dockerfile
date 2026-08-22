FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    curl \
    ca-certificates \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

RUN cargo install cargo-binstall && \
    cargo binstall lune -y

WORKDIR /app

RUN git clone --depth 1 https://github.com/Nicell/lynx.git lynx

COPY .luaurc .
COPY server.luau .

# COPY flag.txt /flag.txt
# RUN chmod 444 /flag.txt

COPY flag.txt /flag.txt

RUN FLAG_ID=$(cat /proc/sys/kernel/random/uuid) && \
    cp /flag.txt /flag-${FLAG_ID}.txt && \
    chmod 444 /flag-${FLAG_ID}.txt && \
    rm /flag.txt

RUN useradd -m -s /bin/bash ctf
USER ctf

EXPOSE 3000

CMD ["lune", "run", "server.luau"]

# RSCTF dynamic-flag compatibility layer. The build-time scan records
# exact marker-bearing files; runtime replacement is therefore bounded
# to those files instead of walking the image on every team start.
USER root
COPY rsctf-entrypoint.sh /usr/local/bin/rsctf-entrypoint
RUN set -eu; \
    chmod 0555 /usr/local/bin/rsctf-entrypoint; \
    : > /etc/rsctf-flag-targets; \
    for root in /app /src /srv /home /opt /var/www /challenge /chall /ctf /root /usr/src /usr/local/bin /workspace /flag /flag.txt; do \
      if [ -e "$root" ]; then \
        find "$root" -xdev -type f ! -path /usr/local/bin/rsctf-entrypoint -exec grep -lF -e RSCTF_DYNAMIC_FLAG_efbca9133bad4b590d1811fac1ddb2d8c529 -e RSCTF_DYNAMIC_FLAG_50dc275a23ca42ac7a1536210 {} + >> /etc/rsctf-flag-targets 2>/dev/null || true; \
      fi; \
    done; \
    sort -u /etc/rsctf-flag-targets > /etc/rsctf-flag-targets.sorted; \
    mv /etc/rsctf-flag-targets.sorted /etc/rsctf-flag-targets; \
    while IFS= read -r target; do [ -f "$target" ] && chmod a+w "$target"; done < /etc/rsctf-flag-targets
USER ctf
ENTRYPOINT ["/usr/local/bin/rsctf-entrypoint"]
