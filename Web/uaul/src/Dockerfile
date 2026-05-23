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
