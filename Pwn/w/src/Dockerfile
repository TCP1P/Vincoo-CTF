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
