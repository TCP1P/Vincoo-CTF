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
