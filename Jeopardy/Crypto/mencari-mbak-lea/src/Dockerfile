FROM python:3.9-slim

RUN apt-get update && apt-get install -y socat && rm -rf /var/lib/apt/lists/*

RUN useradd -m ctf
WORKDIR /home/ctf

COPY server.py .
COPY start.sh .

RUN chown ctf:ctf server.py start.sh && chmod 755 server.py start.sh

USER ctf
EXPOSE 1337

CMD ["./start.sh"]
