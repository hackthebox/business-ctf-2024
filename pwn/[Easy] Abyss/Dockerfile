FROM ubuntu:20.04

RUN apt-get update && apt-get install -y socat

WORKDIR /app
COPY challenge/abyss .
COPY challenge/flag.txt .
RUN echo $(tr -dc A-Za-z0-9 </dev/urandom | head -c 15):$(tr -dc A-Za-z0-9 </dev/urandom | head -c 15) > .creds

RUN useradd -m ctf
USER ctf

EXPOSE 1337
CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/app/abyss"]
