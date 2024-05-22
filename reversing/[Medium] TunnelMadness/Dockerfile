FROM debian:stable-slim
RUN apt-get update && \
    apt-get install -y socat && \
    rm -rf /var/lib/apt/lists/*

EXPOSE 1337
RUN useradd ctf
COPY src/tunnel /
COPY challenge/flag.txt /
USER ctf
CMD ["socat", "tcp-l:1337,nodelay,reuseaddr,fork", "EXEC:stdbuf -o0 /tunnel"]
