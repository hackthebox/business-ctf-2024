FROM ubuntu:20.04

RUN apt-get update && apt-get install -y socat python3

WORKDIR /app
COPY challenge .

RUN useradd -m ctf
USER ctf

EXPOSE 5000
CMD ["socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:python3 /app/chal.py"]
