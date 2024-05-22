FROM ubuntu:latest

EXPOSE 1337

RUN apt update && apt install -y python3 python3-dev python3-pip socat
RUN pip install pycryptodome py_ecc --break-system-packages
RUN useradd --user-group --system --no-log-init ctf

WORKDIR /home/ctf
COPY challenge/* ./
USER ctf

CMD ["socat", "tcp-l:1337,reuseaddr,fork", "EXEC:'python3 /home/ctf/server.py'"]
