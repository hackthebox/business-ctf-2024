FROM python:3.9-slim-bullseye 

COPY ./challenge/backend/requirements.txt /root

ENV RPC_PORT=1337
ENV TCP_PORT=1338
ENV HTTP_PORT=8000

RUN python3 -m pip install -r /root/requirements.txt && \
    useradd -m ctf && \
    apt update && \
    apt install -y curl socat git wget lighttpd && \
    mkdir -p /startup && \
    mkdir -p /var/log/ctf && \
    touch /var/log/ctf/ctf.log


RUN true \
    && curl -L https://foundry.paradigm.xyz | bash \
    && bash -c "source /root/.bashrc && foundryup" \
    && chmod 755 -R /root \
    && true

RUN true \
    && cd /tmp \
    && wget https://github.com/ethereum/solidity/releases/download/v0.8.25/solc-static-linux \
    && mv solc-static-linux /usr/bin/solc \
    && chmod +x /usr/bin/solc \
    && true

COPY ./config/ /startup/
COPY ./challenge/backend/entrypoint.sh /

COPY ./challenge/backend/eth_sandbox /usr/lib/python/eth_sandbox

ENV PYTHONPATH /usr/lib/python

COPY ./challenge/backend/deploy/ /home/ctf/backend/
COPY ./challenge/backend/contracts /home/ctf/backend/contracts
COPY ./challenge/frontend /home/ctf/frontend

RUN true \
    && chmod 777 /entrypoint.sh \
    && cd /home/ctf/backend/contracts \
    && solc --optimize-runs 1000 \
            --metadata \
            --bin ./MoD_devs/src-secrets-embedded_DONOTDISCLOSE/*.sol \
            -o /home/ctf/backend/contracts/compiled \
    && true

EXPOSE 1337
EXPOSE 1338
EXPOSE 8000
ENTRYPOINT ["/bin/bash", "-c", "./entrypoint.sh"]
