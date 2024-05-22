FROM node:18-bookworm-slim as ctf-base

# install utils, create ctf user
RUN true \
    && mkdir /var/log/ctf/ /startup/ \
    && apt update \
    && apt install -y curl git xinetd tini lighttpd python3 python3-pip uuid-runtime \
    && rm -rf /var/cache/apt/archives/ \
    && useradd -m ctf \
    && true

# copy xinetd config and startup scripts
COPY ./startup/ /startup/
COPY entrypoint.sh /entrypoint.sh

#################
#    BACKEND    #
#################
FROM ctf-base as backend

# setup foundry and compile contracts
RUN true \
    && curl -L https://foundry.paradigm.xyz | bash \
    && bash -c "source /root/.bashrc && foundryup" \
    && chmod 755 -R /root/ \
    && true
 
COPY ./backend/contracts/ /tmp/contracts/

RUN true \
    && cd /tmp/contracts/ \
    && /root/.foundry/bin/forge build --out /home/ctf/backend/compiled-contracts/ \
    && rm -rf /tmp/contracts/ \
    && true

# setup challenge handler
COPY ./requirements.txt /tmp/
RUN rm -rf /usr/lib/python3.*/EXTERNALLY-MANAGED
RUN python3 -m pip install -r /tmp/requirements.txt
COPY ./backend/chall_handler/eth_sandbox/ /usr/lib/python3/eth_sandbox/
COPY ./backend/chall_handler/handler.py /home/ctf/backend/handler.py
COPY ./backend/chall_handler/start-handler.sh /home/ctf/backend/chall_handler/


#################
#   FRONTEND    #
#################
FROM backend as frontend

COPY ./frontend/ /home/ctf/frontend/
WORKDIR /home/ctf/frontend/

EXPOSE 8000
EXPOSE 8001
EXPOSE 3001

#RUN yarn install
#RUN export TEAM_UUID=$(uuidgen) && echo $TEAM_UUID > /tmp/TEAM_UUID && export REACT_APP_TEAM_UUID=$TEAM_UUID && yarn build


### Finalizing ###
FROM frontend as final

WORKDIR /home/ctf/
ENTRYPOINT ["tini", "-g", "--"]
CMD ["/entrypoint.sh"]
