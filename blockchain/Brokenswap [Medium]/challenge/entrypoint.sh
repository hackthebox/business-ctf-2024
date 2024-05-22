#!/bin/bash

set -ex

# set environment variables
export PYTHONPATH=/usr/lib/python3/
export NAME=brokenswap
export IMAGE=blockchain_${NAME}
export FLAG="HTB{1_w4sn7_7h3_0nly_7h1ng_br0k3}"
export SHARED_SECRET="e45c7cfb-3fc3-4bef-9574-2ca62b6a556c"
export PUBLIC_IP="0.0.0.0"
export TEAM_UUID=$(uuidgen)
#export TEAM_UUID=$(cat /tmp/TEAM_UUID)
export REACT_APP_TEAM_UUID=$TEAM_UUID
export SRV_PORT=8000
export HANDLER_PORT=8001
export HTTP_PORT=3001

mkdir -p /home/ctf/frontend/public/connection-info/ && \
ln -s /tmp/$TEAM_UUID /home/ctf/frontend/public/connection-info/$TEAM_UUID
echo $REACT_APP_TEAM_UUID >> /home/ctf/frontend/.env.production && cp /home/ctf/frontend/.env.production /home/ctf/frontend/.env

for f in /startup/*; do
    echo "[+] running $f"
    bash "$f"
done

tail -f /var/log/ctf/*