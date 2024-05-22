#!/bin/bash

set -ex

########### ENV VARS ###########
NAME=brokenswap
IMAGE=blockchain_${NAME}
#FLAG="HTB{1_w4sn7_7h3_0nly_7h1ng_br0k3}"
#SHARED_SECRET="e45c7cfb-3fc3-4bef-9574-2ca62b6a556c"
#PUBLIC_IP="0.0.0.0"
#TEAM_UUID=$(uuidgen)
SRV_PORT=8000
HANDLER_PORT=8001
HTTP_PORT=3001
################################

#docker rm -f $IMAGE && \
docker build --tag=$IMAGE:latest ./challenge/ && \
docker run -it --rm \
    -p "$HTTP_PORT:$HTTP_PORT" \
    -p "$SRV_PORT:$SRV_PORT" \
    -p "$HANDLER_PORT:$HANDLER_PORT" \
    --name $IMAGE \
    $IMAGE