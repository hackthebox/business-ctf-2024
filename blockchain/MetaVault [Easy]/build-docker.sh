NAME=metavault
IMAGE=blockchain_${NAME}
RPC_PORT=1337
HTTP_PORT=8000
TCP_PORT=1338

docker rm -f $IMAGE
docker build --tag=$IMAGE:latest . && \
docker run --rm -it \
    -p "$RPC_PORT:$RPC_PORT" \
    -p "$HTTP_PORT:$HTTP_PORT" \
    -p "$TCP_PORT:$TCP_PORT" \
    --name $IMAGE \
    $IMAGE:latest
