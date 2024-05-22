#!/bin/bash
NAME="say_cheese"
docker rm -f hardware_$NAME
docker build --tag=hardware_$NAME . && \
docker run -p 1337:1337 --rm --name=hardware_$NAME --detach hardware_$NAME
