#!/bin/bash

docker rm tunnelmadness
docker build --tag=tunnelmadness . && \
docker run -p 1337:1337 --restart=on-failure --name=tunnelmadness tunnelmadness
