#!/bin/bash
docker rm -f magicom
docker build -t magicom . && \
docker run --name=magicom --rm -p1337:1337 -it magicom