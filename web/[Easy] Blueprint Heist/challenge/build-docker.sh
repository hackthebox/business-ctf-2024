#!/bin/bash

docker rm -f blueprint-heist
docker build --tag=blueprint-heist .
docker run -p 1337:1337 -it --rm --name=blueprint-heist blueprint-heist