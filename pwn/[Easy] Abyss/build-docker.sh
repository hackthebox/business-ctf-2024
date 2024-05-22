#!/bin/bash
docker rm -f pwn_abyss
export DOCKER_BUILDKIT=1
docker build --tag=pwn_abyss .
docker run -p 1337:1337 --restart=on-failure --name=pwn_abyss pwn_abyss
