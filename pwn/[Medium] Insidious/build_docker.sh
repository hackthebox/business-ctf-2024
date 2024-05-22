#!/bin/bash
export DOCKER_BUILDKIT=1
docker build --tag=pwn_insidious .
docker run -it -p 1337:1337 --rm --name=pwn_insidious pwn_insidious
