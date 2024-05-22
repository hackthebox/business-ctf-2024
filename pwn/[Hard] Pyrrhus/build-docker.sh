#!/bin/bash
docker rm -f browser
export DOCKER_BUILDKIT=1
docker build --tag=browser .
docker run -p 1337:5000 --restart=on-failure --name=browser browser
