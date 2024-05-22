#!/bin/sh
docker rm -f web_omniwatch
docker build -t web_omniwatch .
docker run --name=web_omniwatch --rm -p1337:1337 -it web_omniwatch