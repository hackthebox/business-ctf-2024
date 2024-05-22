#!/bin/bash
docker rm -f web_chrono_mind
docker build -t web_chrono_mind .
docker run --rm -it -p 1337:1337 --name=web_chrono_mind web_chrono_mind