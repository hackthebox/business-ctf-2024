#!/bin/bash
docker rm -f web_jailbreak
docker build --tag=web_jailbreak .
docker run -p 1337:1337 -it --rm --name=web_jailbreak -v `pwd`/challenge:/app web_jailbreak