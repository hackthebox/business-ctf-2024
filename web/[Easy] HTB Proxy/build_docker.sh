#!/bin/bash
docker rm -f web_htb_proxy
docker build --tag=web_htb_proxy .
docker run -p 1337:1337 -it --rm --name=web_htb_proxy web_htb_proxy