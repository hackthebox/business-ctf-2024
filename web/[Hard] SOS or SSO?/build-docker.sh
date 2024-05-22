#!/bin/bash
docker build --tag=web_sos_sso .
docker run -it -p 1337:8080 --rm --name=web_sos_sso web_sos_sso