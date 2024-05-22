#!/bin/bash
docker build --tag=bag-secured .
docker run -p 1337:1337 --rm --name=bag-secured -it bag-secured