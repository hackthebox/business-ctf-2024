#!/bin/bash

docker build --tag=pwn_regularity .
docker run -it -p 1337:1337 --rm --name=pwn_regularity pwn_regularity