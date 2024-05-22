#!/bin/bash

docker build --tag=no_gadgets .
docker run -it -p 1337:1337 --rm --name=no_gadgets no_gadgets