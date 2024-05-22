#!/bin/bash
docker build --tag=nothing-without-a-cost .
docker run -p 1337:1337 --rm --name=nothing-without-a-cost -it nothing-without-a-cost