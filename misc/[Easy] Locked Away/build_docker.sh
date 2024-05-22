#!/bin/bash

docker build --tag=misc_locked_away .
docker run -it -p 1337:1337 --rm --name=misc_locked_away misc_locked_away
