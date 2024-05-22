#!/bin/bash
docker build --tag=branching-tactics .
docker run -p 1337:1337 --rm --name=branching-tactics -it branching-tactics